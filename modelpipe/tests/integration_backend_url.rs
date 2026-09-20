//! The backend's permission, through a real `serve`.
//!
//! [`BackendUrl`] is pure address arithmetic and its unit tests check the
//! arithmetic. What they cannot check is the part that matters: that
//! `serve` reads the permission off the value it was handed, and refuses
//! when it is absent. That needs a listener, so it lives here.
//!
//! Discovery and port mapping are off, so nothing contacts n0.

mod common;

use std::time::Duration;

use common::{MockBackend, request, within};
use modelpipe::{BackendUrl, ServeError, TokenPolicy};

const OK_BODY: &str = r#"{"object":"list","data":[]}"#;

/// Start a listener over `backend`, with discovery and port mapping off.
async fn serving(backend: BackendUrl) -> Result<modelpipe::ServeHandle, ServeError> {
    let mut opts = common::serve_options();
    opts.auth = TokenPolicy::Generate;
    within(
        "serve must settle",
        Box::pin(modelpipe::serve(backend, opts)),
    )
    .await
}

/// A wildcard bind is dialled on loopback, and a request goes all the way
/// through to the backend behind it.
///
/// The unit tests assert the string `at` builds. This asserts that string
/// was the *right* one, which only a request can: the mock listens on
/// `127.0.0.1:P`, the value served is built from `0.0.0.0:P`, and the
/// backend counts the request that arrives. Drop the rewrite and the URL
/// classifies `Unspecified`, which `serve` refuses outright.
#[tokio::test]
async fn a_wildcard_bind_is_dialled_on_loopback_and_carries_a_request() {
    let backend = MockBackend::json(200, OK_BODY).await;
    // The mock binds loopback, as every backend in these tests does. What
    // a caller reads back from a server bound to the *wildcard* is the
    // same port with no host, which is the address under test.
    let port = backend
        .url
        .rsplit(':')
        .next()
        .expect("a port")
        .parse::<u16>()
        .expect("a number");
    let wildcard = format!("0.0.0.0:{port}").parse().expect("an address");

    let listener = serving(BackendUrl::at(wildcard))
        .await
        .expect("a wildcard bind is dialled on loopback");
    let token = listener.token().expect("a token is enforced");
    let device = within(
        "connect must settle",
        Box::pin(modelpipe::connect(
            &listener.ticket(),
            common::connect_options(),
        )),
    )
    .await
    .expect("connect");
    device
        .wait_reachable(Duration::from_secs(20))
        .await
        .expect("the device reaches the serve side");

    let answered = within(
        "a request through the tunnel",
        request(
            &device.base_url(),
            "/v1/models",
            Some(&format!("Bearer {token}")),
        ),
    )
    .await
    .expect("request");

    assert!(answered.starts_with("HTTP/1.1 200"), "{answered}");
    assert_eq!(
        backend.accepts(),
        1,
        "the rewritten address is where the backend actually is"
    );

    device.shutdown().await;
    listener.shutdown().await;
}

/// **The permission is read from the value, and its absence refuses.**
///
/// A private URL that nobody permitted is `BackendNotLocal` — the same
/// answer as before this type existed, now reached through the value
/// rather than through an option.
#[tokio::test]
async fn a_private_url_nobody_permitted_is_refused() {
    let Err(refused) = serving(BackendUrl::dial("http://192.168.1.5:11434")).await else {
        panic!("a private address nobody permitted must be refused");
    };

    assert!(
        matches!(&refused, ServeError::BackendNotLocal { url } if url == "http://192.168.1.5:11434"),
        "got {refused:?}"
    );
    assert!(!refused.is_retryable(), "the operator named this address");
}

/// And saying so is what admits it. The address is unroutable here, so the
/// listener gets as far as *dialling* and no further — which is the point:
/// what is being checked is that the locality rule let it through, not
/// that anything answers.
#[tokio::test]
async fn permitting_a_private_url_gets_past_the_locality_rule() {
    let attempted = serving(BackendUrl::dial("http://192.168.0.2:1").allow_private()).await;

    match attempted {
        // Bound: the rule admitted the address. Nothing is listening
        // there, which a request would discover, but `serve` does not
        // connect to the backend to start.
        Ok(handle) => handle.shutdown().await,
        Err(why) => assert!(
            !matches!(why, ServeError::BackendNotLocal { .. }),
            "the permission was not honoured: {why:?}"
        ),
    }
}

/// Link-local is refused however it is asked for, which is the half the
/// permission does not move. `169.254.169.254` is cloud instance metadata,
/// and a tunnel that dialled it on a stranger's behalf would be a
/// credential-exfiltration primitive.
#[tokio::test]
async fn link_local_is_refused_even_when_private_is_permitted() {
    let Err(refused) = serving(BackendUrl::dial("http://169.254.169.254:80").allow_private()).await
    else {
        panic!("metadata is never a backend");
    };

    assert!(
        matches!(refused, ServeError::BackendNotLocal { .. }),
        "got {refused:?}"
    );
}
