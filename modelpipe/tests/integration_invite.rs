//! Pairing through the edge, over a real pipe.
//!
//! Hermetic, like `integration_identity.rs`: discovery and port mapping are
//! off on both sides, so the ticket's own paths are the only ones and nothing
//! contacts n0.

mod common;

use std::num::NonZeroU8;
use std::time::Duration;

use common::{MockBackend, request, within};
use modelpipe::{
    ConnectHandle, ConnectOptions, InviteOptions, InviteOutcome, InviteRefusal, PAIR_PATH,
    ServeError, ServeHandle, ServeOptions, TokenPolicy,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const OK_BODY: &str = r#"{"object":"list","data":[]}"#;

/// A listener over `backend` under `auth`, with discovery and port mapping off.
async fn listening(backend: &MockBackend, auth: TokenPolicy) -> ServeHandle {
    let mut opts = ServeOptions::default();
    opts.auth = auth;
    opts.port_mapping = false;
    opts.discovery = false;
    within(
        "serve must bind",
        Box::pin(modelpipe::serve(&backend.url, opts)),
    )
    .await
    .expect("serve")
}

/// A connect side that has reached `serving`, with discovery and port mapping
/// off.
async fn dialling(serving: &ServeHandle) -> ConnectHandle {
    let mut opts = ConnectOptions::default();
    opts.port_mapping = false;
    opts.discovery = false;
    let connected = within(
        "connect must bind",
        Box::pin(modelpipe::connect(&serving.ticket(), opts)),
    )
    .await
    .expect("connect");
    connected
        .wait_reachable(Duration::from_secs(20))
        .await
        .expect("the serve side is right there");
    connected
}

/// `POST` `body` to `path` through `connected`, bearing `bearer`, and return
/// the raw response.
async fn post(connected: &ConnectHandle, path: &str, bearer: &str, body: &str) -> String {
    let authority = connected.local_addr();
    let mut socket = tokio::net::TcpStream::connect(authority)
        .await
        .expect("the local port");
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Bearer {bearer}\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    socket.write_all(request.as_bytes()).await.expect("write");
    let mut seen = Vec::new();
    socket.read_to_end(&mut seen).await.expect("read");
    String::from_utf8_lossy(&seen).into_owned()
}

/// The `api_key` a 200 carries.
fn api_key(response: &str) -> String {
    let field = r#""api_key":""#;
    let start = response.find(field).expect("an api_key") + field.len();
    let end = response[start..].find('"').expect("its end") + start;
    response[start..end].to_owned()
}

#[tokio::test]
async fn a_device_pairs_through_the_edge_and_its_key_admits() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let serving = listening(&backend, TokenPolicy::Named).await;
    let invite = serving.invite(InviteOptions::default()).expect("an invite");
    invite.arm();
    let device = dialling(&serving).await;

    let response = within(
        "the pairing request",
        post(&device, PAIR_PATH, invite.code().as_str(), "Laptop"),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let key = api_key(&response);
    assert_eq!(key, invite.api_key());
    assert_eq!(
        within("the outcome", invite.handle().outcome()).await,
        InviteOutcome::Redeemed {
            device: invite.device().to_owned(),
            peer: device.peer_id(),
            label: Some("Laptop".to_owned()),
        }
    );

    let admitted = within(
        "a request with the key",
        request(
            &device.base_url(),
            "/v1/models",
            Some(&format!("Bearer {key}")),
        ),
    )
    .await
    .expect("request");
    assert!(admitted.starts_with("HTTP/1.1 200"), "{admitted}");
    assert_eq!(
        backend.accepts(),
        1,
        "the pairing request never reached the backend"
    );

    device.shutdown().await;
    serving.shutdown().await;
}

#[tokio::test]
async fn a_stranger_locked_out_by_wrong_codes_cannot_redeem_and_the_device_still_can() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let serving = listening(&backend, TokenPolicy::Named).await;
    let invite = serving.invite(InviteOptions::default()).expect("an invite");
    invite.arm();
    let code = invite.code().as_str().to_owned();
    let wrong = if code == "000000" { "000001" } else { "000000" };

    let stranger = dialling(&serving).await;
    for _ in 0..3 {
        let refused = within("a wrong code", post(&stranger, PAIR_PATH, wrong, "")).await;
        assert!(refused.starts_with("HTTP/1.1 401"), "{refused}");
    }
    let locked_out = within(
        "the right code, too late",
        post(&stranger, PAIR_PATH, &code, ""),
    )
    .await;
    assert!(locked_out.starts_with("HTTP/1.1 401"), "{locked_out}");
    assert_eq!(
        invite.handle().ended(),
        None,
        "the stranger did not end the invite"
    );

    let device = dialling(&serving).await;
    let paired = within("the device's request", post(&device, PAIR_PATH, &code, "")).await;
    assert!(paired.starts_with("HTTP/1.1 200"), "{paired}");

    stranger.shutdown().await;
    device.shutdown().await;
    serving.shutdown().await;
}

#[tokio::test]
async fn an_invite_ends_once_and_says_how() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let serving = listening(&backend, TokenPolicy::Named).await;

    let mut short = InviteOptions::default();
    short.ttl = Duration::from_millis(200);
    let expiring = serving.invite(short).expect("an invite");
    assert_eq!(
        within("the expiry", expiring.handle().outcome()).await,
        InviteOutcome::Expired
    );

    let withdrawn = serving.invite(InviteOptions::default()).expect("an invite");
    withdrawn.handle().withdraw();
    assert_eq!(withdrawn.handle().ended(), Some(InviteOutcome::Withdrawn));

    let forgotten = serving.invite(InviteOptions::default()).expect("an invite");
    assert!(serving.remove_token(forgotten.device()));
    assert_eq!(
        forgotten.handle().ended(),
        Some(InviteOutcome::Withdrawn),
        "removing the key withdraws its invite"
    );

    let live = serving.invite(InviteOptions::default()).expect("an invite");
    serving.shutdown().await;
    assert_eq!(
        within("the close", live.handle().outcome()).await,
        InviteOutcome::Withdrawn
    );
}

#[tokio::test]
async fn an_invite_the_listener_cannot_honour_is_refused_and_holds_nothing() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let open = listening(&backend, TokenPolicy::InsecureNoAuth).await;
    assert!(matches!(
        open.invite(InviteOptions::default()),
        Err(ServeError::Invite(InviteRefusal::OpenListener))
    ));
    open.shutdown().await;

    let serving = listening(&backend, TokenPolicy::Named).await;
    let mut long = InviteOptions::default();
    long.ttl = Duration::from_mins(16);
    assert!(matches!(
        serving.invite(long),
        Err(ServeError::Invite(InviteRefusal::TtlTooLong))
    ));
    let mut lenient = InviteOptions::default();
    lenient.wrong_codes = NonZeroU8::new(11).expect("eleven is not zero");
    assert!(matches!(
        serving.invite(lenient),
        Err(ServeError::Invite(InviteRefusal::TooManyWrongCodes))
    ));
    assert!(serving.token_names().is_empty(), "nothing was held");
    serving.shutdown().await;
    assert!(matches!(
        serving.invite(InviteOptions::default()),
        Err(ServeError::Invite(InviteRefusal::Closed))
    ));
}
