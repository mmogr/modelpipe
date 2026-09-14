//! Pairing in one call, over a real pipe.
//!
//! Hermetic, like `integration_invite.rs`: discovery and port mapping are off
//! on both sides.

mod common;

use std::time::Duration;

use common::{MockBackend, request, within};
use modelpipe::{
    ConnectOptions, InviteOptions, InviteOutcome, PairError, PairingString, ServeHandle,
    ServeOptions, TokenPolicy, Unreached,
};

const OK_BODY: &str = r#"{"object":"list","data":[]}"#;

fn hermetic() -> ConnectOptions {
    let mut opts = ConnectOptions::default();
    opts.port_mapping = false;
    opts.discovery = false;
    opts
}

async fn listening(backend: &MockBackend) -> ServeHandle {
    let mut opts = ServeOptions::default();
    opts.auth = TokenPolicy::Named;
    opts.port_mapping = false;
    opts.discovery = false;
    within(
        "serve must bind",
        Box::pin(modelpipe::serve(&backend.url, opts)),
    )
    .await
    .expect("serve")
}

#[tokio::test]
async fn a_device_pairs_in_one_call_and_the_key_it_gets_admits_it() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let serving = listening(&backend).await;
    let invite = serving.invite(InviteOptions::default()).expect("an invite");
    invite.arm();

    let paired = within(
        "pairing",
        Box::pin(modelpipe::pair(
            invite.pairing(),
            Some("Laptop"),
            hermetic(),
            Duration::from_secs(20),
        )),
    )
    .await
    .expect("paired");
    assert_eq!(paired.api_key, invite.api_key());
    assert_eq!(paired.device, invite.device());
    assert_eq!(
        within("the outcome", invite.handle().outcome()).await,
        InviteOutcome::Redeemed {
            device: invite.device().to_owned(),
            peer: paired.handle.peer_id(),
            label: Some("Laptop".to_owned()),
        }
    );

    let admitted = within(
        "a request over the same pipe",
        request(
            &paired.handle.base_url(),
            "/v1/models",
            Some(&format!("Bearer {}", paired.api_key)),
        ),
    )
    .await
    .expect("request");
    assert!(admitted.starts_with("HTTP/1.1 200"), "{admitted}");

    paired.handle.shutdown().await;
    serving.shutdown().await;
}

#[tokio::test]
async fn a_wrong_code_is_refused_and_a_ticket_alone_has_no_code() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let serving = listening(&backend).await;
    let invite = serving.invite(InviteOptions::default()).expect("an invite");
    invite.arm();
    let wrong = if invite.code().as_str() == "000000" {
        "000001"
    } else {
        "000000"
    };

    let guess = PairingString::new(serving.ticket(), Some(wrong.parse().expect("a code")));
    let refused = within(
        "a wrong code",
        Box::pin(modelpipe::pair(
            &guess,
            None,
            hermetic(),
            Duration::from_secs(20),
        )),
    )
    .await;
    assert!(matches!(refused, Err(PairError::Refused)), "{refused:?}");
    assert_eq!(
        invite.handle().ended(),
        None,
        "one wrong code does not end the invite"
    );

    let bare = PairingString::new(serving.ticket(), None);
    let no_code = modelpipe::pair(&bare, None, hermetic(), Duration::from_secs(1)).await;
    assert!(matches!(no_code, Err(PairError::NoCode)), "{no_code:?}");

    serving.shutdown().await;
}

#[tokio::test]
async fn a_serve_side_that_has_gone_is_not_reached() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let serving = listening(&backend).await;
    let invite = serving.invite(InviteOptions::default()).expect("an invite");
    let pairing = invite.pairing().clone();
    serving.shutdown().await;

    let result = modelpipe::pair(&pairing, None, hermetic(), Duration::from_millis(300)).await;
    assert!(
        matches!(result, Err(PairError::Unreached(Unreached::TimedOut(_)))),
        "{result:?}"
    );
}
