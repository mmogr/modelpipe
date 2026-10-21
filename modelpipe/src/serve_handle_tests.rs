//! Tests for [`super`] — the steps inside [`ServeHandle`] methods that a
//! public call cannot stop between.
//!
//! Split out via `#[path]` so `serve_handle.rs` stays inside the file-size
//! budget.

use std::time::{Duration, Instant};

use super::*;
use crate::invite::InviteOutcome;
use crate::serve::serve;
use crate::serve_options::ServeOptions;
use crate::token_policy::TokenPolicy;

/// A listener that admits by name, with discovery and port mapping off, and
/// the backend port it was pointed at, kept bound for the test.
async fn listening() -> (ServeHandle, tokio::net::TcpListener) {
    let backend = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let url = format!("http://{}", backend.local_addr().expect("bound"));
    let opts = ServeOptions {
        auth: TokenPolicy::Named,
        discovery: false,
        port_mapping: false,
        ..ServeOptions::default()
    };
    let serving = serve(&url, opts).await.expect("a listener starts");
    (serving, backend)
}

/// The interleaving `remove_token`'s first withdrawal cannot catch: the key
/// is held, then removed, and only then is the invite registered.
#[tokio::test]
async fn an_invite_registered_after_its_key_is_removed_is_withdrawn() {
    let (serving, _backend) = listening().await;
    let key = mint();
    serving.hold("laptop", key.clone(), None).expect("held");
    assert!(serving.remove_token("laptop"));

    let registered =
        serving.register_invite("laptop", &key, Instant::now() + Duration::from_mins(2), 3);
    let handle = InviteHandle {
        id: registered.id,
        outcome: registered.outcome,
        invites: Arc::clone(serving.state.credential.invites()),
    };
    assert_eq!(
        handle.ended(),
        Some(InviteOutcome::Withdrawn),
        "a code for a key nothing holds is never live"
    );
    serving.shutdown().await;
}

/// A key still held keeps its invite live: the check withdraws only what
/// has lost its key.
#[tokio::test]
async fn an_invite_whose_key_is_held_stays_live() {
    let (serving, _backend) = listening().await;
    let key = mint();
    serving.hold("laptop", key.clone(), None).expect("held");

    let registered =
        serving.register_invite("laptop", &key, Instant::now() + Duration::from_mins(2), 3);
    assert_eq!(registered.outcome.borrow().clone(), None);
    let other = serving.register_invite(
        "laptop",
        &mint(),
        Instant::now() + Duration::from_mins(2),
        3,
    );
    assert_eq!(
        other.outcome.borrow().clone(),
        Some(InviteOutcome::Withdrawn),
        "a different key under the same name is not this invite's key"
    );
    serving.shutdown().await;
}
