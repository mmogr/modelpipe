//! The connect side's lasting identity, over a real pipe.
//!
//! A connect side that keeps its key is the same peer every time it
//! connects, and the serve side sees exactly the id the handle reports. The
//! pipes here run with discovery and port mapping off on both sides, so the
//! ticket's own paths are the only ones and nothing contacts n0.

mod common;

use std::path::PathBuf;
use std::time::Duration;

use common::{MockBackend, Scratch, request, within};
use modelpipe::{ConnectOptions, PeerId, ServeHandle, TokenPolicy};

const OK_BODY: &str = r#"{"object":"list","data":[]}"#;

/// Connect options that contact nothing but the ticket's own paths.
fn hermetic(identity: Option<PathBuf>) -> ConnectOptions {
    let mut opts = common::connect_options();
    opts.identity = identity;
    opts
}

/// A listener over `backend`, with discovery and port mapping off.
async fn listening(backend: &MockBackend) -> ServeHandle {
    let mut opts = common::serve_options();
    opts.auth = TokenPolicy::Generate;
    within(
        "serve must bind",
        Box::pin(modelpipe::serve(&backend.url, opts)),
    )
    .await
    .expect("serve")
}

/// Whether `serving` carries a peer with `id`'s fingerprint.
fn carries(serving: &ServeHandle, id: PeerId) -> bool {
    serving
        .peers()
        .iter()
        .any(|peer| peer.fingerprint == id.fingerprint())
}

/// Connect as `identity`, wait until the serve side carries this peer, hang
/// up, and wait until it has let the peer go. The id the handle reported.
async fn seen_as(serving: &ServeHandle, identity: Option<PathBuf>) -> PeerId {
    let connected = within(
        "connect must bind",
        Box::pin(modelpipe::connect(&serving.ticket(), hermetic(identity))),
    )
    .await
    .expect("connect");
    let id = connected.peer_id();
    within("the serve side must carry this peer", async {
        while !carries(serving, id) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    connected.shutdown().await;
    drop(connected);
    within("the serve side must let this peer go", async {
        while carries(serving, id) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    id
}

#[tokio::test]
async fn a_connect_side_that_keeps_its_key_is_the_same_peer_every_time() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let serving = listening(&backend).await;
    let scratch = Scratch::new("connect-identity");
    let key = scratch.join("connect_identity");

    let first = seen_as(&serving, Some(key.clone())).await;
    let second = seen_as(&serving, Some(key.clone())).await;
    assert_eq!(first, second, "the stored key is the same peer");

    let fresh = seen_as(&serving, None).await;
    assert_ne!(fresh, first, "and without it, a new one each time");
    serving.shutdown().await;
}

/// A key others can read is refused as the connect side's own error, naming
/// the file, before anything is dialled.
#[cfg(unix)]
#[tokio::test]
async fn a_connect_identity_others_can_read_is_refused() {
    use modelpipe::ConnectError;
    use std::os::unix::fs::PermissionsExt as _;

    let backend = MockBackend::json(200, OK_BODY).await;
    let serving = listening(&backend).await;
    let scratch = Scratch::new("connect-identity-exposed");
    let key = scratch.join("connect_identity");
    seen_as(&serving, Some(key.clone())).await;
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).expect("chmod");

    let refused = within(
        "connect must refuse at once",
        Box::pin(modelpipe::connect(
            &serving.ticket(),
            hermetic(Some(key.clone())),
        )),
    )
    .await
    .err()
    .expect("a key others can read is refused");
    assert!(
        matches!(&refused, ConnectError::Identity { path, .. } if *path == key.display().to_string()),
        "{refused}"
    );
    assert!(!refused.is_retryable());
    serving.shutdown().await;
}

/// A token pinned to one connect side admits that side, and is refused from
/// another that presents the same key: a copied key is no use on its own.
#[tokio::test]
async fn a_token_pinned_to_one_connect_side_is_refused_from_another() {
    const KEY: &str = "sk-zzq-the-laptops-key";
    let backend = MockBackend::json(200, OK_BODY).await;
    let mut opts = common::serve_options();
    opts.auth = TokenPolicy::Named;
    let serving = within(
        "serve must bind",
        Box::pin(modelpipe::serve(&backend.url, opts)),
    )
    .await
    .expect("serve");
    let scratch = Scratch::new("pinned-token");
    let device = within(
        "the device's connect must bind",
        Box::pin(modelpipe::connect(
            &serving.ticket(),
            hermetic(Some(scratch.join("device"))),
        )),
    )
    .await
    .expect("connect");
    let copied = within(
        "the copy's connect must bind",
        Box::pin(modelpipe::connect(&serving.ticket(), hermetic(None))),
    )
    .await
    .expect("connect");
    serving
        .add_token_pinned("laptop", KEY.to_owned(), device.peer_id())
        .expect("held");
    for side in [&device, &copied] {
        side.wait_reachable(Duration::from_secs(20))
            .await
            .expect("both sides reach the serve side");
    }

    let bearer = format!("Bearer {KEY}");
    let admitted = within(
        "the device's request",
        request(&device.base_url(), "/v1/models", Some(&bearer)),
    )
    .await
    .expect("request");
    assert!(admitted.starts_with("HTTP/1.1 200"), "{admitted}");
    let refused = within(
        "the copy's request",
        request(&copied.base_url(), "/v1/models", Some(&bearer)),
    )
    .await
    .expect("request");
    assert!(refused.starts_with("HTTP/1.1 401"), "{refused}");

    device.shutdown().await;
    copied.shutdown().await;
    serving.shutdown().await;
}
