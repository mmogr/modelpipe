//! Tests for [`super`] — dialling the serve side, and finding it again.
//!
//! Split out via `#[path]` so `peer.rs` stays inside the file-size budget.
//!
//! These bind real endpoints, and they have to. Everything above the
//! transport in this crate is exercised over `tokio::io::duplex()`, but a
//! reconnection is a statement about iroh: that the endpoint id in a ticket
//! outlives the connection made from it, and that dialling it a second time
//! reaches the same peer. A stub cannot be wrong about that in the way the
//! real thing can.
//!
//! Nothing here leaves the machine. Both endpoints are in this process and
//! pair over their own direct addresses.

use std::time::Duration;

use iroh::endpoint::presets;

use super::*;

/// Long enough that a failure is a failure rather than a slow machine.
const PATIENCE: Duration = Duration::from_secs(20);

/// An endpoint that answers this crate's ALPN, standing in for a serve
/// side without any of the listener above it.
///
/// The accepted connections are held rather than dropped: a connection the
/// far end has let go is not the state under test here, and dropping them
/// would make every test below race the peer's own teardown.
async fn accepting() -> (Endpoint, tokio::sync::mpsc::UnboundedReceiver<Connection>) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let endpoint = Endpoint::builder(presets::N0)
        .alpns(vec![transport::ALPN.to_vec()])
        .bind()
        .await
        .expect("an endpoint binds");
    let accepting = endpoint.clone();
    tokio::spawn(async move {
        while let Some(incoming) = accepting.accept().await {
            if let Ok(connection) = incoming.await {
                let _ = tx.send(connection);
            }
        }
    });
    (endpoint, rx)
}

/// A ticket naming an endpoint, exactly as `ServeHandle::ticket` mints one.
fn ticket_for(endpoint: &Endpoint) -> Ticket {
    transport::ticket_from(&endpoint.addr())
}

// ── The first dial ───────────────────────────────────────────────────────

/// A ticket for a live peer reaches it, and the connection is available to
/// the exchanges that will want it.
#[tokio::test]
async fn a_ticket_for_a_live_peer_dials_it_and_holds_the_connection() {
    let (endpoint, _accepted) = accepting().await;
    let peer = tokio::time::timeout(
        PATIENCE,
        Peer::dial(&ticket_for(&endpoint), &ConnectOptions::default()),
    )
    .await
    .expect("the dial must not hang")
    .expect("a live peer is reachable");

    assert!(peer.current().is_some(), "and the connection is held");
}

// ── Finding it again ─────────────────────────────────────────────────────

/// The claim reconnecting rests on: the endpoint id in a ticket outlives
/// any one connection made from it, so dialling a second time reaches the
/// same peer.
///
/// This is the half a stub could not check. `keep_connected` is a loop
/// around exactly this call, and if a second dial to the same address did
/// not work, the loop would spin for ever publishing `Idle` at a peer that
/// was there the whole time.
#[tokio::test]
async fn a_peer_can_be_dialled_again_at_the_same_identity() {
    let (endpoint, _accepted) = accepting().await;
    let peer = tokio::time::timeout(
        PATIENCE,
        Peer::dial(&ticket_for(&endpoint), &ConnectOptions::default()),
    )
    .await
    .expect("the dial must not hang")
    .expect("a live peer is reachable");
    let first = peer.current().expect("a connection").stable_id();

    let path = tokio::time::timeout(PATIENCE, peer.redial())
        .await
        .expect("the re-dial must not hang")
        .expect("the same peer is still there");

    let second = peer.current().expect("a connection").stable_id();
    assert_ne!(first, second, "a genuinely new connection, not the old one");
    assert!(
        matches!(path, PeerPath::Direct | PeerPath::Relayed),
        "and it reports a path it is actually using"
    );
}

// ── Forgetting the right connection ──────────────────────────────────────

/// `forget` clears the connection it was given and nothing else.
///
/// The condition is not defensive tidiness. The reconnect loop notices a
/// death and then takes the write lock, and in between a later pass may
/// already have installed a replacement; an unconditional clear would throw
/// that away and open a gap nobody asked for, which on a busy pipe is a
/// 502 for every request until the next dial lands.
#[tokio::test]
async fn forgetting_a_replaced_connection_leaves_its_successor_alone() {
    let (endpoint, _accepted) = accepting().await;
    let peer = tokio::time::timeout(
        PATIENCE,
        Peer::dial(&ticket_for(&endpoint), &ConnectOptions::default()),
    )
    .await
    .expect("the dial must not hang")
    .expect("a live peer is reachable");
    let stale = peer.current().expect("a connection");

    tokio::time::timeout(PATIENCE, peer.redial())
        .await
        .expect("the re-dial must not hang")
        .expect("the same peer is still there");
    let live = peer.current().expect("a replacement").stable_id();

    peer.forget(&stale);

    assert_eq!(
        peer.current().map(|c| c.stable_id()),
        Some(live),
        "forgetting the connection that died must not drop the one that replaced it"
    );
}

/// The control for the test above: given the connection that is actually
/// held, `forget` does clear it. Without this, a `forget` that had simply
/// stopped working would pass.
#[tokio::test]
async fn forgetting_the_live_connection_clears_it() {
    let (endpoint, _accepted) = accepting().await;
    let peer = tokio::time::timeout(
        PATIENCE,
        Peer::dial(&ticket_for(&endpoint), &ConnectOptions::default()),
    )
    .await
    .expect("the dial must not hang")
    .expect("a live peer is reachable");
    let live = peer.current().expect("a connection");

    peer.forget(&live);

    assert!(
        peer.current().is_none(),
        "and the pipe now knows it has no connection"
    );
}
