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
use crate::lifecycle::PeerPath;

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

/// This side's endpoint, opened against a ticket and nothing dialled.
async fn bound(endpoint: &Endpoint) -> Peer {
    tokio::time::timeout(
        PATIENCE,
        Peer::bind(&ticket_for(endpoint), &ConnectOptions::default()),
    )
    .await
    .expect("the bind must not hang")
    .expect("an endpoint binds")
}

/// [`bound`], with one connection dialled — the state every test below the
/// first dial starts from.
async fn connected(endpoint: &Endpoint) -> Peer {
    let peer = bound(endpoint).await;
    tokio::time::timeout(PATIENCE, peer.redial())
        .await
        .expect("the dial must not hang")
        .expect("a live peer is reachable");
    peer
}

// ── The first dial ───────────────────────────────────────────────────────

/// `bind` opens this side's endpoint and stops there.
///
/// The property `connect` returning early rests on: no dial has happened,
/// so nothing has waited on one. If this ever holds a connection again,
/// `connect` is back to costing its caller thirty seconds at a peer that
/// is not there — and it would do it against a *live* endpoint, which is
/// why this test uses one rather than an address nobody answers.
#[tokio::test]
async fn binding_reaches_nobody_even_when_the_peer_is_right_there() {
    let (endpoint, _accepted) = accepting().await;
    let peer = bound(&endpoint).await;

    assert!(
        peer.current().is_none(),
        "binding must not have dialled anyone"
    );
}

/// A ticket for a live peer reaches it, and the connection is available to
/// the exchanges that will want it.
#[tokio::test]
async fn a_ticket_for_a_live_peer_dials_it_and_holds_the_connection() {
    let (endpoint, _accepted) = accepting().await;
    let peer = connected(&endpoint).await;

    assert!(peer.current().is_some(), "and the connection is held");
}

/// The first connection is the reconnect loop's to make, and this is the
/// only test that would notice if it stopped making it.
///
/// Every other status assertion in the crate starts from a pipe that is
/// already up. A loop that only ever *re*-dialled would leave a freshly
/// connected side at `Idle` for ever, with a bound port answering 502 and
/// nothing anywhere saying why.
#[tokio::test]
async fn the_reconnect_loop_makes_the_first_connection_too() {
    let (endpoint, _accepted) = accepting().await;
    let peer = bound(&endpoint).await;
    let lifecycle = Lifecycle::new();
    assert_eq!(
        lifecycle.status(),
        PipeStatus::Idle,
        "nothing is reached before the loop runs"
    );

    // `keep_connected` never returns, so the reached status is what ends
    // this rather than the loop finishing.
    tokio::time::timeout(PATIENCE, async {
        tokio::select! {
            () = keep_connected(&peer, &lifecycle) => {}
            () = async {
                while lifecycle.status() == PipeStatus::Idle {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            } => {}
        }
    })
    .await
    .expect("the loop must reach a peer that is right there");

    assert!(
        matches!(lifecycle.status(), PipeStatus::Direct | PipeStatus::Relayed),
        "and report the path it took, not merely stop being idle"
    );
    assert!(peer.current().is_some(), "with the connection held");
}

/// The loop goes on *reading* the connection it has, rather than publishing
/// the path it dialled on and then waiting for a death.
///
/// This is the connect side's half of the defect `crate::path_watch` exists
/// for, and it is asserted here because the watcher being correct is not the
/// same claim as the watcher being reached: `path_watch`'s own tests call
/// `follow` directly, and every one of them passes against a
/// `keep_connected` whose third `select!` arm has been deleted.
///
/// Knocked back from outside, which is what makes it deterministic on
/// loopback. Nothing here can make a path actually migrate — and the RTT is
/// no use as a signal either, because two endpoints in one process report
/// sub-millisecond round trips that `PeerView` renders as a constant zero.
/// So the status is set back to `Idle` behind the loop's back: only a loop
/// still reading the live connection can put it back, and one that sampled
/// at dial and stopped leaves it `Idle` for ever.
#[tokio::test]
async fn a_live_connection_keeps_being_read_by_the_reconnect_loop() {
    let (endpoint, _accepted) = accepting().await;
    let peer = bound(&endpoint).await;
    let lifecycle = Lifecycle::new();

    tokio::time::timeout(PATIENCE, async {
        tokio::select! {
            () = keep_connected(&peer, &lifecycle) => {}
            () = async {
                while lifecycle.status() == PipeStatus::Idle {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                let reached = lifecycle.status();
                lifecycle.set_status(PipeStatus::Idle);
                while lifecycle.status() != reached {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            } => {}
        }
    })
    .await
    .expect("a live connection must be re-read, not sampled once");
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
    let peer = connected(&endpoint).await;
    let first = peer.current().expect("a connection").stable_id();

    let reading = tokio::time::timeout(PATIENCE, peer.redial())
        .await
        .expect("the re-dial must not hang")
        .expect("the same peer is still there");

    let second = peer.current().expect("a connection").stable_id();
    assert_ne!(first, second, "a genuinely new connection, not the old one");
    assert!(
        matches!(reading.path, PeerPath::Direct | PeerPath::Relayed),
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
    let peer = connected(&endpoint).await;
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
    let peer = connected(&endpoint).await;
    let live = peer.current().expect("a connection");

    peer.forget(&live);

    assert!(
        peer.current().is_none(),
        "and the pipe now knows it has no connection"
    );
}

// ── Letting go ───────────────────────────────────────────────────────────

/// A live connect side dialled at `far`, with its accept loop running —
/// what `connect` assembles, minus the handle.
async fn live_connect_side(far: &Endpoint) -> std::sync::Arc<crate::dialer::ConnectState> {
    let (state, listener) = tokio::time::timeout(
        PATIENCE,
        crate::dialer::bind(&ticket_for(far), &ConnectOptions::default()),
    )
    .await
    .expect("the bind must not hang")
    .expect("the local port binds");
    tokio::spawn(crate::dialer::local_loop(state.clone(), listener));
    tokio::time::timeout(PATIENCE, state.peer.redial())
        .await
        .expect("the dial must not hang")
        .expect("a live peer is reachable");
    state
}

/// Teardown must close the endpoint, not only the connection on it.
///
/// `Connection::close` merely *queues* a `CONNECTION_CLOSE` frame; the
/// endpoint's close is what flushes it, retransmits it if it is lost and
/// waits for the acknowledgement. Dropping instead aborts the driver that
/// would have sent it — iroh says so at ERROR, on a disconnect nobody did
/// anything wrong in — and the serve side, never told, stays parked in
/// `accept_bi` with a departed peer still in its registry until QUIC's idle
/// timeout notices for it.
///
/// Asserted on the socket rather than on the far side's registry, and here
/// rather than in `tests/integration_pipe.rs`, for two reasons: `endpoint`
/// is private to this module, and one process cannot reproduce the abort at
/// all — both endpoints share a live runtime there, so the queued frame goes
/// out anyway and the defect is invisible end to end.
#[tokio::test]
async fn a_connect_shutdown_closes_the_endpoint_and_not_only_the_connection() {
    let (far, _accepted) = accepting().await;
    let state = live_connect_side(&far).await;

    tokio::time::timeout(PATIENCE, crate::dialer::shutdown(&state))
        .await
        .expect("the shutdown must not hang");

    assert!(
        state.peer.endpoint.is_closed(),
        "a dropped endpoint is one the peer is never told about"
    );
}

/// The deadline'd path had the same omission, and the close belongs outside
/// the deadline: the returned `bool` is a statement about requests draining,
/// not about how long teardown took.
#[tokio::test]
async fn a_connect_shutdown_timeout_closes_the_endpoint_too() {
    let (far, _accepted) = accepting().await;
    let state = live_connect_side(&far).await;

    let drained = tokio::time::timeout(PATIENCE, crate::dialer::shutdown_timeout(&state, PATIENCE))
        .await
        .expect("the shutdown must not hang");

    assert!(drained, "nothing was in flight to wait for");
    assert!(
        state.peer.endpoint.is_closed(),
        "the deadline covers the drain, not whether the peer is told at all"
    );
}
