//! Tests for [`super`] — the loop that notices there is no connection and
//! goes looking.
//!
//! Split out via `#[path]` so `peer_redial.rs` stays inside the file-size
//! budget, and separated from `peer_tests` when the loop itself was.
//!
//! These bind real endpoints, and they have to: a reconnection is a
//! statement about iroh — that the endpoint id in a ticket outlives the
//! connection made from it — and a stub cannot be wrong about that in the
//! way the real thing can. Nothing here leaves the machine.

use std::time::Duration;

use iroh::Endpoint;
use iroh::endpoint::{Connection, presets};

use super::*;
use crate::connect::ConnectOptions;
use crate::ticket::Ticket;
use crate::transport;

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
            () = keep_connected(&peer, &lifecycle, None) => {}
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
            () = keep_connected(&peer, &lifecycle, None) => {}
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

// ── The nudge's pacing ───────────────────────────────────────────────────

/// **The interval is a caller's, so it may be anything.**
///
/// `ConnectOptions::idle_network_nudge` is a public field of arbitrary
/// `Duration`, and `Instant + Duration` panics on overflow. `Duration::MAX`
/// is the obvious spelling of "effectively never", and before this was
/// guarded it panicked the reconnect task at construction — before the
/// first dial, after `connect` had already returned `Ok`. The pipe would
/// sit `Idle` for ever with nothing dialling it and no error anywhere.
#[test]
fn an_interval_too_large_to_add_is_the_never_it_was_reaching_for() {
    let now = Instant::now();
    let mut nudge = Nudge::every(Some(Duration::MAX), now);

    assert!(!nudge.due(now), "and it never comes due");
}

/// No interval is never due, which is what `None` promises a caller that
/// watches a real path monitor instead.
#[test]
fn no_interval_is_never_due() {
    let now = Instant::now();
    let mut nudge = Nudge::every(None, now);

    assert!(!nudge.due(now));
    assert!(!nudge.due(now + Duration::from_mins(59)), "nor much later");
}

/// Due after the interval and not before, then re-armed for another one.
#[test]
fn an_interval_comes_due_once_per_interval() {
    let start = Instant::now();
    let mut nudge = Nudge::every(Some(Duration::from_mins(1)), start);

    assert!(!nudge.due(start), "not immediately");
    assert!(!nudge.due(start + Duration::from_secs(59)), "not early");
    assert!(nudge.due(start + Duration::from_mins(1)), "due");
    assert!(
        !nudge.due(start + Duration::from_secs(61)),
        "and re-armed rather than staying due"
    );
    assert!(nudge.due(start + Duration::from_mins(2)), "due again");
}

/// **Re-anchored on the moment it fired, not on the deadline it passed.**
///
/// This is polled once per re-dial round, and a round against a peer that
/// is simply gone takes as long as iroh needs to give up — tens of
/// seconds. Anchoring on the missed deadline would make it due again
/// immediately, trying to catch up on rounds that never had a chance to
/// happen.
#[test]
fn a_long_round_does_not_make_the_nudge_fire_twice_to_catch_up() {
    let start = Instant::now();
    let mut nudge = Nudge::every(Some(Duration::from_mins(1)), start);

    // One round took five minutes, so the deadline passed four times over.
    assert!(nudge.due(start + Duration::from_mins(5)));
    assert!(
        !nudge.due(start + Duration::from_secs(301)),
        "the backlog is not worked through"
    );
    assert!(nudge.due(start + Duration::from_mins(6)), "one interval on");
}

/// A zero interval is due every round. Bounded by the backoff sleep above
/// it rather than spinning, but worth pinning as what it does rather than
/// leaving a caller to find out.
#[test]
fn a_zero_interval_is_due_every_round() {
    let now = Instant::now();
    let mut nudge = Nudge::every(Some(Duration::ZERO), now);

    assert!(nudge.due(now));
    assert!(nudge.due(now), "and again, with no time passing");
}
