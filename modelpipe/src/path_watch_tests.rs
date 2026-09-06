//! Tests for [`super`] — the rule for reading a path, and the loop that
//! keeps reading it.
//!
//! Split out via `#[path]` so `path_watch.rs` stays inside the file-size
//! budget.
//!
//! Two layers, and the division is what each can prove. The rule and the
//! not-yet-established case are pure and are checked as arithmetic. That
//! this side goes on *asking* is a statement about a live connection, so the
//! last test binds two real endpoints in this process — a stub cannot be
//! wrong about a re-read in the way the real thing was.

use std::net::SocketAddr;
use std::str::FromStr as _;
use std::sync::{Arc, Mutex};

use iroh::endpoint::presets;
use iroh::{Endpoint, RelayUrl};

use super::*;
use crate::transport;

/// Long enough that a failure is a failure rather than a slow machine.
const PATIENCE: Duration = Duration::from_secs(20);

// ── The rule ─────────────────────────────────────────────────────────────

/// The whole of what `Direct` and `Relayed` mean, in one place because both
/// sides read it from here.
#[test]
fn the_relay_is_what_makes_a_path_relayed_and_everything_else_is_direct() {
    let relay = TransportAddr::Relay(
        RelayUrl::from_str("https://relay.example.com/").expect("a relay URL"),
    );
    let direct = TransportAddr::Ip(SocketAddr::from_str("192.0.2.7:41641").expect("an address"));

    assert_eq!(classify(&relay), PeerPath::Relayed);
    assert_eq!(classify(&direct), PeerPath::Direct);
}

/// A connection with nothing selected yet is reported as the worse of the
/// two, which is the same conservatism `aggregate` applies to a mixed set.
///
/// Worth pinning rather than leaving implicit: the alternative anybody
/// reaches for is a third state, and adding one here would put it on the
/// public status a moment later.
#[test]
fn a_path_that_is_not_established_yet_reads_as_relayed_and_unmeasured() {
    assert_eq!(Reading::PENDING.path, PeerPath::Relayed);
    assert_eq!(
        Reading::PENDING.rtt,
        None,
        "there is nothing to measure yet"
    );
}

/// The conversion the log field and `PeerView` share, at the two ends that
/// could be got wrong.
#[test]
fn a_round_trip_time_is_reported_in_whole_milliseconds() {
    assert_eq!(millis(Duration::from_micros(23_400)), 23);
    assert_eq!(millis(Duration::ZERO), 0);
    assert_eq!(
        millis(Duration::MAX),
        u64::MAX,
        "saturating, never wrapping"
    );
}

// ── Following a live one ─────────────────────────────────────────────────

/// An endpoint that answers this crate's ALPN, standing in for the far side
/// of a connection without any of the listener above it.
///
/// The accepted connections are handed back rather than dropped, and the
/// caller holds the receiver: a connection the far end has let go is not the
/// state under test here, and dropping them would race every watcher below
/// against the peer's own teardown. The same shape `peer_tests.rs` uses, for
/// the same reason.
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

/// One live connection to `far`, from an endpoint of this test's own.
async fn connected_to(far: &Endpoint) -> (Endpoint, Connection) {
    let near = Endpoint::builder(presets::N0)
        .bind()
        .await
        .expect("an endpoint binds");
    let connection = tokio::time::timeout(PATIENCE, near.connect(far.addr(), transport::ALPN))
        .await
        .expect("the dial must not hang")
        .expect("a live peer is reachable");
    (near, connection)
}

/// A real connection reports the path it is on and what that path costs.
///
/// Both endpoints are in this process and pair over their own direct
/// addresses, so `Direct` is the answer here — and the RTT being present at
/// all is the half that could not be read before, because `PathEvent` does
/// not carry it.
#[tokio::test]
async fn a_live_connection_reads_as_the_path_it_is_on_with_a_measured_cost() {
    let (far, _accepted) = accepting().await;
    let (_near, connection) = connected_to(&far).await;

    let reading = read(&connection);

    assert_eq!(
        reading.path,
        PeerPath::Direct,
        "two endpoints on one machine do not need a relay"
    );
    assert!(
        reading.rtt.is_some(),
        "a selected path has a round-trip estimate"
    );
}

/// The defect this module exists for: the path was read once, when the
/// connection was established, and never again.
///
/// Nothing in one process can make a path actually migrate — both endpoints
/// are on loopback and go direct immediately — so what is asserted is the
/// property that made the migration invisible: that this side keeps asking.
/// A watcher that sampled once would publish exactly one reading and then
/// sit there, which is what every version before this one did.
#[tokio::test]
async fn a_live_connection_is_read_again_rather_than_sampled_once() {
    let (far, _accepted) = accepting().await;
    let (_near, connection) = connected_to(&far).await;
    let lifecycle = Lifecycle::new();
    let seen: Arc<Mutex<Vec<Reading>>> = Arc::new(Mutex::new(Vec::new()));

    // `follow` runs until the connection or the pipe ends, and neither does
    // here — so the deadline is what returns, and it is set to a small
    // multiple of the cadence rather than to a wall-clock guess.
    let recording = seen.clone();
    let _ = tokio::time::timeout(
        CADENCE * 3 + CADENCE / 2,
        follow(&connection, &lifecycle, move |reading| {
            recording
                .lock()
                .expect("nothing panics holding it")
                .push(reading);
        }),
    )
    .await;

    let readings = seen.lock().expect("nothing panics holding it").clone();
    assert!(
        readings.len() >= 3,
        "three cadences must produce at least three readings, not one: {readings:?}"
    );
    assert!(
        readings.iter().all(|r| r.path == PeerPath::Direct),
        "and each one is a real read of the live connection: {readings:?}"
    );
}

/// Teardown ends the watcher, so a caller that spawns one does not have to
/// cancel it — which is exactly what the serve side relies on.
#[tokio::test]
async fn closing_the_pipe_ends_the_watcher() {
    let (far, _accepted) = accepting().await;
    let (_near, connection) = connected_to(&far).await;
    let lifecycle = Lifecycle::new();
    lifecycle.close(crate::status::CloseReason::Shutdown);

    tokio::time::timeout(PATIENCE, follow(&connection, &lifecycle, |_| {}))
        .await
        .expect("a closed pipe must not leave a watcher reading forever");
}
