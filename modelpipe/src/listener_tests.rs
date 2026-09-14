//! Tests for [`super`] — what the accept loop wires up around a peer.
//!
//! Split out via `#[path]` so `listener.rs` stays inside the file-size
//! budget.
//!
//! Each test asserts not that a piece works but that this side reaches it.
//! The path watcher's own tests call `follow` directly and pass against a
//! `serve_connection` that never spawns one; the caps' own tests in
//! `peers_tests.rs` call the registry and the count directly and pass
//! against an accept loop that never asks either.
//!
//! They go through a real [`serve`] rather than a hand-built [`ServeState`],
//! since what is under test is on the path from `serve` to a connected peer
//! and a state assembled here could be wired up correctly by the test
//! itself.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use iroh::Endpoint;
use iroh::endpoint::presets;

use crate::lifecycle::PeerPath;
use crate::path_watch::Reading;
use crate::peers::{DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_PEERS};
use crate::serve::serve;
use crate::serve_handle::ServeHandle;
use crate::serve_options::ServeOptions;
use crate::status::{CloseReason, PipeStatus};
use crate::transport;

/// Long enough that a failure is a failure rather than a slow machine.
const PATIENCE: Duration = Duration::from_secs(20);

/// A real listener over a backend nothing ever calls.
///
/// The `TcpListener` is returned rather than dropped: `TcpBackend` resolves
/// the URL and checks it is local, and a port that has gone away between the
/// bind and the check is a flake this test has no interest in.
async fn listening() -> (ServeHandle, tokio::net::TcpListener) {
    listening_with(ServeOptions::default()).await
}

/// [`listening`], started with `opts`.
async fn listening_with(opts: ServeOptions) -> (ServeHandle, tokio::net::TcpListener) {
    let backend = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let url = format!("http://{}", backend.local_addr().expect("bound"));
    let serving = serve(&url, opts).await.expect("a listener starts");
    (serving, backend)
}

/// One peer, paired with `serving` and held open for the test.
///
/// A bare iroh endpoint rather than `connect`: registration happens when the
/// connection establishes, before any stream is opened, so the far side of
/// this test needs the ALPN and nothing else.
async fn peer_of(serving: &ServeHandle) -> (Endpoint, iroh::endpoint::Connection) {
    let addr = transport::addr_from(&serving.ticket()).expect("the ticket names an endpoint");
    let near = Endpoint::builder(presets::N0)
        .bind()
        .await
        .expect("an endpoint binds");
    let connection = tokio::time::timeout(PATIENCE, near.connect(addr, transport::ALPN))
        .await
        .expect("the dial must not hang")
        .expect("the listener is right there");
    (near, connection)
}

/// A connected peer goes on being *read*, rather than being recorded on the
/// path it arrived on and left there.
///
/// The serve side's half of the defect `crate::path_watch` exists for. A
/// `serve_connection` that registers the peer and never spawns the watcher
/// passes every other test in this crate: the registry's own tests call
/// `set_path` directly, and every status assertion elsewhere is satisfied by
/// the reading taken at accept.
///
/// Knocked back from outside, which is what makes it deterministic on
/// loopback. Nothing in one process can make a path actually migrate, and
/// the RTT is no use as a signal either — two endpoints on this machine
/// report sub-millisecond round trips that `PeerView` renders as a constant
/// zero. So the aggregate is set back to `Idle` behind the listener's back:
/// `PeerRegistry::mutate` republishes it on every write, so only the
/// watcher's next `set_path` can restore it, and a listener that sampled at
/// accept leaves it `Idle` for ever.
#[tokio::test]
async fn a_connected_peer_keeps_being_read_by_the_listener() {
    let (serving, _backend) = listening().await;
    let (_near, _connection) = peer_of(&serving).await;
    let lifecycle = &serving.state.lifecycle;

    tokio::time::timeout(PATIENCE, async {
        while lifecycle.status() == PipeStatus::Idle {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let reached = lifecycle.status();
        lifecycle.set_status(PipeStatus::Idle);
        while lifecycle.status() != reached {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("a connected peer must be re-read, not sampled once");

    serving.shutdown().await;
}

/// Wait for `done` to hold, failing with `what` after [`PATIENCE`].
async fn until(what: &str, done: impl Fn() -> bool + Send + Sync) {
    tokio::time::timeout(PATIENCE, async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect(what);
}

/// A peer past the cap is sent away, and the registry is exactly as it was:
/// the thirty-two it was carrying, and not the one it refused.
///
/// A `serve_connection` that went on past the registry's `None` would carry
/// the peer anyway, and every test of the registry itself would still pass.
#[tokio::test]
async fn a_refused_connection_leaves_the_registry_as_it_found_it() {
    let (serving, _backend) = listening().await;
    let state = &serving.state;
    let carried: Vec<Arc<str>> = (0..DEFAULT_MAX_PEERS)
        .map(|n| format!("{n:012x}").into())
        .collect();
    for peer in &carried {
        let reading = Reading {
            path: PeerPath::Direct,
            rtt: None,
        };
        let added = state.peers.add(peer, reading, &state.lifecycle);
        assert!(added.is_some(), "under the cap");
    }

    let (_near, connection) = peer_of(&serving).await;
    tokio::time::timeout(PATIENCE, connection.closed())
        .await
        .expect("the listener sends a peer past the cap away");
    until("the refused connection gives its place back", || {
        state.connections.carried() == 0
    })
    .await;

    let after: Vec<Arc<str>> = serving
        .peers()
        .into_iter()
        .map(|v| v.fingerprint.into())
        .collect();
    assert_eq!(after, carried, "the thirty-two, and not the one refused");
    serving.shutdown().await;
}

/// Past the connection cap a dial is refused outright and promptly — never
/// registered, never left to time out — and once a place comes back the next
/// dial is carried.
#[tokio::test]
async fn a_connection_past_the_cap_is_refused_before_it_is_served() {
    let (serving, _backend) = listening().await;
    let held: Vec<_> = (0..DEFAULT_MAX_CONNECTIONS)
        .map(|_| serving.state.connections.admit().expect("under the cap"))
        .collect();

    let addr = transport::addr_from(&serving.ticket()).expect("the ticket names an endpoint");
    let near = Endpoint::builder(presets::N0)
        .bind()
        .await
        .expect("an endpoint binds");
    let refused = tokio::time::timeout(PATIENCE, near.connect(addr, transport::ALPN))
        .await
        .expect("a refusal is prompt, not a hang");
    assert!(refused.is_err(), "the dial past the cap is refused");
    assert!(serving.peers().is_empty(), "and never reaches the registry");

    drop(held);
    let (_again, _connection) = peer_of(&serving).await;
    until("a dial after a place comes back is carried", || {
        serving.peers().len() == 1
    })
    .await;
    serving.shutdown().await;
}

/// A connection holds its place for as long as it is carried and gives it
/// back when it goes: the guard is neither let go early nor kept.
#[tokio::test]
async fn a_connection_holds_its_place_until_it_goes() {
    let (serving, _backend) = listening().await;
    let connections = &serving.state.connections;
    let (_near, connection) = peer_of(&serving).await;
    until("the peer is carried", || serving.peers().len() == 1).await;
    assert_eq!(
        connections.carried(),
        1,
        "a place is held while the peer is here"
    );

    connection.close(0u32.into(), b"done");
    until("a connection that goes gives its place back", || {
        connections.carried() == 0
    })
    .await;
    serving.shutdown().await;
}

/// The peer cap is the embedder's: a listener told to carry one peer carries
/// the first and sends the second away.
#[tokio::test]
async fn a_listener_told_to_carry_one_peer_sends_the_second_away() {
    let (serving, _backend) = listening_with(ServeOptions {
        max_peers: NonZeroUsize::MIN,
        ..ServeOptions::default()
    })
    .await;
    let (_first, _held) = peer_of(&serving).await;
    until("the first peer is carried", || serving.peers().len() == 1).await;

    let (_second, refused) = peer_of(&serving).await;
    tokio::time::timeout(PATIENCE, refused.closed())
        .await
        .expect("the second peer is sent away");
    assert_eq!(serving.peers().len(), 1, "and the first is still carried");
    serving.shutdown().await;
}

/// So is the connection cap: told to carry one connection, a listener
/// refuses the second dial outright.
#[tokio::test]
async fn a_listener_told_to_carry_one_connection_refuses_the_second_dial() {
    let (serving, _backend) = listening_with(ServeOptions {
        max_connections: NonZeroUsize::MIN,
        ..ServeOptions::default()
    })
    .await;
    let (_first, _held) = peer_of(&serving).await;
    until("the first connection is carried", || {
        serving.peers().len() == 1
    })
    .await;

    let addr = transport::addr_from(&serving.ticket()).expect("the ticket names an endpoint");
    let near = Endpoint::builder(presets::N0)
        .bind()
        .await
        .expect("an endpoint binds");
    let refused = tokio::time::timeout(PATIENCE, near.connect(addr, transport::ALPN))
        .await
        .expect("a refusal is prompt, not a hang");
    assert!(refused.is_err(), "the second dial is refused");
    serving.shutdown().await;
}

/// The serve side says why it closed: nothing while live, `Shutdown` after a
/// shutdown, and `ListenerFailed` when its endpoint stops yielding
/// connections with nobody asking.
#[tokio::test]
async fn the_listener_says_why_it_closed() {
    let (serving, _backend) = listening().await;
    assert_eq!(serving.close_reason(), None, "live");
    serving.shutdown().await;
    assert_eq!(serving.close_reason(), Some(CloseReason::Shutdown));

    let (failing, _other) = listening().await;
    failing.state.endpoint.close().await;
    until("the accept loop notices its endpoint is gone", || {
        failing.close_reason().is_some()
    })
    .await;
    assert_eq!(failing.close_reason(), Some(CloseReason::ListenerFailed));
    assert_eq!(failing.status(), PipeStatus::Closed);
}
