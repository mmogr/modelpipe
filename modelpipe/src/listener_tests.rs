//! Tests for [`super`] — what the accept loop wires up around a peer.
//!
//! Split out via `#[path]` so `listener.rs` stays inside the file-size
//! budget.
//!
//! One test, and it is here rather than in `path_watch_tests.rs` because it
//! asserts a different thing: not that the watcher works, but that this side
//! reaches it. The watcher's own tests call `follow` directly and pass
//! against a `serve_connection` that never spawns one.
//!
//! It goes through a real [`serve`] rather than a hand-built [`ServeState`],
//! since the spawn under test is on the path from `serve` to a connected
//! peer and a state assembled here could be wired up correctly by the test
//! itself.

use std::time::Duration;

use iroh::Endpoint;
use iroh::endpoint::presets;

use crate::serve::serve;
use crate::serve_handle::ServeHandle;
use crate::serve_options::ServeOptions;
use crate::status::PipeStatus;
use crate::transport;

/// Long enough that a failure is a failure rather than a slow machine.
const PATIENCE: Duration = Duration::from_secs(20);

/// A real listener over a backend nothing ever calls.
///
/// The `TcpListener` is returned rather than dropped: `TcpBackend` resolves
/// the URL and checks it is local, and a port that has gone away between the
/// bind and the check is a flake this test has no interest in.
async fn listening() -> (ServeHandle, tokio::net::TcpListener) {
    let backend = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let url = format!("http://{}", backend.local_addr().expect("bound"));
    let serving = serve(&url, ServeOptions::default())
        .await
        .expect("a listener starts");
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
