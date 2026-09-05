//! The serve side, running.
//!
//! Holds the state a listener shares — the endpoint, the credential, the
//! backend, the lifecycle — and the accept loop that turns incoming QUIC
//! streams into exchanges.
//!
//! One bi-stream carries exactly one HTTP exchange. That is what lets the
//! edge treat a body as opaque bytes: there is no second request on the
//! stream for a framing disagreement to desynchronize. It also means the
//! client must not try to reuse its local connection, which is why the
//! response it gets carries `Connection: close`.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use iroh::Endpoint;
use tracing::Instrument as _;

use crate::backend::TcpBackend;
use crate::credential::Credential;
use crate::exchange;
use crate::fingerprint;
use crate::lifecycle::{Lifecycle, PeerPath, aggregate};
use crate::peer;

/// How many exchanges one peer may have in flight at once.
///
/// Backpressure rather than refusal: a peer may open more streams, and they
/// wait. What is bounded is the work and the memory a single ticket-holder
/// can command, which — with the head size and the head timeout — is the
/// whole of what a leaked ticket is worth before it authenticates.
///
/// Deliberately generous. A client pipelining a page of requests is normal;
/// a client with sixty-four in flight is not a client.
const MAX_CONCURRENT_STREAMS_PER_PEER: usize = 64;

/// Everything a live listener shares.
///
/// One `Arc`, held by the handle, the accept loop, and every in-flight
/// exchange. Naming it is what keeps the handle from becoming the place
/// state accumulates.
pub(crate) struct ServeState {
    pub(crate) endpoint: Endpoint,
    pub(crate) credential: Credential,
    pub(crate) backend: TcpBackend,
    pub(crate) lifecycle: Lifecycle,
    /// Connected peers and how each is reaching us, keyed by an id that
    /// exists only to remove the right entry when a peer goes.
    peers: Mutex<BTreeMap<u64, PeerPath>>,
    next_peer: AtomicU64,
}

impl ServeState {
    pub(crate) fn new(endpoint: Endpoint, credential: Credential, backend: TcpBackend) -> Self {
        Self {
            endpoint,
            credential,
            backend,
            lifecycle: Lifecycle::new(),
            peers: Mutex::new(BTreeMap::new()),
            next_peer: AtomicU64::new(0),
        }
    }

    /// Record a peer and republish the aggregate status.
    fn add_peer(&self, path: PeerPath) -> u64 {
        let id = self.next_peer.fetch_add(1, Ordering::Relaxed);
        self.with_peers(|peers| {
            peers.insert(id, path);
        });
        id
    }

    fn remove_peer(&self, id: u64) {
        self.with_peers(|peers| {
            peers.remove(&id);
        });
    }

    /// Mutate the peer set and publish what it now means.
    ///
    /// The lock is never held across an await — the closure is synchronous
    /// and the status is computed inside it — so a slow peer cannot stall
    /// another's accept.
    fn with_peers(&self, f: impl FnOnce(&mut BTreeMap<u64, PeerPath>)) {
        let mut guard = self
            .peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut guard);
        let paths: Vec<PeerPath> = guard.values().copied().collect();
        // Released before publishing, so nothing observes the status while
        // the set it describes is still locked.
        drop(guard);
        self.lifecycle.set_status(aggregate(&paths));
    }
}

/// Accept connections until teardown begins or the endpoint stops yielding
/// them.
///
/// Both halves matter, and the first is what makes the drain possible.
/// Closing the endpoint would also end this loop — that is what it used to
/// rely on — but it ends every in-flight exchange with it, so a `shutdown`
/// that wants to drain has nothing left to drain by the time it asks. The
/// loop watches the lifecycle instead, so admission stops while the work
/// already admitted runs on.
pub(crate) async fn accept_loop(state: std::sync::Arc<ServeState>) {
    loop {
        let incoming = tokio::select! {
            // Biased so teardown wins a tie: a `shutdown` racing an
            // incoming connection should stop admitting rather than take
            // one more. The same shape `dialer::local_loop` uses.
            biased;
            () = state.lifecycle.wait_until_closed() => break,
            incoming = state.endpoint.accept() => incoming,
        };
        let Some(incoming) = incoming else { break };
        let state = state.clone();
        tokio::spawn(async move {
            // A connection that fails to establish is not an event worth
            // reporting to the operator: the peer went away, or was never
            // speaking this protocol.
            match incoming.await {
                Ok(connection) => serve_connection(state, connection).await,
                // Below the default level deliberately. A UDP port that is
                // reachable from the internet is a port that gets scanned,
                // and every scan which speaks no QUIC lands exactly here —
                // at `info` this would be the most frequent line in the
                // log while saying nothing at all about this listener.
                Err(error) => tracing::debug!(%error, "a connection never established"),
            }
        });
    }
}

/// Serve every stream one peer opens, until it goes away.
async fn serve_connection(
    state: std::sync::Arc<ServeState>,
    connection: iroh::endpoint::Connection,
) {
    // The path in use right now, by the rule both sides share — see
    // `peer::path_of`, which this side and the connect side had written out
    // identically until it moved there. Paths migrate, a connection that
    // starts relayed may hole-punch a moment later, and following that is
    // `paths_stream`'s job: a refinement rather than a correction, since
    // this snapshot is honest about the moment it was taken.
    let path = peer::path_of(&connection);
    let peer = state.add_peer(path);
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_STREAMS_PER_PEER));

    // Named by the rule a ticket names itself by — see `crate::fingerprint`
    // — so an operator reading this line can hold it against the ticket
    // they handed out and see whether the device that turned up is the one
    // they meant. The whole endpoint id would be ninety-six characters on
    // every line; the public key it is a prefix of is not a secret either
    // way. The same twelve characters reach the backend on every request
    // from this peer, as `X-Modelpipe-Peer`, so a backend's log and this
    // one name a device identically.
    let peer_name: std::sync::Arc<str> = fingerprint::of(connection.remote_id().as_bytes()).into();

    // `info_span!` rather than `debug_span!`, and that is not a taste
    // call: a span disabled by the filter contributes no fields, so at the
    // default verbosity a `debug` span here would leave every exchange line
    // unattributable — which is the one thing this span exists to prevent.
    let span = tracing::info_span!(
        "peer",
        peer = %peer_name,
        // A snapshot, honest about the moment it was taken, exactly as the
        // status published above is. `PipeStatus::as_str` rather than a
        // second spelling of the same two words, because the CLI already
        // prints those and an operator should not have to learn two
        // vocabularies for one fact.
        path = aggregate(&[path]).as_str(),
    );
    span.in_scope(|| tracing::info!("peer connected"));

    loop {
        // Same rule one level down: teardown stops this peer being given
        // new streams, without touching the exchanges it already has.
        let accepted = tokio::select! {
            biased;
            () = state.lifecycle.wait_until_closed() => break,
            accepted = connection.accept_bi() => accepted,
        };
        let Ok((send, recv)) = accepted else { break };
        let state = state.clone();
        // Acquired before the stream is taken on, so a peer opening streams
        // faster than they complete waits here rather than accumulating
        // tasks. `acquire_owned` cannot fail: the semaphore lives as long as
        // this loop and is never closed.
        let Ok(slot) = slots.clone().acquire_owned().await else {
            break;
        };
        // Registered before the task is spawned, so a `shutdown` racing an
        // accept cannot observe zero in flight and return while this
        // exchange is starting.
        let guard = state.lifecycle.enter();
        let peer_name = peer_name.clone();
        // `.instrument`, not an `enter()`: the guard a synchronous enter
        // returns is not `Send` across an await, and this task is spawned.
        // Attaching the span to the future is also what makes the peer
        // fields appear on the exchange's own line — a span entered here
        // would not reach a task at all.
        tokio::spawn(
            async move {
                let _slot = slot;
                let _guard = guard;
                // `join` is what lets the edge stay generic: it never learns
                // that these two halves came from QUIC.
                let mut stream = tokio::io::join(recv, send);
                let _ = exchange::serve_exchange(
                    &mut stream,
                    &state.credential,
                    &state.backend,
                    &peer_name,
                )
                .await;
                deliver(stream).await;
            }
            .instrument(span.clone()),
        );
    }

    span.in_scope(|| tracing::info!("peer disconnected"));
    state.remove_peer(peer);
}

/// Wait until the peer actually has the response, then let the guard go.
///
/// The edge is finished when its last `write_all` returns, and that only
/// means the bytes reached the local QUIC send buffer. `wait_until_drained`
/// released on that, and the `endpoint.close()` after it discards whatever
/// has not been transmitted — QUIC's close is documented as abandoning data
/// the peer has not yet been given, acknowledged or not. So a drain could
/// report success while the tail of a streaming response was still sitting
/// in a buffer about to be thrown away, and the client, reading an
/// `UntilClose` body, could not tell truncation from completion.
///
/// `finish` marks the stream complete and `stopped` resolves once the peer
/// has taken it or given up on it. Errors are ignored on purpose: every one
/// of them means the peer is already gone, which is the same answer as
/// delivery for the purpose of releasing the guard.
///
/// This is the one place the exchange's streams are named as iroh types
/// again, which is why it lives here and not in the edge.
async fn deliver(stream: tokio::io::Join<iroh::endpoint::RecvStream, iroh::endpoint::SendStream>) {
    let (_recv, mut send) = stream.into_inner();
    let _ = send.finish();
    let _ = send.stopped().await;
}

/// Stop admitting, drain, and only then close the endpoint.
///
/// The order is the contract, and it is the whole of it. `close()` is what
/// stops new work — both accept loops watch it — and the drain is what lets
/// the work already admitted finish. Closing the endpoint has to come last
/// because iroh documents it as closing every open connection with error
/// code 0: doing it first ends the exchanges this function exists to
/// protect, and then the drain returns instantly because there is nothing
/// left in flight.
///
/// Measured, before the order was corrected: a client streaming a 200-frame
/// response was cut at frame 5.
pub(crate) async fn shutdown(state: &ServeState) {
    state.lifecycle.close();
    state.lifecycle.wait_until_drained().await;
    state.endpoint.close().await;
    state.lifecycle.mark_torn_down();
}

/// [`shutdown`] with a deadline on the drain, reporting whether it was met.
///
/// Same order for the same reason. The deadline covers the drain alone —
/// wrapping the endpoint close as well would make the returned `bool` a
/// statement about teardown latency rather than about the requests.
pub(crate) async fn shutdown_timeout(state: &ServeState, grace: std::time::Duration) -> bool {
    state.lifecycle.close();
    let drained = tokio::time::timeout(grace, state.lifecycle.wait_until_drained())
        .await
        .is_ok();
    state.endpoint.close().await;
    state.lifecycle.mark_torn_down();
    drained
}
