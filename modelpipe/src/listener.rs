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

use crate::backend::TcpBackend;
use crate::credential::Credential;
use crate::exchange;
use crate::lifecycle::{Lifecycle, PeerPath, aggregate};

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

/// Accept connections until the endpoint stops yielding them.
///
/// Returns when the endpoint is closed, which is how teardown ends this
/// loop: `shutdown` closes the endpoint, `accept` yields `None`, and the
/// loop falls out rather than being cancelled mid-exchange.
pub(crate) async fn accept_loop(state: std::sync::Arc<ServeState>) {
    while let Some(incoming) = state.endpoint.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            // A connection that fails to establish is not an event worth
            // reporting to the operator: the peer went away, or was never
            // speaking this protocol.
            if let Ok(connection) = incoming.await {
                serve_connection(state, connection).await;
            }
        });
    }
}

/// Serve every stream one peer opens, until it goes away.
async fn serve_connection(
    state: std::sync::Arc<ServeState>,
    connection: iroh::endpoint::Connection,
) {
    // The path in use right now. Paths migrate — a connection that starts
    // relayed may hole-punch a moment later — and following that is
    // `paths_stream`'s job, which is a refinement rather than a correction:
    // this snapshot is honest about the moment it was taken.
    //
    // No selected path means nothing is established yet, and the
    // conservative reading is the one the aggregate rule already takes:
    // report the worse of the two.
    let path = connection
        .paths()
        .iter()
        .find(iroh::endpoint::Path::is_selected)
        .map_or(PeerPath::Relayed, |p| {
            if p.remote_addr().is_relay() {
                PeerPath::Relayed
            } else {
                PeerPath::Direct
            }
        });
    let peer = state.add_peer(path);

    while let Ok((send, recv)) = connection.accept_bi().await {
        let state = state.clone();
        // Registered before the task is spawned, so a `shutdown` racing an
        // accept cannot observe zero in flight and return while this
        // exchange is starting.
        let guard = state.lifecycle.enter();
        tokio::spawn(async move {
            let _guard = guard;
            // `join` is what lets the edge stay generic: it never learns
            // that these two halves came from QUIC.
            let mut stream = tokio::io::join(recv, send);
            let _ = exchange::serve_exchange(&mut stream, &state.credential, &state.backend).await;
        });
    }

    state.remove_peer(peer);
}

/// Close the endpoint and wait for the drain.
///
/// The order is the contract. New streams stop being accepted first, then
/// in-flight exchanges are allowed to finish, and only then is the pipe
/// marked torn down — so a caller that rebinds the port immediately after
/// finds it free.
pub(crate) async fn shutdown(state: &ServeState) {
    state.lifecycle.close();
    state.endpoint.close().await;
    state.lifecycle.wait_until_drained().await;
    state.lifecycle.mark_torn_down();
}
