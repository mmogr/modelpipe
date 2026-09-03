//! The live connect side.
//!
//! The twin of [`crate::serve_handle`]; see that module for why they are
//! separate files.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::dialer::{self, ConnectState};
use crate::status::PipeStatus;

/// A live connect side.
///
/// Teardown semantics match [`ServeHandle`](crate::ServeHandle): dropping tears down without
/// waiting, [`shutdown`](Self::shutdown) waits.
///
/// When the far end goes quiet, this side does not guess: unreachability
/// shows as [`PipeStatus::Idle`] while it retries, and it keeps retrying.
/// A sleeping laptop is indistinguishable from a dead one, so timeout
/// policy belongs to the embedder.
///
/// A listener that has restarted since the ticket was issued is *also*
/// this case, and deliberately not a distinct one. The endpoint key is
/// ephemeral, so the restarted process is a different endpoint entirely:
/// dialing the ticket reaches nobody, exactly as an offline peer does.
/// There is no rejection to observe, because there is nobody left to
/// reject. [`PipeStatus::Closed`] therefore means this side is gone —
/// shut down, dropped, or dead after an unrecoverable transport failure
/// — never that the far side declined the pairing.
///
/// Deliberately shares no trait with [`ServeHandle`](crate::ServeHandle): the overlap is
/// three methods, and embedders driving both sides duplicate a small
/// park-and-watch loop. If that ever grows past a nuisance, a shared
/// trait is an additive, non-breaking change — the decision is recorded
/// here so the duplication reads as chosen, not overlooked.
pub struct ConnectHandle {
    state: Arc<ConnectState>,
}

impl ConnectHandle {
    pub(crate) const fn new(state: Arc<ConnectState>) -> Self {
        Self { state }
    }

    /// The bound local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.state.local_addr
    }

    /// The URL to point an OpenAI-compatible client at, ready to paste:
    /// `http://{host}/v1` with a host that is actually dialable. Not
    /// always [`local_addr`](Self::local_addr) verbatim: a wildcard bind
    /// (`0.0.0.0`, `[::]`) is a listen address, not a destination, so it
    /// renders as loopback, and an IPv6 zone id is dropped rather than
    /// emitted in a form no URL parser accepts.
    pub fn base_url(&self) -> String {
        dialer::base_url(self.state.local_addr)
    }

    /// How this side is currently reaching the peer.
    pub fn status(&self) -> PipeStatus {
        self.state.lifecycle.status()
    }

    /// Wait until the status changes, then return the new value.
    ///
    /// Same contract as [`ServeHandle::status_changed`](crate::ServeHandle::status_changed): snapshot
    /// semantics, concurrent callers each against their own snapshot,
    /// and once the pipe is closed every call resolves immediately with
    /// [`PipeStatus::Closed`].
    pub async fn status_changed(&self) -> PipeStatus {
        // The snapshot is taken here, at the moment of the call, which is
        // what makes states that came and went while nobody was waiting
        // coalesce rather than replay.
        let snapshot = self.state.lifecycle.status();
        self.state.lifecycle.changed_since(snapshot).await
    }

    /// Stop accepting local connections, let the in-flight requests
    /// finish, and wait until the local listener is gone.
    ///
    /// Same contract as [`ServeHandle::shutdown`](crate::ServeHandle::shutdown): drains rather than
    /// cuts, does not time out, takes `&self` for shared-state embedders,
    /// and is idempotent. Dropping the handle cuts instead.
    pub async fn shutdown(&self) {
        dialer::shutdown(&self.state).await;
    }

    /// [`shutdown`](Self::shutdown) with a deadline on the drain. Same
    /// contract as [`ServeHandle::shutdown_timeout`](crate::ServeHandle::shutdown_timeout), including the
    /// returned `bool`.
    pub async fn shutdown_timeout(&self, grace: Duration) -> bool {
        dialer::shutdown_timeout(&self.state, grace).await
    }
}

// Dropping a handle tears its side down best-effort and without waiting,
// which is the other half of "`shutdown` drains, `Drop` cuts". The close is
// published synchronously so a watcher sees `Closed` immediately; anything
// that needs an await is handed to the runtime, and a handle dropped
// outside one does the synchronous half only — the process is going away
// regardless.

impl Drop for ConnectHandle {
    fn drop(&mut self) {
        // Publishing `Closed` stops the accept loop; closing the connection
        // is what makes this a cut. Without the second half, `Drop` on this
        // side ended nothing: the spawned `carry` tasks each hold their own
        // `Arc<ConnectState>`, so they kept streaming after the handle that
        // owned them was gone — while the serve side's identically
        // documented `Drop` cut immediately. `Connection::close` is
        // synchronous, so unlike the serve side this needs no runtime.
        self.state.lifecycle.close();
        self.state.connection.close(0u32.into(), b"dropped");
        // Marking teardown complete is still not ours: the accept loop
        // holds the listener, and it is the loop that says when the port is
        // free.
    }
}
