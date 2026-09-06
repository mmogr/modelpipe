//! The live connect side.
//!
//! The twin of [`crate::serve_handle`]; see that module for why they are
//! separate files.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::dialer::{self, ConnectState};
use crate::status::{CloseReason, PipeStatus};

/// A live connect side.
///
/// Teardown semantics match [`ServeHandle`](crate::ServeHandle): dropping tears down without
/// waiting, [`shutdown`](Self::shutdown) waits.
///
/// When the far end is quiet, this side does not guess: unreachability
/// shows as [`PipeStatus::Idle`] while it retries, and it keeps retrying.
/// A sleeping laptop is indistinguishable from a dead one, so timeout
/// policy belongs to the embedder.
///
/// That covers the first dial too. [`connect`](fn@crate::connect) returns
/// once the local port is bound, so a handle begins life at
/// [`PipeStatus::Idle`] whether the peer is absent or merely not reached
/// yet — the two are the same fact, and the handle reports it rather than
/// picking a deadline on the embedder's behalf.
///
/// A listener that has restarted since the ticket was issued is *also*
/// this case, and deliberately not a distinct one. Without an identity
/// file the endpoint key is minted per process, so the restarted listener
/// is a different endpoint entirely and dialing the ticket reaches nobody,
/// exactly as an offline peer does. With one it is the same endpoint and
/// this side reconnects to it — which is what
/// [`ServeOptions::identity`](crate::ServeOptions#structfield.identity)
/// buys, over a network where discovery is reachable. There is no
/// rejection to observe in either case, because there is nobody to
/// reject. [`PipeStatus::Closed`] therefore means this side is gone —
/// shut down, dropped, or the local listener dead under it — never that
/// the far side declined the pairing, and never that the transport gave
/// up: an unreachable peer is [`PipeStatus::Idle`], retried for as long
/// as the pipe is held.
///
/// Deliberately shares no trait with [`ServeHandle`](crate::ServeHandle): the overlap is
/// three methods, and embedders driving both sides duplicate a small
/// park-and-watch loop. If that ever grows past a nuisance, a shared
/// trait is an additive, non-breaking change — the decision is recorded
/// here so the duplication reads as chosen, not overlooked.
pub struct ConnectHandle {
    /// Shared with `network.rs`, the second `impl` block — the same
    /// arrangement [`ServeHandle`](crate::ServeHandle) has with
    /// `serve_status.rs`.
    pub(crate) state: Arc<ConnectState>,
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
        base_url(self.state.local_addr)
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
    ///
    /// # Examples
    ///
    /// Read the current value *before* waiting. The snapshot is taken when
    /// this is polled, so a pipe that reached [`PipeStatus::Direct`] a
    /// moment earlier has nothing left to report and a loop that only
    /// waits never prints its first line:
    ///
    /// ```no_run
    /// # async fn example(connected: &modelpipe::ConnectHandle) {
    /// println!("status: {}", connected.status().as_str());
    /// loop {
    ///     let next = connected.status_changed().await;
    ///     println!("status: {}", next.as_str());
    ///     if next == modelpipe::PipeStatus::Closed {
    ///         break;
    ///     }
    /// }
    /// # }
    /// ```
    pub async fn status_changed(&self) -> PipeStatus {
        // The snapshot is taken here, at the moment of the call, which is
        // what makes states that came and went while nobody was waiting
        // coalesce rather than replay.
        let snapshot = self.state.lifecycle.status();
        // `None` can only mean the snapshot taken a line above was already
        // `Closed`, and this form owes such a caller the terminal status
        // rather than a wait — the clause the doc above states.
        self.state
            .lifecycle
            .changed_since(snapshot)
            .await
            .unwrap_or(PipeStatus::Closed)
    }

    /// Wait until the status differs from `snapshot`, then return it, and
    /// `None` once the pipe is closed and `snapshot` already says so.
    ///
    /// Same contract as
    /// [`ServeHandle::status_changed_since`](crate::ServeHandle::status_changed_since),
    /// which states it in full: the caller supplies the snapshot, so a
    /// transition landing between reading [`status`](Self::status) and
    /// waiting again is reported rather than coalesced away, and the
    /// sequence *ends* rather than repeating a terminal value.
    ///
    /// This is the form to reach for from a language binding.
    /// [`status_changed`](Self::status_changed) snapshots inside itself,
    /// so a generated `next()` built on it drops the transition it was
    /// woken to report and then, after the close, returns `Closed` as fast
    /// as it can be asked — a pipe that has been over for an hour still
    /// costing a core. Neither is a bug in that method: they are the price
    /// of coalescing, and this is the accessor for callers who cannot pay
    /// it.
    ///
    /// # Examples
    ///
    /// The whole loop, with no terminal condition to get wrong:
    ///
    /// ```no_run
    /// # async fn example(connected: &modelpipe::ConnectHandle) {
    /// let mut held = connected.status();
    /// println!("status: {}", held.as_str());
    /// while let Some(next) = connected.status_changed_since(held).await {
    ///     println!("status: {}", next.as_str());
    ///     held = next;
    /// }
    /// # }
    /// ```
    pub async fn status_changed_since(&self, snapshot: PipeStatus) -> Option<PipeStatus> {
        self.state.lifecycle.changed_since(snapshot).await
    }

    /// Why the pipe closed, or `None` while it is still live.
    ///
    /// The diagnostic half of [`status`](Self::status), and the answer to
    /// the question that method cannot be asked: a pipe reports
    /// [`PipeStatus::Closed`] whether a caller ended it or the local
    /// listener died under it, and reports [`PipeStatus::Idle`] both while
    /// looking for a peer that went away and before ever reaching one. A
    /// client that shows "not connected" for all four has told its user
    /// nothing.
    ///
    /// Read it together with the status rather than instead of it. `None`
    /// means the pipe is live and still trying — however idle it looks,
    /// nothing has given up and a peer that comes back is picked up.
    /// [`CloseReason::Shutdown`] means this side ended it on purpose, so
    /// "disconnected" is the honest thing to show;
    /// [`CloseReason::ListenerFailed`] means nobody did, and is worth
    /// showing as the failure it is.
    ///
    /// Once set it never changes. [`PipeStatus::Closed`] is terminal, and
    /// the first reason recorded is the one that keeps — the accept loop
    /// closes the pipe again on its way out, and does not get to overwrite
    /// what the caller who asked already said.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn example(connected: &modelpipe::ConnectHandle) -> &'static str {
    /// match connected.close_reason() {
    ///     // Live. `Idle` here is "looking", not "failed".
    ///     None => "connecting",
    ///     Some(modelpipe::CloseReason::ListenerFailed) => "the local port died",
    ///     Some(_) => "disconnected",
    /// }
    /// # }
    /// ```
    pub fn close_reason(&self) -> Option<CloseReason> {
        self.state.lifecycle.close_reason()
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
        // `Shutdown`, and not a reason of its own: dropping is a teardown
        // this side asked for exactly as `shutdown` is, differing in what
        // becomes of the requests in flight rather than in why the pipe
        // ended. A separate reason would also be one nobody could read —
        // the accessor needs a handle, and this is the handle going away.
        self.state.lifecycle.close(CloseReason::Shutdown);
        self.state.peer.close(b"dropped");
        // Marking teardown complete is still not ours: the accept loop
        // holds the listener, and it is the loop that says when the port is
        // free.
    }
}

/// The URL to point a client at.
///
/// Not the bind address verbatim. A wildcard bind is a listen address, not
/// a destination — nobody can connect to `0.0.0.0` — so it renders as
/// loopback, which is a place the client can actually reach. An IPv6 zone
/// id is dropped rather than emitted, because no URL parser accepts one.
pub(crate) fn base_url(addr: SocketAddr) -> String {
    let host = match addr.ip() {
        ip if ip.is_unspecified() => match ip {
            IpAddr::V4(_) => "127.0.0.1".to_owned(),
            IpAddr::V6(_) => "[::1]".to_owned(),
        },
        IpAddr::V4(v4) => v4.to_string(),
        // Formatting the address rather than the socket address is what
        // drops the zone: `SocketAddrV6`'s own `Display` would include it.
        IpAddr::V6(v6) => format!("[{v6}]"),
    };
    format!("http://{host}:{}/v1", addr.port())
}

#[cfg(test)]
#[path = "connect_handle_tests.rs"]
mod connect_handle_tests;
