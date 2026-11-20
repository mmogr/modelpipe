//! The live connect side: [`ConnectHandle`] and every method this crate gives
//! it. The inherent methods are one `impl` block, with a section for each
//! question they answer.
//!
//! The twin of [`crate::serve_handle`].

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::dialer::{self, ConnectState};
use crate::network::{NetworkMetrics, metrics_of, notify};
use crate::peer_id::PeerId;
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
/// eight methods, and embedders driving both sides duplicate a small
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

    // Where a client points, and who this side is to the far end.

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

    /// Who this side connects as: the peer the serve side sees on every
    /// connection from this pipe.
    ///
    /// Fixed for the life of the handle. Fresh per process unless
    /// [`ConnectOptions::identity`](crate::ConnectOptions#structfield.identity)
    /// names a key to keep, in which case it is the same every time.
    pub fn peer_id(&self) -> PeerId {
        PeerId::from_bytes(*self.state.peer.endpoint.id().as_bytes())
    }

    // What the pipe is doing, and why it closed.

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

    // Waiting to reach the serve side. `connect` returns with the local port
    // bound and the dial still running, and how long to wait for the peer is
    // the caller's to decide. Every caller wrote the same loop to decide it,
    // so this is that loop, written once.

    /// Wait until this side has reached the serve side, for at most `within`.
    ///
    /// Returns the path, [`Direct`](PipeStatus::Direct) or
    /// [`Relayed`](PipeStatus::Relayed), as soon as there is one, including a
    /// path reached before this was called. A pipe that closes first ends the
    /// wait at once.
    ///
    /// Running out ends the wait and not the pipe. The handle keeps trying, so
    /// a caller may wait again, or hand the port out anyway and let a late
    /// serve side be picked up. A `within` too long to add to the clock waits
    /// with no deadline.
    ///
    /// # Errors
    ///
    /// [`Unreached::TimedOut`] when `within` runs out first, and
    /// [`Unreached::Closed`] when the pipe closes first.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(ticket: &modelpipe::Ticket) -> Result<(), Box<dyn std::error::Error>> {
    /// let connected = modelpipe::connect(ticket, modelpipe::ConnectOptions::default()).await?;
    /// let path = connected.wait_reachable(std::time::Duration::from_secs(40)).await?;
    /// println!("reached the serve side: {}", path.as_str());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn wait_reachable(&self, within: Duration) -> Result<PipeStatus, Unreached> {
        let deadline = tokio::time::Instant::now().checked_add(within);
        // The current status first: a pipe that reached its peer before this
        // was called has no change left to wait for.
        let mut held = self.status();
        loop {
            match held {
                PipeStatus::Direct | PipeStatus::Relayed => return Ok(held),
                PipeStatus::Closed => return Err(Unreached::Closed(self.close_reason())),
                PipeStatus::Idle => {}
            }
            let next = self.status_changed_since(held);
            let next = match deadline {
                Some(deadline) => tokio::time::timeout_at(deadline, next)
                    .await
                    .map_err(|_| Unreached::TimedOut(within))?,
                None => next.await,
            };
            // `None` answers only a snapshot that was already `Closed`, and
            // the match above has returned on that.
            held = next.unwrap_or(PipeStatus::Closed);
        }
    }

    // How long this side has been out of touch: not what the pipe is doing
    // but how long it has been doing it. The clock itself lives on
    // `crate::lifecycle::Lifecycle`; the argument for having one, and for it
    // carrying no policy, is ADR 0004.

    /// How long this side has been [`PipeStatus::Idle`],
    /// or `None` when it is not idle — which means it has reached the peer
    /// **or** that the pipe is closed.
    ///
    /// Those two are told apart by the status, not by this: `None` here is
    /// not "reached". A caller that acts on absence should check
    /// [`status`](Self::status) first, which is the live/closed
    /// discriminator.
    ///
    /// `Idle` means the peer is not reachable *and is being dialled
    /// again*, for as long as the pipe is held — so the status alone
    /// cannot tell a packet lost a moment ago from a far machine that has
    /// been asleep since last night. This is the difference, and it is
    /// what a caller needs to decide when to start saying so.
    ///
    /// **The policy stays here.** How long is too long is a product
    /// decision, not a transport one: a desktop tunnel and a phone app
    /// reasonably answer it differently, and the same crate serves both.
    /// What this promises is only the measurement.
    ///
    /// The clock starts at the *transition* into `Idle`, and a re-dial
    /// that finds nobody does not restart it — a peer that is simply gone
    /// would otherwise never look away. It also starts at birth: a handle
    /// is `Idle` from the moment it is returned, so a pipe that has never
    /// reached its peer reports the age of the pipe.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(connected: &modelpipe::ConnectHandle) {
    /// const AWAY_AFTER: std::time::Duration = std::time::Duration::from_secs(30);
    /// if connected.idle_for().is_some_and(|idle| idle >= AWAY_AFTER) {
    ///     println!("the other machine is away; the port stays bound");
    /// }
    /// # }
    /// ```
    pub fn idle_for(&self) -> Option<Duration> {
        self.state.lifecycle.idle_for()
    }

    // The endpoint underneath: telling it the network moved, and reading its
    // counters. Neither hands the endpoint out; `crate::network` says why.

    /// Tell this side's endpoint that the network underneath it may have
    /// changed, and wait for the notice to be taken.
    ///
    /// Same contract as
    /// [`ServeHandle::notify_network_change`](crate::ServeHandle::notify_network_change),
    /// which states it in full — and this is the side that usually needs
    /// it, because the connecting machine is the one that moves.
    ///
    /// It does not replace the re-dial loop and does not start one: this
    /// side already retries a peer it cannot reach, for as long as the pipe
    /// is held. What this fixes is the case underneath that loop, where the
    /// socket it is dialling from is bound to an interface that no longer
    /// exists — a laptop that changed network while suspended, a phone that
    /// came back on cellular.
    pub async fn notify_network_change(&self) {
        notify(&self.state.peer.endpoint).await;
    }

    /// What the transport underneath this pipe has been doing.
    ///
    /// Same contract as
    /// [`ServeHandle::network_metrics`](crate::ServeHandle::network_metrics),
    /// and a separate set of numbers: the two sides are two endpoints, and
    /// a relay that is rate limiting one of them is not necessarily
    /// touching the other.
    pub fn network_metrics(&self) -> NetworkMetrics {
        metrics_of(&self.state.peer.endpoint)
    }

    // How this side stops.

    /// Stop accepting local connections, let the in-flight requests
    /// finish, and wait until the local listener is gone.
    ///
    /// Same contract as [`ServeHandle::shutdown`](crate::ServeHandle::shutdown): drains rather than
    /// cuts, does not time out, takes `&self` for shared-state embedders,
    /// and is idempotent. Dropping the handle cuts instead.
    ///
    /// The drain waits for each response to be written to its local client.
    /// A client that leaves a large response unread holds it, even after
    /// closing its own sending half; one that keeps its socket open once it
    /// has its whole response does not. A request this side refuses itself,
    /// because the serve side cannot be reached, holds it for up to five
    /// seconds after the refusal unless its client closes sooner.
    /// [`shutdown_timeout`](Self::shutdown_timeout) bounds the drain.
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

/// Why [`ConnectHandle::wait_reachable`] returned without reaching the serve
/// side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unreached {
    /// The wait ran out, after the duration it was given, with the pipe still
    /// looking. The pipe keeps looking: the handle is live, and a serve side
    /// that turns up later is picked up.
    TimedOut(Duration),
    /// The pipe closed before it reached the serve side, for the reason
    /// [`ConnectHandle::close_reason`] reports.
    Closed(Option<CloseReason>),
}

impl fmt::Display for Unreached {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimedOut(within) => write!(
                f,
                "could not reach the serve side within {within:?}, directly or via a relay"
            ),
            Self::Closed(Some(reason)) => write!(
                f,
                "the pipe closed ({}) before it reached the serve side",
                reason.as_str()
            ),
            Self::Closed(None) => f.write_str("the pipe closed before it reached the serve side"),
        }
    }
}

impl std::error::Error for Unreached {}

/// The URL to point a client at.
///
/// Not the bind address verbatim. A wildcard bind is a listen address, not
/// a destination — nobody can connect to `0.0.0.0` — so it renders as
/// loopback, which is a place the client can actually reach. An IPv6 zone
/// id is dropped rather than emitted, because no URL parser accepts one.
pub(crate) fn base_url(addr: SocketAddr) -> String {
    // The wildcard rewrite is `backend_url`'s, shared with the pairing
    // exchange and with `BackendUrl::at`, so the three cannot drift.
    let host = match crate::backend_url::dialable_ip(addr.ip()) {
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
