//! The connection to the serve side, and holding on to it.
//!
//! One QUIC connection at a time, *replaced* rather than mutated: an
//! exchange that took a clone finishes on the connection it started on, and
//! a reconnection appears beside it rather than being swapped under its
//! feet.
//!
//! Splitting this from [`crate::dialer`] is a split by lifetime as much as
//! by responsibility. The local listener is bound once and lives until
//! teardown; the connection behind it is the thing that dies and comes
//! back, and every question worth asking about it — is there one right now,
//! how is it reaching the peer, what happens when it goes — belongs
//! together and nowhere near the byte copying.
//!
//! The endpoint id is what makes coming back possible at all. A ticket
//! carries direct addresses to help the first pairing avoid the relay, but
//! the id is the durable half: iroh resolves it through discovery, so a
//! peer that woke up on a different network, behind a different NAT, with
//! every address in the ticket now wrong, is still findable under the same
//! name.
//!
//! What no amount of re-dialling survives is the serve side **restarting**.
//! The endpoint key is minted per process, so a restarted listener is a
//! different peer that the old ticket has no relation to, and dialling on
//! reaches nobody rather than reaching someone who refuses. That is ticket
//! rotation working exactly as designed, and it is a re-pairing rather than
//! a reconnection — which is why this module gives up on nothing and still
//! cannot help you there.

use iroh::endpoint::{Connection, Path};
use iroh::{Endpoint, EndpointAddr};
use std::sync::RwLock;
use std::time::Duration;

use crate::ConnectError;
use crate::lifecycle::{Lifecycle, PeerPath, aggregate};
use crate::status::PipeStatus;
use crate::ticket::Ticket;
use crate::transport;

/// The serve side, as this end knows how to reach it.
pub(crate) struct Peer {
    /// Held for the life of the pipe: it owns the socket every connection
    /// below is opened on, and it is what a re-dial dials from.
    endpoint: Endpoint,
    /// Where to dial, kept rather than derived once. A ticket is a
    /// borrowed argument to [`dial`](Self::dial) and the pipe outlives the
    /// call.
    addr: EndpointAddr,
    /// The live connection, or `None` while there is not one.
    ///
    /// An `RwLock` rather than a `watch`: the readers are per-exchange and
    /// want the current value, not a stream of them, and the one writer is
    /// the reconnect loop.
    ///
    /// `std`'s rather than tokio's, and the reason is `Drop`. Every access
    /// here is a clone or a take of a cheap handle, so the guard is never
    /// held across an await and an async lock buys nothing — while a
    /// *synchronous* one is what lets `ConnectHandle`'s `Drop` still cut
    /// the connection without a runtime, which is a documented difference
    /// between the two sides. The same reasoning `listener.rs` gives for
    /// its peer map.
    connection: RwLock<Option<Connection>>,
}

impl Peer {
    /// Bind an endpoint and reach the ticket's peer for the first time.
    ///
    /// The first dial is the one allowed to fail outright: a caller that
    /// cannot reach the serve side at all wants to be told so by
    /// [`connect`](fn@crate::connect) rather than handed a handle that will
    /// keep trying forever behind their back. Every dial *after* this one
    /// is the reconnect loop's, and those are retried rather than reported.
    pub(crate) async fn dial(ticket: &Ticket) -> Result<Self, ConnectError> {
        let addr = transport::addr_from(ticket)?;
        let endpoint = transport::bind(None).await?;
        let connection = endpoint
            .connect(addr.clone(), transport::ALPN)
            .await
            // Everything a dial can fail with is retryable, and there is no
            // "rejected" case to tell apart: the endpoint key is ephemeral,
            // so a serve side that restarted is a different endpoint and
            // this reaches nobody rather than reaching someone who refuses.
            .map_err(|_| ConnectError::PeerUnreachable)?;
        Ok(Self {
            endpoint,
            addr,
            connection: RwLock::new(Some(connection)),
        })
    }

    /// The connection to use right now, if there is one.
    ///
    /// A clone, so the caller holds it for the whole exchange even if the
    /// reconnect loop replaces the cell a moment later. That is the
    /// difference between a request surviving a reconnection and being cut
    /// by one.
    pub(crate) fn current(&self) -> Option<Connection> {
        self.read().clone()
    }

    /// Forget the current connection, if it is still the one given.
    ///
    /// Conditional on purpose. The reconnect loop notices a death, and by
    /// the time it takes the write lock a later loop may already have
    /// dialled a replacement; clearing unconditionally would throw away a
    /// working connection and produce a gap nobody asked for.
    pub(crate) fn forget(&self, dead: &Connection) {
        let mut held = self.write();
        if held
            .as_ref()
            .is_some_and(|live| live.stable_id() == dead.stable_id())
        {
            *held = None;
        }
    }

    /// Dial again, installing the result if it succeeds.
    pub(crate) async fn redial(&self) -> Option<PeerPath> {
        let connection = self
            .endpoint
            .connect(self.addr.clone(), transport::ALPN)
            .await
            .ok()?;
        let path = path_of(&connection);
        *self.write() = Some(connection);
        Some(path)
    }

    /// Publish the path the current connection is using, if there is one.
    ///
    /// Exists so the initial status can be set before a handle is handed
    /// out — a spawned task has not necessarily run by the time `connect`
    /// returns, and `Idle` is this side's word for "the peer is gone", so
    /// the one moment the answer was wrong it was wrong in the most
    /// misleading direction available.
    pub(crate) fn publish_path(&self, lifecycle: &Lifecycle) {
        if let Some(connection) = self.current() {
            lifecycle.set_status(aggregate(&[path_of(&connection)]));
        }
    }

    /// Close whatever is connected, for teardown.
    pub(crate) fn close(&self, reason: &[u8]) {
        // Taken out from under the lock before it is closed, rather than
        // closed inside the `if let`: that form holds the write guard for
        // the whole body, so a reconnect loop asking for the connection at
        // that moment would wait on a teardown it has no part in. Clippy
        // names this one, and it is right to.
        let dying = self.write().take();
        if let Some(connection) = dying {
            connection.close(0u32.into(), reason);
        }
    }

    // Poisoning is not a state this crate can be in usefully: the guarded
    // value is one cheap handle, nothing between lock and unlock can
    // observe a half-written one, and refusing to serve because some other
    // task panicked would turn a survivable bug into a dead pipe. The same
    // call `listener.rs` makes over its peer map.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, Option<Connection>> {
        self.connection
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Option<Connection>> {
        self.connection
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// How a connection is reaching the peer, read from the live paths.
///
/// Shared with the serve side, which asks the identical question of the
/// identical type. It was written twice, and two copies of a rule about
/// what counts as `Direct` is one copy too many for a value the CLI prints
/// and an embedder watches.
///
/// No selected path means nothing is established yet, and the conservative
/// reading is the one [`crate::lifecycle::aggregate`] already takes: report
/// the worse of the two. A snapshot, honest about the moment it was taken —
/// a path that migrates afterwards is not followed.
pub(crate) fn path_of(connection: &Connection) -> PeerPath {
    connection
        .paths()
        .iter()
        .find(Path::is_selected)
        .map_or(PeerPath::Relayed, |path| {
            if path.remote_addr().is_relay() {
                PeerPath::Relayed
            } else {
                PeerPath::Direct
            }
        })
}

/// How long to wait before the first re-dial, and the ceiling it doubles
/// to.
///
/// The first attempt after a death is immediate — a laptop waking up wants
/// its pipe back now, not in half a second — and only a *failed* dial
/// starts the backoff. The ceiling matters more than the floor: a serve
/// side that is off for the night must not be dialled thousands of times,
/// and thirty seconds is short enough that coming back is noticed promptly
/// and long enough to be nobody's idea of a busy loop.
const FIRST_RETRY: Duration = Duration::from_millis(500);
const RETRY_CEILING: Duration = Duration::from_secs(30);

/// Keep a connection to the peer for as long as the pipe is up.
///
/// This is what makes `ConnectHandle`'s documented behaviour true rather
/// than merely stated. Before it, `dial` opened exactly one connection and
/// held it for life: a peer that went away left the connect side answering
/// 502 to every request, for ever, while its status still read `direct` and
/// nothing on the client machine ever said otherwise. Measured — the serve
/// side killed, the connect process left running: still `direct`, still
/// 502ing, twenty minutes later.
///
/// `Idle` is published while there is no connection, which is the state the
/// handle's own docs promised and no code could reach. It is not a failure
/// and not a timeout: a sleeping laptop and a dead one look identical from
/// here, so this side reports what it sees and leaves the policy to whoever
/// is watching the status.
///
/// The cadence below is not the whole cadence. A dial at a peer that is
/// simply gone takes iroh about thirty seconds to give up on — the figure
/// `dial` above already records, from the occupied-port bug — so the
/// backoff is added to that rather than being the interval between
/// attempts. It is set for the case where dialling *fails fast*, and the
/// ceiling is what keeps a peer that is off for the night from being dialled
/// thousands of times either way.
pub(crate) async fn keep_connected(peer: &Peer, lifecycle: &Lifecycle) {
    let mut backoff = FIRST_RETRY;
    loop {
        // Wait out the connection there is, if there is one.
        if let Some(live) = peer.current() {
            tokio::select! {
                biased;
                () = lifecycle.wait_until_closed() => return,
                _ = live.closed() => {}
            }
            peer.forget(&live);
            lifecycle.set_status(PipeStatus::Idle);
            backoff = FIRST_RETRY;
        }

        // And go looking for its replacement.
        let dialed = tokio::select! {
            biased;
            () = lifecycle.wait_until_closed() => return,
            dialed = peer.redial() => dialed,
        };
        if let Some(path) = dialed {
            lifecycle.set_status(aggregate(&[path]));
            continue;
        }
        tokio::select! {
            biased;
            () = lifecycle.wait_until_closed() => return,
            () = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(RETRY_CEILING);
    }
}

#[cfg(test)]
#[path = "peer_tests.rs"]
mod peer_tests;
