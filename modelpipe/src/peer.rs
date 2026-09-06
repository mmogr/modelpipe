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
//! What no amount of re-dialling survives is the serve side restarting
//! **without an identity file**. The endpoint key is minted per process by
//! default, so such a listener is a different peer the old ticket has no
//! relation to, and dialling on reaches nobody rather than reaching someone
//! who refuses. That is ticket rotation working exactly as designed, and it
//! is a re-pairing rather than a reconnection — which is why this module
//! gives up on nothing and still cannot help you there.
//!
//! A listener started with `--identity` keeps its id across the restart, so
//! the loop below *is* what reconnects to it. The addresses in the ticket
//! are still a snapshot of the old process's ports, so finding the new ones
//! is discovery's job rather than this module's — see `identity.rs` for
//! why a durable ticket is not automatically a reachable one.

use iroh::endpoint::{Connection, Path};
use iroh::{Endpoint, EndpointAddr};
use std::sync::RwLock;
use std::time::Duration;

use crate::ConnectError;
use crate::connect::ConnectOptions;
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
    /// borrowed argument to [`bind`](Self::bind) and the pipe outlives the
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
    /// Open this side's endpoint and work out where the ticket points.
    ///
    /// Deliberately stops short of dialling. Every dial is
    /// [`keep_connected`]'s, the first one included, which is what lets
    /// [`connect`](fn@crate::connect) return with the local port bound and
    /// nobody reached yet: iroh spends about thirty seconds giving up on a
    /// peer that is not there, and a caller blocked for that long cannot
    /// even be told which port it was given.
    ///
    /// What can still fail here is local and immediate — a ticket naming an
    /// address nobody could be at, a relay that does not parse, a socket
    /// this machine will not open — and that is exactly the set
    /// [`connect`](fn@crate::connect) still reports through its `Result`.
    pub(crate) async fn bind(ticket: &Ticket, opts: &ConnectOptions) -> Result<Self, ConnectError> {
        let addr = transport::addr_from(ticket)?;
        // No stored key on this side: nothing dials *us*, so this
        // endpoint's identity is never in anybody's ticket and has nothing
        // to outlive. The serve side's `--identity` is the mirror of this.
        let net = transport::NetOptions {
            port_mapping: opts.port_mapping,
            discovery: opts.discovery,
        };
        let endpoint = transport::bind(opts.relay.as_deref(), None, net).await?;
        Ok(Self {
            endpoint,
            addr,
            // Empty, and the reconnect loop fills it. `Idle` is therefore
            // the honest status the moment a handle is handed out.
            connection: RwLock::new(None),
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

/// Reach the peer, and keep a connection to it for as long as the pipe is
/// up.
///
/// **Every dial is this loop's, the first one included.** That is what lets
/// [`connect`](fn@crate::connect) return once the local port is bound:
/// [`Peer::bind`] opens an endpoint and reaches nobody, and the pipe starts
/// life here, at `Idle`, with a listener already answering.
///
/// It is also what makes `ConnectHandle`'s documented behaviour true rather
/// than merely stated. Before it, the connect side opened exactly one
/// connection and held it for life, so a peer that went away left it 502ing
/// for ever while its status still read `direct` — measured twenty minutes
/// after the serve side was killed.
///
/// `Idle` is published while there is no connection, and it is the only
/// thing a caller is owed about a dial that has not landed. It is not a
/// failure and not a timeout: a sleeping laptop, a dead one and a serve
/// side five seconds from starting look identical from here, so this side
/// reports what it sees and leaves the policy to whoever watches the status.
///
/// The cadence below is not the whole cadence. A dial at a peer that is
/// simply gone takes iroh about thirty seconds to give up on, so the
/// backoff is added to that rather than being the interval between
/// attempts. It is set for the case where dialling *fails fast*, and the
/// ceiling is what keeps a peer off for the night from being dialled
/// thousands of times either way.
pub(crate) async fn keep_connected(peer: &Peer, lifecycle: &Lifecycle) {
    let mut backoff = FIRST_RETRY;
    // One line per episode of having nobody, not one per attempt. The first
    // dial's failure is why a freshly returned handle reads `Idle`, and
    // without saying so nothing at default verbosity does — but a serve
    // side off for the night must not narrate every retry until morning.
    let mut announced = false;
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
            // The state change, said once. Every request from here until a
            // re-dial succeeds is answered 502 by `dialer::carry`, and this
            // is the line that explains all of them — which is why it is
            // `info` while the individual attempts below are not.
            tracing::info!("the peer went away, and this side is looking for it");
            announced = true;
            backoff = FIRST_RETRY;
        }

        // And go looking for it.
        let dialed = tokio::select! {
            biased;
            () = lifecycle.wait_until_closed() => return,
            dialed = peer.redial() => dialed,
        };
        if let Some(path) = dialed {
            let status = aggregate(&[path]);
            lifecycle.set_status(status);
            tracing::info!(path = status.as_str(), "the peer is back");
            announced = false;
            continue;
        }
        if !announced {
            announced = true;
            tracing::info!("the serve side did not answer, and this side is looking for it");
        }
        // `debug`, not `info`: a serve side that is off for the night is
        // dialled until morning, and the fact worth an operator's attention
        // is the line above rather than every attempt under it.
        tracing::debug!(
            backoff_ms = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX),
            "a dial found nobody"
        );
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
