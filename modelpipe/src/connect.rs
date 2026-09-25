//! Binding a local port that is the remote backend: the entry point,
//! what it is given, and how it fails.
//!
//! Orchestration. The live listener you get back lives in
//! [`crate::connect_handle`]; this module owns the call and its inputs.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use crate::connect_handle::ConnectHandle;
use crate::dialer;
use crate::ticket::Ticket;
use crate::transport;

/// How often an idle pipe tells its endpoint the network may have changed.
///
/// A default rather than a rule: see
/// [`ConnectOptions::idle_network_nudge`].
const IDLE_NETWORK_NUDGE: Duration = Duration::from_mins(1);

/// Why [`connect`] failed. Same contract as [`ServeError`](crate::ServeError): variants a
/// retry policy can match on, transport details behind `source`.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConnectError {
    /// The ticket names an address nobody could ever be at — an endpoint
    /// id that is not a key. Retryable in the sense the other variants
    /// are, and dialling it again will fail again.
    ///
    /// **Not what an offline serve side looks like.** [`connect`] returns
    /// once the local port is bound, so a peer that is merely absent is
    /// never reported here: it is a handle at
    /// [`PipeStatus::Idle`](crate::PipeStatus::Idle) that keeps trying. A
    /// ticket outlived by its listener is that case too, and there is no
    /// "ticket rejected" to distinguish it from — a serve side that
    /// restarted **without** an identity file is a *different* endpoint, so
    /// the old ticket reaches nobody rather than reaching someone who
    /// refuses. A caller wanting to tell "offline" from "re-paired" has to
    /// ask a human, not this enum.
    PeerUnreachable,
    /// The local address the caller asked for could not be bound.
    ///
    /// Only that one. The p2p endpoint this side also binds is
    /// [`Endpoint`](Self::Endpoint), and keeping them apart is what makes
    /// this variant's permanence true rather than merely stated.
    Bind(std::io::Error),
    /// The p2p endpoint could not be set up. The twin of
    /// [`ServeError::Bind`](crate::ServeError::Bind), and retryable for the
    /// same reason: no address here was chosen by anyone.
    Endpoint(std::io::Error),
    /// [`ConnectOptions::relay`] does not parse as a relay URL. The twin of
    /// [`ServeError::InvalidRelay`](crate::ServeError::InvalidRelay), with
    /// the same scope: syntactic, before anything is dialled, and the
    /// operator's to fix.
    InvalidRelay {
        /// The offending URL, for the error message.
        url: String,
    },
    /// [`ConnectOptions::identity`] names a file this side cannot use as its
    /// endpoint key: one that is not a key, one others can read, a path that
    /// is not a regular file (a symlink included), or one it cannot read or
    /// write. The twin of
    /// [`ServeError::Identity`](crate::ServeError::Identity), and permanent
    /// for the same reason: the path is the caller's.
    Identity {
        /// The offending path, for the error message.
        path: String,
        /// What went wrong with it.
        source: std::io::Error,
    },
}

impl ConnectError {
    /// Whether trying again could succeed without anyone changing
    /// anything. Same contract, and same no-`_`-arm rule, as
    /// [`ServeError::is_retryable`](crate::ServeError::is_retryable).
    ///
    /// The two enums look like they disagree about "a bind failed", and
    /// they do not: they name two different failures.
    /// [`Bind`](Self::Bind) is the address the caller passed through
    /// [`ConnectOptions::bind`], which retrying will fail on forever;
    /// [`Endpoint`](Self::Endpoint) is the p2p socket nobody chose, which
    /// is [`ServeError::Bind`](crate::ServeError::Bind) by another name and
    /// retryable exactly as that one is.
    ///
    /// Splitting them is what makes the classification honest. While one
    /// variant carried both, two of its three producers named no
    /// caller-chosen address at all — including the iroh endpoint, bound
    /// with `None` — so a supervisor following this contract abandoned
    /// `connect` permanently over a transient `EMFILE`.
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::PeerUnreachable | Self::Endpoint(_) => true,
            Self::Bind(_) | Self::InvalidRelay { .. } | Self::Identity { .. } => false,
        }
    }
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerUnreachable => {
                write!(f, "could not reach the serve side, directly or via a relay")
            }
            // Neither interpolates its source: `anyhow` prints the
            // top-level Display and then the chain, so a variant that does
            // both prints the OS error twice.
            Self::Bind(_) => f.write_str("could not bind the requested local address"),
            Self::Endpoint(_) => f.write_str("could not set up the p2p endpoint"),
            Self::InvalidRelay { url } => {
                write!(
                    f,
                    "{url} does not parse as a relay URL — check the value passed as the relay"
                )
            }
            // The cause is `source`, for the reason `Bind` gives.
            Self::Identity { path, .. } => write!(f, "the identity file at {path} cannot be used"),
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PeerUnreachable | Self::InvalidRelay { .. } => None,
            Self::Bind(e) | Self::Endpoint(e) | Self::Identity { source: e, .. } => Some(e),
        }
    }
}

/// Options for [`connect`]. Same contract as [`ServeOptions`](crate::ServeOptions).
///
/// Derives `Debug` where [`ServeOptions`](crate::ServeOptions) hand-writes one: nothing here
/// is a credential, so there is nothing to redact.
#[derive(Debug)]
#[non_exhaustive]
pub struct ConnectOptions {
    /// Local address to bind. `None` picks a free port on loopback.
    pub bind: Option<SocketAddr>,
    /// Self-hosted relay URL for *this* side's endpoint. `None` uses iroh's
    /// public relays. The serve side's relay travels in the ticket and is
    /// dialled regardless; this is the relay this endpoint registers with
    /// and falls back to, which until now was always a public one.
    pub relay: Option<String>,
    /// Same as [`ServeOptions::port_mapping`](crate::ServeOptions#structfield.port_mapping).
    pub port_mapping: bool,
    /// Same as [`ServeOptions::discovery`](crate::ServeOptions#structfield.discovery),
    /// from the side that *resolves*: with it off, this side dials only
    /// the paths the ticket carries.
    pub discovery: bool,
    /// Same as [`ServeOptions::relay_only`](crate::ServeOptions#structfield.relay_only),
    /// and it takes only one side to force the outcome: with no IP
    /// transport here, the ticket's direct addresses are unreachable from
    /// this endpoint and the relay is the only path left. Setting it on
    /// this side is the cheaper of the two, because it needs no
    /// re-pairing — the serve side keeps the ticket it already handed out.
    pub relay_only: bool,
    /// Where to keep this side's endpoint key, so a serve side sees the same
    /// peer every time this machine connects.
    ///
    /// `None`, the default, mints a fresh key per process, as every version
    /// before this one did. Nothing dials a connect side, so its key is in no
    /// ticket, but the serve side does see it: as the peer in
    /// [`ServeHandle::peers`](crate::ServeHandle::peers) and the
    /// `X-Modelpipe-Peer` header, and as [`ConnectHandle::peer_id`] here. A
    /// key kept in this file makes that the same across restarts, which is
    /// what lets a serve side recognise a device by it.
    ///
    /// The file rules are
    /// [`ServeOptions::identity`](crate::ServeOptions#structfield.identity)'s:
    /// minted on first use, created readable only by its owner, and refused
    /// as [`ConnectError::Identity`] when others can read it or when the
    /// path is not a regular file, a symlink included. Keep it apart
    /// from any listener's file, because one key is one endpoint.
    pub identity: Option<std::path::PathBuf>,
    /// How often, while there is no connection, to tell this endpoint the
    /// network may have changed. `None` never does.
    ///
    /// The re-dial loop does not need this: it keeps dialling on its own,
    /// and finds a peer that comes back. What it does not fix is the
    /// *socket underneath*, which a suspend can leave bound to an
    /// interface that no longer exists — a laptop that changed network
    /// while its lid was shut is the case. The endpoint rebinds when it
    /// is told the network moved, and nothing else in this crate tells
    /// it.
    ///
    /// Only ever while idle, so the cost is bounded by how long there is
    /// nobody to talk to, and the call is harmless when nothing changed.
    /// A caller that watches the real thing — `NWPathMonitor`,
    /// `netlink` — should do that instead and set this to `None`; this is
    /// the floor for a caller that watches nothing.
    ///
    /// Once a minute by default — and **a floor, not a period**: it is
    /// checked once per re-dial round, and a round against a peer that is
    /// gone lasts as long as the transport takes to give up, so a minute
    /// means a nudge every minute *or more*.
    pub idle_network_nudge: Option<Duration>,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            bind: None,
            relay: None,
            idle_network_nudge: Some(IDLE_NETWORK_NUDGE),
            port_mapping: true,
            discovery: true,
            relay_only: false,
            identity: None,
        }
    }
}

/// Bind a local port that transparently is the remote backend. Point any
/// OpenAI-compatible client at [`ConnectHandle::base_url`], with the
/// serve side's bearer token as the API key.
///
/// **Returns as soon as that port is bound.** Reaching the serve side runs
/// on a background task, so an absent peer costs the caller nothing: iroh
/// spends about thirty seconds giving up on one, and a caller blocked for
/// that long cannot even be told which port it was given, let alone point a
/// client at it. Requests arriving before the pairing forms are answered
/// `502` rather than refused, which is the same answer they get if the peer
/// goes away later.
///
/// The dial's outcome is the handle's to report, not this `Result`'s:
/// [`ConnectHandle::status`] reads [`PipeStatus::Idle`](crate::PipeStatus::Idle)
/// until a connection forms and [`Direct`](crate::PipeStatus::Direct) or
/// [`Relayed`](crate::PipeStatus::Relayed) once one has, and
/// [`ConnectHandle::status_changed`] delivers each transition. A dial that
/// fails is not an error and not the end — this side keeps trying, because
/// a sleeping laptop, a dead one and a serve side five seconds from
/// starting are the same picture from here. **Deciding how long to wait
/// before giving up is the caller's**, and `modelpipe-cli` is one worked
/// example of making that decision.
///
/// What this `Result` still reports is everything local and immediate: an
/// address that will not bind, a relay that will not parse, an endpoint
/// this machine will not open.
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Tickets are text: they arrive over whatever channel you already
/// // trust, and parse before anything is dialled.
/// let ticket: modelpipe::Ticket = "pipeabc…".parse()?;
///
/// let connected = modelpipe::connect(&ticket, modelpipe::ConnectOptions::default()).await?;
///
/// // Point an OpenAI-compatible client here, with the serve side's token
/// // as the API key.
/// println!("{}", connected.base_url());
/// println!("reaching the peer: {}", connected.status().as_str());
///
/// connected.shutdown().await;
/// # Ok(())
/// # }
/// ```
///
/// To bind somewhere specific, assign to [`ConnectOptions::bind`] — the
/// same `default()`-then-assign shape [`serve`](fn@crate::serve) uses, and
/// for the same reason:
///
/// ```no_run
/// # async fn example(ticket: &modelpipe::Ticket) -> Result<(), Box<dyn std::error::Error>> {
/// let mut opts = modelpipe::ConnectOptions::default();
/// opts.bind = Some("127.0.0.1:8080".parse()?);
/// let connected = modelpipe::connect(ticket, opts).await?;
/// # let _ = connected;
/// # Ok(())
/// # }
/// ```
pub async fn connect(ticket: &Ticket, opts: ConnectOptions) -> Result<ConnectHandle, ConnectError> {
    // Cheapest and the operator's to fix, so first — the order `serve`
    // keeps for the same value.
    if let Some(relay) = opts.relay.as_deref() {
        transport::validate_relay_for_connect(relay)?;
    }
    // Read before `opts` is borrowed into the bind and then dropped.
    let nudge = opts.idle_network_nudge;
    let (state, listener) = dialer::bind(ticket, &opts).await?;
    tokio::spawn(dialer::local_loop(state.clone(), listener));
    // The reconnect loop takes the two halves it needs by reference, so
    // the `Arc` that keeps them alive is held here rather than threaded
    // through `peer`, which has no business knowing how the connect side
    // stores its state.
    let watching = state.clone();
    // The dial lives in here, first attempt included. Spawning it rather
    // than awaiting it is the whole of this function's contract: the handle
    // below is handed out with a port already answering.
    tokio::spawn(async move {
        crate::peer_redial::keep_connected(&watching.peer, &watching.lifecycle, nudge).await;
    });
    Ok(ConnectHandle::new(state))
}

#[cfg(test)]
#[path = "connect_tests.rs"]
mod connect_tests;
