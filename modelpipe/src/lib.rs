//! Reach an OpenAI-compatible model server from anywhere over p2p.
//!
//! This is the API sketch under review — the contract, not the
//! implementation. Signatures are settled intent; bodies are `todo!()`.
//! The iroh types stay out of the public surface deliberately: callers
//! hold [`Ticket`]s and handles, so an iroh major upgrade is this crate's
//! problem, not its dependents'. The same rule shapes the error types:
//! failures arrive as [`ServeError`] / [`ConnectError`] variants a caller
//! can match a retry policy against, with the transport's own error
//! reachable only as an opaque [`source`](std::error::Error::source).

use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

/// A pairing ticket: how one machine finds and authenticates another's
/// listener. Base32 on the wire so it survives QR codes, terminals, and
/// being read aloud.
///
/// Contains the serve side's endpoint identity (endpoint id plus a set of
/// transport addresses) and a backend-kind hint — and deliberately *not*
/// the bearer token, which travels separately so that a leaked ticket
/// alone cannot make a request. The format is versioned; see the README
/// for the payload shape and the current status of the wire spec.
#[derive(Clone)]
pub struct Ticket {
    // Field layout is private; the README's table is the public contract.
    _private: (),
}

impl Ticket {
    /// Short fingerprint of the serve side's identity, for `status`
    /// output and eyeball comparison. Never the full key.
    pub fn fingerprint(&self) -> String {
        todo!()
    }
}

impl fmt::Debug for Ticket {
    // Hand-written, never derived: `Display` emits the full ticket (that
    // is its job — the CLI prints it), so a derived `Debug` over the real
    // fields would copy pairing credentials into every downstream panic
    // message and `tracing` line. The fingerprint is the only part of a
    // ticket a log should ever see.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ticket").field(&self.fingerprint()).finish()
    }
}

impl fmt::Display for Ticket {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl FromStr for Ticket {
    type Err = TicketParseError;

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

/// Why a ticket string failed to parse. Deliberately coarse: a ticket is
/// pasted or scanned, so the only useful advice is "re-copy it".
#[derive(Debug)]
#[non_exhaustive]
pub enum TicketParseError {
    /// Not base32, truncated, or checksum failure.
    Malformed,
    /// Parsed, but a format version this build doesn't speak.
    UnsupportedVersion(u8),
}

impl fmt::Display for TicketParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => write!(f, "ticket is malformed — re-copy it from the serve side"),
            Self::UnsupportedVersion(v) => write!(f, "ticket format v{v} is newer than this build"),
        }
    }
}

impl std::error::Error for TicketParseError {}

/// Why [`serve`] failed. The variants are the caller's retry policy:
/// [`BackendNotLocal`](Self::BackendNotLocal) is permanent and
/// user-fixable, the rest describe the machine underneath.
#[derive(Debug)]
#[non_exhaustive]
pub enum ServeError {
    /// The backend URL did not resolve to an accepted address. Loopback
    /// always passes; RFC 1918 / `fc00::/7` only with
    /// [`ServeOptions::allow_private_backend`]; link-local
    /// (`169.254.0.0/16`, `fe80::/10` — where cloud instance metadata
    /// lives) and public addresses, never. The check runs against the
    /// *resolved* address of every outbound connection, not the URL text,
    /// so a DNS name cannot smuggle an address past it.
    BackendNotLocal {
        /// The offending URL, for the error message.
        url: String,
    },
    /// The p2p listener could not be set up.
    Bind(std::io::Error),
    /// The transport failed. The inner error is deliberately opaque:
    /// naming iroh's types here would put them in the public surface.
    Transport(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for ServeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendNotLocal { url } => write!(
                f,
                "backend {url} is not a local address — modelpipe exposes your own server, not the network behind it"
            ),
            Self::Bind(e) => write!(f, "could not set up the p2p listener: {e}"),
            Self::Transport(e) => write!(f, "transport failure: {e}"),
        }
    }
}

impl std::error::Error for ServeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BackendNotLocal { .. } => None,
            Self::Bind(e) => Some(e),
            Self::Transport(e) => Some(&**e),
        }
    }
}

/// Why [`connect`] failed. Same contract as [`ServeError`]: variants a
/// retry policy can match on, transport details behind `source`.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConnectError {
    /// The serve side is reachable but does not recognize this ticket —
    /// it has restarted since the ticket was issued. Not retryable:
    /// re-pair with a fresh ticket.
    TicketRejected,
    /// The peer could not be reached, directly or through a relay.
    /// Retryable: the serve side may be offline, or the network in
    /// between temporarily unwilling.
    PeerUnreachable,
    /// The requested local address could not be bound.
    Bind(std::io::Error),
    /// The transport failed some other way. Opaque on purpose; see
    /// [`ServeError::Transport`].
    Transport(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TicketRejected => write!(
                f,
                "the serve side no longer recognizes this ticket — it restarted; pair again with a fresh one"
            ),
            Self::PeerUnreachable => {
                write!(f, "could not reach the serve side, directly or via a relay")
            }
            Self::Bind(e) => write!(f, "could not bind the local address: {e}"),
            Self::Transport(e) => write!(f, "transport failure: {e}"),
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TicketRejected | Self::PeerUnreachable => None,
            Self::Bind(e) => Some(e),
            Self::Transport(e) => Some(&**e),
        }
    }
}

/// Options for [`serve`].
///
/// Start from `Default` — the recommended configuration — and set what
/// you need. `#[non_exhaustive]`, so a new option is not a breaking
/// change for callers who construct it that way.
#[derive(Default)]
#[non_exhaustive]
pub struct ServeOptions {
    /// Serve without a bearer token. The ticket becomes the only lock,
    /// which is exactly the failure mode this crate exists to close —
    /// hence the name. Off by default, loudly discouraged.
    pub insecure_no_auth: bool,
    /// Self-hosted relay URL. `None` uses iroh's public relays, which
    /// carry only ciphertext either way.
    pub relay: Option<String>,
    /// Accept a backend on a private (RFC 1918 / `fc00::/7`) address
    /// rather than loopback only. Off by default: `serve` extends trust
    /// outward from this machine, and pointing it into the LAN is a
    /// decision the operator should make explicitly. Link-local ranges
    /// are never accepted regardless; see
    /// [`ServeError::BackendNotLocal`].
    pub allow_private_backend: bool,
}

/// Options for [`connect`]. Same contract as [`ServeOptions`].
#[derive(Default)]
#[non_exhaustive]
pub struct ConnectOptions {
    /// Local address to bind. `None` picks a free port on loopback.
    pub bind: Option<SocketAddr>,
}

/// Expose the OpenAI-compatible server at `backend_url` (e.g.
/// `http://127.0.0.1:11434`) to holders of the returned handle's ticket.
///
/// Generates a bearer token (unless `insecure_no_auth`) and rejects any
/// incoming request whose `Authorization` header doesn't carry it —
/// before a byte reaches the backend. Read the token off the handle
/// ([`ServeHandle::token`]) and give it to clients alongside the ticket;
/// it is deliberately not *inside* the ticket, so the two credentials
/// travel — and leak — independently.
///
/// The backend must be local. Loopback always passes; private-range
/// addresses only with [`ServeOptions::allow_private_backend`]; anything
/// else is [`ServeError::BackendNotLocal`]. This crate extends trust
/// outward, it does not re-export someone else's server.
pub async fn serve(backend_url: &str, opts: ServeOptions) -> Result<ServeHandle, ServeError> {
    let _ = (backend_url, opts);
    todo!()
}

/// Bind a local port that transparently is the remote backend. Point any
/// OpenAI-compatible client at [`ConnectHandle::base_url`], with the
/// serve side's bearer token as the API key.
pub async fn connect(ticket: &Ticket, opts: ConnectOptions) -> Result<ConnectHandle, ConnectError> {
    let _ = (ticket, opts);
    todo!()
}

/// A live serve side.
///
/// Dropping it tears the listener down best-effort, without waiting;
/// [`shutdown`](Self::shutdown) is the graceful version that completes
/// once the listener is gone. Either way the ticket is dead from that
/// moment and a new [`serve`] mints a fresh one — there is no way to keep
/// a ticket valid across restarts, so ticket rotation *is* the restart.
/// (Token rotation is cheaper: [`rotate_token`](Self::rotate_token).)
pub struct ServeHandle {
    _private: (),
}

impl ServeHandle {
    /// The ticket to hand to connecting machines (print it, QR it).
    pub fn ticket(&self) -> &Ticket {
        todo!()
    }

    /// The bearer token clients must present, or `None` when serving
    /// open. Print it next to the ticket; it reaches client machines
    /// out-of-band, which is what makes it a second lock rather than a
    /// decoration on the first.
    pub fn token(&self) -> Option<&str> {
        todo!()
    }

    /// Mint and install a replacement bearer token, returning it. The old
    /// token stops working immediately; the ticket — and every existing
    /// pairing — stays valid, so this is the recovery move for a leaked
    /// token and it costs nothing but redistributing the new one. When
    /// serving open, this turns auth *on* from this call forward.
    pub fn rotate_token(&self) -> String {
        todo!()
    }

    /// Current transport status, for `status` output.
    pub fn status(&self) -> PipeStatus {
        todo!()
    }

    /// Wait for the next status transition and return the new status.
    /// This is how a caller surfaces "direct ↔ relayed" changes as they
    /// happen, rather than polling [`status`](Self::status).
    pub async fn status_changed(&self) -> PipeStatus {
        todo!()
    }

    /// Tear down and wait until the listener is gone.
    pub async fn shutdown(self) {
        todo!()
    }
}

/// A live connect side.
///
/// Teardown semantics match [`ServeHandle`]: dropping tears down without
/// waiting, [`shutdown`](Self::shutdown) waits.
pub struct ConnectHandle {
    _private: (),
}

impl ConnectHandle {
    /// The bound local address.
    pub fn local_addr(&self) -> SocketAddr {
        todo!()
    }

    /// The URL to point an OpenAI-compatible client at, ready to paste:
    /// `http://{host}/v1` with a host that is actually dialable. Not
    /// always [`local_addr`](Self::local_addr) verbatim: a wildcard bind
    /// (`0.0.0.0`, `[::]`) is a listen address, not a destination, so it
    /// renders as loopback, and an IPv6 zone id is dropped rather than
    /// emitted in a form no URL parser accepts.
    pub fn base_url(&self) -> String {
        todo!()
    }

    /// Current transport status, for `status` output.
    pub fn status(&self) -> PipeStatus {
        todo!()
    }

    /// Wait for the next status transition and return the new status.
    /// See [`ServeHandle::status_changed`].
    pub async fn status_changed(&self) -> PipeStatus {
        todo!()
    }

    /// Tear down and wait until the local listener is gone.
    pub async fn shutdown(self) {
        todo!()
    }
}

/// What the transport is doing right now. The `Relayed` case is worth
/// surfacing to users: it explains latency and is expected under
/// carrier-grade or strict corporate NAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PipeStatus {
    /// Waiting for the first peer, or between connections.
    Idle,
    /// Direct hole-punched connection established.
    Direct,
    /// Falling back through an (encrypted, unreadable) relay.
    Relayed,
}
