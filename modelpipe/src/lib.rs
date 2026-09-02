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
use std::time::Duration;

/// A pairing ticket: how one machine finds and authenticates another's
/// listener.
///
/// Base32 on the wire so it survives terminals, being read aloud, and —
/// with the case rule the README's format section records — QR codes.
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
/// pasted or scanned, so the advice is one line — re-copy it, or, when
/// the format is newer than this build, upgrade.
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

/// Why [`serve`] failed.
///
/// The variants are the caller's retry policy:
/// [`BackendNotLocal`](Self::BackendNotLocal) and
/// [`InvalidRelay`](Self::InvalidRelay) are permanent and user-fixable,
/// the rest describe the machine underneath.
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
    /// [`ServeOptions::relay`] does not parse as a relay URL. Syntactic
    /// validation only, before the listener starts: it catches the typo
    /// class that mangles the URL itself, and is permanent and
    /// user-fixable like [`BackendNotLocal`](Self::BackendNotLocal). A
    /// well-formed URL naming the wrong host is indistinguishable from a
    /// downed relay, and still surfaces as a transport error.
    InvalidRelay {
        /// The offending URL, for the error message.
        url: String,
    },
    /// The p2p listener could not be set up.
    Bind(std::io::Error),
    /// The transport failed. The inner error is deliberately opaque:
    /// naming iroh's types here would put them in the public surface.
    Transport(Box<dyn std::error::Error + Send + Sync>),
}

impl ServeError {
    /// Whether trying again could succeed without anyone changing
    /// anything.
    ///
    /// This exists because the enum is `#[non_exhaustive]`, which is what
    /// makes the classification promised above impossible for a caller to
    /// compute for itself: a downstream `match` needs a `_` arm, and a
    /// variant added in a later release lands silently in whichever
    /// bucket that arm chose. Deciding here means a new variant is a
    /// compile error in *this* crate — the only place that can answer it.
    ///
    /// Written as a full `match` with no `_` arm for exactly that reason.
    /// `matches!` would compile past a new variant and is banned here.
    pub const fn is_retryable(&self) -> bool {
        match self {
            // Both are the operator's to fix, and no amount of waiting
            // changes either one.
            Self::BackendNotLocal { .. } | Self::InvalidRelay { .. } => false,
            // Nothing here names an address the caller chose — `serve`
            // takes no bind option — so a failure is a machine condition,
            // and transient resource exhaustion is the common shape.
            Self::Bind(_) | Self::Transport(_) => true,
        }
    }
}

impl fmt::Display for ServeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendNotLocal { url } => write!(
                f,
                "backend {url} is not a local address — modelpipe exposes your own server, not the network behind it"
            ),
            Self::InvalidRelay { url } => {
                write!(
                    f,
                    "{url} does not parse as a relay URL — check the value passed as the relay"
                )
            }
            Self::Bind(e) => write!(f, "could not set up the p2p listener: {e}"),
            Self::Transport(e) => write!(f, "transport failure: {e}"),
        }
    }
}

impl std::error::Error for ServeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BackendNotLocal { .. } | Self::InvalidRelay { .. } => None,
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
    /// The peer could not be reached, directly or through a relay.
    /// Retryable: the serve side may be offline, or the network in
    /// between temporarily unwilling.
    ///
    /// This is also what a ticket outlived by its listener looks like.
    /// There is no "ticket rejected" case to distinguish it from: the
    /// endpoint key is ephemeral, so a restarted serve side is a
    /// *different* endpoint, and dialing the old one reaches nobody
    /// rather than reaching someone who refuses. A caller that wants to
    /// tell "offline" from "re-paired" has to ask a human, not this
    /// enum.
    PeerUnreachable,
    /// The requested local address could not be bound.
    Bind(std::io::Error),
    /// The transport failed some other way. Opaque on purpose; see
    /// [`ServeError::Transport`].
    Transport(Box<dyn std::error::Error + Send + Sync>),
}

impl ConnectError {
    /// Whether trying again could succeed without anyone changing
    /// anything. Same contract, and same no-`_`-arm rule, as
    /// [`ServeError::is_retryable`].
    ///
    /// The two enums disagree about [`Bind`](Self::Bind), and the
    /// disagreement is the point rather than an oversight: here the
    /// caller named the address, through [`ConnectOptions::bind`], so a
    /// bind failure is theirs to resolve by choosing another port. On the
    /// serve side no address is caller-chosen, which is why the same
    /// variant is retryable there. This is also why the two enums are
    /// kept as separate types with duplicated arms instead of being
    /// collapsed into one — they are two contracts that must stay free to
    /// diverge, and here they already have.
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::PeerUnreachable | Self::Transport(_) => true,
            Self::Bind(_) => false,
        }
    }
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
            Self::PeerUnreachable => None,
            Self::Bind(e) => Some(e),
            Self::Transport(e) => Some(&**e),
        }
    }
}

/// How the serve side authenticates requests.
///
/// One field, only valid states — the contradictory combinations a
/// bool-plus-option pair would allow simply don't exist. Embedders with
/// an existing bearer credential (an API key their clients already
/// present) use [`Supplied`](Self::Supplied): the same key is then
/// enforced at the tunnel edge, before a byte reaches the backend, and
/// the embedder keeps exactly one credential.
#[derive(Default)]
#[non_exhaustive]
pub enum TokenPolicy {
    /// Generate a fresh random token at listen time; read it back with
    /// [`ServeHandle::token`]. The recommended default for standalone
    /// use.
    #[default]
    Generate,
    /// Enforce this caller-supplied token instead of generating one.
    /// Rotating a supplied credential belongs to the caller — push the
    /// replacement into a running listener with
    /// [`ServeHandle::set_token`].
    Supplied(String),
    /// Serve without a bearer token. The ticket becomes the only lock,
    /// which is exactly the failure mode this crate exists to close —
    /// hence the name. Loudly discouraged.
    InsecureNoAuth,
}

impl fmt::Debug for TokenPolicy {
    // Hand-written for the same reason `Debug for Ticket` is, one screen
    // up: a derive over `Supplied(String)` copies the credential into
    // every downstream panic message and `tracing` line. This type is
    // also the reason the derive cannot simply be omitted — without a
    // `Debug` at all, an embedder holding a `ServeOptions` in their own
    // struct cannot `#[derive(Debug)]` on it, and the obvious fix they
    // reach for is the one that leaks.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Generate => f.write_str("Generate"),
            Self::Supplied(_) => f.write_str("Supplied(<redacted>)"),
            Self::InsecureNoAuth => f.write_str("InsecureNoAuth"),
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
    /// What the listener requires in `Authorization: Bearer …`.
    pub auth: TokenPolicy,
    /// Self-hosted relay URL. `None` uses iroh's public relays, which
    /// carry only ciphertext either way. Parsed when [`serve`] starts: a
    /// value that is not a relay URL at all is
    /// [`ServeError::InvalidRelay`] up front; a well-formed URL naming
    /// the wrong relay still fails later, as transport.
    pub relay: Option<String>,
    /// Loopback always passes and never needs this. Set it to also
    /// accept a backend on a private (RFC 1918 / `fc00::/7`) address.
    /// Off by default: `serve` extends trust outward from this machine,
    /// and pointing it into the LAN is a decision the operator should
    /// make explicitly. Link-local ranges are never accepted regardless;
    /// see [`ServeError::BackendNotLocal`].
    pub allow_private_backend: bool,
}

impl fmt::Debug for ServeOptions {
    // Delegates to `TokenPolicy`'s redacting `Debug` rather than deriving,
    // which would inline the credential. Written out field by field so
    // that adding an option to this `#[non_exhaustive]` struct without
    // adding it here is a visible omission rather than a silent one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServeOptions")
            .field("auth", &self.auth)
            .field("relay", &self.relay)
            .field("allow_private_backend", &self.allow_private_backend)
            .finish()
    }
}

/// Options for [`connect`]. Same contract as [`ServeOptions`].
///
/// Derives `Debug` where [`ServeOptions`] hand-writes one: nothing here
/// is a credential, so there is nothing to redact.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct ConnectOptions {
    /// Local address to bind. `None` picks a free port on loopback.
    pub bind: Option<SocketAddr>,
}

/// Expose the OpenAI-compatible server at `backend_url` (e.g.
/// `http://127.0.0.1:11434`) to holders of the returned handle's ticket.
///
/// Enforces a bearer token per [`ServeOptions::auth`] — generated at
/// listen time, or supplied by the caller — and rejects any incoming
/// request whose `Authorization` header doesn't carry it (compared in
/// constant time), before a byte reaches the backend. Read the token off
/// the handle ([`ServeHandle::token`]) and give it to clients alongside
/// the ticket; it is deliberately not *inside* the ticket, so the two
/// credentials travel — and leak — independently. Serving open
/// ([`TokenPolicy::InsecureNoAuth`]) is the one exception: nothing is
/// enforced, and [`ServeHandle::token`] returns `None`.
///
/// The backend must be local. Loopback always passes; private-range
/// addresses only with [`ServeOptions::allow_private_backend`]; anything
/// else is [`ServeError::BackendNotLocal`]. This crate extends trust
/// outward, it does not re-export someone else's server.
///
/// After a successful return, per-request trouble — the backend down or
/// refusing, a re-resolved backend address failing the locality check —
/// surfaces to the *remote client* as failed requests; the pipe itself
/// stays up and its status stays [`Direct`](PipeStatus::Direct)/
/// [`Relayed`](PipeStatus::Relayed). Only the death of the pipe is a
/// status: [`PipeStatus::Closed`]. Finer-grained states can be added
/// compatibly later (`PipeStatus` is `#[non_exhaustive]`).
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
    ///
    /// Returns an owned clone, for the same reason
    /// [`token`](Self::token) does — and for one this handle has that a
    /// credential does not. iroh discovers direct addresses *over time*:
    /// a ticket read the instant [`serve`] returns is legitimately
    /// relay-only, and the same call later carries the direct addresses
    /// hole-punching has since found. A borrow would force the listener
    /// to mint one ticket at startup and hand out that snapshot forever,
    /// so the cheaper signature is the one that quietly makes the ticket
    /// wrong.
    pub fn ticket(&self) -> Ticket {
        todo!()
    }

    /// The bearer token clients must present, or `None` when serving
    /// open. Print it next to the ticket; it reaches client machines
    /// out-of-band, which is what makes it a second lock rather than a
    /// decoration on the first.
    ///
    /// Under [`TokenPolicy::Supplied`] this echoes the supplied value, as
    /// later replaced through [`set_token`](Self::set_token) or
    /// [`rotate_token`](Self::rotate_token) — an embedder can always read
    /// back what the listener currently enforces. Returns an owned clone
    /// on purpose: [`set_token`](Self::set_token) takes `&self`, so a lent
    /// `&str` could outlive the credential it names, and honoring such a
    /// borrow would force the implementation to keep every rotated-out
    /// secret alive (and un-zeroizable) for the handle's whole lifetime.
    ///
    /// `String` is the settled type here, not a placeholder for a
    /// zeroizing wrapper. The token's whole job is to be read back and
    /// handed to a person — the CLI prints it to stdout, an embedder puts
    /// it in a config — so it lands in terminal scrollback and process
    /// memory the caller controls long before any wrapper could scrub the
    /// copy this returns. A `Secret<String>` here would encrypt the last
    /// three feet of a journey that is public at both ends, and swapping
    /// it in later would be a breaking change; the honest position is to
    /// say so once, here.
    pub fn token(&self) -> Option<String> {
        todo!()
    }

    /// Install `token` as the bearer credential, replacing whatever the
    /// listener currently enforces; the old value stops working
    /// immediately and the ticket — every existing pairing — stays
    /// valid. This is how an embedder that supplied its own key
    /// ([`TokenPolicy::Supplied`]) propagates a rotation of that key
    /// into a running listener. When serving open, this turns auth *on*
    /// from this call forward.
    ///
    /// Single-token by design: there is no dual-accept window where old
    /// and new both pass, so rolling a replacement out to several clients
    /// necessarily races their reconfiguration — plan rotations
    /// accordingly. The credential gates request *admission*, not
    /// delivery: a request that passed auth before the call runs to
    /// completion (a streaming response is not cut mid-body).
    pub fn set_token(&self, token: String) {
        // drop, not `let _`: the sketch must consume the String the real
        // implementation will store, or needless_pass_by_value fires.
        drop(token);
        todo!()
    }

    /// [`set_token`](Self::set_token) with a freshly minted random
    /// token, returned so the caller can redistribute it. The recovery
    /// move for a leaked generated token.
    ///
    /// For [`TokenPolicy::Supplied`] embedders this is the wrong tool: it
    /// desynchronizes the shared credential — the tunnel edge then wants
    /// a token the embedder's own backend has never heard of. Supplied
    /// embedders rotate by pushing their replacement through
    /// [`set_token`](Self::set_token).
    pub fn rotate_token(&self) -> String {
        todo!()
    }

    /// Current transport status, for `status` output.
    pub fn status(&self) -> PipeStatus {
        todo!()
    }

    /// Wait until the status changes, then return the new value.
    ///
    /// This is how a caller surfaces "direct ↔ relayed" changes as they
    /// happen, rather than polling [`status`](Self::status). Snapshot
    /// semantics: each call compares against the status at the moment
    /// the call was made, so states that came and went while nobody was
    /// waiting are coalesced away, never replayed. Any number of callers
    /// may wait concurrently — a daemon and a UI stream can both watch
    /// one handle — each resolving against its own snapshot. On
    /// teardown, graceful or not, the status becomes
    /// [`PipeStatus::Closed`] and every waiting call resolves with it;
    /// once closed, calls resolve immediately, so a watcher can never
    /// block on a pipe that is already gone.
    pub async fn status_changed(&self) -> PipeStatus {
        todo!()
    }

    /// Stop admitting new requests, let the in-flight ones finish, and
    /// wait until the listener is gone.
    ///
    /// **This drains rather than cuts, and it does not time out.** For a
    /// pipe whose payload is a ten-minute token stream that is the whole
    /// question, so it is answered here rather than left to the
    /// implementation: the same promise [`set_token`](Self::set_token)
    /// already makes — that a streaming response is not cut mid-body —
    /// holds for teardown. A request admitted before this call runs to
    /// completion; one arriving after it does not get in.
    ///
    /// Dropping the handle is the other half of the pair and cuts
    /// immediately, without waiting. Both are needed: a daemon shutting
    /// down cleanly wants the drain, and a process that has already
    /// decided to die should not be held open by a backend that has
    /// stopped producing tokens. [`shutdown_timeout`](Self::shutdown_timeout)
    /// is the middle ground.
    ///
    /// Takes `&self` so a handle parked in shared state (an `Arc` in a
    /// daemon) can still be shut down gracefully — by-value `self` would
    /// leave such embedders only the best-effort drop path. Idempotent:
    /// every call after teardown has begun (however it began) awaits the
    /// same completion.
    pub async fn shutdown(&self) {
        todo!()
    }

    /// [`shutdown`](Self::shutdown) with a deadline on the drain.
    ///
    /// Returns `true` if every in-flight request finished within `grace`,
    /// and `false` if the deadline arrived first and the remainder were
    /// cut. Either way the listener is gone when this returns, so a
    /// caller that does not care which happened can ignore the value.
    ///
    /// This ships alongside `shutdown` rather than after it because the
    /// unbounded wait has a real failure mode — a backend that has wedged
    /// mid-generation never completes, and an embedder with only the
    /// unbounded call would have to reach for the drop path and lose the
    /// drain entirely.
    pub async fn shutdown_timeout(&self, grace: Duration) -> bool {
        let _ = grace;
        todo!()
    }
}

/// A live connect side.
///
/// Teardown semantics match [`ServeHandle`]: dropping tears down without
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
/// Deliberately shares no trait with [`ServeHandle`]: the overlap is
/// three methods, and embedders driving both sides duplicate a small
/// park-and-watch loop. If that ever grows past a nuisance, a shared
/// trait is an additive, non-breaking change — the decision is recorded
/// here so the duplication reads as chosen, not overlooked.
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

    /// Wait until the status changes, then return the new value.
    ///
    /// Same contract as [`ServeHandle::status_changed`]: snapshot
    /// semantics, concurrent callers each against their own snapshot,
    /// and once the pipe is closed every call resolves immediately with
    /// [`PipeStatus::Closed`].
    pub async fn status_changed(&self) -> PipeStatus {
        todo!()
    }

    /// Stop accepting local connections, let the in-flight requests
    /// finish, and wait until the local listener is gone.
    ///
    /// Same contract as [`ServeHandle::shutdown`]: drains rather than
    /// cuts, does not time out, takes `&self` for shared-state embedders,
    /// and is idempotent. Dropping the handle cuts instead.
    pub async fn shutdown(&self) {
        todo!()
    }

    /// [`shutdown`](Self::shutdown) with a deadline on the drain. Same
    /// contract as [`ServeHandle::shutdown_timeout`], including the
    /// returned `bool`.
    pub async fn shutdown_timeout(&self, grace: Duration) -> bool {
        let _ = grace;
        todo!()
    }
}

/// What the transport is doing right now.
///
/// The `Relayed` case is worth surfacing to users: it explains latency
/// and is expected under carrier-grade or strict corporate NAT. `Closed`
/// is the terminal state, and `status_changed` guarantees to deliver it —
/// a watcher never blocks forever on a pipe that is already gone.
///
/// One listener can serve several peers at once — a phone and a laptop
/// holding the same ticket — so on the serve side this is an aggregate,
/// and it reports **the worst active path**: `Relayed` if any connected
/// peer is relayed, `Direct` only when all of them are direct. Reporting
/// the best path instead would hide exactly what `Relayed` exists to
/// explain, leaving the owner of the slow device with no way to find out
/// why. The cost is accepted and stated plainly: with a mixed set this
/// value describes no single peer, and a per-peer accessor is the
/// additive change that would fix that if the need proves real.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PipeStatus {
    /// No peer is connected — waiting for the first, or between
    /// connections.
    Idle,
    /// Every connected peer has a direct hole-punched connection.
    Direct,
    /// At least one connected peer is falling back through an (encrypted,
    /// unreadable) relay.
    Relayed,
    /// The pipe is gone — shut down, dropped, or dead after an
    /// unrecoverable transport failure. Terminal: no transition follows.
    /// Carried as a bare state rather than a reason so this type stays
    /// `Copy`; a diagnostic accessor on the handle can be added
    /// compatibly if the need proves real.
    Closed,
}

impl PipeStatus {
    /// A stable lowercase identifier: `"idle"`, `"direct"`, `"relayed"`,
    /// `"closed"`.
    ///
    /// For status output, log fields and anything else that wants to name
    /// the state without matching on it. Deliberately an identifier and
    /// not a sentence — freezing `"relayed"` costs nothing, while freezing
    /// "falling back through a relay" would make every wording improvement
    /// a breaking change for whoever grepped for it.
    ///
    /// A variant added later returns its own new identifier, so a caller
    /// rendering this string keeps working; one *matching* on the string
    /// has the same obligation it would have had matching on the enum.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Direct => "direct",
            Self::Relayed => "relayed",
            Self::Closed => "closed",
        }
    }
}

// Auto-trait promises, pinned. The handles and the ticket live inside
// consumers' `select!` arms, spawned tasks and daemon state, and the error
// types ride through `anyhow` — those embeddings need these bounds, and a
// sketch whose types are only *accidentally* `Send + Sync` would let the
// implementation break every consumer after the fact. A regression here is
// a compile error in this crate instead.
#[expect(dead_code, reason = "compile-time pin; never called")]
const fn auto_trait_promises() {
    const fn assert<T: Send + Sync + 'static>() {}
    // Declared with `assert` above rather than beside their call sites:
    // an item after a statement is a clippy error, and these are items.
    const fn assert_clone<T: Clone>() {}
    const fn assert_copy_eq<T: Copy + Eq>() {}

    assert::<Ticket>();
    assert::<ServeHandle>();
    assert::<ConnectHandle>();
    assert::<PipeStatus>();
    assert::<ServeError>();
    assert::<ConnectError>();
    assert::<TicketParseError>();
    // The options structs and the policy they carry. Until now these were
    // only *accidentally* `Send`, by way of `future_promises` pinning the
    // futures that consume them; nothing said so, and an implementation
    // could have made one of them `!Send` without failing a single check.
    // Pinning `TokenPolicy` also forbids a future variant holding
    // something like an `Rc<dyn Fn…>` — that is the intent, not a side
    // effect: a credential source that cannot cross a thread boundary
    // would break every embedder holding the listener in a spawned task.
    assert::<ServeOptions>();
    assert::<ConnectOptions>();
    assert::<TokenPolicy>();

    // Two promises the docs make that no check enforced. `Ticket: Clone`
    // is what `ServeHandle::ticket` returning owned depends on, and
    // `PipeStatus: Copy + Eq` is stated at its derive and relied on by
    // `status_changed`'s snapshot comparison.
    assert_clone::<Ticket>();
    assert_copy_eq::<PipeStatus>();
}

// The async surface gets the same treatment: a spawned task awaiting one
// of these futures needs them `Send`, and an implementation that held a
// non-Send guard across an await point would compile on its own while
// breaking exactly that embedding. Pinning the futures has to name them,
// which means calling the functions — dead code, type-checked, never run.
#[expect(dead_code, reason = "compile-time pin; never called")]
fn future_promises(serve_side: &ServeHandle, connect_side: &ConnectHandle, ticket: &Ticket) {
    fn assert_send(_: impl Send) {}
    assert_send(serve("", ServeOptions::default()));
    assert_send(connect(ticket, ConnectOptions::default()));
    assert_send(serve_side.status_changed());
    assert_send(serve_side.shutdown());
    assert_send(serve_side.shutdown_timeout(Duration::from_secs(0)));
    assert_send(connect_side.status_changed());
    assert_send(connect_side.shutdown());
    assert_send(connect_side.shutdown_timeout(Duration::from_secs(0)));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Distinctive enough that finding it anywhere in a rendering is
    /// unambiguous, and not a substring of any word the formatter emits.
    const SECRET: &str = "sk-zzq-a-very-distinctive-credential-value";

    // ── Credential redaction ─────────────────────────────────────────────

    /// A derived `Debug` would inline the credential, putting it into
    /// every downstream panic message and `tracing` line — the same
    /// failure the hand-written `Debug for Ticket` exists to prevent, on
    /// the other type in this crate that holds a secret.
    #[test]
    fn debug_for_token_policy_never_renders_the_supplied_token() {
        let rendered = format!("{:?}", TokenPolicy::Supplied(SECRET.to_owned()));
        assert!(
            !rendered.contains(SECRET),
            "the token leaked into Debug output: {rendered}"
        );
        // Asserting the positive too, so the test cannot pass because the
        // impl rendered nothing at all.
        assert!(
            rendered.contains("Supplied") && rendered.contains("redacted"),
            "Debug should still say which variant it is: {rendered}"
        );
    }

    /// The variants carrying no secret must still be legible — a redacting
    /// `Debug` that redacted everything would be useless and would quietly
    /// pass the test above.
    #[test]
    fn debug_for_token_policy_names_the_variants_that_hold_nothing() {
        assert_eq!(format!("{:?}", TokenPolicy::Generate), "Generate");
        assert_eq!(
            format!("{:?}", TokenPolicy::InsecureNoAuth),
            "InsecureNoAuth"
        );
    }

    /// `ServeOptions` is the type an embedder is most likely to hold in a
    /// struct of their own and derive `Debug` on, which is how a supplied
    /// credential reaches a log without anyone deciding it should.
    #[test]
    fn debug_for_serve_options_never_renders_the_supplied_token() {
        // A struct literal rather than the `Default`-then-mutate dance an
        // out-of-crate embedder is forced into by `#[non_exhaustive]`:
        // inside the crate the literal is legal, and clippy rejects the
        // dance. What is under test is the `Debug` impl, which cannot tell
        // how the value was built.
        let opts = ServeOptions {
            auth: TokenPolicy::Supplied(SECRET.to_owned()),
            relay: Some("https://relay.example.com/".to_owned()),
            ..Default::default()
        };
        let rendered = format!("{opts:?}");
        assert!(
            !rendered.contains(SECRET),
            "the token leaked through ServeOptions: {rendered}"
        );
        assert!(
            rendered.contains("relay.example.com"),
            "the non-secret fields should still be visible: {rendered}"
        );
    }

    // ── Retry classification ─────────────────────────────────────────────

    /// Both are the operator's to fix, and no amount of waiting changes
    /// either one.
    #[test]
    fn a_user_fixable_serve_error_is_not_retryable() {
        for e in [
            ServeError::BackendNotLocal {
                url: "http://example.com".to_owned(),
            },
            ServeError::InvalidRelay {
                url: "not a url".to_owned(),
            },
        ] {
            assert!(!e.is_retryable(), "{e} should not be retryable");
        }
    }

    /// `serve` takes no bind option, so nothing here names an address the
    /// caller chose — a failure describes the machine underneath.
    #[test]
    fn a_machine_serve_error_is_retryable() {
        for e in [
            ServeError::Bind(std::io::Error::other("no sockets left")),
            ServeError::Transport("relay handshake failed".into()),
        ] {
            assert!(e.is_retryable(), "{e} should be retryable");
        }
    }

    #[test]
    fn an_unreachable_peer_is_retryable() {
        assert!(ConnectError::PeerUnreachable.is_retryable());
        assert!(ConnectError::Transport("stream reset".into()).is_retryable());
    }

    /// The one point where the two enums disagree, and the reason they
    /// stay two types rather than one shared enum: here the caller named
    /// the port through `ConnectOptions::bind`, so retrying the same value
    /// fails the same way forever.
    #[test]
    fn a_connect_bind_failure_is_not_retryable_because_the_caller_chose_the_address() {
        let e = ConnectError::Bind(std::io::Error::other("address in use"));
        assert!(!e.is_retryable(), "{e} should not be retryable");
    }

    // ── Status identifiers ───────────────────────────────────────────────

    /// The identifiers are frozen surface once anything greps for them, so
    /// pin the spellings and the distinctness in one place.
    #[test]
    fn every_status_renders_a_distinct_stable_identifier() {
        let all = [
            PipeStatus::Idle,
            PipeStatus::Direct,
            PipeStatus::Relayed,
            PipeStatus::Closed,
        ];
        let rendered: Vec<&str> = all.iter().map(|s| s.as_str()).collect();
        assert_eq!(rendered, ["idle", "direct", "relayed", "closed"]);

        let mut deduped = rendered.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(
            deduped.len(),
            rendered.len(),
            "identifiers must be distinct"
        );
    }
}
