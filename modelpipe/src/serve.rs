//! Exposing a local backend: the entry point, what it is given, and how
//! it fails.
//!
//! Orchestration. The live listener you get back lives in
//! [`crate::serve_handle`]; this module owns the call and its inputs.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::backend::TcpBackend;
use crate::credential::Credential;
use crate::identity;
use crate::listener::{ServeState, accept_loop};
use crate::serve_error::ServeError;
use crate::serve_handle::ServeHandle;
use crate::token_policy::TokenPolicy;
use crate::transport;

/// Options for [`serve`].
///
/// Start from `Default` — the recommended configuration — and set what
/// you need. `#[non_exhaustive]`, so a new option is not a breaking
/// change for callers who construct it that way.
#[non_exhaustive]
pub struct ServeOptions {
    /// What the listener requires in `Authorization: Bearer …`.
    pub auth: TokenPolicy,
    /// Self-hosted relay URL. `None` uses iroh's public relays, which
    /// carry only ciphertext either way. Parsed when [`serve`] starts, and
    /// that parse is the only check there is: a value that is not a relay
    /// URL at all is [`ServeError::InvalidRelay`] up front.
    ///
    /// A well-formed URL naming a relay that does not exist is **accepted
    /// silently**. Nothing dials it here, so the endpoint binds, `serve`
    /// returns `Ok`, and the ticket carries the URL verbatim. The cost is
    /// paid by whoever holds that ticket: they lose one path to this
    /// machine, which is invisible when hole-punching finds a direct one
    /// and is [`ConnectError::PeerUnreachable`](crate::ConnectError::PeerUnreachable)
    /// when it does not.
    pub relay: Option<String>,
    /// Where to keep this listener's endpoint key, so its ticket survives
    /// a restart.
    ///
    /// `None` — the default — generates a fresh key per process, so every
    /// ticket is disposable: restart and every ticket ever handed out names
    /// a peer nobody is. That is the rotation [`ServeHandle`] documents,
    /// and also why a paired device is re-paired after every reboot.
    ///
    /// Naming a path stores the key there, minting one on first use. The
    /// trade is real in both directions — a ticket that survives a restart
    /// is a *leaked* ticket that survives one too, revocation becomes
    /// deleting this file, and there is now a secret on disk where there
    /// was none — and is argued in full in ADR 0002. The file is created
    /// readable only by its owner, and a listener refuses to start on one
    /// others can read.
    pub identity: Option<std::path::PathBuf>,
    /// Widen the backend rule to accept a private address as well as
    /// loopback. Off by default: pointing `serve` into the LAN is a
    /// decision the operator should make explicitly.
    ///
    /// This moves exactly one class and nothing else — link-local and
    /// public addresses are refused whatever it is set to. The full rule
    /// is on [`ServeError::BackendNotLocal`].
    pub allow_private_backend: bool,
    /// Wait, up to this long, for the endpoint to reach a relay before
    /// [`serve`] returns.
    ///
    /// `None` — the default — returns as soon as the socket is bound and
    /// the accept loop is running, which is the fastest a listener can
    /// start and is what an embedder holding the handle in a daemon wants.
    /// The cost is paid by [`ServeHandle::ticket`]: a ticket read in that
    /// first instant carries only what the endpoint has found so far, and
    /// reaching a relay takes a network round trip that binding does not.
    ///
    /// Set it when a *person* is about to be handed the ticket — printed,
    /// or rendered as a QR code — because that ticket is copied once and
    /// then used from a machine that is not this one. Waiting costs
    /// seconds; a ticket that is missing the path its holder needed costs
    /// a re-pair.
    ///
    /// A duration rather than a `bool` because the underlying wait has no
    /// natural end: it is satisfied by a relay handshake completing, so on
    /// a machine with no route to one — an air-gapped LAN, a laptop in
    /// flight — it would never return. **Expiry is not an error.** The
    /// listener is up either way, and a ticket with direct addresses and
    /// no relay still pairs across a LAN, so [`serve`] returns `Ok` and
    /// the caller is free to say nothing about it.
    pub wait_online: Option<Duration>,
    /// Ask the local gateway for a `UPnP` / NAT-PMP / PCP port mapping, so
    /// a peer behind a stricter NAT can reach this machine directly more
    /// often.
    ///
    /// `true` — the default — is what every version before this one did.
    /// `false` skips the gateway probe entirely, including the SSDP
    /// multicast that raises firewall dialogs on some desktops; the cost
    /// is a connection that falls back to the relay a little more often
    /// behind some NATs. Nothing about pairing changes either way.
    pub port_mapping: bool,
    /// Publish this endpoint's addresses to n0's discovery service, and
    /// resolve peers through it.
    ///
    /// `true` — the default — is what makes a ticket work after this
    /// machine changes network: the ticket names the endpoint, and
    /// discovery is how a holder finds where it is now. It is also a
    /// contact with n0 before any client connects, refreshed while the
    /// listener runs, and it is what
    /// [`identity`](Self::identity) depends on to make a stored key worth
    /// anything.
    ///
    /// `false` removes that contact, and the property with it: a ticket
    /// then carries every path its holder will ever have, so it works on
    /// the LAN it was minted on and through the relay it names, and fails
    /// the moment this machine's addresses change. An embedder that mints
    /// a fresh ticket per session — and so never needed a stale one to
    /// keep working — loses little; one relying on `identity` loses the
    /// thing it was for.
    pub discovery: bool,
}

impl Default for ServeOptions {
    /// Written out because two of the booleans default to `true`, which
    /// `#[derive(Default)]` cannot express — and because "the default is
    /// what every version before did" is a promise worth a function.
    fn default() -> Self {
        Self {
            auth: TokenPolicy::default(),
            relay: None,
            identity: None,
            allow_private_backend: false,
            wait_online: None,
            port_mapping: true,
            discovery: true,
        }
    }
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
            .field("identity", &self.identity)
            .field("allow_private_backend", &self.allow_private_backend)
            .field("wait_online", &self.wait_online)
            .field("port_mapping", &self.port_mapping)
            .field("discovery", &self.discovery)
            .finish()
    }
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
/// The backend must be local: this crate extends trust outward from your
/// machine, it does not re-export someone else's server. Which addresses
/// count, and what widens that, is on [`ServeError::BackendNotLocal`].
///
/// After a successful return, per-request trouble — the backend down or
/// refusing, a re-resolved backend address failing the locality check —
/// surfaces to the *remote client* as failed requests; the pipe itself
/// stays up and its status stays [`Direct`](crate::PipeStatus::Direct)/
/// [`Relayed`](crate::PipeStatus::Relayed). Only the death of the pipe is a
/// status: [`PipeStatus::Closed`](crate::PipeStatus::Closed). Finer-grained states can be added
/// compatibly later (`PipeStatus` is `#[non_exhaustive]`).
///
/// # Examples
///
/// [`ServeOptions`] is `#[non_exhaustive]`, so a struct literal will not
/// compile outside this crate: start from `default()` and assign. That is
/// the whole reason the type is shaped this way — a new option must not
/// break you — and it is what every embedder ends up writing.
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut opts = modelpipe::ServeOptions::default();
/// opts.auth = modelpipe::TokenPolicy::Supplied("sk-your-existing-key".to_owned());
///
/// let serving = modelpipe::serve("http://127.0.0.1:11434", opts).await?;
///
/// // Two credentials, printed separately because they travel separately.
/// println!("ticket: {}", serving.ticket());
/// println!("token:  {}", serving.token().expect("a token is enforced"));
///
/// serving.shutdown().await;
/// # Ok(())
/// # }
/// ```
///
/// `no_run` throughout this crate: these compile, which is what proves the
/// paths and the signatures, but running one would bind a real endpoint and
/// contact a discovery service.
pub async fn serve(backend_url: &str, opts: ServeOptions) -> Result<ServeHandle, ServeError> {
    // Order matters, and it is the order of what the operator can fix. The
    // relay value and the backend URL are theirs; binding an endpoint is the
    // machine's. Checking the cheap, user-fixable things first means a typo
    // is reported as a typo rather than after a socket has been opened.
    if let Some(relay) = opts.relay.as_deref() {
        transport::validate_relay(relay)?;
    }
    // Before the backend and before the socket, because it is the cheapest
    // of the three and the same rule applies: a credential no client could
    // present is the operator's typo, and reporting it after a listener is
    // up would mean reporting it as a stream of refused requests instead.
    let (credential, _) = Credential::new(&opts.auth)?;
    // Before the socket and before the backend for the reason the two above
    // it come first: a path the operator cannot use is theirs to fix, and
    // finding out after a listener is up would mean finding out as a ticket
    // that is not the one they expected.
    let key = opts
        .identity
        .as_deref()
        .map(identity::load_or_mint)
        .transpose()?;
    let backend = TcpBackend::new(backend_url, opts.allow_private_backend).await?;
    let net = transport::NetOptions {
        port_mapping: opts.port_mapping,
        discovery: opts.discovery,
    };
    let endpoint = transport::bind(opts.relay.as_deref(), key, net).await?;
    // After the endpoint exists and before the handle wraps it, which is
    // the only window where waiting is free of consequence: nothing has
    // been spawned yet, so a caller who gives up here has nothing to tear
    // down. Deliberately not an error on expiry — see the field's docs.
    if let Some(within) = opts.wait_online {
        transport::wait_online(&endpoint, within).await;
    }

    let state = Arc::new(ServeState::new(endpoint, credential, backend));
    tokio::spawn(accept_loop(state.clone()));
    Ok(ServeHandle::new(state))
}

#[cfg(test)]
#[path = "serve_tests.rs"]
mod serve_tests;
