//! Exposing a local backend: the entry point, what it is given, and how
//! it fails.
//!
//! Orchestration. The live listener you get back lives in
//! [`crate::serve_handle`]; this module owns the call and its inputs.

use std::fmt;
use std::sync::Arc;

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
    let endpoint = transport::bind(opts.relay.as_deref(), key).await?;

    let state = Arc::new(ServeState::new(endpoint, credential, backend));
    tokio::spawn(accept_loop(state.clone()));
    Ok(ServeHandle::new(state))
}

#[cfg(test)]
#[path = "serve_tests.rs"]
mod serve_tests;
