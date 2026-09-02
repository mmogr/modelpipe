//! Exposing a local backend: the entry point, what it is given, and how
//! it fails.
//!
//! Orchestration. The live listener you get back lives in
//! [`crate::serve_handle`]; this module owns the call and its inputs.

use std::fmt;
use std::sync::Arc;

use crate::backend::TcpBackend;
use crate::credential::{Credential, TokenPolicy};
use crate::listener::{ServeState, accept_loop};
use crate::serve_handle::ServeHandle;
use crate::transport;

/// Why [`serve`] failed.
///
/// The variants are the caller's retry policy: everything the operator
/// typed is permanent and theirs to fix, and everything about the machine
/// underneath is worth trying again. [`is_retryable`](Self::is_retryable)
/// is that split, decided here rather than at a downstream `match`.
#[derive(Debug)]
#[non_exhaustive]
pub enum ServeError {
    /// The backend URL is not one this crate can use at all — it does not
    /// parse, it names no host, or its scheme is not `http`.
    ///
    /// Separate from [`BackendNotLocal`](Self::BackendNotLocal), which is a
    /// verdict about an *address*. Reporting these as "not a local address"
    /// was worse than imprecise: it pointed the operator at
    /// `allow_private_backend`, which fixes none of them, and it said
    /// `https://127.0.0.1:11434` was not local when the objection is the
    /// scheme. Only `http` is accepted, because the hop that matters is
    /// already encrypted by QUIC and accepting `https` would mean either
    /// verifying a certificate for a loopback name or not verifying one.
    InvalidBackendUrl {
        /// The offending URL, for the error message.
        url: String,
    },
    /// The backend URL parsed, but its host resolved to nothing.
    ///
    /// Retryable, and that is the whole reason it is not folded into
    /// [`BackendNotLocal`](Self::BackendNotLocal): a resolver outage is a
    /// machine condition that clears, and reporting it as a permanent
    /// verdict about the operator's URL told a supervisor to give up on a
    /// backend that was about to come back.
    BackendUnresolvable {
        /// The offending URL, for the error message.
        url: String,
    },
    /// The backend URL resolved, and to no address this listener may dial.
    /// Loopback always passes; RFC 1918 / `fc00::/7` only with
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
    /// The p2p listener could not be set up. The inner error is the
    /// machine's own: naming iroh's types here would put them in the
    /// public surface, so it arrives as `io::Error` and nothing more.
    Bind(std::io::Error),
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
            // Everything the operator typed. No amount of waiting changes
            // a URL, a scheme or a relay value.
            Self::InvalidBackendUrl { .. }
            | Self::BackendNotLocal { .. }
            | Self::InvalidRelay { .. } => false,
            // Everything about the machine underneath. `serve` takes no
            // bind option, so no address here was caller-chosen, and both
            // transient resource exhaustion and a resolver that is briefly
            // unavailable are the common shapes.
            Self::Bind(_) | Self::BackendUnresolvable { .. } => true,
        }
    }
}

impl fmt::Display for ServeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBackendUrl { url } => write!(
                f,
                "{url} is not a backend URL modelpipe can use — it must be http:// with a host, e.g. http://127.0.0.1:11434"
            ),
            Self::BackendUnresolvable { url } => {
                write!(f, "the host in {url} did not resolve to any address")
            }
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
            // Deliberately not interpolating `e`: it is returned from
            // `source()`, and `anyhow`'s `Termination` prints the top-level
            // Display and then the chain — so naming it here printed the OS
            // error twice.
            Self::Bind(_) => f.write_str("could not set up the p2p listener"),
        }
    }
}

impl std::error::Error for ServeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidBackendUrl { .. }
            | Self::BackendUnresolvable { .. }
            | Self::BackendNotLocal { .. }
            | Self::InvalidRelay { .. } => None,
            Self::Bind(e) => Some(e),
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
    let backend = TcpBackend::new(backend_url, opts.allow_private_backend).await?;
    let endpoint = transport::bind(opts.relay.as_deref()).await?;
    let (credential, _) = Credential::new(&opts.auth);

    let state = Arc::new(ServeState::new(endpoint, credential, backend));
    tokio::spawn(accept_loop(state.clone()));
    Ok(ServeHandle::new(state))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Distinct from the sentinel `credential.rs` uses, so a leak names
    /// the type it escaped through.
    const SUPPLIED: &str = "sk-zzq-serve-options-sentinel";

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
            auth: TokenPolicy::Supplied(SUPPLIED.to_owned()),
            relay: Some("https://relay.example.com/".to_owned()),
            ..Default::default()
        };
        let rendered = format!("{opts:?}");
        assert!(
            !rendered.contains(SUPPLIED),
            "the token leaked through ServeOptions: {rendered}"
        );
        assert!(
            rendered.contains("relay.example.com"),
            "the non-secret fields should still be visible: {rendered}"
        );
    }

    /// Both are the operator's to fix, and no amount of waiting changes
    /// either one.
    #[test]
    fn a_user_fixable_serve_error_is_not_retryable() {
        for e in [
            ServeError::InvalidBackendUrl {
                url: "https://127.0.0.1:11434".to_owned(),
            },
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
            ServeError::BackendUnresolvable {
                url: "http://ollama.local:11434".to_owned(),
            },
        ] {
            assert!(e.is_retryable(), "{e} should be retryable");
        }
    }
}
