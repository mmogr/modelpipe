//! Exposing a local backend: the entry point, what it is given, and how
//! it fails.
//!
//! Orchestration. The live listener you get back lives in
//! [`crate::handle`]; this module owns the call and its inputs.

use std::fmt;

use crate::credential::TokenPolicy;
use crate::handle::ServeHandle;

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
    let _ = (backend_url, opts);
    todo!()
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
}
