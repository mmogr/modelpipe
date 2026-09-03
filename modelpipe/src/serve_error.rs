//! How exposing a backend refuses.
//!
//! Split from [`mod@crate::serve`] when that module grew a third thing to hold:
//! the call, its inputs, and the contract it fails by. This is the third,
//! and it is a contract rather than a detail — the variants *are* a
//! caller's retry policy, and [`ServeError::is_retryable`] is that split
//! decided here rather than at a downstream `match`.
//!
//! Its connect-side twin still lives beside [`connect`](fn@crate::connect),
//! which is where it belongs until it earns the same treatment. Splitting
//! both for symmetry would be moving a file to make a diagram tidy.

use std::fmt;

/// Why [`serve`](fn@crate::serve) failed.
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
    /// [`ServeOptions::allow_private_backend`](crate::ServeOptions::allow_private_backend); link-local
    /// (`169.254.0.0/16`, `fe80::/10` — where cloud instance metadata
    /// lives) and public addresses, never. The check runs against the
    /// *resolved* address of every outbound connection, not the URL text,
    /// so a DNS name cannot smuggle an address past it.
    BackendNotLocal {
        /// The offending URL, for the error message.
        url: String,
    },
    /// [`TokenPolicy::Supplied`](crate::TokenPolicy::Supplied) carried a token that cannot be presented.
    ///
    /// Empty, or nothing but whitespace. Such a value fails *closed* — the
    /// enforced header becomes `"Bearer "` with a trailing space, and HTTP
    /// header parsers trim trailing whitespace, so no conforming client can
    /// ever match it. The listener would start, report the token it was
    /// given, and then refuse every request for the life of the process
    /// with nothing in its output to say why. Refusing at `serve` time is
    /// the difference between a misconfiguration and a mystery.
    ///
    /// Carries no payload on purpose: the offending value is a credential,
    /// and an error is a thing that gets logged.
    InvalidToken,
    /// [`ServeOptions::relay`](crate::ServeOptions::relay) does not parse as a relay URL. Syntactic
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
    /// [`ServeOptions::identity`](crate::ServeOptions::identity) names a file this listener cannot use as
    /// its endpoint key — unreadable, unwritable, not base32, the wrong
    /// length, or readable by other users on the machine.
    ///
    /// One variant for all of them because they are one verdict: the
    /// operator named this path, and retrying it fails identically. Which
    /// it was rides in [`source`](std::error::Error::source), the shape
    /// [`Bind`](Self::Bind) uses, rather than in five variants a caller
    /// would match to reach one arm. The path is carried and the key is
    /// not, for the reason [`InvalidToken`](Self::InvalidToken) carries
    /// nothing.
    Identity {
        /// The offending path, for the error message.
        path: String,
        /// What went wrong with it.
        source: std::io::Error,
    },
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
            | Self::InvalidToken
            | Self::InvalidRelay { .. }
            | Self::Identity { .. } => false,
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
            Self::InvalidToken => f.write_str(
                "the supplied bearer token is empty — no client could present it, so every request would be refused",
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
            // The cause is in `source` and `anyhow` prints the chain, so
            // naming it here would print it twice — the rule `Bind` above
            // follows for the same reason.
            Self::Identity { path, .. } => {
                write!(f, "the identity file at {path} cannot be used")
            }
        }
    }
}

impl std::error::Error for ServeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidBackendUrl { .. }
            | Self::BackendUnresolvable { .. }
            | Self::BackendNotLocal { .. }
            | Self::InvalidToken
            | Self::InvalidRelay { .. } => None,
            Self::Bind(e) | Self::Identity { source: e, .. } => Some(e),
        }
    }
}

#[cfg(test)]
#[path = "serve_error_tests.rs"]
mod serve_error_tests;
