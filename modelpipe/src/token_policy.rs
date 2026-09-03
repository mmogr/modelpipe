//! What the operator asked for, as opposed to what the listener enforces.
//!
//! Split from [`crate::credential`] when that file outgrew the budget, and
//! the line is a real one rather than a convenient one. This is a *request*
//! — a value an embedder constructs and hands to
//! [`serve`](fn@crate::serve) — while `Credential` beside it is the live
//! cell a request is checked against. One is public API and never changes
//! after `serve` returns; the other is behind an `RwLock` because it
//! rotates underneath in-flight requests.
//!
//! The redaction tests live here with the type they are about. A derived
//! `Debug` on this enum is the single most likely way a bearer token
//! reaches a log file or a panic message, which is why the impl below is
//! hand-written and why it is tested from three directions — here, from
//! `serve_tests` through `ServeOptions`, and from `tests/api_surface.rs` as
//! an external dependent that derives its own `Debug` over ours.

use std::fmt;

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
    /// [`ServeHandle::token`](crate::ServeHandle::token). The recommended default for standalone
    /// use.
    #[default]
    Generate,
    /// Enforce this caller-supplied token instead of generating one.
    /// Rotating a supplied credential belongs to the caller — push the
    /// replacement into a running listener with
    /// [`ServeHandle::set_token`](crate::ServeHandle::set_token).
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Distinctive enough that finding it anywhere in a rendering is
    /// unambiguous, and not a substring of any word the formatter emits.
    const SECRET: &str = "sk-zzq-a-very-distinctive-credential-value";

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
}
