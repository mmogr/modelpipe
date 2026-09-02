//! What the serve side requires in `Authorization: Bearer …`.
//!
//! Owns the policy a listener is configured with, the cell that holds the
//! credential it currently enforces, and the comparison itself. It does not
//! know what an HTTP request looks like: it is handed the bytes of an
//! `Authorization` header, or nothing, and answers whether they admit.
//!
//! The cell is always present, even when serving open. `set_token` takes
//! `&self` and turns authentication *on* at runtime, so a listener that had
//! decided at startup not to install a check could not honour that later —
//! the difference between open and closed is whether the cell holds a
//! credential, never whether the check runs.

// Scoped to the non-test build: `TokenPolicy` below is public and used, but
// the cell that enforces a credential has no caller until the listener
// lands. When it does, this goes unfulfilled — the reminder to delete it.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the listener holds the cell; tests exercise it meanwhile"
    )
)]

use std::fmt;
use std::sync::{Arc, RwLock};

use subtle::ConstantTimeEq;

use crate::base32;

/// Bytes of entropy in a generated token: 256 bits, which is not a number
/// anyone needs to reason about again.
const MINTED_ENTROPY_BYTES: usize = 32;

/// The scheme, with its trailing space, as it appears in the header.
const BEARER_PREFIX: &str = "Bearer ";

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

/// The credential a listener currently enforces, and the comparison
/// against it.
pub(crate) struct Credential {
    /// `None` means serving open. Wrapped in an `Arc` so a rotation swaps a
    /// pointer rather than mutating a buffer some request may be part way
    /// through comparing against.
    enforced: RwLock<Option<Arc<Enforced>>>,
}

/// A credential in both the forms the edge needs.
struct Enforced {
    /// What [`ServeHandle::token`](crate::ServeHandle::token) reports.
    token: String,
    /// The full `Bearer <token>` header value, pre-formatted so the
    /// per-request check is a comparison and not an allocation. On a
    /// streaming endpoint this runs once per request forever; building the
    /// string each time would be a needless allocation on the hot path and,
    /// worse, a needless copy of the secret.
    header: String,
}

impl Credential {
    /// Build the cell a policy asks for, returning the token to show the
    /// operator — `None` when serving open.
    pub(crate) fn new(policy: &TokenPolicy) -> (Self, Option<String>) {
        let token = match policy {
            TokenPolicy::Generate => Some(mint()),
            TokenPolicy::Supplied(t) => Some(t.clone()),
            TokenPolicy::InsecureNoAuth => None,
            // `TokenPolicy` is `#[non_exhaustive]` within its own crate only
            // for downstream matches; here the match is total and a new
            // variant must be a compile error rather than silently serving
            // open, which is the one wrong default this type could have.
        };
        let cell = Self {
            enforced: RwLock::new(token.as_deref().map(Enforced::new)),
        };
        (cell, token)
    }

    /// Whether an `Authorization` header value admits.
    ///
    /// `None` is a request with no such header, which is distinct from one
    /// carrying an empty value only in that neither is ever accepted while
    /// a credential is enforced.
    ///
    /// The comparison is constant-time in the bytes, via `subtle`. Length is
    /// not: an unequal-length value is rejected without comparing, which is
    /// standard and deliberate — the length of the expected header is a
    /// fixed parameter of the system, not a secret, and pretending otherwise
    /// would mean comparing against a padded buffer for no gain.
    pub(crate) fn admits(&self, offered: Option<&[u8]>) -> bool {
        // The Arc is cloned and the lock released before comparing, so a
        // rotation is never blocked behind an in-flight request.
        let enforced = self.snapshot();
        let Some(enforced) = enforced else {
            return true; // serving open
        };
        let Some(offered) = offered else {
            return false;
        };
        let expected = enforced.header.as_bytes();
        expected.len() == offered.len() && bool::from(expected.ct_eq(offered))
    }

    /// What the listener currently enforces, or `None` when serving open.
    pub(crate) fn token(&self) -> Option<String> {
        self.snapshot().map(|e| e.token.clone())
    }

    /// Install `token`, replacing whatever is enforced. Turns
    /// authentication on if it was off.
    pub(crate) fn set(&self, token: &str) {
        *self.write() = Some(Enforced::new(token));
    }

    /// Install a freshly minted token and return it.
    pub(crate) fn rotate(&self) -> String {
        let token = mint();
        self.set(&token);
        token
    }

    fn snapshot(&self) -> Option<Arc<Enforced>> {
        self.read().clone()
    }

    // A poisoned lock cannot happen here: nothing panics while holding it —
    // the only operations are a clone and a store. Recovering the guard
    // rather than propagating is the honest response to an impossible case,
    // and turns a hypothetical panic in one request into no effect on the
    // rest.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, Option<Arc<Enforced>>> {
        self.enforced
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Option<Arc<Enforced>>> {
        self.enforced
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl fmt::Debug for Credential {
    /// Reports only whether a credential is enforced, never which one — the
    /// same rule `Debug for TokenPolicy` follows one screen up.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = if self.read().is_some() {
            "enforced"
        } else {
            "open"
        };
        f.debug_tuple("Credential").field(&state).finish()
    }
}

impl Enforced {
    fn new(token: &str) -> Arc<Self> {
        Arc::new(Self {
            token: token.to_owned(),
            header: format!("{BEARER_PREFIX}{token}"),
        })
    }
}

/// A fresh token from the operating system's CSPRNG.
///
/// Base32 of 256 random bits, reusing the ticket's alphabet rather than
/// inventing a second one: it has no characters a person can confuse when
/// reading a token off a screen, it survives a shell without quoting, and it
/// is already a header-safe subset of ASCII.
fn mint() -> String {
    let mut bytes = [0u8; MINTED_ENTROPY_BYTES];
    // A CSPRNG that cannot produce bytes is not a condition to paper over
    // with a weaker source: serving with a guessable credential would be
    // worse than not serving.
    getrandom::fill(&mut bytes).expect("the OS CSPRNG must be available");
    base32::encode(&bytes)
}

#[cfg(test)]
#[path = "credential_tests.rs"]
mod credential_tests;
