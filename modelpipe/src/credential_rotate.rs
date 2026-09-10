//! The primary credential — its type, and everything that writes it or
//! what is presented upstream in its place.
//!
//! A child of [`super`] via `#[path]`, the way the test files are, rather
//! than a sibling module: these methods touch the cell and the grace
//! window directly, and keeping them a child keeps both fields private.
//! Split off when named tokens brought `credential.rs` to the file-size
//! budget. The division is by question — `credential.rs` answers *what
//! admits*, and this file *what the listener holds of its own* and what
//! becomes of it when the operator changes it.

use std::sync::Arc;
use std::time::Duration;

use super::Credential;
use crate::minting::{mint, presentable};

/// What the listener enforces of its own, apart from anything added by
/// name.
#[derive(Clone)]
pub(super) enum Primary {
    /// Serving open: everything admits, and nothing else is consulted.
    Open,
    /// No token of its own — [`TokenPolicy::Named`](crate::TokenPolicy::Named). Only named tokens, a
    /// graced key and grants admit. This is *closed*, and the difference
    /// from [`Open`](Self::Open) is the whole reason the cell is an enum
    /// rather than an `Option`: before named tokens, "no primary" and
    /// "serving open" were the same state.
    Absent,
    /// The enforced token.
    Token(Arc<Enforced>),
}

/// The token a listener enforces.
///
/// One field, since the scheme stopped being part of what is compared: the
/// `Authorization` value is split at its single space and only the
/// credential after it is matched, so the pre-built `"Bearer <token>"`
/// string this used to carry beside the token had no reader left.
pub(super) struct Enforced {
    /// What [`ServeHandle::token`](crate::ServeHandle::token) reports.
    pub(super) token: String,
}

impl Enforced {
    pub(super) fn new(token: String) -> Arc<Self> {
        Arc::new(Self { token })
    }
}

impl Credential {
    /// Install `token`, replacing whatever is enforced. Turns
    /// authentication on if it was off, and gives a listener that had no
    /// token of its own ([`TokenPolicy::Named`](crate::TokenPolicy::Named))
    /// one — the named tokens are untouched either way.
    ///
    /// Returns whether it did. A token nothing can present is refused here
    /// for the reason [`Credential::new`] refuses it, and refusing means
    /// keeping the credential already in force — installing it would take a
    /// working listener down to one that answers nothing.
    pub(crate) fn set(&self, token: String) -> bool {
        self.install(token, None)
    }

    /// [`set`](Self::set), keeping the key it replaced admitting until
    /// `grace` elapses. See [`Superseded::hold`](crate::superseded::Superseded::hold)
    /// for what a second rotation inside that window does, which `grace`
    /// values hold nothing at all, and why.
    pub(crate) fn set_with_grace(&self, token: String, grace: Duration) -> bool {
        self.install(token, Some(grace))
    }

    /// The one place the primary is written.
    ///
    /// `grace` is `Some` only for a rotation asked to leave an overlap
    /// behind. Everything else releases the window instead — a plain
    /// [`set`](Self::set), which is how "the old value stops working
    /// immediately" stays true even when one is called mid-window, and a
    /// rotation onto a listener that had no token to leave behind, whether
    /// it was serving open or admitting by name only.
    ///
    /// A refused token returns before either lock is taken, so an open
    /// window is left exactly as it was — neither shut nor extended. That
    /// is the right behaviour (a rotation that did not happen must not
    /// change what admits) and it is the one the callers above have to
    /// document, because "nothing changed" reads to an operator as "no old
    /// key is admitting" and mid-window those are different claims.
    ///
    /// The old key is held *before* the new one is enforced, and both
    /// happen under the primary's write lock, so the **stored state** is
    /// never a gap: at every instant a reader could observe it, one of the
    /// two values is admitting. That is the only place these two locks
    /// nest, and this is the order.
    ///
    /// It does not follow — and is not claimed — that no request can be
    /// refused during a rotation. [`admits`](Self::admits) reads the
    /// credentials under separate locks, releasing each before taking the
    /// next, precisely so a rotation is never held up behind an in-flight
    /// request. A rotation landing between those reads can refuse a value
    /// that admitted before it and admits after it. That is fail-closed, it
    /// is the snapshot race `admits` has always run, and the honest
    /// guarantee is about the state rather than about every request that
    /// races it.
    fn install(&self, token: String, grace: Option<Duration>) -> bool {
        if !presentable(&token) {
            return false;
        }
        let mut primary = self.write();
        match (grace, &*primary) {
            (Some(grace), Primary::Token(old)) => self.superseded.hold(old.token.clone(), grace),
            _ => self.superseded.release(),
        }
        *primary = Primary::Token(Enforced::new(token));
        true
    }

    /// What the backend is told in `Authorization` from now on: `Some` to
    /// present that bearer in the client's place, `None` to forward the
    /// client's own. Returns whether it took — `Some` of a value nothing
    /// could present is refused, and what was in force stays in force.
    pub(crate) fn set_upstream(&self, token: Option<String>) -> bool {
        if token.as_deref().is_some_and(|t| !presentable(t)) {
            return false;
        }
        *self
            .upstream
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = token.map(Arc::from);
        true
    }

    /// The bearer presented upstream, if one replaces the client's.
    pub(crate) fn upstream(&self) -> Option<Arc<str>> {
        self.upstream
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Install a freshly minted token and return it.
    pub(crate) fn rotate(&self) -> String {
        let token = mint();
        // Always presentable: 256 bits of base32 is never empty. Asserted
        // rather than ignored, so that a change to `mint` that broke it
        // fails here instead of producing a listener nobody can reach.
        assert!(self.set(token.clone()), "a minted token is always usable");
        token
    }
}
