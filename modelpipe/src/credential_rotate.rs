//! Everything that writes the primary credential.
//!
//! A child of [`super`] via `#[path]`, the way the test files are, rather
//! than a sibling module: these methods touch the cell and the grace
//! window directly, and keeping them a child keeps both fields private.
//! Split off when named tokens brought `credential.rs` to the file-size
//! budget. The division is by question — `credential.rs` answers *what
//! admits*, and this file *what becomes of what is enforced* when the
//! operator changes it.

use std::time::Duration;

use super::{Credential, Enforced, Primary};
use crate::minting::{mint, presentable};

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
