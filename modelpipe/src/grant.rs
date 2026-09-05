//! Credentials that admit once, then never again.
//!
//! The bearer token a listener enforces is one value, replaced whole by a
//! rotation and never admitted twice by design. A *grant* is the other
//! shape a credential can take: handed out for a single request, dead the
//! moment it is used, and dead anyway when its deadline passes. It exists
//! so an embedder can run a pairing handshake through the tunnel — a new
//! device presents a short-lived code, and what comes back over the
//! encrypted hop is the real key — without the code ever becoming a second
//! standing credential.
//!
//! Kept beside, not inside, [`crate::credential`]: the primary token has a
//! rotation contract that this module must not be able to disturb, and the
//! file-size gate says the same thing from the other direction.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use subtle::ConstantTimeEq;

/// One admission, or none.
struct Grant {
    token: String,
    expires: Instant,
}

/// Every grant currently live on a listener.
pub(crate) struct Grants {
    live: Mutex<Vec<Grant>>,
}

impl Grants {
    pub(crate) const fn new() -> Self {
        Self {
            live: Mutex::new(Vec::new()),
        }
    }

    /// Add a grant that admits one request bearing `token` before `ttl`
    /// elapses.
    ///
    /// The same token granted twice is two grants and two admissions, which
    /// is what the caller asked for and is not corrected here.
    pub(crate) fn add(&self, token: String, ttl: Duration) {
        let expires = Instant::now() + ttl;
        self.lock().push(Grant { token, expires });
    }

    /// Whether `presented` is a live grant — and if so, consume it.
    ///
    /// Expired grants are swept on every call rather than by a timer, so a
    /// listener nobody pairs with never holds more than the grants it was
    /// given. The comparison is constant-time in the token, the same rule
    /// the primary credential keeps; which *position* in the list matched
    /// is not hidden, and is not a secret either.
    pub(crate) fn consume(&self, presented: &[u8]) -> bool {
        let now = Instant::now();
        let mut live = self.lock();
        live.retain(|grant| grant.expires > now);
        let matched = live.iter().position(|grant| {
            let expected = grant.token.as_bytes();
            expected.len() == presented.len() && bool::from(expected.ct_eq(presented))
        });
        if let Some(index) = matched {
            live.swap_remove(index);
        }
        drop(live);
        matched.is_some()
    }

    /// How many grants are live, for a `Debug` that reports state and not
    /// secrets.
    pub(crate) fn count(&self) -> usize {
        let now = Instant::now();
        let mut live = self.lock();
        live.retain(|grant| grant.expires > now);
        live.len()
    }

    // A poisoned lock cannot happen here: nothing panics while holding it.
    // Recovering the guard is the honest response to an impossible case.
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Grant>> {
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
#[path = "grant_tests.rs"]
mod grant_tests;
