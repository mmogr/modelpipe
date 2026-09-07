//! The key a rotation replaced, still admitting for a little longer.
//!
//! Replacing the enforced token is total and instant: the value installed
//! is the only one that admits, from the next request onward. That is the
//! right default, and it is exactly what an operator retiring a *leaked*
//! key wants. It is the wrong shape for a **planned** rotation across
//! machines that are already paired, because there is no order in which to
//! perform one. Push the replacement into the listener first and every
//! paired machine is refused until it is reconfigured; reconfigure the
//! machines first and they present a key the listener does not yet
//! enforce. Either way the fleet is down for the width of the rollout, and
//! the width of a rollout is not something the rotating side controls.
//!
//! A *superseded* key is the third option: for a bounded window after a
//! rotation, the value it replaced goes on admitting, so the rollout has
//! somewhere to happen. It is neither of the two credentials this crate
//! already had. Unlike a [`grant`](crate::grant) it admits as many
//! requests as arrive — it is the key those machines are still holding,
//! not a one-shot pairing code, and spending it on the first request would
//! un-pair the second one. Unlike the enforced token it dies on a
//! deadline rather than on the next rotation, so an overlap that nobody
//! remembers to close still closes.
//!
//! Kept beside, not inside, [`crate::credential`] for the reason
//! [`crate::grant`] is: the primary token has a rotation contract that a
//! second credential's state must not be able to disturb, and the
//! file-size gate says the same thing from the other direction.

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use subtle::ConstantTimeEq;

/// A key that has been replaced, and the moment it stops admitting.
struct Held {
    token: String,
    expires: Instant,
}

/// The at-most-one key a listener still honours after replacing it.
pub(crate) struct Superseded {
    held: Mutex<Option<Held>>,
}

impl Superseded {
    pub(crate) const fn new() -> Self {
        Self {
            held: Mutex::new(None),
        }
    }

    /// Honour `token` until `grace` elapses, replacing whatever was held.
    ///
    /// **Windows do not chain.** A second rotation inside an open window
    /// retires the key the first one was protecting rather than adding to
    /// a set, so this slot holds one key and never a growing set: what is
    /// enforced, plus the one thing it directly replaced. (A live
    /// [`grant`](crate::grant) is a third credential with its own
    /// lifetime, and is not what this bounds.) Three reasons, heaviest
    /// first.
    ///
    /// 1. Chaining would make *how many credentials does this listener
    ///    accept* a function of how often the embedder happened to rotate.
    ///    Nobody chooses that number, and nobody could read it back. One
    ///    slot answers the question with a constant.
    /// 2. It matches what the window is for. The key an already-paired
    ///    machine is still holding is the one immediately before the
    ///    current one; a machine two rotations behind has slept through a
    ///    whole rollout, and a window wide enough to cover it hides that
    ///    rather than fixing it.
    /// 3. It bounds what a *rushed* sequence leaves behind. Rotating again
    ///    inside an open window is what an operator does on discovering
    ///    the last rotation was not enough, and chaining would leave every
    ///    key in that sequence admitting at once. One slot leaves one.
    ///    Note this is a bound and not a rescue: the key most recently
    ///    replaced still admits for the grace just given it, so a rotation
    ///    away from a *leaked* key wants no grace at all — see
    ///    [`ServeHandle::set_token_with_grace`](crate::ServeHandle::set_token_with_grace).
    ///
    /// Two `grace` values hold nothing rather than something, and both
    /// fail closed:
    ///
    /// - Zero, which would be a key that has already expired. Storing it
    ///   would park a retired secret that nothing sweeps until the next
    ///   request, which is what the sweep in [`admits`](Self::admits)
    ///   exists to prevent; the boundary belongs on the safe side anyway.
    /// - Anything so large the clock cannot represent the deadline —
    ///   [`Duration::MAX`] is the obvious way to write "no expiry", and an
    ///   unwrapped config parse is the accidental way. `Instant + Duration`
    ///   **panics** on overflow, and this runs inside the enforced write
    ///   lock, so a panic here would abandon the rotation mid-flight and
    ///   poison that lock. Refusing to hold anything is the fail-closed
    ///   reading of a window nobody could have meant.
    pub(crate) fn hold(&self, token: String, grace: Duration) {
        let now = Instant::now();
        *self.lock() = match now.checked_add(grace) {
            Some(expires) if expires > now => Some(Held { token, expires }),
            _ => None,
        };
    }

    /// Stop honouring whatever was held, now.
    pub(crate) fn release(&self) {
        *self.lock() = None;
    }

    /// Whether `presented` is the held key, still inside its window.
    ///
    /// Admits repeatedly, which is the whole difference from a grant: this
    /// is a key several machines are holding, so nothing is spent by
    /// presenting it and the second machine to arrive is not refused for
    /// being second.
    ///
    /// An expired key is *dropped* here, not merely refused. There is no
    /// timer — sweeping on this path is what makes a listener stop
    /// referencing a retired secret rather than keeping it alive on the
    /// strength of never being asked. Dropped, not scrubbed: the `String`
    /// returns to the allocator with its bytes intact, and this crate does
    /// not zeroize (see
    /// [`ServeHandle::token`](crate::ServeHandle::token)).
    ///
    /// The comparison is constant-time in the token, the same rule the
    /// primary credential keeps. Whether a window is open at all is not,
    /// and is not a secret: it is a consequence of a rotation the operator
    /// performed, on a schedule the operator chose.
    pub(crate) fn admits(&self, presented: &[u8]) -> bool {
        self.sweep().as_ref().is_some_and(|key| {
            let expected = key.token.as_bytes();
            expected.len() == presented.len() && bool::from(expected.ct_eq(presented))
        })
    }

    /// Whether a window is open, for a `Debug` that reports state and not
    /// secrets.
    pub(crate) fn is_open(&self) -> bool {
        self.sweep().is_some()
    }

    /// Drop an expired key, and hand back the slot either way.
    fn sweep(&self) -> MutexGuard<'_, Option<Held>> {
        let now = Instant::now();
        let mut held = self.lock();
        if held.as_ref().is_some_and(|key| key.expires <= now) {
            *held = None;
        }
        held
    }

    // A poisoned lock cannot happen here: nothing panics while holding it —
    // the only operations are a comparison and a store, and `hold` computes
    // its deadline with `checked_add` before taking the lock precisely so
    // that stays true. Recovering the guard rather than propagating is the
    // honest response to an impossible case, and matches what `credential`
    // and `grant` do with theirs.
    fn lock(&self) -> MutexGuard<'_, Option<Held>> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
#[path = "superseded_tests.rs"]
mod superseded_tests;
