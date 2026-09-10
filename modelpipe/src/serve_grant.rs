//! What a device that is not yet paired may present.
//!
//! A fifth `impl` block of [`ServeHandle`], split off for the reason
//! `serve_grace.rs` was: `serve_handle.rs` sits under the file-size budget
//! by less than a method whose contract is longer than the method. The
//! division is by question again — `serve_handle.rs` answers *who may use
//! this listener*, `serve_grace.rs` *what becomes of the machines already
//! using it when that changes*, and this file *how a machine that is not
//! yet one of them gets in once*.
//!
//! Two shapes of the same primitive. [`grant_once`](ServeHandle::grant_once)
//! is the grant as it always was: spent by its own presentation, dead at
//! its deadline, and otherwise untouchable from the far side.
//! [`grant_once_bounded`](ServeHandle::grant_once_bounded) also dies at a
//! number of wrong presentations, which is the property an embedder needs
//! the moment the listener's endpoint key outlives a restart — a code with
//! twenty bits of entropy is safe for two minutes only if guessing it costs
//! the guesser the code.

use std::num::NonZeroU8;
use std::time::Duration;

use crate::serve_error::ServeError;
use crate::serve_handle::ServeHandle;

impl ServeHandle {
    /// Admit **one** request bearing `secret` before `ttl` elapses, on top
    /// of whatever [`set_token`](Self::set_token) enforces.
    ///
    /// A pairing primitive, not a second key. An embedder that wants a new
    /// device to *fetch* the real credential over the encrypted hop mints a
    /// short code, grants it here, shows it once, and serves a handshake
    /// route behind the tunnel: the device presents the code as its bearer,
    /// the edge lets exactly that request through, and the route answers
    /// with the key. The code is spent when presented and dead anyway when
    /// `ttl` passes, so a photograph of the screen is worth nothing later.
    ///
    /// **While live, a grant is equivalent to the token for the whole
    /// tunnel** — the edge cannot scope the one request it admits. Keep
    /// `ttl` short and make the secret unguessable for that window. Wrong
    /// presentations do not shorten it: this is the grant for a listener
    /// whose ticket dies with the process, where the window is the whole
    /// defence and a guesser has to find the listener first. A listener
    /// whose ticket lasts wants
    /// [`grant_once_bounded`](Self::grant_once_bounded) instead. The
    /// enforced token is untouched either way: [`token`](Self::token) still
    /// reports it, it still admits, and a rotation through
    /// [`set_token`](Self::set_token) neither spends nor extends a grant.
    ///
    /// # Errors
    ///
    /// [`ServeError::InvalidToken`] if `secret` is empty or nothing but
    /// whitespace, in which case nothing is granted — the value
    /// [`set_token`](Self::set_token) refuses, refused for the same reason.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(serving: &modelpipe::ServeHandle) -> Result<(), Box<dyn std::error::Error>> {
    /// serving.grant_once("483920".to_owned(), std::time::Duration::from_mins(2))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn grant_once(&self, secret: String, ttl: Duration) -> Result<(), ServeError> {
        self.grant(secret, ttl, None)
    }

    /// [`grant_once`](Self::grant_once), except the grant is also gone the
    /// moment `burn_after` wrong presentations have been made while it is
    /// live.
    ///
    /// A wrong presentation is a well-formed bearer that admits nowhere:
    /// not the enforced token, not a key still admitting under
    /// [`set_token_with_grace`](Self::set_token_with_grace), and not a
    /// grant. A request with no `Authorization` at all, or one with another
    /// scheme, is refused without counting — it is not a guess. What is
    /// counted counts against every bounded grant at once, because the
    /// edge cannot tell which one a guess was aimed at, and a guesser does
    /// not get to choose. So a device that is still presenting a key this
    /// listener no longer honours can burn an open pairing; that is the
    /// intended reading — from the edge, it *is* a guesser — and the cost
    /// is one more `grant_once_bounded`.
    ///
    /// This is the grant for a listener whose endpoint key is stored
    /// ([`ServeOptions::identity`](crate::ServeOptions::identity)). Such a
    /// ticket outlives every restart, so anyone who has seen it once can
    /// watch for a pairing to open and then spend the whole window
    /// guessing. Six digits are a million possibilities; three wrong
    /// guesses is the difference between two minutes of that and a
    /// mistyped digit.
    ///
    /// # Errors
    ///
    /// [`ServeError::InvalidToken`] if `secret` is empty or nothing but
    /// whitespace — as [`grant_once`](Self::grant_once), and nothing is
    /// granted.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(serving: &modelpipe::ServeHandle) -> Result<(), Box<dyn std::error::Error>> {
    /// let three = std::num::NonZeroU8::new(3).expect("three is not zero");
    /// serving.grant_once_bounded("483920".to_owned(), std::time::Duration::from_mins(2), three)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn grant_once_bounded(
        &self,
        secret: String,
        ttl: Duration,
        burn_after: NonZeroU8,
    ) -> Result<(), ServeError> {
        self.grant(secret, ttl, Some(burn_after))
    }

    fn grant(
        &self,
        secret: String,
        ttl: Duration,
        burn_after: Option<NonZeroU8>,
    ) -> Result<(), ServeError> {
        if self.state.credential.grant(secret, ttl, burn_after) {
            Ok(())
        } else {
            Err(ServeError::InvalidToken)
        }
    }
}
