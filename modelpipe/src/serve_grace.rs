//! Rotating the credential without un-pairing everything at once.
//!
//! A fourth `impl` block of [`ServeHandle`] — after `serve_handle.rs`,
//! `serve_status.rs` and `network.rs` — split off for the reason
//! `serve_status.rs` was: `serve_handle.rs` is close enough to the
//! file-size budget that a method whose contract is longer than the method
//! does not fit beside the others. The division is by question —
//! `serve_handle.rs` answers *who may use this listener*, and this file
//! answers *what becomes of the machines that were already using it* when
//! that answer changes.

use std::time::Duration;

use crate::serve_error::ServeError;
use crate::serve_handle::ServeHandle;

impl ServeHandle {
    /// [`set_token`](Self::set_token), except the key it replaces goes on
    /// admitting until `grace` elapses.
    ///
    /// The rollout problem this exists for has no solution with one
    /// credential. Several machines are paired and holding the current
    /// key; the key has to change. Push the replacement in first and every
    /// one of them is refused — `invalid or missing bearer token` at the
    /// edge — until it is reconfigured. Reconfigure them first and they
    /// present a value this listener does not yet enforce. There is no
    /// third ordering, and the outage lasts as long as the slowest machine
    /// takes to notice. `grace` is a window in which both values admit, so
    /// the rollout has somewhere to happen.
    ///
    /// **This widens what the tunnel edge admits, and nothing beyond it.**
    /// A request bearing the old key gets through this listener and then
    /// meets whatever the backend behind it checks. If that backend reads
    /// the same rotated key from the same store, it now expects the *new*
    /// value and refuses the request a layer later — the window bought
    /// nothing, and the failure just moved. A dual-accept rollout needs
    /// both ends to hold two values at once; this is the end that belongs
    /// to the tunnel.
    ///
    /// While the window is open **two values are the credential** for the
    /// whole tunnel, exactly as [`grant_once`](Self::grant_once) says of a
    /// live grant. Size `grace` by how long the rollout actually takes and
    /// not by what is convenient — a window measured in hours is a second
    /// standing key with a comment attached.
    ///
    /// Windows do not chain. A second call inside an open window retires
    /// the key the first one was protecting, so this never accumulates:
    /// what is enforced, plus the one thing it directly replaced. (A live
    /// [`grant_once`](Self::grant_once) code is a third credential with
    /// its own lifetime, untouched by any of this.)
    /// [`set_token`](Self::set_token) closes an open window outright, and
    /// is the way to end an overlap early — a rotation that says nothing
    /// about grace is a rotation that wants none.
    ///
    /// Two `grace` values hold nothing, and both fail closed.
    /// [`Duration::ZERO`] is [`set_token`](Self::set_token): the replaced
    /// key is dropped rather than parked already-expired, so the boundary
    /// falls on the safe side rather than admitting one last request. So
    /// is any `grace` too large for the clock to represent a deadline from
    /// — [`Duration::MAX`] is the obvious way to write "never expire", and
    /// **it holds no key at all** rather than holding one forever. If that
    /// is not what you meant, name a window you can defend. On a listener
    /// that was serving open there is no key to hold either, and this
    /// turns authentication on exactly as `set_token` does.
    ///
    /// Not a replacement for [`rotate_token`](Self::rotate_token) on a
    /// *leaked* key. There the whole point is that the old value dies now,
    /// and any window is time an attacker still has.
    ///
    /// # Errors
    ///
    /// [`ServeError::InvalidToken`] if `token` is empty or nothing but
    /// whitespace — the value [`set_token`](Self::set_token) refuses,
    /// refused for the same reason. **Nothing changes**: what was in force
    /// stays in force, no window opens, and an already-open window is
    /// neither shut nor extended.
    ///
    /// Read that last clause carefully if you are rotating on a schedule.
    /// A refusal means this call did nothing — it does **not** mean no old
    /// key is admitting. An operator who opened an hour-long window and
    /// then pushed a rotation whose config value came back blank still has
    /// the first replaced key admitting for the rest of that hour.
    /// [`set_token`](Self::set_token) with a value you have checked is how
    /// to end it.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(serving: &modelpipe::ServeHandle) -> Result<(), Box<dyn std::error::Error>> {
    /// // Paired laptops keep working on the old key while they pick the
    /// // new one up; after five minutes, only the new one admits.
    /// serving.set_token_with_grace(
    ///     std::env::var("MODELPIPE_TOKEN")?,
    ///     std::time::Duration::from_mins(5),
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Cutting a window short, because the rollout finished early:
    ///
    /// ```no_run
    /// # fn example(serving: &modelpipe::ServeHandle, current: String) -> Result<(), modelpipe::ServeError> {
    /// serving.set_token(current)?; // the previous key stops admitting here
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_token_with_grace(&self, token: String, grace: Duration) -> Result<(), ServeError> {
        if self.state.credential.set_with_grace(token, grace) {
            Ok(())
        } else {
            Err(ServeError::InvalidToken)
        }
    }
}
