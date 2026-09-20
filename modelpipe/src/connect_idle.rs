//! How long a connect side has been out of touch.
//!
//! An `impl ConnectHandle` of its own, the way [`crate::connect_reach`]
//! is: `connect_handle.rs` is at its size budget, and this is a distinct
//! question from the ones there — not *what* the pipe is doing but *how
//! long* it has been doing it.
//!
//! The clock itself lives on [`crate::lifecycle::Lifecycle`]; the argument
//! for having one, and for it carrying no policy, is ADR 0004.

use std::time::Duration;

use crate::connect_handle::ConnectHandle;

impl ConnectHandle {
    /// How long this side has been [`PipeStatus::Idle`](crate::PipeStatus::Idle),
    /// or `None` when it is not idle — which means it has reached the peer
    /// **or** that the pipe is closed.
    ///
    /// Those two are told apart by the status, not by this: `None` here is
    /// not "reached". A caller that acts on absence should check
    /// [`status`](Self::status) first, which is the live/closed
    /// discriminator.
    ///
    /// `Idle` means the peer is not reachable *and is being dialled
    /// again*, for as long as the pipe is held — so the status alone
    /// cannot tell a packet lost a moment ago from a far machine that has
    /// been asleep since last night. This is the difference, and it is
    /// what a caller needs to decide when to start saying so.
    ///
    /// **The policy stays here.** How long is too long is a product
    /// decision, not a transport one: a desktop tunnel and a phone app
    /// reasonably answer it differently, and the same crate serves both.
    /// What this promises is only the measurement.
    ///
    /// The clock starts at the *transition* into `Idle`, and a re-dial
    /// that finds nobody does not restart it — a peer that is simply gone
    /// would otherwise never look away. It also starts at birth: a handle
    /// is `Idle` from the moment it is returned, so a pipe that has never
    /// reached its peer reports the age of the pipe.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(connected: &modelpipe::ConnectHandle) {
    /// const AWAY_AFTER: std::time::Duration = std::time::Duration::from_secs(30);
    /// if connected.idle_for().is_some_and(|idle| idle >= AWAY_AFTER) {
    ///     println!("the other machine is away; the port stays bound");
    /// }
    /// # }
    /// ```
    pub fn idle_for(&self) -> Option<Duration> {
        self.state.lifecycle.idle_for()
    }
}
