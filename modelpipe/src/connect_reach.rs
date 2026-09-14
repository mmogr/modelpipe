//! Waiting for a connect side to reach its serve side.
//!
//! Another `impl` block of [`ConnectHandle`], beside the one in
//! `network.rs`, split out because `connect_handle.rs` is near its size
//! budget. [`connect`](fn@crate::connect) returns with the local port bound
//! and the dial still running, and how long to wait for the peer is the
//! caller's to decide. Every caller wrote the same loop to decide it, so this
//! is that loop, written once.

use std::fmt;
use std::time::Duration;

use crate::connect_handle::ConnectHandle;
use crate::status::{CloseReason, PipeStatus};

/// Why [`ConnectHandle::wait_reachable`] returned without reaching the serve
/// side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unreached {
    /// The wait ran out, after the duration it was given, with the pipe still
    /// looking. The pipe keeps looking: the handle is live, and a serve side
    /// that turns up later is picked up.
    TimedOut(Duration),
    /// The pipe closed before it reached the serve side, for the reason
    /// [`ConnectHandle::close_reason`] reports.
    Closed(Option<CloseReason>),
}

impl fmt::Display for Unreached {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimedOut(within) => write!(
                f,
                "could not reach the serve side within {within:?}, directly or via a relay"
            ),
            Self::Closed(Some(reason)) => write!(
                f,
                "the pipe closed ({}) before it reached the serve side",
                reason.as_str()
            ),
            Self::Closed(None) => f.write_str("the pipe closed before it reached the serve side"),
        }
    }
}

impl std::error::Error for Unreached {}

impl ConnectHandle {
    /// Wait until this side has reached the serve side, for at most `within`.
    ///
    /// Returns the path, [`Direct`](PipeStatus::Direct) or
    /// [`Relayed`](PipeStatus::Relayed), as soon as there is one, including a
    /// path reached before this was called. A pipe that closes first ends the
    /// wait at once.
    ///
    /// Running out ends the wait and not the pipe. The handle keeps trying, so
    /// a caller may wait again, or hand the port out anyway and let a late
    /// serve side be picked up. A `within` too long to add to the clock waits
    /// with no deadline.
    ///
    /// # Errors
    ///
    /// [`Unreached::TimedOut`] when `within` runs out first, and
    /// [`Unreached::Closed`] when the pipe closes first.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(ticket: &modelpipe::Ticket) -> Result<(), Box<dyn std::error::Error>> {
    /// let connected = modelpipe::connect(ticket, modelpipe::ConnectOptions::default()).await?;
    /// let path = connected.wait_reachable(std::time::Duration::from_secs(40)).await?;
    /// println!("reached the serve side: {}", path.as_str());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn wait_reachable(&self, within: Duration) -> Result<PipeStatus, Unreached> {
        let deadline = tokio::time::Instant::now().checked_add(within);
        // The current status first: a pipe that reached its peer before this
        // was called has no change left to wait for.
        let mut held = self.status();
        loop {
            match held {
                PipeStatus::Direct | PipeStatus::Relayed => return Ok(held),
                PipeStatus::Closed => return Err(Unreached::Closed(self.close_reason())),
                PipeStatus::Idle => {}
            }
            let next = self.status_changed_since(held);
            let next = match deadline {
                Some(deadline) => tokio::time::timeout_at(deadline, next)
                    .await
                    .map_err(|_| Unreached::TimedOut(within))?,
                None => next.await,
            };
            // `None` answers only a snapshot that was already `Closed`, and
            // the match above has returned on that.
            held = next.unwrap_or(PipeStatus::Closed);
        }
    }
}
