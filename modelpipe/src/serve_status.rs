//! What the serve side reports about the peers it is carrying.
//!
//! The second `impl` block of [`ServeHandle`], split from
//! `serve_handle.rs` when the per-peer view arrived and that file reached
//! its budget. The division is by question: `serve_handle.rs` answers
//! *who may use this listener and how does it stop*, and this file answers
//! *who is using it right now, and how are they reaching it*.

use crate::serve_handle::ServeHandle;
use crate::status::{PeerView, PipeStatus};

impl ServeHandle {
    /// How this side is currently reaching its peers.
    ///
    /// An aggregate over every connected peer, reporting the worst active
    /// path — see [`PipeStatus`] for why. [`peers`](Self::peers) is the
    /// per-peer answer.
    pub fn status(&self) -> PipeStatus {
        self.state.lifecycle.status()
    }

    /// Wait until the status changes, then return the new value.
    ///
    /// This is how a caller surfaces "direct ↔ relayed" changes as they
    /// happen, rather than polling [`status`](Self::status). Snapshot
    /// semantics: each call compares against the status at the moment
    /// the call was made, so states that came and went while nobody was
    /// waiting are coalesced away, never replayed. Any number of callers
    /// may wait concurrently — a daemon and a UI stream can both watch
    /// one handle — each resolving against its own snapshot. On
    /// teardown, graceful or not, the status becomes
    /// [`PipeStatus::Closed`] and every waiting call resolves with it;
    /// once closed, calls resolve immediately, so a watcher can never
    /// block on a pipe that is already gone.
    ///
    /// [`status_changed_since`](Self::status_changed_since) is the form for
    /// a caller that holds the value it last rendered; the two coexist
    /// because they answer different questions, and this one is the right
    /// answer for a watcher that is already parked.
    pub async fn status_changed(&self) -> PipeStatus {
        // The snapshot is taken here, at the moment of the call, which is
        // what makes states that came and went while nobody was waiting
        // coalesce rather than replay.
        let snapshot = self.state.lifecycle.status();
        // `None` can only mean the snapshot taken a line above was already
        // `Closed`, and this form owes such a caller the terminal status
        // rather than a wait — the clause the doc above states.
        self.state
            .lifecycle
            .changed_since(snapshot)
            .await
            .unwrap_or(PipeStatus::Closed)
    }

    /// Wait until the status differs from `snapshot`, then return it, and
    /// `None` once the pipe is closed and `snapshot` already says so.
    ///
    /// The gap-free half of [`status_changed`](Self::status_changed), for a
    /// caller holding the last value it rendered. That method takes its
    /// snapshot *inside itself*, at the moment it is polled, so a
    /// transition landing between a caller's [`status`](Self::status) and
    /// its next `status_changed` is coalesced away and never reported. For
    /// a watcher already parked on the handle that is exactly right — the
    /// states nobody was waiting for are not worth replaying. For anything
    /// that renders a value and *then* goes back to waiting it is a dropped
    /// transition, and no ordering of the two calls closes the window,
    /// because the race is inside the second one. Passing what was rendered
    /// closes it.
    ///
    /// **`None` ends the sequence, and that is the point.**
    /// [`PipeStatus::Closed`] is terminal, so a caller that has seen it has
    /// nothing further to wait for; a method that answered `Closed` again,
    /// immediately and forever, would make the loop below a busy loop on
    /// one core with no await in it anywhere. Every snapshot that is not
    /// already `Closed` is still delivered `Closed` exactly once, so
    /// nothing is lost by watching this way.
    ///
    /// Concurrent callers are as welcome as they are on
    /// [`status_changed`](Self::status_changed), each against the snapshot
    /// it passed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(serving: &modelpipe::ServeHandle) {
    /// let mut held = serving.status();
    /// println!("status: {}", held.as_str());
    /// // Ends on its own when the pipe does.
    /// while let Some(next) = serving.status_changed_since(held).await {
    ///     println!("status: {}", next.as_str());
    ///     held = next;
    /// }
    /// # }
    /// ```
    pub async fn status_changed_since(&self, snapshot: PipeStatus) -> Option<PipeStatus> {
        self.state.lifecycle.changed_since(snapshot).await
    }

    /// Every peer connected right now, in the order they arrived.
    ///
    /// The per-peer answer to the question [`status`](Self::status)
    /// aggregates: with a phone and a laptop on one ticket, this is what
    /// says *which* of them is relayed. Each entry names the peer by the
    /// same fingerprint the `peer` log field and the `X-Modelpipe-Peer`
    /// header carry, so a device is one name everywhere.
    ///
    /// A snapshot, honest about the moment it was taken — a peer may have
    /// left by the time the list is read. Empty when idle or closed.
    pub fn peers(&self) -> Vec<PeerView> {
        self.state.peers.views()
    }
}
