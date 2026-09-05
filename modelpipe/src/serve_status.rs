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
    pub async fn status_changed(&self) -> PipeStatus {
        // The snapshot is taken here, at the moment of the call, which is
        // what makes states that came and went while nobody was waiting
        // coalesce rather than replay.
        let snapshot = self.state.lifecycle.status();
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
