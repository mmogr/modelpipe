//! The machinery both handles need: publishing status, and knowing when
//! teardown has actually finished.
//!
//! Neither handle owns this, and that is the point. `ServeHandle` and
//! `ConnectHandle` share no public trait — a decision recorded on
//! [`ConnectHandle`](crate::ConnectHandle) — but they need the same three
//! things underneath, and the prose describing them had already started to
//! drift: `status_changed` states four clauses on one handle and "same
//! contract as" on the other. Two implementations under one prose contract
//! is where the second quietly does something else, and no lint reports
//! prose drift.
//!
//! Pure of iroh, and testable without one.

// Scoped to the non-test build: the handles hold this, and land next.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the handles hold this; tests exercise it meanwhile"
    )
)]

use tokio::sync::watch;

use crate::status::{CloseReason, PipeStatus};

/// How one connected peer is reaching us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerPath {
    /// Hole-punched.
    Direct,
    /// Falling back through a relay.
    Relayed,
}

/// The shared state behind a live pipe.
pub(crate) struct Lifecycle {
    /// Held for the lifetime of the pipe, so a watcher never sees the
    /// sender drop while the pipe is alive.
    status: watch::Sender<PipeStatus>,
    /// Distinct from `status`, and the distinction is load-bearing — see
    /// [`Lifecycle::wait_until_torn_down`].
    torn_down: watch::Sender<bool>,
    /// Exchanges still running. `shutdown` drains rather than cuts, so it
    /// needs to know when the last one finishes.
    in_flight: watch::Sender<usize>,
    /// Why the pipe closed, or `None` while it has not. Separate from
    /// `status` because [`PipeStatus`] is `Copy` and small by design and
    /// the reason is not part of it — see [`CloseReason`].
    ///
    /// A `watch` like the rest, for consistency rather than because
    /// anything waits on it: the reason is read after `Closed` has been
    /// observed, never awaited on its own.
    close_reason: watch::Sender<Option<CloseReason>>,
}

/// Held for as long as one exchange is running.
///
/// A guard rather than a pair of calls, because the decrement has to happen
/// on every exit path — including a panic in the middle of forwarding a
/// body. A missed decrement makes `shutdown` wait forever for work that
/// finished, which is the worst failure this could have: it looks like a
/// hang in the caller's code.
pub(crate) struct InFlight {
    counter: watch::Sender<usize>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.counter.send_modify(|n| *n = n.saturating_sub(1));
    }
}

impl Lifecycle {
    pub(crate) fn new() -> Self {
        Self {
            status: watch::Sender::new(PipeStatus::Idle),
            torn_down: watch::Sender::new(false),
            in_flight: watch::Sender::new(0),
            close_reason: watch::Sender::new(None),
        }
    }

    /// Register an exchange as running until the returned guard is dropped.
    pub(crate) fn enter(&self) -> InFlight {
        self.in_flight.send_modify(|n| *n += 1);
        InFlight {
            counter: self.in_flight.clone(),
        }
    }

    /// How many exchanges are running.
    pub(crate) fn in_flight(&self) -> usize {
        *self.in_flight.borrow()
    }

    /// Wait until every in-flight exchange has finished.
    ///
    /// This is the drain in "`shutdown` drains, `Drop` cuts". A request
    /// admitted before teardown began runs to completion, which is the same
    /// promise `set_token` already makes about not cutting a streaming
    /// response mid-body.
    pub(crate) async fn wait_until_drained(&self) {
        let mut rx = self.in_flight.subscribe();
        if *rx.borrow_and_update() == 0 {
            return;
        }
        let _ = rx.wait_for(|n| *n == 0).await;
    }

    /// The current status.
    pub(crate) fn status(&self) -> PipeStatus {
        *self.status.borrow()
    }

    /// Publish a new status, unless the pipe has already closed.
    ///
    /// `Closed` is terminal: once set, nothing moves the pipe out of it. A
    /// late status update from a task that has not noticed teardown yet is
    /// dropped rather than resurrecting a dead pipe.
    pub(crate) fn set_status(&self, next: PipeStatus) {
        self.status.send_if_modified(|current| {
            if *current == PipeStatus::Closed || *current == next {
                false
            } else {
                *current = next;
                true
            }
        });
    }

    /// Wait until the status differs from `snapshot`, then return it — or
    /// `None` when nothing is ever going to differ from it again.
    ///
    /// Snapshot semantics, and deliberately **not** a bare
    /// `Receiver::changed()`. Two things that would break:
    ///
    /// * A caller arriving after the pipe closed would block forever —
    ///   there is no further change to wait for — whereas the contract
    ///   promises `Closed` is always delivered and never blocks.
    /// * A dropped sender makes `changed()` return `Err`, which is not a
    ///   status. Here it can only mean the pipe is gone, so it reports
    ///   exactly that.
    ///
    /// `None` is the third, and it is what keeps a caller that loops on
    /// this from spinning. [`PipeStatus::Closed`] is terminal, so a caller
    /// whose snapshot is *already* `Closed` has been told everything there
    /// is; answering `Closed` again — at once, forever, with no await
    /// anywhere in the path — turns the obvious loop into a busy loop on
    /// one core. Ending the sequence is the answer a caller cannot get
    /// wrong, which matters most where the caller is generated rather than
    /// written. Every other snapshot is still delivered `Closed` exactly
    /// once.
    pub(crate) async fn changed_since(&self, snapshot: PipeStatus) -> Option<PipeStatus> {
        let mut rx = self.status.subscribe();
        loop {
            let current = *rx.borrow_and_update();
            if current != snapshot {
                return Some(current);
            }
            // Terminal, so a watcher can never block on a pipe already gone
            // — and is never handed the same terminal answer twice.
            if current == PipeStatus::Closed {
                return None;
            }
            if rx.changed().await.is_err() {
                return Some(PipeStatus::Closed);
            }
        }
    }

    /// Mark the pipe closed, recording why. Idempotent.
    ///
    /// This says the pipe is *over*, not that its resources are released —
    /// which is why [`wait_until_torn_down`](Self::wait_until_torn_down)
    /// exists separately.
    ///
    /// **First reason in is the one that keeps**, which is what makes the
    /// answer stable rather than a race: a pipe is routinely closed more
    /// than once — the connect side's accept loop closes it again on its
    /// way out — and a caller who shut down cleanly must not end up reading
    /// a listener failure for it. It is also why the reason is recorded
    /// *before* `Closed` is published: a watcher woken by the status reads
    /// the reason next, and would otherwise find `None` on a pipe that had
    /// one.
    pub(crate) fn close(&self, reason: CloseReason) {
        self.close_reason.send_if_modified(|held| {
            if held.is_some() {
                false
            } else {
                *held = Some(reason);
                true
            }
        });
        self.set_status(PipeStatus::Closed);
    }

    /// Why the pipe closed, or `None` while it has not.
    pub(crate) fn close_reason(&self) -> Option<CloseReason> {
        *self.close_reason.borrow()
    }

    /// Resolve once the pipe is closed, and not before.
    ///
    /// For loops that must stop accepting on teardown: `select!` on this
    /// and the accept, and the loop falls out rather than being cancelled
    /// part way through handing off a connection.
    pub(crate) async fn wait_until_closed(&self) {
        let mut rx = self.status.subscribe();
        if *rx.borrow_and_update() == PipeStatus::Closed {
            return;
        }
        let _ = rx.wait_for(|s| *s == PipeStatus::Closed).await;
    }

    /// Signal that teardown has finished and every resource is released.
    pub(crate) fn mark_torn_down(&self) {
        self.torn_down.send_replace(true);
    }

    /// Wait until teardown has actually completed.
    ///
    /// **Not the same as observing [`PipeStatus::Closed`]**, and conflating
    /// the two is a bug with a specific symptom. Dropping a handle tears
    /// down *without waiting*, so `Closed` is published while the socket is
    /// still held; a `shutdown` that resolved on seeing `Closed` would
    /// return to a caller who immediately rebinds the same port and gets
    /// `EADDRINUSE`. Status answers "is the pipe over"; this answers "is
    /// the port free".
    pub(crate) async fn wait_until_torn_down(&self) {
        let mut rx = self.torn_down.subscribe();
        // The initial value counts: teardown may already have finished, and
        // a caller arriving late must not wait for an event that has been
        // and gone.
        if *rx.borrow_and_update() {
            return;
        }
        // `Err` means the sender is gone, which can only happen once the
        // pipe has been dropped entirely — by which point teardown is as
        // complete as it will ever be.
        let _ = rx.wait_for(|done| *done).await;
    }
}

/// The status a listener reports for a set of connected peers.
///
/// **The worst active path.** `Relayed` if any peer is relayed, `Direct`
/// only when all of them are, `Idle` when none is connected. Reporting the
/// best path instead would hide exactly what `Relayed` exists to explain —
/// the owner of the one slow device would have no way to find out why —
/// and the cost is stated plainly in [`PipeStatus`]: with a mixed set this
/// value describes no single peer.
pub(crate) fn aggregate(peers: &[PeerPath]) -> PipeStatus {
    if peers.is_empty() {
        PipeStatus::Idle
    } else if peers.contains(&PeerPath::Relayed) {
        PipeStatus::Relayed
    } else {
        PipeStatus::Direct
    }
}

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod lifecycle_tests;
