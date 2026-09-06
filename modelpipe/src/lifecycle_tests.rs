//! Tests for [`super`] — status publication and teardown.
//!
//! Split out via `#[path]` so `lifecycle.rs` stays inside the file-size
//! budget.
//!
//! Every await here is wrapped in a timeout. The contract these tests are
//! checking is largely about *not blocking*, and a test for that which can
//! itself block would hang the suite instead of failing it.

use std::future::Future;
use std::time::Duration;

use super::*;

/// Resolve `future`, or fail with `why` rather than hanging the suite.
async fn within<F: Future>(why: &str, future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .unwrap_or_else(|_| panic!("{why}"))
}

// ── Status ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_pipe_starts_idle_and_publishes_what_it_is_told() {
    let life = Lifecycle::new();
    assert_eq!(life.status(), PipeStatus::Idle);

    life.set_status(PipeStatus::Direct);
    assert_eq!(life.status(), PipeStatus::Direct);
    life.set_status(PipeStatus::Relayed);
    assert_eq!(life.status(), PipeStatus::Relayed);
}

/// Snapshot semantics: a caller whose snapshot is already stale is told so
/// at once rather than waiting for a further change that may never come.
#[tokio::test]
async fn a_watcher_holding_a_stale_snapshot_returns_immediately() {
    let life = Lifecycle::new();
    life.set_status(PipeStatus::Direct);

    let seen = within(
        "a stale snapshot must resolve without waiting",
        life.changed_since(PipeStatus::Idle),
    )
    .await;
    assert_eq!(seen, Some(PipeStatus::Direct));
}

#[tokio::test]
async fn a_watcher_holding_a_current_snapshot_waits_for_the_next_change() {
    let life = std::sync::Arc::new(Lifecycle::new());
    let watcher = {
        let life = life.clone();
        tokio::spawn(async move { life.changed_since(PipeStatus::Idle).await })
    };

    // Give the watcher a moment to park, then move the status.
    tokio::task::yield_now().await;
    life.set_status(PipeStatus::Relayed);

    let seen = within("the watcher must wake", watcher).await.unwrap();
    assert_eq!(seen, Some(PipeStatus::Relayed));
}

/// Several callers may watch one pipe — a daemon and a status line, say —
/// each against its own snapshot.
#[tokio::test]
async fn concurrent_watchers_each_resolve_against_their_own_snapshot() {
    let life = std::sync::Arc::new(Lifecycle::new());
    life.set_status(PipeStatus::Direct);

    let from_idle = {
        let life = life.clone();
        tokio::spawn(async move { life.changed_since(PipeStatus::Idle).await })
    };
    let from_direct = {
        let life = life.clone();
        tokio::spawn(async move { life.changed_since(PipeStatus::Direct).await })
    };

    tokio::task::yield_now().await;
    life.set_status(PipeStatus::Relayed);

    assert_eq!(
        within("stale snapshot", from_idle).await.unwrap(),
        Some(PipeStatus::Direct),
        "the stale watcher gets the value it had not seen"
    );
    assert_eq!(
        within("current snapshot", from_direct).await.unwrap(),
        Some(PipeStatus::Relayed),
        "the current watcher gets the new one"
    );
}

// ── Closed is terminal ───────────────────────────────────────────────────

/// The clause a bare `Receiver::changed()` cannot honour: a watcher that
/// arrives *after* the pipe has closed has no further change to wait for,
/// and must be told the pipe is gone rather than blocking forever.
#[tokio::test]
async fn a_watcher_arriving_after_close_resolves_immediately_rather_than_hanging() {
    let life = Lifecycle::new();
    life.close(CloseReason::Shutdown);

    for snapshot in [PipeStatus::Idle, PipeStatus::Direct, PipeStatus::Relayed] {
        let seen = within(
            "a closed pipe must never block a watcher",
            life.changed_since(snapshot),
        )
        .await;
        assert_eq!(seen, Some(PipeStatus::Closed), "from snapshot {snapshot:?}");
    }
}

/// And the clause that stops the same watcher spinning once it has been
/// told. `Closed` is terminal, so a caller whose snapshot already *is*
/// `Closed` has nothing left to be told; answering `Closed` again — at
/// once, forever, with no await anywhere in the path — makes the obvious
/// loop over this method a busy loop on one core, which is exactly the
/// shape a generated language binding writes.
///
/// The two halves are one contract: every other snapshot is delivered
/// `Closed` exactly once, and then the sequence ends.
#[tokio::test]
async fn a_watcher_that_already_holds_closed_is_told_there_is_nothing_further() {
    let life = Lifecycle::new();
    life.close(CloseReason::Shutdown);

    let first = within(
        "the close must still be delivered once",
        life.changed_since(PipeStatus::Idle),
    )
    .await;
    assert_eq!(first, Some(PipeStatus::Closed));

    let again = within(
        "and a closed pipe must never block a watcher, however it is asked",
        life.changed_since(PipeStatus::Closed),
    )
    .await;
    assert_eq!(
        again, None,
        "the second ask has to end the sequence rather than repeat it"
    );
}

/// The loop the contract is written for, run to completion. A caller that
/// carries the value it was last given ends up here, and this asserts the
/// loop *arrives* at an end.
///
/// **Bounded rather than timed, and the bound is the assertion.** The
/// failure being guarded against is a method that answers `Closed` again
/// immediately — a loop with no await anywhere in it, which starves the
/// runtime it is on. A timeout cannot fire inside one, so a timed version
/// of this test hangs the suite instead of failing it; counting the turns
/// is what turns the same defect into a message.
#[tokio::test]
async fn a_loop_carrying_the_last_value_forward_terminates_at_the_close() {
    // Three transitions happen below; a watcher arriving after them is owed
    // one value and an end. Ten is far past any honest reading of that.
    // Declared first because an item after a statement is a clippy error.
    const CEILING: usize = 10;

    let life = Lifecycle::new();
    life.set_status(PipeStatus::Relayed);
    life.set_status(PipeStatus::Direct);
    life.close(CloseReason::Shutdown);

    let mut held = PipeStatus::Idle;
    let mut seen = vec![held];
    while let Some(next) = life.changed_since(held).await {
        seen.push(next);
        held = next;
        assert!(
            seen.len() <= CEILING,
            "the sequence has to end rather than repeat: {seen:?}"
        );
    }

    // The intermediate states are coalesced away — nobody was waiting for
    // them — and the terminal one arrives exactly once.
    assert_eq!(seen, [PipeStatus::Idle, PipeStatus::Closed]);
}

#[tokio::test]
async fn a_parked_watcher_is_woken_by_the_close() {
    let life = std::sync::Arc::new(Lifecycle::new());
    let watcher = {
        let life = life.clone();
        tokio::spawn(async move { life.changed_since(PipeStatus::Idle).await })
    };
    tokio::task::yield_now().await;
    life.close(CloseReason::Shutdown);

    assert_eq!(
        within("close must wake a parked watcher", watcher)
            .await
            .unwrap(),
        Some(PipeStatus::Closed)
    );
}

/// Terminal means terminal. A task that has not noticed teardown must not
/// be able to resurrect the pipe by publishing a stale status.
#[tokio::test]
async fn nothing_moves_a_pipe_out_of_closed() {
    let life = Lifecycle::new();
    life.close(CloseReason::Shutdown);
    for late in [PipeStatus::Idle, PipeStatus::Direct, PipeStatus::Relayed] {
        life.set_status(late);
        assert_eq!(life.status(), PipeStatus::Closed, "after a late {late:?}");
    }
}

#[tokio::test]
async fn closing_twice_is_harmless() {
    let life = Lifecycle::new();
    life.close(CloseReason::Shutdown);
    life.close(CloseReason::Shutdown);
    assert_eq!(life.status(), PipeStatus::Closed);
}

// ── Why it closed ────────────────────────────────────────────────────────

/// `None` is what "still live" looks like, and it is the half of the
/// contract a caller reads most: an idle pipe that has not closed is one
/// still looking for its peer, not one that failed.
#[tokio::test]
async fn a_live_pipe_has_no_close_reason_however_idle_it_looks() {
    let life = Lifecycle::new();
    assert_eq!(life.status(), PipeStatus::Idle);

    assert_eq!(life.close_reason(), None);
}

#[tokio::test]
async fn closing_records_why() {
    for reason in [CloseReason::Shutdown, CloseReason::ListenerFailed] {
        let life = Lifecycle::new();
        life.close(reason);
        assert_eq!(life.close_reason(), Some(reason));
    }
}

/// First reason in keeps, and this is not tidiness: the accept loop closes
/// the pipe again on its way out, after whoever asked already said why, so
/// a last-writer-wins cell would report every cleanly shut-down connect
/// side as a listener that failed.
#[tokio::test]
async fn the_first_reason_recorded_is_the_one_that_keeps() {
    let life = Lifecycle::new();
    life.close(CloseReason::Shutdown);
    life.close(CloseReason::ListenerFailed);

    assert_eq!(life.close_reason(), Some(CloseReason::Shutdown));
}

/// The ordering with a symptom. A watcher woken by `Closed` reads the
/// reason on the next line, and would find `None` on a pipe that had one if
/// the status were published first.
#[tokio::test]
async fn a_watcher_woken_by_the_close_can_already_read_the_reason() {
    let life = std::sync::Arc::new(Lifecycle::new());
    let watcher = {
        let life = life.clone();
        tokio::spawn(async move {
            let status = life.changed_since(PipeStatus::Idle).await;
            (status, life.close_reason())
        })
    };
    tokio::task::yield_now().await;
    life.close(CloseReason::ListenerFailed);

    let (status, reason) = within("close must wake a parked watcher", watcher)
        .await
        .unwrap();
    assert_eq!(status, Some(PipeStatus::Closed));
    assert_eq!(
        reason,
        Some(CloseReason::ListenerFailed),
        "the reason must be readable by the time the status says to look"
    );
}

// ── Teardown ─────────────────────────────────────────────────────────────

/// The distinction with a symptom. Dropping a handle publishes `Closed`
/// without waiting, so a `shutdown` that resolved on seeing `Closed` would
/// return while the socket was still held — and the caller who immediately
/// rebinds the port gets `EADDRINUSE`.
#[tokio::test]
async fn closing_the_pipe_does_not_by_itself_mean_teardown_finished() {
    let life = std::sync::Arc::new(Lifecycle::new());
    life.close(CloseReason::Shutdown);
    assert_eq!(life.status(), PipeStatus::Closed);

    let waiter = {
        let life = life.clone();
        tokio::spawn(async move { life.wait_until_torn_down().await })
    };
    tokio::task::yield_now().await;
    assert!(
        !waiter.is_finished(),
        "a closed status must not be mistaken for released resources"
    );

    life.mark_torn_down();
    within("teardown must complete the wait", waiter)
        .await
        .unwrap();
}

/// Idempotent: every caller after teardown began awaits the same
/// completion, including ones that arrive long after it finished.
#[tokio::test]
async fn a_waiter_arriving_after_teardown_returns_immediately() {
    let life = Lifecycle::new();
    life.mark_torn_down();
    within(
        "an already-finished teardown must not be waited on",
        life.wait_until_torn_down(),
    )
    .await;
}

#[tokio::test]
async fn every_concurrent_waiter_is_released_by_one_teardown() {
    let life = std::sync::Arc::new(Lifecycle::new());
    let waiters: Vec<_> = (0..4)
        .map(|_| {
            let life = life.clone();
            tokio::spawn(async move { life.wait_until_torn_down().await })
        })
        .collect();

    tokio::task::yield_now().await;
    life.mark_torn_down();
    for waiter in waiters {
        within("all waiters must be released", waiter)
            .await
            .unwrap();
    }
}

// ── Aggregation ──────────────────────────────────────────────────────────

/// The worst active path. One relayed peer among many direct ones makes the
/// listener report `Relayed`, because that is the state worth explaining.
#[test]
fn a_listener_reports_the_worst_active_path() {
    use PeerPath::{Direct, Relayed};

    assert_eq!(aggregate(&[]), PipeStatus::Idle, "no peers");
    assert_eq!(aggregate(&[Direct]), PipeStatus::Direct);
    assert_eq!(aggregate(&[Direct, Direct]), PipeStatus::Direct);
    assert_eq!(aggregate(&[Relayed]), PipeStatus::Relayed);
    assert_eq!(
        aggregate(&[Direct, Relayed]),
        PipeStatus::Relayed,
        "one relayed peer is what the user needs told"
    );
    assert_eq!(
        aggregate(&[Relayed, Direct]),
        PipeStatus::Relayed,
        "and order does not matter"
    );
}

/// The README's own scenario — a phone and a laptop on one ticket — which
/// the `Idle` doc used to assume away by describing a single peer.
#[test]
fn the_phone_and_laptop_case_is_representable() {
    let phone_relayed_laptop_direct = [PeerPath::Relayed, PeerPath::Direct];
    assert_eq!(
        aggregate(&phone_relayed_laptop_direct),
        PipeStatus::Relayed,
        "the slow device is the one that needs explaining"
    );
}

// ── Draining ─────────────────────────────────────────────────────────────

/// The drain in "shutdown drains, Drop cuts": a request admitted before
/// teardown began runs to completion.
#[tokio::test]
async fn a_drain_waits_for_every_in_flight_exchange() {
    let life = std::sync::Arc::new(Lifecycle::new());
    let first = life.enter();
    let second = life.enter();
    assert_eq!(life.in_flight(), 2);

    let drain = {
        let life = life.clone();
        tokio::spawn(async move { life.wait_until_drained().await })
    };
    tokio::task::yield_now().await;
    assert!(!drain.is_finished(), "two exchanges are still running");

    drop(first);
    tokio::task::yield_now().await;
    assert!(!drain.is_finished(), "one still is");

    drop(second);
    within("the drain must complete", drain).await.unwrap();
}

#[tokio::test]
async fn a_drain_with_nothing_in_flight_returns_at_once() {
    let life = Lifecycle::new();
    assert_eq!(life.in_flight(), 0);
    within(
        "an idle pipe has nothing to drain",
        life.wait_until_drained(),
    )
    .await;
}

/// The decrement must survive a panic in the middle of an exchange. A
/// missed one makes `shutdown` wait forever for work that finished, which
/// presents as a hang in the caller's code.
#[tokio::test]
async fn a_panicking_exchange_still_releases_its_slot() {
    let life = std::sync::Arc::new(Lifecycle::new());
    let panicked = {
        let life = life.clone();
        tokio::spawn(async move {
            let _guard = life.enter();
            panic!("an exchange died mid-body");
        })
    };
    assert!(panicked.await.is_err(), "the task really did panic");
    assert_eq!(life.in_flight(), 0, "and its slot came back");
    within(
        "a drain must not hang on a dead exchange",
        life.wait_until_drained(),
    )
    .await;
}
