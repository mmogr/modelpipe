//! Tests for [`super`] — waiting for a serve side that may never answer.
//!
//! Split out via `#[path]` so `park.rs` stays inside the file-size budget,
//! the same way every other module in the workspace does it.
//!
//! Driven through [`AsyncStatus`] rather than a real handle, which is the
//! reason that trait is a trait: `connect` no longer fails on an absent
//! peer, so the sentence the terminal gets for one is produced here — and
//! a test that had to bind two endpoints to check a `match` would be a
//! test nobody runs.
use std::collections::VecDeque;

use super::*;

/// A status source under the test's control.
///
/// `later` is delivered one value per [`AsyncStatus::changed`], in order.
/// Once it runs out `changed` pends for ever, which is exactly what a
/// handle sitting at `Idle` behind a dial that will not land does.
struct Scripted {
    now: PipeStatus,
    later: VecDeque<PipeStatus>,
}

impl Scripted {
    fn new(now: PipeStatus, later: &[PipeStatus]) -> Self {
        Self {
            now,
            later: later.iter().copied().collect(),
        }
    }
}

impl AsyncStatus for Scripted {
    fn current(&self) -> PipeStatus {
        self.now
    }

    async fn changed(&mut self) -> PipeStatus {
        match self.later.pop_front() {
            Some(next) => {
                self.now = next;
                next
            }
            None => std::future::pending().await,
        }
    }
}

/// Short enough that the pending case is a test rather than a coffee break.
/// The real value is `FIRST_CONTACT`, and what is under test is the
/// decision, not the number.
const BRIEFLY: Duration = Duration::from_millis(50);

/// A pipe that connected before anyone asked has nothing left to report,
/// and waiting alone would sit here until the deadline. This is the case
/// that made the current value worth reading first.
#[tokio::test]
async fn a_pipe_that_is_already_carrying_is_not_waited_for() {
    let status = Scripted::new(PipeStatus::Direct, &[]);

    first_contact(status, BRIEFLY)
        .await
        .expect("a connected pipe must not be reported as unreachable");
}

/// The ordinary case: the port is bound, the dial lands a moment later.
#[tokio::test]
async fn a_pairing_that_forms_a_moment_later_is_waited_for() {
    let status = Scripted::new(PipeStatus::Idle, &[PipeStatus::Relayed]);

    first_contact(status, BRIEFLY)
        .await
        .expect("a pipe that connects while waiting has reached its peer");
}

/// The case this function exists for, and the one `connect`'s `Result` used
/// to cover: nobody answers, and the terminal is told so rather than left
/// at a silent prompt for ever.
#[tokio::test]
async fn a_serve_side_that_never_answers_is_reported_rather_than_waited_on_for_ever() {
    let status = Scripted::new(PipeStatus::Idle, &[]);

    let e = first_contact(status, BRIEFLY)
        .await
        .expect_err("an absent peer must not be reported as reachable");

    // The wording `ConnectError::PeerUnreachable` printed. It moved out of
    // the library, and a user who greps their notes for it must still find
    // it on their screen.
    assert_eq!(
        e.to_string(),
        "could not reach the serve side, directly or via a relay"
    );
}

/// A pipe that closed before it ever connected is the same news to the
/// operator, and there is nothing left to wait for — so it must not sit out
/// the whole deadline first.
#[tokio::test]
async fn a_pipe_that_closes_before_it_connects_is_reported_at_once() {
    let status = Scripted::new(PipeStatus::Idle, &[PipeStatus::Closed]);

    let started = std::time::Instant::now();
    let e = first_contact(status, BRIEFLY)
        .await
        .expect_err("a closed pipe never reached anyone");

    assert!(
        started.elapsed() < BRIEFLY,
        "a terminal state must end the wait rather than run it out"
    );
    assert_eq!(
        e.to_string(),
        "could not reach the serve side, directly or via a relay"
    );
}
