//! Tests for [`super`] — waiting for a serve side that may never answer.
//!
//! Split out via `#[path]` so `park.rs` stays inside the file-size budget,
//! the same way every other module in the workspace does it.
//!
//! Driven through [`AsyncStatus`] rather than a real handle, which is the
//! reason that trait is a trait: `connect` no longer fails on an absent
//! peer, so the sentence the terminal gets for one is produced here — and
//! a test that had to bind two endpoints to check a `match` would be a
//! test nobody runs. The same trait is what lets [`park`] be driven at all:
//! no relay in CI will rate limit an endpoint on demand, so the readings
//! that produce a `relay:` line are scripted here rather than provoked.
use std::collections::VecDeque;

use super::*;

/// A status source under the test's control.
///
/// `later` is delivered one value per [`AsyncStatus::changed`], in order.
/// Once it runs out `changed` pends for ever, which is exactly what a
/// handle sitting at `Idle` behind a dial that will not land does.
///
/// The metrics move in step with it: `metrics` is what [`AsyncStatus::metrics`]
/// reports now, and `metrics_later` advances it once per `changed`, so a
/// script pairs each status the pipe reaches with the counters it had when
/// it got there.
struct Scripted {
    now: PipeStatus,
    later: VecDeque<PipeStatus>,
    metrics: NetworkMetrics,
    metrics_later: VecDeque<NetworkMetrics>,
}

impl Scripted {
    fn new(now: PipeStatus, later: &[PipeStatus]) -> Self {
        Self {
            now,
            later: later.iter().copied().collect(),
            metrics: NetworkMetrics::default(),
            metrics_later: VecDeque::new(),
        }
    }

    /// Pair the script with readings: `first` is what `current`'s reading
    /// sees, and `later` is one reading per `changed`, in the same order.
    fn reading(mut self, first: NetworkMetrics, later: &[NetworkMetrics]) -> Self {
        self.metrics = first;
        self.metrics_later = later.iter().copied().collect();
        self
    }
}

impl AsyncStatus for Scripted {
    fn current(&self) -> PipeStatus {
        self.now
    }

    fn metrics(&self) -> NetworkMetrics {
        self.metrics
    }

    async fn changed(&mut self) -> PipeStatus {
        match self.later.pop_front() {
            Some(next) => {
                self.now = next;
                if let Some(reading) = self.metrics_later.pop_front() {
                    self.metrics = reading;
                }
                next
            }
            None => std::future::pending().await,
        }
    }
}

/// A reading in which `throttled` of `total` relay connections were rate
/// limited.
///
/// Built by mutation because `NetworkMetrics` is `#[non_exhaustive]` and a
/// struct literal therefore cannot cross the crate boundary — the same
/// reason `main.rs` builds its options structs this way.
fn reading(total: u64, throttled: u64) -> NetworkMetrics {
    let mut metrics = NetworkMetrics::default();
    metrics.relay_connections = total;
    metrics.relay_connections_ratelimited = throttled;
    metrics
}

/// A signal listener for tests that never send one.
///
/// [`park`] takes one because the real command does. Every script below
/// ends in `Closed`, which is the loop's other way out.
fn quiet() -> Interrupt {
    Interrupt::new().expect("a signal listener")
}

/// Run [`park`] over a script and return everything it printed.
///
/// `&mut status`, not `status`, so this drives the impl `main.rs` drives.
/// Both call sites there are `park(&mut handle, …)`, which reaches every
/// method through `impl<T: AsyncStatus> AsyncStatus for &mut T`; taking
/// `Scripted` by value left that blanket impl with no coverage at all, and
/// replacing its `metrics` body with `NetworkMetrics::default()` — which
/// makes this whole feature print nothing in production — kept all 419
/// tests green.
async fn parked(mut status: Scripted) -> String {
    let mut out = Vec::new();
    park(&mut status, &mut quiet(), &mut out)
        .await
        .expect("a script that closes must end the park cleanly");
    String::from_utf8(out).expect("the CLI writes text")
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

/// A pipe no relay has ever throttled — which is nearly every pipe — must
/// read exactly as it read before the `relay:` line existed.
///
/// This is the `token_line`/`qr` rule applied here: output that would be
/// noise is an absent line, not a line of zeroes.
#[test]
fn a_relay_that_is_not_throttling_says_nothing() {
    assert_eq!(throttle_line(0, NetworkMetrics::default()), None);
    // And not merely because every number is zero: an endpoint that made
    // four relay connections and had none of them throttled is the
    // ordinary healthy case, and it is also silent.
    assert_eq!(throttle_line(0, reading(4, 0)), None);
}

/// The count is printed with its denominator, because the field's own docs
/// say the useful reading is the proportion — two of five connections
/// throttled is a different situation from two of two hundred.
#[test]
fn the_first_throttled_connection_is_reported_with_its_denominator() {
    assert_eq!(
        throttle_line(0, reading(5, 2)).expect("a throttled connection is news"),
        "relay:  rate limiting this endpoint — 2 of 5 relay connections throttled"
    );
}

/// The counter is a monotonic total for the life of one endpoint, not a
/// flag saying "throttled right now". A line printed on every reading
/// would announce one old event for the rest of the session.
#[test]
fn a_count_that_has_not_moved_is_not_said_twice() {
    assert_eq!(throttle_line(2, reading(5, 2)), None);
    // The negative control for it: a reading below the mark is not news
    // either, and must not underflow on the way to saying so.
    assert_eq!(throttle_line(2, reading(5, 1)), None);
}

/// The other half of the same rule — the counter moving again is a new
/// connection the relay throttled, and that is worth a second line.
#[test]
fn a_further_throttled_connection_is_news_again() {
    assert_eq!(
        throttle_line(2, reading(6, 3)).expect("a third throttled connection is news"),
        "relay:  rate limiting this endpoint — 3 of 6 relay connections throttled"
    );
}

/// `ticket: `, `token:  ` and `status: ` all put their value in the same
/// column, and these lines are read off one screen together. A single
/// space after `relay:` would silently break the alignment.
#[test]
fn the_relay_line_aligns_with_the_status_line() {
    let relay = throttle_line(0, reading(1, 1)).expect("a throttled connection is news");
    let status = "status: relayed";
    assert_eq!(
        relay.find("rate"),
        status.find("relayed"),
        "the value columns must agree: {relay:?} vs {status:?}"
    );
}

/// The baseline for everything below: every status the pipe reaches gets a
/// line, in order, starting with the one it was already at — and a pipe
/// with clean counters says nothing else at all.
#[tokio::test]
async fn every_status_the_pipe_reaches_is_printed_and_a_clean_relay_adds_nothing() {
    let printed = parked(Scripted::new(
        PipeStatus::Idle,
        &[PipeStatus::Relayed, PipeStatus::Closed],
    ))
    .await;

    assert_eq!(printed, "status: idle\nstatus: relayed\nstatus: closed\n");
}

/// The line this change exists for, and the case it exists for: the pipe
/// is `relayed`, the peer is present, nothing is failing, and the relay is
/// holding the endpoint back. The correction has to land *under* the
/// status line it contradicts, or that line stands alone and says the pipe
/// is fine.
///
/// The same assertion pins the counter's monotonicity end to end: the
/// reading is unchanged when the pipe closes, and no second line appears.
#[tokio::test]
async fn the_relay_throttling_is_printed_under_the_status_it_contradicts_and_only_once() {
    let printed = parked(
        Scripted::new(PipeStatus::Idle, &[PipeStatus::Relayed, PipeStatus::Closed])
            .reading(reading(0, 0), &[reading(3, 1), reading(3, 1)]),
    )
    .await;

    assert_eq!(
        printed,
        "status: idle\n\
         status: relayed\n\
         relay:  rate limiting this endpoint — 1 of 3 relay connections throttled\n\
         status: closed\n"
    );
}

/// The serve side reaches its relay during `wait_online`, before `park` is
/// ever called, so a throttled endpoint has a non-zero counter at the
/// first reading. That reading is taken from the current status rather
/// than waited for, exactly as the status itself is.
///
/// A later throttled connection is news again, which is what makes the
/// printed number a running total and the decision to print it a delta.
#[tokio::test]
async fn throttling_that_predates_the_park_is_reported_and_so_is_the_next_one() {
    let printed = parked(
        Scripted::new(
            PipeStatus::Relayed,
            &[PipeStatus::Direct, PipeStatus::Closed],
        )
        .reading(reading(3, 1), &[reading(4, 2), reading(4, 2)]),
    )
    .await;

    assert_eq!(
        printed,
        "status: relayed\n\
         relay:  rate limiting this endpoint — 1 of 3 relay connections throttled\n\
         status: direct\n\
         relay:  rate limiting this endpoint — 2 of 4 relay connections throttled\n\
         status: closed\n"
    );
}
