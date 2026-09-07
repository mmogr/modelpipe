//! Waiting on a live pipe, and letting go of it.
//!
//! Split from `main.rs` when the file-size gate said it was holding two
//! things: parsing what the operator typed, and then sitting on the result
//! until they ask for it back. This is the second. `interrupt.rs` beside it
//! owns hearing the ask; this owns what happens either side of it.
//!
//! Both halves of the CLI end up here, which is why the trait exists at
//! all — the two handles deliberately share none, and inventing a public
//! one in the library to save a few lines in a CLI would put it on a
//! surface that has to live with it.

use std::future::Future;
use std::io::Write;
use std::time::Duration;

use modelpipe::{NetworkMetrics, PipeStatus};

use crate::interrupt::Interrupt;

/// How long a fresh connect side may sit at `Idle` before this command
/// gives up on the serve side.
///
/// Not a library default, and deliberately not one. `connect` returns as
/// soon as the local port is bound and then keeps trying for as long as the
/// handle lives, because a sleeping laptop, a dead one and a serve side
/// five seconds from starting look identical from down there — so the
/// deadline belongs to whoever is willing to give up, which for an
/// interactive command is this one.
///
/// Longer than the thirty-odd seconds iroh spends giving up on a peer that
/// is not there. Under that, this would report an absent peer while the
/// first dial was still in flight, which is a worse answer than the slow
/// one it replaced.
pub(crate) const FIRST_CONTACT: Duration = Duration::from_secs(40);

/// Park until a shutdown signal, reporting the transport path and every
/// change to it.
///
/// `Relayed` is worth surfacing: it explains latency, and a user who does
/// not know their traffic is going through a relay has no way to guess why
/// the pipe feels slow. `Idle` on the connect side is worth more — it is
/// the only thing that says the far end has gone away and this side is
/// looking for it.
///
/// The starting value is printed rather than waited for, which is not
/// belt-and-braces. `status_changed` compares against the status at the
/// moment it is called, so a pipe that reached `Direct` before this
/// function was first polled has nothing left to report — and that race is
/// real: the connect side publishes its path before the first accept, and
/// its `status:` line appeared in two runs out of three.
///
/// `out` is `std::io::stderr()` in `main.rs` and a buffer in the tests,
/// which is the whole reason it is a parameter: these lines are the CLI's
/// only output while a pipe is live, and a macro that writes straight to
/// the process's stderr cannot be asserted on. Everything the tests below
/// pin — that a status is printed, that the relay's throttling is printed
/// *under* it, and that it is printed once — was unreachable before.
pub(crate) async fn park(
    mut status: impl AsyncStatus,
    interrupt: &mut Interrupt,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    // What the last `relay:` line already said. A counter that only climbs
    // needs a low-water mark, or one old event is re-announced for ever.
    let mut reported = 0;
    report(out, status.current(), status.metrics(), &mut reported);
    loop {
        // Bound out of the `select!` rather than reported inside an arm:
        // `status.changed()` borrows `status` for as long as that arm is
        // alive, and the reading on the next line needs it back.
        let next = tokio::select! {
            r = interrupt.next() => {
                r?;
                return Ok(());
            }
            next = status.changed() => next,
        };
        report(out, next, status.metrics(), &mut reported);
        if next == PipeStatus::Closed {
            return Ok(());
        }
    }
}

/// Print one reading of the pipe: what it is doing, and — when there is
/// news of it — what the relay is doing to it.
///
/// The two go out together, in that order, because the throttling is a
/// correction to the line above it. A rate-limited pipe reads `relayed`
/// with a peer present and nothing failing, which is indistinguishable
/// from a healthy relayed pipe; printing the correction anywhere else
/// would leave the misleading line standing on its own.
///
/// A write error is dropped rather than propagated. This is progress
/// commentary on stderr, and a terminal that has gone away is no reason to
/// tear down a pipe that is still carrying requests — which is more than
/// the `eprintln!` this replaced offered, since that panicked.
fn report(out: &mut impl Write, status: PipeStatus, metrics: NetworkMetrics, reported: &mut u64) {
    let _ = writeln!(out, "status: {}", status.as_str());
    if let Some(line) = throttle_line(*reported, metrics) {
        *reported = metrics.relay_connections_ratelimited;
        let _ = writeln!(out, "{line}");
    }
}

/// The `relay:` line a reading earns, or `None` when it says nothing new.
///
/// **Nothing at zero**, which is the shape `main.rs` already uses for
/// output that would otherwise be noise: `token_line` and `qr` both hand
/// back an `Option<String>` and the caller prints what is there. A pipe no
/// relay has ever throttled — nearly every pipe — must read exactly as it
/// read before this line existed.
///
/// **Nothing twice.** `relay_connections_ratelimited` is a monotonic total
/// for the life of one endpoint rather than a flag saying "throttled right
/// now", so a line emitted on every reading would keep announcing one old
/// event for the rest of the session. `reported` is what has already been
/// said, and only a count above it is news — which makes the printed
/// number a running total and the decision to print it a delta. Both
/// halves are wanted: the total is the thing that relates to
/// `relay_connections`, and the delta is what stops the line repeating.
///
/// The value column is the one `ticket:`, `token:` and `status:` use, so
/// all four line up when they reach the same terminal.
fn throttle_line(reported: u64, metrics: NetworkMetrics) -> Option<String> {
    let throttled = metrics.relay_connections_ratelimited;
    if throttled <= reported {
        return None;
    }
    Some(format!(
        "relay:  rate limiting this endpoint — {throttled} of {} relay connections throttled",
        metrics.relay_connections
    ))
}

/// Wait for the pipe to reach the serve side, or say that it could not.
///
/// This is the sentence `connect` used to produce. It blocked until the
/// first dial landed and reported an absent peer through its `Result`;
/// it now returns with the local port bound and the dial still running, so
/// the wait — and the deadline it needs — moved out here rather than
/// disappearing. The wording is the one `ConnectError::PeerUnreachable`
/// printed, because it is the same fact reported from one step further out.
///
/// Nothing is printed on the way to stdout until this returns `Ok`, which
/// is the other half of not regressing: a script capturing the URL gets one
/// only for a pipe that actually reached its peer, exactly as before.
///
/// `grace` is [`FIRST_CONTACT`] everywhere but the tests, which pass a
/// short one so that checking the decision does not mean waiting out the
/// number.
pub(crate) async fn first_contact(
    mut status: impl AsyncStatus,
    grace: Duration,
) -> anyhow::Result<()> {
    let reached = tokio::time::timeout(grace, async {
        // The current value first. `changed` snapshots at the moment it is
        // polled, so a pipe that connected before this ran has nothing left
        // to report and waiting alone would sit here until the deadline.
        let mut now = status.current();
        while now == PipeStatus::Idle {
            now = status.changed().await;
        }
        now
    })
    .await;
    match reached {
        // A pipe that closed without ever connecting is the same news, and
        // there is nothing left to wait for either way.
        Ok(PipeStatus::Closed) | Err(_) => {
            anyhow::bail!("could not reach the serve side, directly or via a relay")
        }
        Ok(_) => Ok(()),
    }
}

/// Shut down gracefully, unless the operator asks again.
///
/// The graceful path can legitimately take a while — it is waiting for
/// admitted requests to finish, which is the whole promise — so a second
/// signal has to be able to stop waiting. Dropping the handle is the cut,
/// and returning from here does exactly that.
pub(crate) async fn shut_down(handle: impl Future<Output = ()>, interrupt: &mut Interrupt) {
    tokio::select! {
        () = handle => {}
        _ = interrupt.next() => {
            eprintln!("interrupted again — cutting rather than waiting");
        }
    }
}

/// What this module needs from either handle.
///
/// A trait here rather than in the library: the two handles deliberately
/// share none, and inventing a public one to save a few lines in a CLI
/// would put it on a surface that has to live with it.
///
/// `metrics` is named for the reading and not for the call behind it. The
/// handles' own method is `network_metrics`, and a trait method sharing
/// that name would be shadowed by the inherent one at every call site
/// here — including inside the impls below, where `self.network_metrics()`
/// would resolve to the inherent method today and to unbounded recursion
/// the day it stopped being inherent. The tests drive a fake, so nothing
/// in the suite would ever see it.
pub(crate) trait AsyncStatus {
    fn current(&self) -> PipeStatus;
    /// The transport counters behind the status, read at the same moments.
    /// A monotonic total needs two readings to mean anything, and the
    /// status line is the only regular tick this command has.
    fn metrics(&self) -> NetworkMetrics;
    fn changed(&mut self) -> impl Future<Output = PipeStatus>;
}

impl AsyncStatus for modelpipe::ServeHandle {
    fn current(&self) -> PipeStatus {
        self.status()
    }

    fn metrics(&self) -> NetworkMetrics {
        self.network_metrics()
    }

    async fn changed(&mut self) -> PipeStatus {
        self.status_changed().await
    }
}

impl AsyncStatus for modelpipe::ConnectHandle {
    fn current(&self) -> PipeStatus {
        self.status()
    }

    fn metrics(&self) -> NetworkMetrics {
        self.network_metrics()
    }

    async fn changed(&mut self) -> PipeStatus {
        self.status_changed().await
    }
}

impl<T: AsyncStatus> AsyncStatus for &mut T {
    fn current(&self) -> PipeStatus {
        (**self).current()
    }

    fn metrics(&self) -> NetworkMetrics {
        (**self).metrics()
    }

    async fn changed(&mut self) -> PipeStatus {
        (**self).changed().await
    }
}

#[cfg(test)]
#[path = "park_tests.rs"]
mod park_tests;
