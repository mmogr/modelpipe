//! Reaching the serve side again, and again, for as long as the pipe is up.
//!
//! Split from [`crate::peer`], which owns *the connection there is*: this
//! owns the loop that notices there is none and goes looking. One function
//! and the two constants it paces itself by — kept apart because `peer.rs`
//! is at its size budget, and because the two answer different questions.

use std::time::Duration;

use tokio::time::Instant;

use crate::lifecycle::{Lifecycle, aggregate};
use crate::path_watch;
use crate::peer::Peer;
use crate::status::PipeStatus;

/// How long to wait before the first re-dial, and the ceiling it doubles
/// to.
///
/// The first attempt after a death is immediate — a laptop waking up wants
/// its pipe back now, not in half a second — and only a *failed* dial
/// starts the backoff. The ceiling matters more than the floor: a serve
/// side that is off for the night must not be dialled thousands of times,
/// and thirty seconds is short enough that coming back is noticed promptly
/// and long enough to be nobody's idea of a busy loop.
const FIRST_RETRY: Duration = Duration::from_millis(500);
const RETRY_CEILING: Duration = Duration::from_secs(30);

/// Reach the peer, and keep a connection to it for as long as the pipe is
/// up.
///
/// **Every dial is this loop's, the first one included.** That is what lets
/// [`connect`](fn@crate::connect) return once the local port is bound:
/// [`Peer::bind`] opens an endpoint and reaches nobody, and the pipe starts
/// life here, at `Idle`, with a listener already answering.
///
/// It is also what makes `ConnectHandle`'s documented behaviour true rather
/// than merely stated. Before it, the connect side opened exactly one
/// connection and held it for life, so a peer that went away left it 502ing
/// for ever while its status still read `direct` — measured twenty minutes
/// after the serve side was killed.
///
/// `Idle` is published while there is no connection, and it is the only
/// thing a caller is owed about a dial that has not landed. It is not a
/// failure and not a timeout: a sleeping laptop, a dead one and a serve
/// side five seconds from starting look identical from here, so this side
/// reports what it sees and leaves the policy to whoever watches the status.
///
/// The cadence below is not the whole cadence. A dial at a peer that is
/// simply gone takes iroh about thirty seconds to give up on, so the
/// backoff is added to that rather than being the interval between
/// attempts. It is set for the case where dialling *fails fast*, and the
/// ceiling is what keeps a peer off for the night from being dialled
/// thousands of times either way.
pub(crate) async fn keep_connected(peer: &Peer, lifecycle: &Lifecycle, nudge: Option<Duration>) {
    let mut backoff = FIRST_RETRY;
    let mut nudge = Nudge::every(nudge, Instant::now());
    // One line per episode of having nobody, not one per attempt. The first
    // dial's failure is why a freshly returned handle reads `Idle`, and
    // without saying so nothing at default verbosity does — but a serve
    // side off for the night must not narrate every retry until morning.
    let mut announced = false;
    loop {
        // Wait out the connection there is, if there is one — following
        // where it goes while we wait. The third arm is what makes the
        // status track a connection that hole-punches after establishing,
        // or falls back after hole-punching; it only ever completes for the
        // reasons the two above it do, and they win the tie.
        if let Some(live) = peer.current() {
            tokio::select! {
                biased;
                () = lifecycle.wait_until_closed() => return,
                _ = live.closed() => {}
                () = path_watch::follow(&live, lifecycle, |reading| {
                    lifecycle.set_status(aggregate(&[reading.path]));
                }) => {}
            }
            peer.forget(&live);
            lifecycle.set_status(PipeStatus::Idle);
            // The state change, said once. Every request from here until a
            // re-dial succeeds is answered 502 by `dialer::carry`, and this
            // is the line that explains all of them — which is why it is
            // `info` while the individual attempts below are not.
            tracing::info!("the peer went away, and this side is looking for it");
            announced = true;
            backoff = FIRST_RETRY;
        }

        // And go looking for it.
        let dialed = tokio::select! {
            biased;
            () = lifecycle.wait_until_closed() => return,
            dialed = peer.redial() => dialed,
        };
        if let Some(reading) = dialed {
            let status = aggregate(&[reading.path]);
            lifecycle.set_status(status);
            tracing::info!(path = status.as_str(), "the peer is back");
            announced = false;
            continue;
        }
        if !announced {
            announced = true;
            tracing::info!("the serve side did not answer, and this side is looking for it");
        }
        // `debug`, not `info`: a serve side that is off for the night is
        // dialled until morning, and the fact worth an operator's attention
        // is the line above rather than every attempt under it.
        tracing::debug!(
            backoff_ms = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX),
            "a dial found nobody"
        );
        tokio::select! {
            biased;
            () = lifecycle.wait_until_closed() => return,
            () = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(RETRY_CEILING);
        // After the sleep rather than before the dial, so the very first
        // attempt — the one a freshly bound handle makes — is never
        // delayed by it. Only ever reached while there is no connection.
        if nudge.due(Instant::now()) {
            tracing::debug!("telling the endpoint the network may have changed");
            // Raced against the close like every other await in this loop:
            // iroh's rebind is not instant, and a shutdown arriving during
            // one would otherwise go unobserved until it returned.
            tokio::select! {
                biased;
                () = lifecycle.wait_until_closed() => return,
                () = crate::network::notify(&peer.endpoint) => {}
            }
        }
    }
}

/// When the endpoint is next due to be told the network may have changed.
///
/// Its own value rather than two locals in the loop, because it is the
/// only *policy* here and a policy nothing can exercise is a comment with
/// a timer attached. Nothing in it touches an endpoint, so its whole
/// behaviour — including the two ends of the range a caller may set — is
/// checkable without binding one.
struct Nudge {
    every: Option<Duration>,
    due: Option<Instant>,
}

impl Nudge {
    /// Due one interval after `now`, or never when there is no interval.
    ///
    /// `now` is an argument rather than a clock read, so the whole of this
    /// is deterministic in a test.
    ///
    /// **`checked_add`, because the interval is a caller's.**
    /// [`ConnectOptions::idle_network_nudge`](crate::ConnectOptions#structfield.idle_network_nudge)
    /// is a public field of arbitrary `Duration`, and `Instant + Duration`
    /// panics on overflow — so `Some(Duration::MAX)`, the obvious spelling
    /// of "effectively never", would have killed this task before its
    /// first dial, leaving a pipe that is `Idle` for ever with nothing
    /// dialling and no error anywhere. An interval that cannot be added is
    /// treated as the "never" it was reaching for.
    fn every(every: Option<Duration>, now: Instant) -> Self {
        Self {
            every,
            due: every.and_then(|every| now.checked_add(every)),
        }
    }

    /// Whether the endpoint is due to be told, re-arming if it is.
    ///
    /// Re-anchored on `now` rather than on the deadline it passed: this is
    /// polled once per re-dial round, and a round against a peer that is
    /// simply gone takes as long as iroh needs to give up. Anchoring on
    /// the deadline would try to catch up on rounds that never had a
    /// chance to happen.
    fn due(&mut self, now: Instant) -> bool {
        let Some(due) = self.due else {
            return false;
        };
        if now < due {
            return false;
        }
        self.due = self.every.and_then(|every| now.checked_add(every));
        true
    }
}

#[cfg(test)]
#[path = "peer_redial_tests.rs"]
mod peer_redial_tests;
