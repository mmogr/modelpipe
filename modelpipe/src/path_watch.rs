//! How a connection is routed, followed for as long as it lives.
//!
//! iroh establishes over a relay and hole-punches to a direct path a moment
//! later, so the path a connection has when it is accepted is routinely not
//! the path it spends its life on. Both sides used to read it exactly once,
//! at that moment, and never again: a session that upgraded reported
//! `relayed` until it ended, and one that degraded went on reporting
//! `direct`. That leaves the status unable to answer the only question it
//! exists for — *is hole punching working from here* — which is why this
//! module is a watcher and not a second copy of the reading.
//!
//! **A poll rather than iroh's event stream, and the choice was costed
//! rather than assumed.** [`Connection::path_events`] is the event-shaped
//! API and looks like the obvious pick, but iroh re-exports neither the
//! `Stream` trait nor `n0_future`, so calling `next` on it means taking a
//! direct dependency on one of `futures-core` / `futures-lite` /
//! `tokio-stream` / `n0-future` to keep a status line honest.
//! [`Connection::paths`] needs none of them, and is the call the single
//! reading already made. The second reason is what settles it: a
//! `PathEvent` carries no round-trip time, and the RTT is the half of a
//! reading that makes it a measurement rather than a label — so an
//! event-driven watcher would have had to poll for the number anyway, and
//! would have been both mechanisms instead of one.
//!
//! (Not `paths_stream` either, for a plainer reason: it borrows the
//! `Connection` and yields values iroh documents as unable to cross a task
//! boundary.)
//!
//! [`Connection::paths`]: iroh::endpoint::Connection::paths
//! [`Connection::path_events`]: iroh::endpoint::Connection::path_events

use std::time::Duration;

use iroh::TransportAddr;
use iroh::endpoint::{Connection, Path};

use crate::lifecycle::{Lifecycle, PeerPath, aggregate};

/// How often the selected path is read again.
///
/// A status line's resolution, not a measurement's. Nothing in this crate
/// decides anything on the value — it is printed by the CLI and rendered by
/// an embedder — so a change is worth knowing about within a second and is
/// not worth a wakeup more often than that. The cost of the read is one
/// mutex and a QUIC statistics copy per connection.
const CADENCE: Duration = Duration::from_secs(1);

/// How a connection is reaching the peer, and what that path costs.
///
/// Shared by both sides, which ask the identical question of the identical
/// type. The rule was written twice before it moved here, and two copies of
/// a rule about what counts as `Direct` is one copy too many for a value the
/// CLI prints and an embedder watches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Reading {
    /// Direct or relayed, by the rule in [`classify`].
    pub(crate) path: PeerPath,
    /// Round-trip time over the selected path, or `None` while there is no
    /// selected path to measure one over.
    ///
    /// QUIC's own smoothed estimate, so it moves a little between readings
    /// even on a path that has not changed. That is the point of carrying
    /// it: `relayed` says a connection went the long way round, and this
    /// says what the long way round cost.
    pub(crate) rtt: Option<Duration>,
}

impl Reading {
    /// What a connection with no selected path yet reads as.
    ///
    /// `Relayed`, deliberately, and this is the one place the decision is
    /// written down. Nothing is established, and the conservative answer is
    /// the one [`aggregate`] already takes for a mixed set: report the worse
    /// of the two. A third variant would push the case onto every caller and
    /// then onto the public [`PipeStatus`](crate::PipeStatus), which has
    /// `Idle` for "no peer" and deliberately nothing for "a peer whose path
    /// is a few milliseconds old".
    pub(crate) const PENDING: Self = Self {
        path: PeerPath::Relayed,
        rtt: None,
    };
}

/// Read how `connection` is routed right now.
///
/// A snapshot, honest about the moment it was taken — which is the whole
/// reason [`follow`] exists to take it again.
pub(crate) fn read(connection: &Connection) -> Reading {
    connection
        .paths()
        .iter()
        .find(Path::is_selected)
        .map_or(Reading::PENDING, |path| Reading {
            path: classify(path.remote_addr()),
            rtt: Some(path.rtt()),
        })
}

/// The rule: the relay is what this crate can name, so it is what is tested
/// for, and everything else counts as direct.
///
/// Not the inverse test on `is_ip`, and `TransportAddr` being
/// `#[non_exhaustive]` is why the difference matters. The distinction being
/// drawn is *through the relay or not*, which is what explains latency and
/// what the README promises; a transport iroh adds later is not the relay
/// and should not be reported as if it were.
fn classify(remote: &TransportAddr) -> PeerPath {
    if remote.is_relay() {
        PeerPath::Relayed
    } else {
        PeerPath::Direct
    }
}

/// A duration as whole milliseconds, saturating.
///
/// `tracing` has no `u128` field and neither does [`PeerView`], so the
/// conversion happens once, here. Saturation is unreachable arithmetic
/// rather than a policy: it would take a round trip of half a billion years.
///
/// [`PeerView`]: crate::PeerView
pub(crate) fn millis(rtt: Duration) -> u64 {
    u64::try_from(rtt.as_millis()).unwrap_or(u64::MAX)
}

/// Follow `connection`'s path until it — or the pipe — ends, handing every
/// reading to `publish`.
///
/// Ends on its own, which is what lets a caller spawn it and forget it: the
/// connection closing and the pipe closing are both arms here. The connect
/// side selects on this beside its own copies of those two and gets the same
/// answer either way; the serve side has an accept loop to run at the same
/// time and spawns it instead.
///
/// `publish` is called on every reading rather than only on a change,
/// because the RTT moves when the path does not and a status page rendering
/// it wants the current number. It is the *status* that must not churn, and
/// that is already handled where it belongs:
/// [`Lifecycle::set_status`](crate::lifecycle::Lifecycle::set_status) drops
/// a value equal to the one in force.
pub(crate) async fn follow(
    connection: &Connection,
    lifecycle: &Lifecycle,
    publish: impl FnMut(Reading),
) {
    tokio::select! {
        // Biased so teardown wins a tie, the shape every loop in this crate
        // uses: a pipe that is closing should stop reading rather than take
        // one more sample.
        biased;
        () = lifecycle.wait_until_closed() => {}
        _ = connection.closed() => {}
        () = repeat(connection, publish) => {}
    }
}

/// Read again forever, at [`CADENCE`]. Never returns; [`follow`] is what
/// ends it.
async fn repeat(connection: &Connection, mut publish: impl FnMut(Reading)) {
    let mut ticks = tokio::time::interval(CADENCE);
    // A laptop that was asleep for an hour has three thousand missed ticks
    // waiting for it, and the default behaviour is to deliver them all
    // without yielding — a burst of identical readings on exactly the
    // machine least able to afford one. `Delay` takes the overdue tick now
    // and puts the next one a cadence out, which is the catch-up worth
    // having.
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick is immediate, so this is the reading the caller has
    // already announced — published, because being the only writer is what
    // keeps the two sides' status honest, but never logged: a watcher that
    // reported its starting path as a change would be saying something
    // happened when nothing had.
    ticks.tick().await;
    let mut last = read(connection);
    publish(last);
    loop {
        ticks.tick().await;
        let now = read(connection);
        if now.path != last.path {
            // `info`, the level a peer arriving and leaving are reported at,
            // because this is the same class of event: it is the line that
            // says whether hole punching worked from where this machine is
            // sitting, and it was previously impossible to emit at all.
            tracing::info!(
                path = aggregate(&[now.path]).as_str(),
                rtt_ms = now.rtt.map(millis),
                "the path to the peer changed"
            );
        }
        last = now;
        publish(now);
    }
}

#[cfg(test)]
#[path = "path_watch_tests.rs"]
mod path_watch_tests;
