//! What the transport is doing right now.
//!
//! Pure: a plain state value with no machinery behind it. The watch cell
//! that publishes transitions, and the aggregation that turns several
//! peers' connection types into one of these, live with the handles.

/// What the transport is doing right now.
///
/// The `Relayed` case is worth surfacing to users: it explains latency
/// and is expected under carrier-grade or strict corporate NAT. `Closed`
/// is the terminal state, and `status_changed` guarantees to deliver it —
/// a watcher never blocks forever on a pipe that is already gone.
///
/// One listener can serve several peers at once — a phone and a laptop
/// holding the same ticket — so on the serve side this is an aggregate,
/// and it reports **the worst active path**: `Relayed` if any connected
/// peer is relayed, `Direct` only when all of them are direct. Reporting
/// the best path instead would hide exactly what `Relayed` exists to
/// explain, leaving the owner of the slow device with no way to find out
/// why. The cost is accepted and stated plainly: with a mixed set this
/// value describes no single peer, and a per-peer accessor is the
/// additive change that would fix that if the need proves real.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "lowercase")
)]
#[non_exhaustive]
pub enum PipeStatus {
    /// No peer is connected — waiting for the first, or between
    /// connections.
    Idle,
    /// Every connected peer has a direct hole-punched connection.
    Direct,
    /// At least one connected peer is falling back through an (encrypted,
    /// unreadable) relay.
    Relayed,
    /// The pipe is gone — shut down, dropped, or, on the connect side, the
    /// *local* listener stopped accepting under it. Terminal: no transition
    /// follows.
    ///
    /// **A transport failure is not one of the ways to get here**, and the
    /// sentence that used to say it was described a path neither side has.
    /// Nothing gives up on reaching a peer: an unreachable one is
    /// [`Idle`](Self::Idle), retried for as long as the pipe is held, which
    /// is the whole reason that state and this one are different answers.
    /// Every close is a local decision, and [`CloseReason`] says which one.
    ///
    /// Carried as a bare state rather than a reason so this type stays
    /// `Copy`; the need proved real, and the diagnostic accessor that
    /// answers *which* of those it was is
    /// [`ConnectHandle::close_reason`](crate::ConnectHandle::close_reason).
    Closed,
}

/// Why a pipe reached [`PipeStatus::Closed`].
///
/// The distinction [`PipeStatus`] deliberately does not carry, kept out of
/// it so that type stays `Copy` and stays small enough to sit in a
/// watcher's own state. Read it from
/// [`ConnectHandle::close_reason`](crate::ConnectHandle::close_reason),
/// which answers `None` for as long as the pipe is live.
///
/// **What it is for is telling a failure from a success**, which the status
/// alone cannot do. A connect side reports [`PipeStatus::Idle`] both while
/// it is looking for a peer that has gone away and before it has ever
/// reached one, and it reports [`PipeStatus::Closed`] whether a caller
/// asked for that or the local listener died under it. So: `None` means the
/// pipe is still live and still trying, however idle it looks;
/// [`Shutdown`](Self::Shutdown) means this side ended it on purpose; and
/// [`ListenerFailed`](Self::ListenerFailed) means nobody did.
///
/// `#[non_exhaustive]`, because the set of ways a pipe can end is not
/// closed — a caller matching on it needs a `_` arm and a plan for the
/// reasons that do not exist yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CloseReason {
    /// This side ended the pipe on purpose: `shutdown`,
    /// `shutdown_timeout`, or the handle being dropped.
    ///
    /// The three differ in what becomes of the requests already in flight
    /// — `shutdown` drains, a drop cuts — and not in why the pipe ended,
    /// which is what this answers. There is deliberately no separate
    /// reason for the drop, because there would be no way to read one:
    /// the accessor needs a handle, and a dropped handle is the one thing
    /// a caller no longer has.
    Shutdown,
    /// The local listener stopped accepting and could not carry on. Nobody
    /// asked for this one: it is the reason here that reports a failure
    /// rather than an intention, and the one worth waking somebody over.
    ListenerFailed,
}

impl CloseReason {
    /// A stable lowercase identifier: `"shutdown"`, `"listener_failed"`.
    ///
    /// Same contract as [`PipeStatus::as_str`], for the same reasons —
    /// an identifier rather than a sentence, frozen once anything greps
    /// for it, and a reason added later returns its own new one.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Shutdown => "shutdown",
            Self::ListenerFailed => "listener_failed",
        }
    }
}

impl PipeStatus {
    /// A stable lowercase identifier: `"idle"`, `"direct"`, `"relayed"`,
    /// `"closed"`.
    ///
    /// For status output, log fields and anything else that wants to name
    /// the state without matching on it. Deliberately an identifier and
    /// not a sentence — freezing `"relayed"` costs nothing, while freezing
    /// "falling back through a relay" would make every wording improvement
    /// a breaking change for whoever grepped for it.
    ///
    /// A variant added later returns its own new identifier, so a caller
    /// rendering this string keeps working; one *matching* on the string
    /// has the same obligation it would have had matching on the enum.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Direct => "direct",
            Self::Relayed => "relayed",
            Self::Closed => "closed",
        }
    }
}

/// One connected peer, as the serve side sees it.
///
/// Returned by [`ServeHandle::peers`](crate::ServeHandle::peers). The
/// `path` is a [`PipeStatus`] rather than a narrower enum so a caller
/// renders both with one `as_str`; for a single peer it is only ever
/// `Direct` or `Relayed`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct PeerView {
    /// The peer's fingerprint: twelve hex characters, the same rule the
    /// `peer` log field and the `X-Modelpipe-Peer` header use, so a device
    /// is one name everywhere it appears.
    pub fingerprint: String,
    /// How this peer is reaching the listener right now.
    ///
    /// **Right now, and re-read while the connection lives.** A connection
    /// commonly establishes through a relay and hole-punches to a direct
    /// path a moment later, and this follows that; before it did, a
    /// listener reported whichever path a peer happened to arrive on for
    /// the whole of that peer's session.
    pub path: PipeStatus,
    /// Round-trip time to this peer over the path above, in whole
    /// milliseconds, or `None` while no path is established yet.
    ///
    /// QUIC's own smoothed estimate rather than a probe this crate sends,
    /// so it costs nothing to read and moves a little between calls even on
    /// a path that has not changed. It is what turns [`path`](Self::path)
    /// into a measurement: `relayed` says a peer went the long way round,
    /// and this says what the long way round cost it.
    ///
    /// Milliseconds rather than a `Duration` because this struct is a DTO —
    /// it is the shape a status page renders, and the one the `serde`
    /// feature exists for — and `Duration` serializes as a two-field
    /// struct of seconds and nanoseconds. A round trip is never measured
    /// finer than this by anything that would display it.
    pub rtt_ms: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The identifiers are frozen surface once anything greps for them, so
    /// pin the spellings and the distinctness in one place.
    #[test]
    fn every_status_renders_a_distinct_stable_identifier() {
        let all = [
            PipeStatus::Idle,
            PipeStatus::Direct,
            PipeStatus::Relayed,
            PipeStatus::Closed,
        ];
        let rendered: Vec<&str> = all.iter().map(|s| s.as_str()).collect();
        assert_eq!(rendered, ["idle", "direct", "relayed", "closed"]);

        let mut deduped = rendered.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(
            deduped.len(),
            rendered.len(),
            "identifiers must be distinct"
        );
    }

    /// The same rule for the reasons, and the same reason for it.
    #[test]
    fn every_close_reason_renders_a_distinct_stable_identifier() {
        let all = [CloseReason::Shutdown, CloseReason::ListenerFailed];
        let rendered: Vec<&str> = all.iter().map(|r| r.as_str()).collect();
        assert_eq!(rendered, ["shutdown", "listener_failed"]);

        let mut deduped = rendered.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(
            deduped.len(),
            rendered.len(),
            "identifiers must be distinct"
        );
    }

    /// The whole point of the type: a pipe somebody ended and a pipe that
    /// broke are not the same answer, and comparing them must say so.
    #[test]
    fn a_failure_is_not_equal_to_a_deliberate_close() {
        assert_ne!(CloseReason::ListenerFailed, CloseReason::Shutdown);
    }
}
