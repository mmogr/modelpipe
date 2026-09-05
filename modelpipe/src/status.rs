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
    /// The pipe is gone — shut down, dropped, or dead after an
    /// unrecoverable transport failure. Terminal: no transition follows.
    /// Carried as a bare state rather than a reason so this type stays
    /// `Copy`; a diagnostic accessor on the handle can be added
    /// compatibly if the need proves real.
    Closed,
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
    pub path: PipeStatus,
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
}
