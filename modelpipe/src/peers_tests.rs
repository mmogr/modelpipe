//! Tests for [`super::PeerRegistry`] — the connected set and what it
//! reports.

use std::time::Duration;

use super::*;
use crate::status::PipeStatus;

fn name(s: &str) -> Arc<str> {
    s.into()
}

/// A peer that hole-punched, and one that did not.
///
/// The round-trip times are plausible rather than meaningful — what the
/// registry does with a reading is carry it — and they differ so that a
/// view holding the wrong peer's would be visible rather than merely wrong.
fn hole_punched() -> Reading {
    Reading {
        path: PeerPath::Direct,
        rtt: Some(Duration::from_millis(4)),
    }
}

fn via_relay() -> Reading {
    Reading {
        path: PeerPath::Relayed,
        rtt: Some(Duration::from_millis(91)),
    }
}

#[test]
fn an_empty_registry_is_idle_and_reports_nobody() {
    let registry = PeerRegistry::new();
    let lifecycle = Lifecycle::new();
    assert!(registry.views().is_empty());
    assert_eq!(lifecycle.status(), PipeStatus::Idle);
}

#[test]
fn each_peer_is_reported_by_name_and_path_in_arrival_order() {
    let registry = PeerRegistry::new();
    let lifecycle = Lifecycle::new();
    registry.add(name("3ca82708b995"), hole_punched(), &lifecycle);
    registry.add(name("7f0e11a2c3d4"), via_relay(), &lifecycle);

    let views = registry.views();
    assert_eq!(views.len(), 2);
    assert_eq!(views[0].fingerprint, "3ca82708b995");
    assert_eq!(views[0].path, PipeStatus::Direct);
    assert_eq!(views[1].fingerprint, "7f0e11a2c3d4");
    assert_eq!(views[1].path, PipeStatus::Relayed);
}

/// The reading is quantitative, and the view is where an embedder reads the
/// number: a relayed peer is not merely slower, it is slower by an amount.
#[test]
fn each_peer_is_reported_with_what_its_path_costs() {
    let registry = PeerRegistry::new();
    let lifecycle = Lifecycle::new();
    registry.add(name("3ca82708b995"), hole_punched(), &lifecycle);
    registry.add(name("7f0e11a2c3d4"), via_relay(), &lifecycle);

    let views = registry.views();
    assert_eq!(views[0].rtt_ms, Some(4));
    assert_eq!(views[1].rtt_ms, Some(91));
}

/// The whole point of the registry holding a reading rather than a path
/// taken at accept time: a connection that establishes over the relay and
/// hole-punches a moment later has to stop being reported as relayed.
#[test]
fn a_peer_that_changes_path_is_reported_on_the_one_it_moved_to() {
    let registry = PeerRegistry::new();
    let lifecycle = Lifecycle::new();
    let peer = registry.add(name("3ca82708b995"), via_relay(), &lifecycle);
    assert_eq!(lifecycle.status(), PipeStatus::Relayed, "as it arrived");

    registry.set_path(peer, hole_punched(), &lifecycle);

    assert_eq!(registry.views()[0].path, PipeStatus::Direct);
    assert_eq!(registry.views()[0].rtt_ms, Some(4), "and what it now costs");
    assert_eq!(
        lifecycle.status(),
        PipeStatus::Direct,
        "the aggregate follows the peer it is aggregating"
    );
}

/// A watcher can be a tick behind the removal that ended it, and the entry
/// it writes then must not come back — a departed device left in `peers()`
/// for ever is worse than the stale path this whole module exists to fix.
#[test]
fn a_reading_that_lands_after_a_peer_left_does_not_bring_it_back() {
    let registry = PeerRegistry::new();
    let lifecycle = Lifecycle::new();
    let peer = registry.add(name("3ca82708b995"), via_relay(), &lifecycle);
    registry.remove(peer, &lifecycle);

    registry.set_path(peer, hole_punched(), &lifecycle);

    assert!(registry.views().is_empty(), "nobody is connected");
    assert_eq!(lifecycle.status(), PipeStatus::Idle);
}

/// The aggregate is the worst path across the set, and the per-peer view
/// is what says which peer that was.
#[test]
fn the_aggregate_is_the_worst_path_and_the_view_says_whose() {
    let registry = PeerRegistry::new();
    let lifecycle = Lifecycle::new();
    let direct = registry.add(name("aaaaaaaaaaaa"), hole_punched(), &lifecycle);
    assert_eq!(lifecycle.status(), PipeStatus::Direct);

    let relayed = registry.add(name("bbbbbbbbbbbb"), via_relay(), &lifecycle);
    assert_eq!(lifecycle.status(), PipeStatus::Relayed, "one relayed peer");
    let slow: Vec<_> = registry
        .views()
        .into_iter()
        .filter(|v| v.path == PipeStatus::Relayed)
        .map(|v| v.fingerprint)
        .collect();
    assert_eq!(slow, ["bbbbbbbbbbbb"], "and the view names it");

    registry.remove(relayed, &lifecycle);
    assert_eq!(lifecycle.status(), PipeStatus::Direct);
    registry.remove(direct, &lifecycle);
    assert_eq!(lifecycle.status(), PipeStatus::Idle);
    assert!(registry.views().is_empty());
}

#[test]
fn removing_one_peer_leaves_the_others_alone() {
    let registry = PeerRegistry::new();
    let lifecycle = Lifecycle::new();
    let first = registry.add(name("aaaaaaaaaaaa"), hole_punched(), &lifecycle);
    registry.add(name("bbbbbbbbbbbb"), hole_punched(), &lifecycle);
    registry.remove(first, &lifecycle);
    let left: Vec<_> = registry
        .views()
        .into_iter()
        .map(|v| v.fingerprint)
        .collect();
    assert_eq!(left, ["bbbbbbbbbbbb"]);
}

// ── The stream budget ────────────────────────────────────────────────────

/// The cap is per peer: two connections from one endpoint draw on one
/// semaphore, and a different endpoint gets its own.
#[test]
fn connections_from_one_peer_share_a_budget_and_peers_do_not() {
    let registry = PeerRegistry::new();
    let lifecycle = Lifecycle::new();
    let alice = name("aaaaaaaaaaaa");
    let bob = name("bbbbbbbbbbbb");
    registry.add(alice.clone(), hole_punched(), &lifecycle);
    registry.add(alice.clone(), hole_punched(), &lifecycle);
    registry.add(bob.clone(), hole_punched(), &lifecycle);

    let first = registry.slots(&alice);
    let second = registry.slots(&alice);
    let other = registry.slots(&bob);
    assert!(Arc::ptr_eq(&first, &second), "one peer, one budget");
    assert!(!Arc::ptr_eq(&first, &other), "another peer, another budget");
    assert_eq!(first.available_permits(), MAX_CONCURRENT_STREAMS_PER_PEER);
}

/// A permit taken over one connection is a permit the same peer's other
/// connection cannot take — which is the whole of what "per peer" means.
#[test]
fn a_stream_on_one_connection_counts_against_the_peers_other_connections() {
    let registry = PeerRegistry::new();
    let lifecycle = Lifecycle::new();
    let alice = name("aaaaaaaaaaaa");
    registry.add(alice.clone(), hole_punched(), &lifecycle);
    registry.add(alice.clone(), hole_punched(), &lifecycle);
    let via_first = registry.slots(&alice);
    let via_second = registry.slots(&alice);

    let held: Vec<_> = (0..MAX_CONCURRENT_STREAMS_PER_PEER)
        .map(|_| {
            via_first
                .clone()
                .try_acquire_owned()
                .expect("within the cap")
        })
        .collect();
    assert!(
        via_second.clone().try_acquire_owned().is_err(),
        "the other connection finds the budget spent"
    );
    drop(held);
    assert!(
        via_second.try_acquire_owned().is_ok(),
        "and refilled once released"
    );
}

/// The budget outlives any one connection and dies with the last, so a
/// peer that paired once and left holds nothing for the life of the
/// listener.
#[test]
fn a_budget_survives_one_connection_leaving_and_dies_with_the_last() {
    let registry = PeerRegistry::new();
    let lifecycle = Lifecycle::new();
    let alice = name("aaaaaaaaaaaa");
    let first = registry.add(alice.clone(), hole_punched(), &lifecycle);
    let second = registry.add(alice.clone(), hole_punched(), &lifecycle);
    let budget = registry.slots(&alice);
    let _also = registry.slots(&alice);

    registry.remove(first, &lifecycle);
    assert!(
        Arc::ptr_eq(&budget, &registry.slots(&alice)),
        "the surviving connection still draws on the same budget"
    );
    registry.release(&alice); // the share `slots` above just took, for the assertion

    registry.remove(second, &lifecycle);
    assert!(
        !Arc::ptr_eq(&budget, &registry.slots(&alice)),
        "a peer that comes back after leaving entirely starts a fresh budget"
    );
}
