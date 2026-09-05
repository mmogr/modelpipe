//! Tests for [`super::PeerRegistry`] — the connected set and what it
//! reports.

use super::*;
use crate::status::PipeStatus;

fn name(s: &str) -> Arc<str> {
    s.into()
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
    registry.add(name("3ca82708b995"), PeerPath::Direct, &lifecycle);
    registry.add(name("7f0e11a2c3d4"), PeerPath::Relayed, &lifecycle);

    let views = registry.views();
    assert_eq!(views.len(), 2);
    assert_eq!(views[0].fingerprint, "3ca82708b995");
    assert_eq!(views[0].path, PipeStatus::Direct);
    assert_eq!(views[1].fingerprint, "7f0e11a2c3d4");
    assert_eq!(views[1].path, PipeStatus::Relayed);
}

/// The aggregate is the worst path across the set, and the per-peer view
/// is what says which peer that was.
#[test]
fn the_aggregate_is_the_worst_path_and_the_view_says_whose() {
    let registry = PeerRegistry::new();
    let lifecycle = Lifecycle::new();
    let direct = registry.add(name("aaaaaaaaaaaa"), PeerPath::Direct, &lifecycle);
    assert_eq!(lifecycle.status(), PipeStatus::Direct);

    let relayed = registry.add(name("bbbbbbbbbbbb"), PeerPath::Relayed, &lifecycle);
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
    let first = registry.add(name("aaaaaaaaaaaa"), PeerPath::Direct, &lifecycle);
    registry.add(name("bbbbbbbbbbbb"), PeerPath::Direct, &lifecycle);
    registry.remove(first, &lifecycle);
    let left: Vec<_> = registry
        .views()
        .into_iter()
        .map(|v| v.fingerprint)
        .collect();
    assert_eq!(left, ["bbbbbbbbbbbb"]);
}
