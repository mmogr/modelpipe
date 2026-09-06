//! Who is connected to the serve side right now, and how.
//!
//! Split from [`crate::listener`] when the per-peer view arrived: the
//! accept loop is about turning QUIC streams into exchanges, and the set of
//! peers it is currently serving is a different thing — one that can be
//! read without an endpoint, tested without a socket, and reported to an
//! embedder as a list rather than only as the aggregate
//! [`PipeStatus`](crate::PipeStatus) it collapses to.
//!
//! Pure: a map behind a `std` mutex, never held across an await. The
//! status it publishes goes through the lifecycle it is handed, so this
//! module owns the *set* and nothing about how a change is broadcast.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::lifecycle::{Lifecycle, PeerPath, aggregate};
use crate::status::PeerView;

/// The connected peers, keyed by an id that exists only to remove the
/// right entry when one goes.
pub(crate) struct PeerRegistry {
    peers: Mutex<BTreeMap<u64, (Arc<str>, PeerPath)>>,
    next: AtomicU64,
}

impl PeerRegistry {
    pub(crate) const fn new() -> Self {
        Self {
            peers: Mutex::new(BTreeMap::new()),
            next: AtomicU64::new(0),
        }
    }

    /// Record a peer and republish the aggregate status.
    ///
    /// `name` is the fingerprint the listener derived for the connection,
    /// which is what [`views`](Self::views) reports and what the `peer`
    /// log field and the `X-Modelpipe-Peer` header already carry — one
    /// rule, so a device is named identically everywhere it appears.
    pub(crate) fn add(&self, name: Arc<str>, path: PeerPath, lifecycle: &Lifecycle) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.mutate(lifecycle, |peers| {
            peers.insert(id, (name, path));
        });
        id
    }

    pub(crate) fn remove(&self, id: u64, lifecycle: &Lifecycle) {
        self.mutate(lifecycle, |peers| {
            peers.remove(&id);
        });
    }

    /// A snapshot of every connected peer, in the order they connected.
    ///
    /// A snapshot and nothing more: a peer may leave between the return
    /// and the read, and a status is honest about the moment it was taken.
    pub(crate) fn views(&self) -> Vec<PeerView> {
        self.lock()
            .values()
            .map(|(name, path)| PeerView {
                fingerprint: name.to_string(),
                path: aggregate(&[*path]),
            })
            .collect()
    }

    /// Mutate the peer set and publish what it now means.
    ///
    /// The lock is never held across an await — the closure is synchronous
    /// and the status is computed inside it — so a slow peer cannot stall
    /// another's accept.
    fn mutate(
        &self,
        lifecycle: &Lifecycle,
        f: impl FnOnce(&mut BTreeMap<u64, (Arc<str>, PeerPath)>),
    ) {
        let mut guard = self.lock();
        f(&mut guard);
        let paths: Vec<PeerPath> = guard.values().map(|(_, path)| *path).collect();
        // Released before publishing, so nothing observes the status while
        // the set it describes is still locked.
        drop(guard);
        lifecycle.set_status(aggregate(&paths));
    }

    // A poisoned lock cannot happen here: nothing panics while holding it.
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<u64, (Arc<str>, PeerPath)>> {
        self.peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
#[path = "peers_tests.rs"]
mod peers_tests;
