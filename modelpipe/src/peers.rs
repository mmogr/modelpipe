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

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Semaphore;

use crate::lifecycle::{Lifecycle, PeerPath, aggregate};
use crate::status::PeerView;

/// How many exchanges one peer may have in flight at once, across every
/// connection it holds.
///
/// Backpressure rather than refusal: a peer may open more streams, and they
/// wait. What is bounded is the work and the memory a single ticket-holder
/// can command, which — with the head size and the head timeout — is the
/// whole of what a leaked ticket is worth before it authenticates.
///
/// Per *peer*, not per connection, and the difference is the bound. The
/// semaphore used to be built inside the connection loop, so a holder who
/// opened N connections had 64·N streams — the cap the docs promised was
/// off by whatever the peer chose. It now lives here, keyed by the peer's
/// identity, and every connection from one endpoint draws on one budget.
///
/// Deliberately generous. A client pipelining a page of requests is normal;
/// a client with sixty-four in flight is not a client.
pub(crate) const MAX_CONCURRENT_STREAMS_PER_PEER: usize = 64;

/// One peer's stream budget, and how many connections are drawing on it.
struct Budget {
    slots: Arc<Semaphore>,
    connections: usize,
}

/// The connected peers, keyed by an id that exists only to remove the
/// right entry when one goes.
pub(crate) struct PeerRegistry {
    peers: Mutex<BTreeMap<u64, (Arc<str>, PeerPath)>>,
    /// Stream budgets by peer identity, shared across that peer's
    /// connections and dropped when its last one goes.
    budgets: Mutex<HashMap<Arc<str>, Budget>>,
    next: AtomicU64,
}

impl PeerRegistry {
    pub(crate) fn new() -> Self {
        Self {
            peers: Mutex::new(BTreeMap::new()),
            budgets: Mutex::new(HashMap::new()),
            next: AtomicU64::new(0),
        }
    }

    /// The stream budget for `name`, shared with every other connection
    /// that peer currently holds. Call once per connection, after
    /// [`add`](Self::add); [`remove`](Self::remove) returns the share.
    pub(crate) fn slots(&self, name: &Arc<str>) -> Arc<Semaphore> {
        let mut budgets = self.lock_budgets();
        let budget = budgets.entry(name.clone()).or_insert_with(|| Budget {
            slots: Arc::new(Semaphore::new(MAX_CONCURRENT_STREAMS_PER_PEER)),
            connections: 0,
        });
        budget.connections += 1;
        let slots = budget.slots.clone();
        drop(budgets);
        slots
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
        let mut departed = None;
        self.mutate(lifecycle, |peers| {
            departed = peers.remove(&id).map(|(name, _)| name);
        });
        if let Some(name) = departed {
            self.release(&name);
        }
    }

    /// Give back one connection's share of a peer's budget, dropping the
    /// budget with its last connection so an endpoint that paired once and
    /// left does not hold a semaphore for the life of the listener.
    fn release(&self, name: &Arc<str>) {
        let mut budgets = self.lock_budgets();
        if let Some(budget) = budgets.get_mut(name) {
            budget.connections = budget.connections.saturating_sub(1);
            if budget.connections == 0 {
                budgets.remove(name);
            }
        }
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

    fn lock_budgets(&self) -> std::sync::MutexGuard<'_, HashMap<Arc<str>, Budget>> {
        self.budgets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
#[path = "peers_tests.rs"]
mod peers_tests;
