//! Who is connected to the serve side right now, how, and how many it
//! will carry.
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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Semaphore;

use crate::lifecycle::{Lifecycle, PeerPath, aggregate};
use crate::path_watch::{self, Reading};
use crate::status::PeerView;

/// How many exchanges one peer may have in flight at once, across every
/// connection it holds.
///
/// Backpressure rather than refusal: a peer may open more streams, and they
/// wait. What is bounded is the work and the memory one identity can
/// command; an identity costs nothing to mint, so how many a ticket-holder
/// can bring at once is the peer cap,
/// [`ServeOptions::max_peers`](crate::ServeOptions::max_peers).
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

/// How many distinct peers a listener carries at once, unless
/// [`ServeOptions::max_peers`](crate::ServeOptions::max_peers) says otherwise.
///
/// A peer is a fingerprint, so a second connection from a device already
/// here is not a new peer: it counts against the connection cap and not
/// against this.
pub(crate) const DEFAULT_MAX_PEERS: usize = 32;

/// How many connections a listener carries at once, handshakes included,
/// unless [`ServeOptions::max_connections`](crate::ServeOptions::max_connections)
/// says otherwise.
///
/// Both caps refuse where the stream cap waits, and what would be waited
/// for is the difference. A stream that waits is waiting on its own peer's
/// exchanges, which that peer is finishing. A connection or a peer that
/// waited would be waiting on some *other* peer to leave, and the queue it
/// sat in would be the thing with no bound. So the one past either cap is
/// turned away at once, and nothing is held for it.
pub(crate) const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// The connections a listener is carrying, counted against its cap.
pub(crate) struct Connections {
    carried: Arc<AtomicUsize>,
    max: usize,
}

/// One connection's place in the count, given back when it drops — on
/// every way out of the task that holds it, a panic included.
pub(crate) struct Carried(Arc<AtomicUsize>);

impl Connections {
    /// A count that carries at most `max` connections.
    pub(crate) fn new(max: NonZeroUsize) -> Self {
        Self {
            carried: Arc::default(),
            max: max.get(),
        }
    }

    /// A place for one more connection, or `None` when every place is taken.
    pub(crate) fn admit(&self) -> Option<Carried> {
        self.carried
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < self.max).then_some(n + 1)
            })
            .ok()
            .map(|_| Carried(self.carried.clone()))
    }

    #[cfg(test)]
    pub(crate) fn carried(&self) -> usize {
        self.carried.load(Ordering::Relaxed)
    }
}

impl Default for Connections {
    /// The count a listener started from `ServeOptions::default()` keeps.
    fn default() -> Self {
        Self::new(NonZeroUsize::new(DEFAULT_MAX_CONNECTIONS).expect("the default is not zero"))
    }
}

impl Drop for Carried {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// One peer's stream budget, and how many connections are drawing on it.
struct Budget {
    slots: Arc<Semaphore>,
    connections: usize,
}

/// The connected peers, keyed by an id that exists only to name the right
/// entry when one changes path or goes.
pub(crate) struct PeerRegistry {
    peers: Mutex<BTreeMap<u64, (Arc<str>, Reading)>>,
    /// Stream budgets by peer identity, shared across that peer's
    /// connections and dropped when its last one goes.
    budgets: Mutex<HashMap<Arc<str>, Budget>>,
    next: AtomicU64,
    /// How many distinct peers it carries.
    max_peers: usize,
}

impl Default for PeerRegistry {
    /// The registry a listener started from `ServeOptions::default()` keeps.
    fn default() -> Self {
        Self::new(NonZeroUsize::new(DEFAULT_MAX_PEERS).expect("the default is not zero"))
    }
}

impl PeerRegistry {
    pub(crate) fn new(max_peers: NonZeroUsize) -> Self {
        Self {
            peers: Mutex::new(BTreeMap::new()),
            budgets: Mutex::new(HashMap::new()),
            next: AtomicU64::new(0),
            max_peers: max_peers.get(),
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
    ///
    /// `reading` is how that connection is routed *at this instant*, and is
    /// routinely not how it will be routed a second later — see
    /// [`set_path`](Self::set_path), which is the other half of this.
    ///
    /// `None`, and the set left as it was, when `name` is not here already
    /// and as many others as the cap allows are.
    pub(crate) fn add(
        &self,
        name: &Arc<str>,
        reading: Reading,
        lifecycle: &Lifecycle,
    ) -> Option<u64> {
        self.mutate(lifecycle, |peers| {
            let here: HashSet<&str> = peers.values().map(|(held, _)| &**held).collect();
            if here.len() >= self.max_peers && !here.contains(&**name) {
                return None;
            }
            let id = self.next.fetch_add(1, Ordering::Relaxed);
            peers.insert(id, (name.clone(), reading));
            Some(id)
        })
    }

    /// Record what one peer's path has become, and republish what the set
    /// now means.
    ///
    /// The write [`crate::path_watch`] makes on the serve side, keyed by the
    /// `id` [`add`](Self::add) returned. Everything in this registry used to
    /// be written once at accept and never again, which is exactly why a
    /// connection that hole-punched after establishing went on being
    /// reported as relayed for the rest of its life.
    ///
    /// A peer that has already left is not resurrected: a watcher may still
    /// be a tick behind [`remove`](Self::remove), and re-inserting the entry
    /// it just removed would leave a departed device in `peers()` for ever.
    pub(crate) fn set_path(&self, id: u64, reading: Reading, lifecycle: &Lifecycle) {
        self.mutate(lifecycle, |peers| {
            if let Some((_, held)) = peers.get_mut(&id) {
                *held = reading;
            }
        });
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
            .map(|(name, reading)| PeerView {
                fingerprint: name.to_string(),
                path: aggregate(&[reading.path]),
                rtt_ms: reading.rtt.map(path_watch::millis),
            })
            .collect()
    }

    /// Mutate the peer set and publish what it now means.
    ///
    /// The lock is never held across an await — the closure is synchronous
    /// and the status is computed inside it — so a slow peer cannot stall
    /// another's accept.
    fn mutate<R>(
        &self,
        lifecycle: &Lifecycle,
        f: impl FnOnce(&mut BTreeMap<u64, (Arc<str>, Reading)>) -> R,
    ) -> R {
        let mut guard = self.lock();
        let result = f(&mut guard);
        let paths: Vec<PeerPath> = guard.values().map(|(_, reading)| reading.path).collect();
        // Released before publishing, so nothing observes the status while
        // the set it describes is still locked.
        drop(guard);
        lifecycle.set_status(aggregate(&paths));
        result
    }

    // A poisoned lock cannot happen here: nothing panics while holding it.
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<u64, (Arc<str>, Reading)>> {
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
