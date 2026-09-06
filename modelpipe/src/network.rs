//! What an embedder may ask of the endpoint, without ever being handed one.
//!
//! Two capabilities live on the iroh endpoint and on nothing else: telling
//! it the network underneath it moved, and reading what the transport has
//! actually been doing. Both are wanted by an embedder — a phone client
//! needs the first on resume, and a status page needs the second to explain
//! a pipe that is slow rather than broken — and neither can be reached
//! without the endpoint.
//!
//! **An `endpoint()` accessor is therefore the one shape this module must
//! not be.** [`crate::transport`] states the promise it would break: no
//! iroh type reaches the public surface, checked rather than asserted by
//! `tests/api_surface.rs`. The manifest asks for `iroh = "1"`, a caret
//! major, precisely so that an iroh 2.0 is this crate's problem to absorb;
//! an `Endpoint` in one public signature would make it every dependent's,
//! and would do it at the moment they can least afford it — a phone binding
//! is generated code, and a type it cannot name is a type it cannot pass.
//! So each capability gets its own method, taking and returning values this
//! crate owns.
//!
//! It is also why this module borrows rather than holds. It names
//! [`Endpoint`] to spell two private helpers and keeps nothing past the end
//! of a call, which is the lifetime line [`crate::transport`] draws.
//!
//! The asymmetry between the two sides is [`crate::listener`] and
//! [`crate::peer`]'s, not this module's: the serve side keeps its endpoint
//! in `ServeState`, and the connect side keeps its in the `Peer` it dials
//! from. Both are reachable within the crate; neither is reachable outside
//! it.

use iroh::Endpoint;

use crate::connect_handle::ConnectHandle;
use crate::serve_handle::ServeHandle;

/// What the transport underneath a pipe has been doing, as plain numbers.
///
/// A snapshot taken at the moment it was asked for, and owned outright:
/// every field is a `u64` this crate copied out of iroh's counters, rather
/// than a borrow of them. That is the difference between a status page and
/// a leak — `Endpoint::metrics` hands back a reference to iroh's own
/// metrics types, and returning one would put both iroh and its metrics
/// crate in the signature of a method whose entire output is three
/// integers.
///
/// **Monotonic totals for the life of one endpoint, not rates and not
/// gauges.** They only ever climb, and they start at zero when the pipe is
/// created; what a caller wants is nearly always the difference between two
/// readings, or the ratio between two fields of one. A pipe that is torn
/// down and re-established starts a fresh endpoint and therefore fresh
/// counts.
///
/// `#[non_exhaustive]`, so fields can be added without breaking a caller,
/// and `Copy` so holding one in a UI's state costs nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct NetworkMetrics {
    /// Relay connections this endpoint established, counted once each time
    /// one is made — so a relay that drops and is reconnected to counts
    /// twice.
    ///
    /// The denominator for the two fields below. On its own it says only
    /// whether this endpoint has ever reached a relay at all, which is
    /// worth knowing on a machine that reports no relay in its ticket.
    pub relay_connections: u64,
    /// Failed attempts to reach a relay, counted per attempt.
    ///
    /// An unreachable relay increments this on every retry, so the number
    /// grows without bound while nothing works and stops the moment
    /// something does. It is a rate in disguise: two readings a few seconds
    /// apart say whether this endpoint is currently failing to reach a
    /// relay, which no single reading can.
    pub relay_connections_failed: u64,
    /// Relay connections on which the relay reported that it was rate
    /// limiting this endpoint.
    ///
    /// **The one a status page has no other way to learn.** A throttled
    /// pipe is not down: requests still cross it, slowly, and every other
    /// signal available says the pipe is fine — the status reads `relayed`,
    /// the peer is present, and nothing fails. This is what separates "the
    /// relay is far away" from "the relay is holding this endpoint back",
    /// and the answer changes what an operator should do about it.
    ///
    /// Counted at most once per connection, so it is a count of affected
    /// connections rather than of complaints; relate it to
    /// [`relay_connections`](Self::relay_connections) for the proportion.
    pub relay_connections_ratelimited: u64,
}

impl ServeHandle {
    /// Tell this side's endpoint that the network underneath it may have
    /// changed, and wait for the notice to be taken.
    ///
    /// A *notifier*, not an observer, which is why it takes nothing and
    /// returns nothing: it pushes a fact in rather than reading one out.
    /// The endpoint responds by rebinding its sockets and re-checking its
    /// relay connection, which is what repairs a pipe whose addresses are
    /// all now wrong.
    ///
    /// Harmless when nothing changed, and harmless when the endpoint had
    /// already noticed by itself — so the honest rule is to call it
    /// whenever the host knows something this library cannot, and not to
    /// try to be clever about when.
    ///
    /// **The reason it is on the public surface is the hosts that cannot be
    /// detected from inside.** iroh watches the platform for link changes
    /// where the platform will say; on Android that information is only
    /// available to Java code, and on iOS the sleep/wake detection is
    /// deliberately disabled in favour of a poll measured in the hour. An
    /// app resuming on a new cellular bearer therefore has a pipe with
    /// nothing left to repair it until that poll comes round — unless the
    /// app itself says so, here, from the resume it already handles.
    ///
    /// Safe on a pipe that is already closed: the endpoint ignores the
    /// notice and this returns.
    pub async fn notify_network_change(&self) {
        notify(&self.state.endpoint).await;
    }

    /// What the transport underneath this listener has been doing.
    ///
    /// See [`NetworkMetrics`]: monotonic totals for this endpoint's whole
    /// life, so the useful reading is a difference or a ratio rather than
    /// one number.
    pub fn network_metrics(&self) -> NetworkMetrics {
        metrics_of(&self.state.endpoint)
    }
}

impl ConnectHandle {
    /// Tell this side's endpoint that the network underneath it may have
    /// changed, and wait for the notice to be taken.
    ///
    /// Same contract as
    /// [`ServeHandle::notify_network_change`](crate::ServeHandle::notify_network_change),
    /// which states it in full — and this is the side that usually needs
    /// it, because the connecting machine is the one that moves.
    ///
    /// It does not replace the re-dial loop and does not start one: this
    /// side already retries a peer it cannot reach, for as long as the pipe
    /// is held. What this fixes is the case underneath that loop, where the
    /// socket it is dialling from is bound to an interface that no longer
    /// exists — a laptop that changed network while suspended, a phone that
    /// came back on cellular.
    pub async fn notify_network_change(&self) {
        notify(&self.state.peer.endpoint).await;
    }

    /// What the transport underneath this pipe has been doing.
    ///
    /// Same contract as
    /// [`ServeHandle::network_metrics`](crate::ServeHandle::network_metrics),
    /// and a separate set of numbers: the two sides are two endpoints, and
    /// a relay that is rate limiting one of them is not necessarily
    /// touching the other.
    pub fn network_metrics(&self) -> NetworkMetrics {
        metrics_of(&self.state.peer.endpoint)
    }
}

/// Push the notice in. Written once rather than twice because the two
/// handles owe the identical promise, and prose that is stated twice is
/// prose that drifts — the argument [`crate::lifecycle`] opens with.
async fn notify(endpoint: &Endpoint) {
    endpoint.network_change().await;
}

/// Copy the three counters out of iroh's metrics into values this crate
/// owns.
///
/// `Endpoint::metrics` sits behind iroh's `metrics` feature. That feature
/// is one of iroh's defaults *and* is named explicitly in this crate's
/// manifest, for the reason the `tokio` entry beside it gives: a feature
/// that is used should be declared, rather than arriving free from a
/// dependency's private choice and disappearing in a release that changed
/// nothing here.
fn metrics_of(endpoint: &Endpoint) -> NetworkMetrics {
    let socket = &endpoint.metrics().socket;
    NetworkMetrics {
        relay_connections: socket.relay_conns_success.get(),
        relay_connections_failed: socket.relay_conns_failed.get(),
        relay_connections_ratelimited: socket.relay_conns_ratelimited.get(),
    }
}

#[cfg(test)]
#[path = "network_tests.rs"]
mod network_tests;
