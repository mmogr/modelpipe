//! Tests for [`super`] — the two capabilities that belong to the endpoint.
//!
//! Split out via `#[path]` so `network.rs` stays inside the file-size
//! budget, the same way every other module in the crate does it.
//!
//! **What cannot be tested here, said rather than left to be discovered.**
//! [`notify`] has no observable effect on one machine, and that is iroh's
//! design rather than a gap in these tests: the notice is handed to the
//! network monitor, which re-reads the interface state and returns early
//! when it has not actually changed — which, in a test, it has not. So the
//! assertions below are the two things that *are* observable and that a
//! caller depends on: the call returns, and it returns on an endpoint that
//! has already closed. Whether the notice does its job is a claim about a
//! machine that moved between networks, and it is measured on a phone
//! rather than asserted in CI.

use std::time::Duration;

use super::*;
use crate::transport::{NetOptions, bind, ticket_from, wait_online};

/// Resolve `future`, or fail with `why` rather than hanging the suite.
///
/// Both `notify` tests are tests about *not blocking*, so a bare await here
/// would hang the run instead of failing it.
async fn within<F: std::future::Future>(why: &str, future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .unwrap_or_else(|_| panic!("{why}"))
}

/// An endpoint that contacts nothing it is not told to.
async fn quiet_endpoint(relay: Option<&str>) -> Endpoint {
    let net = NetOptions {
        port_mapping: false,
        discovery: false,
        relay_only: false,
    };
    bind(relay, None, net).await.expect("binding must succeed")
}

/// A relay URL that parses and that nothing is behind. Loopback rather than
/// a name, so nothing here waits on a resolver.
const UNUSED_RELAY: &str = "https://127.0.0.1:1/";

#[tokio::test]
async fn a_notice_of_a_network_change_returns_rather_than_waiting_for_one() {
    let endpoint = quiet_endpoint(Some(UNUSED_RELAY)).await;
    within(
        "notifying a live endpoint must return, not park until something changes",
        notify(&endpoint),
    )
    .await;
    endpoint.close().await;
}

/// The case a phone binding reaches first, and the one worth pinning: an app
/// resumes, tells the pipe the network moved, and the pipe was torn down
/// while it was in the background. iroh answers such a notice by ignoring
/// it; what matters here is that the answer arrives at all, because the
/// alternative — a resume handler that never returns — is indistinguishable
/// from a hung app.
#[tokio::test]
async fn a_notice_arriving_after_the_endpoint_closed_is_ignored_rather_than_hanging() {
    let endpoint = quiet_endpoint(Some(UNUSED_RELAY)).await;
    endpoint.close().await;
    within(
        "a closed endpoint must refuse the notice quickly, not swallow the caller",
        notify(&endpoint),
    )
    .await;
}

/// The counters are read from the endpoint that was asked, and they move.
///
/// Both halves are the claim, and a snapshot of constants satisfies
/// neither. The pair is also what pins
/// [`relay_connections`](NetworkMetrics::relay_connections) to iroh's
/// success counter specifically rather than to whichever counter sits next
/// to it: the endpoint that reached a relay reports one and no failures,
/// where a success-for-failure mix-up would report exactly the reverse.
///
/// Honest about the reach it does not have. Nothing here can separate the
/// failed counter from the rate-limited one, because both are zero on a
/// healthy connection and no test in this process can make a relay throttle
/// it. The rate-limit field is the one this module exists for and the one
/// no test can produce; that mapping is a reading of iroh's manifest, and
/// this test says how far it goes rather than implying further.
///
/// **This needs a route to a relay**, which
/// `transport_tests::relay_only_mints_a_ticket_that_names_the_relay_and_nothing_else`
/// already establishes as a dependency this suite accepts. The assertion is
/// guarded by an independently observed fact — a relay in the endpoint's own
/// ticket — so a failure says which of the two things went wrong.
#[tokio::test]
async fn the_counters_are_the_endpoints_own_and_move_when_it_reaches_a_relay() {
    let online = quiet_endpoint(None).await;
    wait_online(&online, Duration::from_secs(20)).await;

    // Independent evidence that the handshake happened: `ticket_from` reads
    // the endpoint's address set, and a relay is in it only once a relay
    // connection has completed.
    assert!(
        !ticket_from(&online.addr()).relay_urls().is_empty(),
        "this test needs a route to a relay, and this endpoint reached none"
    );

    let reached = metrics_of(&online);
    assert!(
        reached.relay_connections >= 1,
        "the endpoint that reached a relay has to count it: {reached:?}"
    );
    assert_eq!(
        reached.relay_connections_failed, 0,
        "and must not count that same event as a failure: {reached:?}"
    );

    // A second endpoint never dials one, so its counters stay where they
    // started — which is what makes the reading above that endpoint's own
    // rather than something process-wide.
    let never = quiet_endpoint(Some(UNUSED_RELAY)).await;
    assert_eq!(
        metrics_of(&never),
        NetworkMetrics::default(),
        "an endpoint that reached nothing has nothing to report"
    );

    online.close().await;
    never.close().await;
}
