//! The idle clock, on a real pipe.
//!
//! `lifecycle_tests` checks the clock's arithmetic under paused time. What
//! it cannot check is that the clock a caller reads through
//! [`ConnectHandle::idle_for`] is the one a live pipe moves — that the
//! wiring exists at all. That needs two endpoints, so it lives here.
//!
//! Discovery and port mapping are off, so nothing contacts n0.

mod common;

use std::time::Duration;

use common::{MockBackend, within};
use modelpipe::{PipeStatus, TokenPolicy};

const OK_BODY: &str = r#"{"object":"list","data":[]}"#;

/// Long enough that a failure is a failure rather than a slow machine.
const PATIENCE: Duration = Duration::from_secs(20);

/// A pipe that has reached its peer reports no idle time; one that has
/// lost it reports time that grows.
///
/// Real time, not paused: a paused clock would not advance while the two
/// endpoints are doing real network work, and what is under test here is
/// the wiring rather than the arithmetic. The assertions are therefore
/// about *direction* — none, then some, then more — which no amount of
/// machine slowness makes wrong.
#[tokio::test]
async fn a_live_pipe_reports_no_idle_time_and_a_lost_one_reports_growing_time() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let mut opts = common::serve_options();
    opts.auth = TokenPolicy::Generate;
    let serving = within(
        "serve must bind",
        Box::pin(modelpipe::serve(backend.url.as_str(), opts)),
    )
    .await
    .expect("serve");

    let device = within(
        "connect must settle",
        Box::pin(modelpipe::connect(
            &serving.ticket(),
            common::connect_options(),
        )),
    )
    .await
    .expect("connect");

    // Before the peer is reached, the pipe is idle from birth — which is
    // the case a clock started only on a transition would miss.
    assert!(
        device.idle_for().is_some(),
        "a pipe that has not reached its peer is idle"
    );

    device
        .wait_reachable(PATIENCE)
        .await
        .expect("the device reaches the serve side");
    assert_eq!(
        device.idle_for(),
        None,
        "a reached peer is not idle: {:?}",
        device.status()
    );

    // Take the far side away and wait for this side to notice.
    serving.shutdown().await;
    let noticed = tokio::time::timeout(PATIENCE, async {
        loop {
            if device.status() == PipeStatus::Idle {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(noticed.is_ok(), "this side must notice the peer is gone");

    let first = device.idle_for().expect("a lost peer is idle");
    tokio::time::sleep(Duration::from_millis(150)).await;
    let later = device.idle_for().expect("and stays idle");
    assert!(
        later > first,
        "the clock must run: {first:?} then {later:?}"
    );

    device.shutdown().await;
}

/// A closed pipe is `Closed`, not idle — which is what lets a caller use
/// the status as the live/closed discriminator and the clock only for how
/// long a *live* pipe has been out of touch.
#[tokio::test]
async fn a_closed_pipe_is_closed_rather_than_idle() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let mut opts = common::serve_options();
    opts.auth = TokenPolicy::Generate;
    let serving = within(
        "serve must bind",
        Box::pin(modelpipe::serve(backend.url.as_str(), opts)),
    )
    .await
    .expect("serve");
    let device = within(
        "connect must settle",
        Box::pin(modelpipe::connect(
            &serving.ticket(),
            common::connect_options(),
        )),
    )
    .await
    .expect("connect");

    device.shutdown().await;

    assert_eq!(device.status(), PipeStatus::Closed);
    assert_eq!(
        device.idle_for(),
        None,
        "a closed pipe is not an idle one, however long it has been closed"
    );
    serving.shutdown().await;
}
