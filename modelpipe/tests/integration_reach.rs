//! Waiting for a connect side to reach its serve side, over a real pipe.
//!
//! The pipes here run with discovery and port mapping off on both sides, as
//! in `integration_identity.rs`, so the ticket's own paths are the only ones
//! and nothing contacts n0.

mod common;

use std::time::Duration;

use common::{MockBackend, within};
use modelpipe::{
    CloseReason, ConnectHandle, PipeStatus, ServeHandle, Ticket, TokenPolicy, Unreached,
};

const OK_BODY: &str = r#"{"object":"list","data":[]}"#;

/// A listener over `backend`, with discovery and port mapping off.
async fn listening(backend: &MockBackend) -> ServeHandle {
    let mut opts = common::serve_options();
    opts.auth = TokenPolicy::Generate;
    within(
        "serve must bind",
        Box::pin(modelpipe::serve(&backend.url, opts)),
    )
    .await
    .expect("serve")
}

/// A connect side dialling `ticket`, with discovery and port mapping off.
async fn dialling(ticket: &Ticket) -> ConnectHandle {
    let opts = common::connect_options();
    within(
        "connect must bind",
        Box::pin(modelpipe::connect(ticket, opts)),
    )
    .await
    .expect("connect")
}

/// The ticket of a serve side that has been shut down: a peer nobody is.
async fn a_ticket_nobody_answers(backend: &MockBackend) -> Ticket {
    let serving = listening(backend).await;
    let ticket = serving.ticket();
    serving.shutdown().await;
    ticket
}

#[tokio::test]
async fn a_wait_for_a_serve_side_that_is_there_returns_the_path() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let serving = listening(&backend).await;
    let connected = dialling(&serving.ticket()).await;

    let path = connected
        .wait_reachable(Duration::from_secs(20))
        .await
        .expect("the serve side is right there");
    assert!(
        matches!(path, PipeStatus::Direct | PipeStatus::Relayed),
        "{path:?}"
    );

    // A pipe already reached has nothing left to wait for.
    let again = tokio::time::timeout(
        Duration::from_secs(1),
        connected.wait_reachable(Duration::from_secs(20)),
    )
    .await
    .expect("a second wait returns at once");
    assert!(
        matches!(again, Ok(PipeStatus::Direct | PipeStatus::Relayed)),
        "{again:?}"
    );

    connected.shutdown().await;
    serving.shutdown().await;
}

#[tokio::test]
async fn a_wait_that_runs_out_leaves_the_pipe_trying() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let ticket = a_ticket_nobody_answers(&backend).await;
    let connected = dialling(&ticket).await;

    let within = Duration::from_millis(300);
    assert_eq!(
        connected.wait_reachable(within).await,
        Err(Unreached::TimedOut(within))
    );
    assert_eq!(connected.status(), PipeStatus::Idle, "still looking");
    assert_eq!(connected.close_reason(), None, "and not closed");

    connected.shutdown().await;
}

#[tokio::test]
async fn a_pipe_shut_down_mid_wait_ends_the_wait_with_its_reason() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let ticket = a_ticket_nobody_answers(&backend).await;
    let connected = dialling(&ticket).await;
    let shut = Err(Unreached::Closed(Some(CloseReason::Shutdown)));

    let (waited, ()) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(connected.wait_reachable(Duration::from_mins(1)), async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            connected.shutdown().await;
        })
    })
    .await
    .expect("the close ends the wait, not its minute");
    assert_eq!(waited, shut);

    let after = tokio::time::timeout(
        Duration::from_secs(1),
        connected.wait_reachable(Duration::from_mins(1)),
    )
    .await
    .expect("a wait on a closed pipe returns at once");
    assert_eq!(after, shut);
}
