//! The pipe, end to end, over a real iroh connection.
//!
//! Everything below runs two endpoints on one machine and pairs them with a
//! real ticket. That is the point: every layer beneath has been tested in
//! isolation, and this is where the claim "the README's first code block is
//! true" is either demonstrated or not.
//!
//! These are also the only tests that can check the asymmetry the product
//! is built on — that restarting the listener rotates the ticket while
//! rotating the token leaves every pairing intact — because it is a
//! statement about two live sides, not about either one.

mod common;

use std::time::Duration;

use common::{MockBackend, request, within};
use modelpipe::{ConnectOptions, PipeStatus, ServeOptions, Ticket, TokenPolicy};

const OK_BODY: &str = r#"{"object":"list","data":[]}"#;

/// Bring up a listener over `backend`, and a connect side paired to it.
async fn paired(
    backend: &MockBackend,
    auth: TokenPolicy,
) -> (modelpipe::ServeHandle, modelpipe::ConnectHandle, String) {
    let mut serve_opts = ServeOptions::default();
    serve_opts.auth = auth;
    // Boxed: binding an iroh endpoint is a large future, and holding one
    // inline in a test that also holds the connect side pushes the whole
    // task's frame past what clippy's nursery is willing to see on a stack.
    let serving = within(
        "serve must bind",
        Box::pin(modelpipe::serve(&backend.url, serve_opts)),
    )
    .await
    .expect("serve");

    let ticket = serving.ticket();
    let connected = within(
        "connect must pair with the listener",
        Box::pin(modelpipe::connect(&ticket, ConnectOptions::default())),
    )
    .await
    .expect("connect");

    let url = connected.base_url();
    (serving, connected, url)
}

fn bearer(handle: &modelpipe::ServeHandle) -> String {
    format!("Bearer {}", handle.token().expect("a token is enforced"))
}

// ── The first byte ───────────────────────────────────────────────────────

/// The README's first code block, made true.
#[tokio::test]
async fn a_request_crosses_the_pipe_and_the_response_comes_back() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let (serving, connected, url) = paired(&backend, TokenPolicy::Generate).await;

    let response = within(
        "a request must cross the pipe",
        request(&url, "/v1/models", Some(&bearer(&serving))),
    )
    .await
    .expect("request");

    assert!(response.starts_with("HTTP/1.1 200 OK"), "got: {response}");
    assert!(
        response.contains(OK_BODY),
        "the body must arrive: {response}"
    );
    assert_eq!(
        backend.accepts(),
        1,
        "and the backend served it exactly once"
    );

    let sent = backend.received().await;
    assert!(sent.contains("GET /v1/models"), "the path survives: {sent}");
    assert!(
        sent.contains(&format!(
            "Host: {}",
            backend.url.trim_start_matches("http://")
        )),
        "the Host names the backend: {sent}"
    );

    connected.shutdown().await;
    serving.shutdown().await;
}

/// `base_url` is meant to be pasted into a client, so it must be a URL
/// pointing at something that answers.
#[tokio::test]
async fn the_base_url_is_something_a_client_can_actually_use() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let (serving, connected, url) = paired(&backend, TokenPolicy::Generate).await;

    assert!(
        url.starts_with("http://127.0.0.1:"),
        "loopback by default: {url}"
    );
    assert!(url.ends_with("/v1"), "and the OpenAI base path: {url}");
    assert_eq!(
        connected.local_addr().to_string(),
        url.trim_start_matches("http://").trim_end_matches("/v1"),
        "the URL names the port actually bound"
    );

    connected.shutdown().await;
    serving.shutdown().await;
}

// ── Auth, at the far end of a real connection ────────────────────────────

/// The claim the crate is built on, checked across the whole pipe rather
/// than at the edge in isolation: a refused request never becomes a backend
/// connection.
#[tokio::test]
async fn an_unauthorized_request_never_reaches_the_backend() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let (serving, connected, url) = paired(&backend, TokenPolicy::Generate).await;

    for auth in [None, Some("Bearer wrong"), Some("Basic whatever")] {
        let response = within("a refusal must arrive", request(&url, "/v1/models", auth))
            .await
            .expect("request");
        assert!(
            response.starts_with("HTTP/1.1 401"),
            "{auth:?} must be refused: {response}"
        );
    }
    assert_eq!(
        backend.accepts(),
        0,
        "after three refused requests the backend was never contacted"
    );

    connected.shutdown().await;
    serving.shutdown().await;
}

/// Serving open is a deliberate configuration, and the flag's name is the
/// warning rather than a second check.
#[tokio::test]
async fn serving_open_forwards_without_a_credential() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let (serving, connected, url) = paired(&backend, TokenPolicy::InsecureNoAuth).await;

    assert_eq!(serving.token(), None, "there is no token to report");
    let response = within("must forward", request(&url, "/v1/models", None))
        .await
        .expect("request");
    assert!(response.starts_with("HTTP/1.1 200"), "got: {response}");

    connected.shutdown().await;
    serving.shutdown().await;
}

// ── The asymmetry ────────────────────────────────────────────────────────

/// Half of the product's rotation story, and the half only two live sides
/// can demonstrate: **the token rotates in place**. The ticket does not
/// change, the pairing stays up, and the next request needs the new value.
#[tokio::test]
async fn rotating_the_token_leaves_the_ticket_and_the_live_pairing_intact() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let (serving, connected, url) = paired(&backend, TokenPolicy::Generate).await;

    let ticket_before = serving.ticket().to_string();
    let old = bearer(&serving);
    assert!(
        within("first request", request(&url, "/v1/models", Some(&old)))
            .await
            .expect("request")
            .starts_with("HTTP/1.1 200")
    );

    let fresh = serving.rotate_token();
    assert_eq!(
        serving.ticket().to_string(),
        ticket_before,
        "rotating a token must not disturb the ticket"
    );

    let refused = within("old credential", request(&url, "/v1/models", Some(&old)))
        .await
        .expect("request");
    assert!(
        refused.starts_with("HTTP/1.1 401"),
        "the old token dies immediately: {refused}"
    );

    let accepted = within(
        "new credential",
        request(&url, "/v1/models", Some(&format!("Bearer {fresh}"))),
    )
    .await
    .expect("request");
    assert!(
        accepted.starts_with("HTTP/1.1 200"),
        "and the same pairing carries the new one: {accepted}"
    );

    connected.shutdown().await;
    serving.shutdown().await;
}

/// `set_token` is how a `Supplied` embedder propagates a rotation of a key
/// its own backend already knows.
#[tokio::test]
async fn a_supplied_credential_can_be_replaced_in_place() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let (serving, connected, url) =
        paired(&backend, TokenPolicy::Supplied("first-key".to_owned())).await;

    assert_eq!(serving.token().as_deref(), Some("first-key"));
    serving.set_token("second-key".to_owned());

    assert!(
        within("old", request(&url, "/v1/models", Some("Bearer first-key")))
            .await
            .expect("request")
            .starts_with("HTTP/1.1 401")
    );
    assert!(
        within(
            "new",
            request(&url, "/v1/models", Some("Bearer second-key"))
        )
        .await
        .expect("request")
        .starts_with("HTTP/1.1 200")
    );

    connected.shutdown().await;
    serving.shutdown().await;
}

/// The other half: **restarting the listener rotates the ticket**, and the
/// old one does not merely fail authentication — it reaches nobody, because
/// the endpoint key is ephemeral and the restarted process is a different
/// endpoint entirely.
#[tokio::test]
async fn restarting_the_listener_mints_a_ticket_the_old_one_cannot_impersonate() {
    let backend = MockBackend::json(200, OK_BODY).await;

    let first = within(
        "serve",
        Box::pin(modelpipe::serve(&backend.url, ServeOptions::default())),
    )
    .await
    .expect("serve");
    let old_ticket = first.ticket().to_string();
    first.shutdown().await;
    drop(first);

    let second = within(
        "serve again",
        Box::pin(modelpipe::serve(&backend.url, ServeOptions::default())),
    )
    .await
    .expect("serve");
    let new_ticket = second.ticket().to_string();

    assert_ne!(
        old_ticket, new_ticket,
        "a restart must mint a different ticket"
    );
    let old: Ticket = old_ticket.parse().expect("the old ticket still parses");
    let new: Ticket = new_ticket.parse().expect("parses");
    assert_ne!(
        old.fingerprint(),
        new.fingerprint(),
        "and a different identity, not merely different addresses"
    );

    second.shutdown().await;
}

// ── Streaming ────────────────────────────────────────────────────────────

/// The product is a token stream. A buffering pipe would return the same
/// bytes with the same status and pass every test above.
#[tokio::test]
async fn a_streaming_response_arrives_as_it_is_produced() {
    let backend =
        MockBackend::streaming(&["data: one\n\n", "data: two\n\n", "data: [DONE]\n\n"]).await;
    let (serving, connected, url) = paired(&backend, TokenPolicy::Generate).await;

    let started = std::time::Instant::now();
    let response = within(
        "the stream must complete",
        request(&url, "/v1/chat/completions", Some(&bearer(&serving))),
    )
    .await
    .expect("request");

    assert!(response.contains("data: one"), "got: {response}");
    assert!(response.contains("data: [DONE]"), "got: {response}");
    assert!(
        started.elapsed() >= Duration::from_millis(60),
        "the backend paused between frames, so a response that arrived \
         instantly would mean the frames were produced before being sent"
    );

    connected.shutdown().await;
    serving.shutdown().await;
}

// ── Status and teardown ──────────────────────────────────────────────────

#[tokio::test]
async fn a_shutdown_pipe_reports_closed_and_never_blocks_a_watcher() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let (serving, connected, _url) = paired(&backend, TokenPolicy::Generate).await;

    serving.shutdown().await;
    assert_eq!(serving.status(), PipeStatus::Closed);
    assert_eq!(
        within(
            "a closed pipe must not block a watcher",
            serving.status_changed()
        )
        .await,
        PipeStatus::Closed
    );

    connected.shutdown().await;
    assert_eq!(connected.status(), PipeStatus::Closed);
}

/// `shutdown` completing must mean the port is free, not merely that the
/// status says `Closed` — otherwise a caller that rebinds immediately gets
/// `EADDRINUSE`.
#[tokio::test]
async fn a_completed_shutdown_releases_the_local_port() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let (serving, connected, _url) = paired(&backend, TokenPolicy::Generate).await;
    let port = connected.local_addr();

    connected.shutdown().await;
    drop(connected);

    tokio::net::TcpListener::bind(port)
        .await
        .expect("the port must be free the moment shutdown returns");

    serving.shutdown().await;
}

#[tokio::test]
async fn shutting_down_twice_is_harmless() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let (serving, connected, _url) = paired(&backend, TokenPolicy::Generate).await;

    serving.shutdown().await;
    within("the second call must not hang", serving.shutdown()).await;
    connected.shutdown().await;
    within("nor on the connect side", connected.shutdown()).await;
}
