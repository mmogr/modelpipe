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

use common::{MockBackend, Scratch, request, within};
use modelpipe::{ConnectOptions, PipeStatus, ServeOptions, Ticket, TokenPolicy};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

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
    serving
        .set_token("second-key".to_owned())
        .expect("a usable token is installed");

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

// ── Teardown, observed rather than announced ─────────────────────────────

/// `shutdown` drains rather than cuts, and the only way to see the
/// difference is to have something in flight while it runs.
///
/// Every teardown assertion before this one checked that the status became
/// `Closed` — which `lifecycle.close()` sets with no transport involved —
/// so reducing `listener::shutdown` to `close(); mark_torn_down();` left
/// the whole suite green. Measured before the order was corrected: the
/// client was cut at frame 5 of 200.
#[tokio::test]
async fn a_serve_shutdown_lets_an_admitted_request_finish() {
    let backend = MockBackend::streaming(&[
        "data: one\n\n",
        "data: two\n\n",
        "data: three\n\n",
        "data: [DONE]\n\n",
    ])
    .await;
    let (serving, connected, url) = paired(&backend, TokenPolicy::Generate).await;
    let auth = bearer(&serving);
    let authority = url
        .trim_start_matches("http://")
        .trim_end_matches("/v1")
        .to_owned();

    // Start the request and wait until the first frame has arrived, so the
    // exchange is provably admitted and provably unfinished.
    let reading = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut socket = tokio::net::TcpStream::connect(&authority)
            .await
            .expect("connect");
        socket
            .write_all(
                format!(
                    "GET /v1/chat/completions HTTP/1.1\r\nHost: x\r\n\
                     Authorization: {auth}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("write");
        let mut seen = Vec::new();
        socket.read_to_end(&mut seen).await.expect("read");
        String::from_utf8_lossy(&seen).into_owned()
    });
    tokio::time::sleep(Duration::from_millis(40)).await;

    within("the drain must not hang", serving.shutdown()).await;

    let body = within("the admitted request must complete", reading)
        .await
        .expect("reader");
    assert!(
        body.contains("data: [DONE]"),
        "shutdown promises the drain, so an admitted request runs to \
         completion; the client got: {body}"
    );

    connected.shutdown().await;
}

/// One accepted-but-silent TCP connection must not hold the drain open.
///
/// This is what every `OpenAI` SDK does on its first call — open the socket,
/// then think — and what any health probe does deliberately. The in-flight
/// guard used to be taken at accept, and `copy_bidirectional` never returns
/// for a socket that says nothing, so a single one wedged `shutdown`
/// permanently. In the CLI that is unrecoverable: tokio keeps the SIGINT
/// handler installed, so the second Ctrl-C is swallowed too.
#[tokio::test]
async fn an_idle_local_connection_does_not_wedge_the_connect_side_drain() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let (serving, connected, url) = paired(&backend, TokenPolicy::Generate).await;
    let authority = url
        .trim_start_matches("http://")
        .trim_end_matches("/v1")
        .to_owned();

    let _idle = tokio::net::TcpStream::connect(&authority)
        .await
        .expect("an SDK preconnect");
    tokio::time::sleep(Duration::from_millis(50)).await;

    within(
        "one silent connection must not hold the drain open",
        connected.shutdown(),
    )
    .await;

    serving.shutdown().await;
}

/// `shutdown_timeout` returning must mean the port is free, exactly as
/// `shutdown` does — and it must leave a later `shutdown` able to say the
/// same. It used to set the teardown latch itself while the accept loop
/// still owned the listener, so it returned `true` with the port bound and
/// poisoned the latch for every call after it.
#[tokio::test]
async fn a_connect_shutdown_timeout_releases_the_port_and_leaves_the_latch_honest() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let (serving, connected, _url) = paired(&backend, TokenPolicy::Generate).await;
    let port = connected.local_addr();

    let drained = within(
        "nothing is in flight, so the drain must succeed",
        connected.shutdown_timeout(Duration::from_secs(5)),
    )
    .await;
    assert!(drained, "there was nothing to wait for");
    tokio::net::TcpListener::bind(port)
        .await
        .expect("the port must be free the moment shutdown_timeout returns");

    // And the promise survives: a later `shutdown` must not resolve against
    // a latch someone else already set.
    within("a second call must not hang", connected.shutdown()).await;
    serving.shutdown().await;
}

/// A live pairing reports the path it is actually using, on both sides.
///
/// The connect side published no status at all: `Direct` and `Relayed` were
/// unreachable there, so `status()` said `Idle` on a working pipe and
/// `status_changed()` never fired. Deleting the serve side's peer
/// registration — the crate's only other producer — also left the suite
/// green, because every other status assertion checks only `Closed`.
#[tokio::test]
async fn a_live_pairing_reports_a_transport_path_on_both_sides() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let (serving, connected, url) = paired(&backend, TokenPolicy::Generate).await;

    within(
        "a request must cross the pipe",
        request(&url, "/v1/models", Some(&bearer(&serving))),
    )
    .await
    .expect("request");

    for (side, status) in [("serve", serving.status()), ("connect", connected.status())] {
        assert!(
            matches!(status, PipeStatus::Direct | PipeStatus::Relayed),
            "the {side} side is carrying traffic and reports {status:?}"
        );
    }

    connected.shutdown().await;
    serving.shutdown().await;
}

// ── Cancellation ─────────────────────────────────────────────────────────

/// The failure that is invisible to every other test in this file.
///
/// A client that hangs up mid-generation must take the backend's work with
/// it. If it does not, the model keeps producing tokens for a request
/// nobody is waiting for — and every functional assertion still passes,
/// because the request "worked". The only way to see it is to count what
/// the backend produced after the client left.
#[tokio::test]
async fn a_client_that_disconnects_mid_stream_stops_the_backend() {
    let (backend, frames_written) = MockBackend::endless_stream().await;
    let (serving, connected, url) = paired(&backend, TokenPolicy::Generate).await;

    let authority = url
        .trim_start_matches("http://")
        .trim_end_matches("/v1")
        .to_owned();
    let auth = bearer(&serving);

    // Open a request, read enough to know the stream is flowing, then hang
    // up without reading the rest.
    {
        let mut socket = tokio::net::TcpStream::connect(&authority)
            .await
            .expect("connect");
        let request = format!(
            "GET /v1/chat/completions HTTP/1.1\r\nHost: {authority}\r\n\
             Authorization: {auth}\r\n\r\n"
        );
        tokio::io::AsyncWriteExt::write_all(&mut socket, request.as_bytes())
            .await
            .expect("write");

        let mut seen = vec![0u8; 64];
        within(
            "the stream must start",
            tokio::io::AsyncReadExt::read(&mut socket, &mut seen),
        )
        .await
        .expect("read");
        // Dropped here: the client is gone mid-generation.
    }

    // Let the news travel, then see whether the backend is still producing.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let after_disconnect = frames_written.load(std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let later = frames_written.load(std::sync::atomic::Ordering::SeqCst);

    assert_eq!(
        later,
        after_disconnect,
        "the backend produced {} more frames after the client left; a \
         cancelled request must not leave a generation running",
        later - after_disconnect
    );

    connected.shutdown().await;
    serving.shutdown().await;
}

// ── Connection reuse ─────────────────────────────────────────────────────

/// One bi-stream carries one exchange, so a client must not put a second
/// request on the same local connection — it would go down a stream the
/// serve side has finished with, and hang until the client's timeout.
///
/// Real `OpenAI` clients pool connections by default, so this is not an edge
/// case: it is what the first SDK to point at modelpipe would do. Telling
/// the client is the whole mechanism, and it is one header.
#[tokio::test]
async fn a_response_tells_the_client_not_to_reuse_the_connection() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let (serving, connected, url) = paired(&backend, TokenPolicy::Generate).await;

    let response = within(
        "a request must cross the pipe",
        request(&url, "/v1/models", Some(&bearer(&serving))),
    )
    .await
    .expect("request");

    assert!(
        response.to_ascii_lowercase().contains("connection: close"),
        "a pooling client will otherwise send its next request down a \
         stream nobody is reading: {response}"
    );

    connected.shutdown().await;
    serving.shutdown().await;
}

/// A listener restarted with a stored identity keeps the ticket it had.
///
/// The other half of the asymmetry, and the one that was not previously
/// available at any price. `restarting_the_listener_mints_a_ticket_the_old
/// _one_cannot_impersonate` above pins the default — a fresh key per
/// process, so a restart re-pairs every device — and this pins the opt-out.
///
/// What is compared is the fingerprint, which is the identity and nothing
/// else — the addresses beside it in a ticket are hints for avoiding the
/// relay, and a restarted process holds a different UDP port regardless.
/// It is a prefix rather than the whole key because that is what the public
/// surface offers, and it is the value a person compares by eye for exactly
/// this question; the full-key form of the claim is
/// `the_same_key_binds_to_the_same_endpoint_and_a_different_one_does_not`
/// in `transport_tests.rs`, where the bytes are reachable.
///
/// Reaching the restarted listener's *new port* with the old ticket is then
/// iroh's discovery doing its job, over a network this suite deliberately
/// does not require. The claim owned here is the one this crate can be
/// wrong about: that the key comes back, and the ticket still names this
/// listener.
#[tokio::test]
async fn a_listener_restarted_with_a_stored_identity_keeps_its_ticket() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let scratch = Scratch::new("identity");
    let key = scratch.join("key");

    let mut first = ServeOptions::default();
    first.identity = Some(key.clone());
    let before = within(
        "serve must bind",
        Box::pin(modelpipe::serve(&backend.url, first)),
    )
    .await
    .expect("serve");
    let ticket_before = before.ticket();
    before.shutdown().await;

    let mut second = ServeOptions::default();
    second.identity = Some(key.clone());
    let after = within(
        "the restarted listener must bind",
        Box::pin(modelpipe::serve(&backend.url, second)),
    )
    .await
    .expect("serve");
    let ticket_after = after.ticket();

    assert_eq!(
        ticket_before.fingerprint(),
        ticket_after.fingerprint(),
        "a stored identity is what makes a ticket outlive the process"
    );

    after.shutdown().await;
}

/// The control, and the promise that the default has not quietly changed:
/// without a stored identity the restarted listener is a different peer, as
/// it has always been.
#[tokio::test]
async fn a_listener_restarted_without_one_is_a_different_peer_as_before() {
    let backend = MockBackend::json(200, OK_BODY).await;

    let before = within(
        "serve must bind",
        Box::pin(modelpipe::serve(&backend.url, ServeOptions::default())),
    )
    .await
    .expect("serve");
    let ticket_before = before.ticket();
    before.shutdown().await;

    let after = within(
        "serve must bind again",
        Box::pin(modelpipe::serve(&backend.url, ServeOptions::default())),
    )
    .await
    .expect("serve");

    assert_ne!(
        ticket_before.fingerprint(),
        after.ticket().fingerprint(),
        "the default stays ephemeral, which is the revocation the README sells"
    );

    after.shutdown().await;
}

/// An identity file the operator cannot use stops the listener before it
/// starts, rather than after — which would mean finding out as a ticket
/// that is not the one they expected, on a listener already accepting.
#[tokio::test]
async fn an_unusable_identity_refuses_to_serve_at_all() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let scratch = Scratch::new("bad-identity");
    let key = scratch.join("key");
    std::fs::write(&key, "not a key\n").expect("write");

    let mut opts = ServeOptions::default();
    opts.identity = Some(key);
    let refused = within(
        "serve must refuse rather than hang",
        Box::pin(modelpipe::serve(&backend.url, opts)),
    )
    .await;

    let Err(refused) = refused else {
        panic!("an unusable identity must not start a listener");
    };
    assert!(!refused.is_retryable(), "the operator named this path");
    assert_eq!(backend.accepts(), 0, "and nothing was served");
}

/// A rotation that cannot be presented is refused *and reported*, with the
/// credential already in force left exactly where it was.
///
/// The silent version of this is the dangerous one, and it is the one that
/// shipped: a rotation reads its replacement from somewhere — a config
/// file, a secrets fetch, an environment variable — and when that somewhere
/// comes back blank an embedder who is told nothing believes the old key is
/// dead and retires it everywhere else, while this listener goes on
/// accepting it. A credential the operator thinks is revoked and is not.
/// `serve` has always refused the same value loudly.
///
/// Its negative control is `a_supplied_credential_can_be_replaced_in_place`
/// above: that one proves a usable token really does displace the old one,
/// so this cannot pass by `set_token` having stopped working at all.
#[tokio::test]
async fn a_refused_rotation_reports_it_and_leaves_the_previous_credential_in_force() {
    let backend = MockBackend::json(200, OK_BODY).await;
    let (serving, connected, url) =
        paired(&backend, TokenPolicy::Supplied("the-only-key".to_owned())).await;

    for blank in ["", "   ", "\t\n"] {
        assert!(
            serving.set_token(blank.to_owned()).is_err(),
            "{blank:?} is a credential no conforming client could ever send"
        );
    }

    assert_eq!(
        serving.token().as_deref(),
        Some("the-only-key"),
        "the handle still reports what it is actually enforcing"
    );
    assert!(
        within(
            "the key the operator may now believe is dead",
            request(&url, "/v1/models", Some("Bearer the-only-key")),
        )
        .await
        .expect("request")
        .starts_with("HTTP/1.1 200"),
        "and it is still the key that works"
    );

    connected.shutdown().await;
    serving.shutdown().await;
}

/// An upload that stops mid-body must not hold the drain open.
///
/// The unit tests pin the answer the edge gives; this pins the consequence
/// that made it a release blocker. A wedged exchange never releases its
/// in-flight guard, and `shutdown` waits on precisely that — so one aborted
/// upload made the first Ctrl-C on `modelpipe serve` hang while the second
/// cut the pipe, taking every other request with it.
///
/// Measured, before the two halves were told apart: still running at twenty
/// seconds, against one second for the same shutdown with only ordinary
/// traffic in flight. Its negative control is
/// `a_serve_shutdown_lets_an_admitted_request_finish` above — that one
/// proves the drain still waits for work genuinely in progress, so this one
/// cannot pass by `shutdown` having been reduced to a cut.
#[tokio::test]
async fn an_aborted_upload_does_not_wedge_the_serve_side_drain() {
    let backend = MockBackend::reads_whole_body(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    )
    .await;
    let (serving, connected, url) = paired(&backend, TokenPolicy::Generate).await;
    let authority = url
        .trim_start_matches("http://")
        .trim_end_matches("/v1")
        .to_owned();

    let mut socket = tokio::net::TcpStream::connect(&authority)
        .await
        .expect("a client");
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: {authority}\r\n\
         Authorization: {}\r\nContent-Length: 1000\r\n\r\n{{\"model\":\"",
        bearer(&serving)
    );
    socket
        .write_all(request.as_bytes())
        .await
        .expect("the head and a tenth of the body");
    socket.flush().await.expect("flush");
    // Half-close, not a full one: the upload is over and the client is
    // still listening, which is what an interrupted `curl -d @file` leaves
    // behind.
    socket.shutdown().await.expect("half-close");

    let reader = tokio::spawn(async move {
        let mut seen = Vec::new();
        let _ = socket.read_to_end(&mut seen).await;
        String::from_utf8_lossy(&seen).into_owned()
    });
    // Long enough for the exchange to be admitted and registered in flight,
    // which is what makes this a test of the drain rather than of an empty
    // one.
    tokio::time::sleep(Duration::from_millis(50)).await;

    within(
        "an aborted upload must not hold the serve-side drain open",
        serving.shutdown(),
    )
    .await;

    let seen = reader.await.expect("the reader task");
    assert!(
        seen.starts_with("HTTP/1.1 400"),
        "and the client is told, rather than left with an empty stream: {seen}"
    );

    connected.shutdown().await;
}
