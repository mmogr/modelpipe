//! Tests for [`super`] — when the connect side's drain stops waiting on one
//! exchange, and what the request half may still do after that.
//!
//! Split out via `#[path]` so `dialer.rs` stays inside the file-size
//! budget.
//!
//! Every test drives [`relay`] over `tokio::io::duplex()`, which is why it
//! is generic over its streams: the peer of a duplex half sees `Ok(0)`
//! exactly where a socket's peer sees a FIN. Virtual time throughout, so a
//! wait that must not end costs nothing. The first two claims below are
//! also checked over a real pairing in `tests/integration_pipe.rs`; the
//! request half's bound and the early answer are checked only here.

use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, duplex};
use tokio::task::JoinHandle;

use super::*;
use crate::lifecycle::Lifecycle;

const REQUEST: &[u8] = b"GET /v1/models HTTP/1.1\r\nHost: x\r\n\r\n";

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";

/// Well inside [`REQUEST_DRAIN`], so a drain that waited out the request
/// half instead of the response cannot pass for one that did not.
const PROMPTLY: Duration = Duration::from_secs(1);

/// One exchange in flight: the local client's end of its socket, the serve
/// side's end of the stream, and the relay between them, holding a guard
/// from `lifecycle.enter()` exactly as `local_loop` hands one to `carry`.
fn exchange(
    lifecycle: &Lifecycle,
    buffer: usize,
) -> (DuplexStream, DuplexStream, JoinHandle<std::io::Result<()>>) {
    let (client, local) = duplex(buffer);
    let (serve, stream) = duplex(buffer);
    let (from_client, to_client) = tokio::io::split(local);
    let (recv, send) = tokio::io::split(stream);
    let relaying = tokio::spawn(relay(from_client, to_client, recv, send, lifecycle.enter()));
    (client, serve, relaying)
}

/// The serve side reads the request, answers in full and finishes its
/// stream; the client reads the answer to its end.
async fn answer_in_full(client: &mut DuplexStream, serve: &mut DuplexStream) {
    client.write_all(REQUEST).await.expect("the request");
    let mut asked = vec![0u8; REQUEST.len()];
    serve
        .read_exact(&mut asked)
        .await
        .expect("the request arrives");
    assert_eq!(asked, REQUEST);
    serve.write_all(RESPONSE).await.expect("the response");
    serve.shutdown().await.expect("the serve side finishes");
    let mut answered = Vec::new();
    client
        .read_to_end(&mut answered)
        .await
        .expect("the response arrives, and then its end");
    assert_eq!(answered, RESPONSE);
}

/// A client with its whole response that neither closes nor sends anything
/// more has no exchange in flight.
#[tokio::test(start_paused = true)]
async fn a_client_that_keeps_its_socket_after_the_response_does_not_hold_the_drain() {
    let lifecycle = Lifecycle::new();
    let (mut client, mut serve, _relaying) = exchange(&lifecycle, 64 * 1024);
    answer_in_full(&mut client, &mut serve).await;

    tokio::time::timeout(PROMPTLY, lifecycle.wait_until_drained())
        .await
        .expect("the response is over, so the drain must not wait on the client's socket");
    drop(client);
}

/// The other side of the same line: a response the client has not taken
/// yet is in flight, even when the client has finished sending. Its
/// half-close ends the request half first, so a guard let go when either
/// half ends would be let go here too early.
#[tokio::test(start_paused = true)]
async fn a_response_the_client_has_not_read_holds_the_drain_until_it_is_read() {
    let lifecycle = Lifecycle::new();
    // Small buffers, so the response below cannot sit in them unread.
    let (mut client, mut serve, relaying) = exchange(&lifecycle, 1024);
    client.write_all(REQUEST).await.expect("the request");
    client
        .shutdown()
        .await
        .expect("the client finishes sending");
    let mut asked = Vec::new();
    serve
        .read_to_end(&mut asked)
        .await
        .expect("the request arrives, and then its end");
    assert_eq!(asked, REQUEST);

    let large = vec![b'x'; 64 * 1024];
    let answering = tokio::spawn(async move {
        serve.write_all(&large).await.expect("the response");
        serve.shutdown().await.expect("the serve side finishes");
    });

    let waited = tokio::time::timeout(Duration::from_mins(1), lifecycle.wait_until_drained()).await;
    assert!(
        waited.is_err(),
        "the response is still being written to the client, so the drain must wait for it"
    );

    let mut answered = Vec::new();
    client
        .read_to_end(&mut answered)
        .await
        .expect("the response arrives, and then its end");
    assert_eq!(answered.len(), 64 * 1024);
    answering.await.expect("the serve side");
    tokio::time::timeout(PROMPTLY, lifecycle.wait_until_drained())
        .await
        .expect("once the response has been read, the drain must not wait");

    // The request half ended first, so there is nothing left to drain.
    let ended = tokio::time::timeout(PROMPTLY, relaying)
        .await
        .expect("a client that already finished sending gets no request drain")
        .expect("the relay task");
    assert!(ended.is_ok(), "the exchange itself went right: {ended:?}");
}

/// What is left of the exchange once the response is over has a bound,
/// and it is the one a refused client gets for the same wait.
#[tokio::test(start_paused = true)]
async fn the_request_half_outlives_the_response_by_the_refusal_drain_and_no_more() {
    let lifecycle = Lifecycle::new();
    let (mut client, mut serve, mut relaying) = exchange(&lifecycle, 64 * 1024);
    answer_in_full(&mut client, &mut serve).await;

    let early = tokio::time::timeout(
        REFUSAL_DRAIN
            .checked_sub(Duration::from_millis(1))
            .expect("a drain longer than a millisecond"),
        &mut relaying,
    )
    .await;
    assert!(
        early.is_err(),
        "the client may go on sending until the refusal drain has passed"
    );
    let ended = tokio::time::timeout(Duration::from_millis(2), &mut relaying)
        .await
        .expect("a client that keeps its socket open is let go at the refusal drain")
        .expect("the relay task");
    assert!(ended.is_ok(), "the exchange itself went right: {ended:?}");
    drop(client);
}

/// A backend may answer before the request body is over. The answer
/// arrives whole, the drain stops waiting once it has, and what the client
/// sends after it still goes up, byte for byte, until its own end.
#[tokio::test(start_paused = true)]
async fn an_early_answer_arrives_whole_and_the_rest_of_the_body_still_goes_up() {
    let lifecycle = Lifecycle::new();
    let (mut client, mut serve, relaying) = exchange(&lifecycle, 64 * 1024);
    let head: &[u8] =
        b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n";
    client.write_all(head).await.expect("the head");
    client.write_all(b"01234").await.expect("half the body");

    let mut asked = vec![0u8; head.len() + 5];
    serve
        .read_exact(&mut asked)
        .await
        .expect("the head and half the body");
    assert_eq!(asked, [head, b"01234"].concat());
    let early: &[u8] =
        b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    serve.write_all(early).await.expect("the early answer");
    serve.shutdown().await.expect("the serve side finishes");

    let mut answered = Vec::new();
    client
        .read_to_end(&mut answered)
        .await
        .expect("the answer arrives, and then its end");
    assert_eq!(answered, early);
    tokio::time::timeout(PROMPTLY, lifecycle.wait_until_drained())
        .await
        .expect("the answer is out, so the drain must not wait on the upload");

    client
        .write_all(b"56789")
        .await
        .expect("the rest of the body");
    client
        .shutdown()
        .await
        .expect("the client finishes sending");
    let mut rest = Vec::new();
    serve
        .read_to_end(&mut rest)
        .await
        .expect("the rest of the body arrives, and then its end");
    assert_eq!(rest, b"56789");

    let ended = tokio::time::timeout(PROMPTLY, relaying)
        .await
        .expect("the request half ends on the client's own end, inside the drain")
        .expect("the relay task");
    assert!(ended.is_ok(), "the exchange itself went right: {ended:?}");
}
