//! Tests for [`super`] — which half of the copy gave out, and what the
//! backend is told about it.
//!
//! Split out via `#[path]` so `request_body.rs` stays inside the file-size
//! budget.
//!
//! Every test here drives [`send`] rather than [`carry`]: the fault verdict
//! and the half-close are the two things this module decides on its own,
//! and both are observable without a response ever coming back. What
//! [`carry`] does with the verdict is a property of the whole edge, so it
//! is asserted in `exchange_tests.rs`, where a real backend answers.
//!
//! No socket anywhere. `tokio::io::duplex()`'s peer sees `Ok(0)` exactly
//! where a `TcpStream`'s peer sees a FIN, which is the whole reason this
//! module is generic over its streams.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncReadExt, duplex};

use super::*;

/// Long enough that a hang is unambiguous, short enough that a broken tree
/// still finishes its test run.
const PATIENCE: Duration = Duration::from_secs(5);

/// A sink that refuses every byte, standing in for a backend that has
/// stopped reading.
struct Refusing;

impl AsyncWrite for Refusing {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Err(std::io::Error::other("the backend stopped reading")))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A sink that takes bytes happily and then fails to shut down — a socket
/// the peer has already reset, which answers `ENOTCONN`.
struct ShutdownRefused;

impl AsyncWrite for ShutdownRefused {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::NotConnected)))
    }
}

// ── Which half gave out ──────────────────────────────────────────────────

/// The case the whole module exists for. A body shorter than its declared
/// length is not a source *error* — `Buffered` reports a clean end and
/// `body::forward` synthesizes the `UnexpectedEof` afterwards — so the only
/// way to know the client was at fault is that the sink never was.
#[tokio::test]
async fn a_body_that_stops_short_is_charged_to_the_client_and_not_to_the_backend() {
    let mut source: &[u8] = b"0123456789";
    let mut from_client = Buffered::new(&mut source, Vec::new());
    let mut to_backend: Vec<u8> = Vec::new();

    let fault = send(&mut from_client, &mut to_backend, Framing::Length(1000)).await;

    assert_eq!(fault, Some(Fault::Client));
    assert_eq!(
        to_backend, b"0123456789",
        "the prefix that did arrive still goes upstream"
    );
}

/// The control for the test above, and the reason the verdict is a verdict
/// rather than a constant: the same call with the same complete body, over
/// a sink that refuses, must come back charged the other way. Without this
/// a `send` that simply always answered `Client` would pass.
#[tokio::test]
async fn a_backend_that_stops_taking_bytes_is_charged_to_the_backend_and_not_to_the_client() {
    let mut source: &[u8] = b"0123456789";
    let mut from_client = Buffered::new(&mut source, Vec::new());

    let fault = send(&mut from_client, &mut Refusing, Framing::Length(10)).await;

    assert_eq!(fault, Some(Fault::Backend));
}

/// An unreadable chunk-size line is the client's too, and it is the case
/// where the client is usually still *there* — it did not hang up, it sent
/// something this edge will not go on reading. `body::forward` reports it
/// as `ErrorKind::Other`, indistinguishable by kind from a sink failure,
/// which is why the sink is watched rather than the error inspected.
#[tokio::test]
async fn an_unreadable_chunk_size_is_charged_to_the_client() {
    let mut source: &[u8] = b"zz\r\n";
    let mut from_client = Buffered::new(&mut source, Vec::new());
    let mut to_backend: Vec<u8> = Vec::new();

    let fault = send(&mut from_client, &mut to_backend, Framing::Chunked).await;

    assert_eq!(fault, Some(Fault::Client));
}

/// `poll_shutdown` goes through the same flag as `poll_write`, so asking
/// who was at fault after attempting it would charge every client failure
/// on an already-reset connection to the backend — a 502 in place of the
/// 400 the client is owed. The ordering inside `send` is the only thing
/// preventing that, and nothing else would notice if it were swapped.
#[tokio::test]
async fn a_shutdown_that_fails_does_not_turn_a_client_fault_into_a_backend_one() {
    let mut source: &[u8] = b"0123456789";
    let mut from_client = Buffered::new(&mut source, Vec::new());

    let fault = send(
        &mut from_client,
        &mut ShutdownRefused,
        Framing::Length(1000),
    )
    .await;

    assert_eq!(
        fault,
        Some(Fault::Client),
        "the shutdown's own failure must not be read as the backend's"
    );
}

// ── What the backend is told ─────────────────────────────────────────────

/// The liveness fix itself. A backend blocked reading against a length that
/// will never arrive moves only when it sees the end of the stream, and
/// this is the assertion that it does: `read_to_end` resolves, which on a
/// duplex can only happen if `poll_shutdown` was actually called.
#[tokio::test]
async fn an_unfinishable_body_half_closes_the_upstream_write() {
    let (mut edge, mut backend) = duplex(64 * 1024);
    let mut source: &[u8] = b"0123456789";
    let mut from_client = Buffered::new(&mut source, Vec::new());

    let fault = send(&mut from_client, &mut edge, Framing::Length(1000)).await;
    assert_eq!(fault, Some(Fault::Client));

    let mut seen = Vec::new();
    tokio::time::timeout(PATIENCE, backend.read_to_end(&mut seen))
        .await
        .expect("the backend must be told the body stopped")
        .expect("no transport failure");
    assert_eq!(seen, b"0123456789");
}

/// The control for the test above, and the promise that this fix cannot
/// truncate anybody: a body that arrived whole leaves the write open, so
/// the backend goes on waiting for the answer it owes rather than being
/// told the request was abandoned.
///
/// Virtual time, so the read that must *not* resolve costs nothing. A
/// timeout expiring is the assertion here — the same shape
/// `a_peer_that_never_finishes_asking_is_timed_out` uses.
#[tokio::test(start_paused = true)]
async fn a_body_that_arrives_whole_leaves_the_upstream_write_open() {
    let (mut edge, mut backend) = duplex(64 * 1024);
    let mut source: &[u8] = b"0123456789";
    let mut from_client = Buffered::new(&mut source, Vec::new());

    let fault = send(&mut from_client, &mut edge, Framing::Length(10)).await;
    assert_eq!(fault, None, "a complete body is nobody's fault");

    let mut arrived = [0u8; 10];
    backend
        .read_exact(&mut arrived)
        .await
        .expect("the whole body arrives");
    assert_eq!(&arrived, b"0123456789");

    let mut after = [0u8; 1];
    let further = tokio::time::timeout(Duration::from_secs(30), backend.read(&mut after)).await;
    assert!(
        further.is_err(),
        "a complete body must not be followed by an end-of-stream the client never sent"
    );
}
