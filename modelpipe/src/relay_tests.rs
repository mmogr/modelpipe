//! The relay path, against a relay in this process.
//!
//! A phone on a carrier network reaches its desktop through a relay, so the
//! relayed path is the one that most needs to work. These tests run a
//! relay on loopback (`iroh::test_utils`), which `transport::bind` trusts
//! in tests despite its self-signed certificate, so none of them needs the
//! internet.

/// A relay on loopback, and the URL to hand `--relay`.
///
/// The relay runs for as long as the first half is held.
pub(crate) async fn local() -> (impl Sized, String) {
    let (_map, url, server) = iroh::test_utils::run_relay_server()
        .await
        .expect("a relay starts on loopback");
    (server, url.to_string())
}

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

use crate::{ConnectHandle, ConnectOptions, PipeStatus, ServeHandle, ServeOptions, connect, serve};

/// Long enough that a failure is a failure rather than a slow machine.
const PATIENCE: Duration = Duration::from_secs(20);

const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n";

/// A backend that answers one request with [`HEAD`] and `first`, then
/// `second` once `go` is notified, then closes.
async fn backend(first: &'static [u8], second: &'static [u8], go: Arc<Notify>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let url = format!("http://{}", listener.local_addr().expect("bound"));
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("the edge connects");
        let mut head = Vec::new();
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let mut buf = [0; 1024];
            let n = stream.read(&mut buf).await.expect("the head arrives");
            assert!(n > 0, "the edge hung up mid-head");
            head.extend_from_slice(&buf[..n]);
        }
        stream.write_all(HEAD).await.expect("written");
        stream.write_all(first).await.expect("written");
        stream.flush().await.expect("flushed");
        go.notified().await;
        stream.write_all(second).await.expect("written");
    });
    url
}

/// A pipe whose only path is the relay: the serve side has no IP transport
/// at all, so nothing can hole-punch past it.
async fn relayed(backend: &str, relay: &str) -> (ServeHandle, ConnectHandle) {
    let serving = serve(
        backend,
        ServeOptions {
            relay: Some(relay.to_owned()),
            relay_only: true,
            discovery: false,
            port_mapping: false,
            // The ticket names the relay only once it has been reached.
            wait_online: Some(PATIENCE),
            ..ServeOptions::default()
        },
    )
    .await
    .expect("serve binds against the relay");
    let connected = connect(
        &serving.ticket(),
        ConnectOptions {
            relay: Some(relay.to_owned()),
            discovery: false,
            port_mapping: false,
            ..ConnectOptions::default()
        },
    )
    .await
    .expect("connect binds");
    let path = connected
        .wait_reachable(PATIENCE)
        .await
        .expect("the serve side is reached over the relay");
    assert_eq!(path, PipeStatus::Relayed, "there is no other path to take");
    (serving, connected)
}

/// Read from `stream` until what has arrived contains `wanted`.
async fn read_until(stream: &mut TcpStream, seen: &mut Vec<u8>, wanted: &[u8]) {
    while !seen.windows(wanted.len()).any(|w| w == wanted) {
        let mut buf = [0; 1024];
        let n = stream.read(&mut buf).await.expect("the pipe reads");
        assert!(n > 0, "the pipe closed before {wanted:?} arrived: {seen:?}");
        seen.extend_from_slice(&buf[..n]);
    }
}

/// A streaming response crosses a relay-only pipe as it is written: the
/// first frame reaches the client while the backend is still holding the
/// second, which it sends only once the client has the first.
///
/// An edge that buffered the response would deadlock here, and the timeout
/// is what turns that into a failure.
#[tokio::test]
async fn a_streaming_response_crosses_a_relay_only_pipe_frame_by_frame() {
    let (_relay, relay) = local().await;
    let go = Arc::new(Notify::new());
    let backend = backend(b"data: one\n\n", b"data: two\n\n", go.clone()).await;
    let (serving, connected) = relayed(&backend, &relay).await;
    let token = serving.token().expect("a generated token");

    tokio::time::timeout(PATIENCE, async {
        let mut client = TcpStream::connect(connected.local_addr())
            .await
            .expect("the local port answers");
        client
            .write_all(
                format!(
                    "GET /v1/events HTTP/1.1\r\nHost: pipe\r\nAuthorization: Bearer {token}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("the request is written");
        let mut seen = Vec::new();
        read_until(&mut client, &mut seen, b"data: one").await;
        assert!(seen.starts_with(b"HTTP/1.1 200"), "{seen:?}");
        go.notify_one();
        read_until(&mut client, &mut seen, b"data: two").await;
    })
    .await
    .expect("each frame arrives while the backend holds the next");

    assert_eq!(connected.status(), PipeStatus::Relayed);
    assert_eq!(
        serving.peers().first().map(|peer| peer.path),
        Some(PipeStatus::Relayed),
        "the serve side sees the same path"
    );
    connected.shutdown().await;
    serving.shutdown().await;
}

/// A request with no token is refused at the far edge over the relay just
/// as it is over a direct path: the relay changes the route, not the edge.
#[tokio::test]
async fn a_request_without_the_token_is_refused_over_the_relay_too() {
    let (_relay, relay) = local().await;
    let backend = backend(b"", b"", Arc::new(Notify::new())).await;
    let (serving, connected) = relayed(&backend, &relay).await;

    let answer = tokio::time::timeout(PATIENCE, async {
        let mut client = TcpStream::connect(connected.local_addr())
            .await
            .expect("the local port answers");
        client
            .write_all(b"GET /v1/models HTTP/1.1\r\nHost: pipe\r\n\r\n")
            .await
            .expect("the request is written");
        let mut answer = Vec::new();
        client
            .read_to_end(&mut answer)
            .await
            .expect("the answer is read");
        answer
    })
    .await
    .expect("a refusal arrives");
    assert!(answer.starts_with(b"HTTP/1.1 401"), "{answer:?}");

    connected.shutdown().await;
    serving.shutdown().await;
}
