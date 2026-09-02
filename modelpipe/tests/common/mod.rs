//! Shared harness for the end-to-end tests.
//!
//! `mod common` is compiled once per integration-test binary and not every
//! binary uses every helper, so unused items are allowed here rather than
//! split into a per-consumer module.
#![allow(dead_code)]
// `pub(crate)` throughout, never `pub`: the workspace denies
// `unreachable_pub`, and a helper in a test binary has no reachable public
// path — the same rule gglib's own test fixtures follow.

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A stand-in for the model server, speaking hand-written HTTP/1.1.
///
/// Hand-rolled rather than reaching for a mock HTTP library, for the reason
/// the crate itself takes almost no dependencies: this is a few dozen lines
/// over `tokio`, which is already here, and a fake whose behaviour is
/// written down is easier to reason about than one whose behaviour is
/// configured.
///
/// Every canned response carries `Connection: close`, so the accept count
/// is exactly the request count.
pub(crate) struct MockBackend {
    pub(crate) url: String,
    /// Connections accepted. The number that distinguishes "the client was
    /// refused" from "the backend never heard about it".
    accepts: Arc<AtomicUsize>,
    /// Everything the backend was sent, one entry per connection.
    received: Arc<tokio::sync::Mutex<Vec<Vec<u8>>>>,
}

impl MockBackend {
    /// Answer every request with `response`.
    pub(crate) async fn always(response: &'static [u8]) -> Self {
        Self::spawn(move |_| response.to_vec()).await
    }

    /// Answer with a JSON body of the given status.
    pub(crate) async fn json(status: u16, body: &'static str) -> Self {
        Self::spawn(move |_| {
            format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .into_bytes()
        })
        .await
    }

    /// Answer with an SSE stream whose frames are written with a pause
    /// between them, so a buffering edge is visible as a delay rather than
    /// only as a different byte order.
    pub(crate) async fn streaming(frames: &'static [&'static str]) -> Self {
        Self::spawn_with(move |mut socket| async move {
            let mut seen = Vec::new();
            let _ = read_head(&mut socket, &mut seen).await;
            let _ = socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
                )
                .await;
            let _ = socket.flush().await;
            for frame in frames {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                let _ = socket.write_all(frame.as_bytes()).await;
                let _ = socket.flush().await;
            }
            seen
        })
        .await
    }

    async fn spawn(respond: impl Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static) -> Self {
        let respond = Arc::new(respond);
        Self::spawn_with(move |mut socket| {
            let respond = respond.clone();
            async move {
                let mut seen = Vec::new();
                let _ = read_head(&mut socket, &mut seen).await;
                let _ = socket.write_all(&respond(&seen)).await;
                let _ = socket.flush().await;
                seen
            }
        })
        .await
    }

    async fn spawn_with<F, Fut>(handle: F) -> Self
    where
        F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Vec<u8>> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accepts = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(tokio::sync::Mutex::new(Vec::new()));

        let counter = accepts.clone();
        let sink = received.clone();
        let handle = Arc::new(handle);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                let sink = sink.clone();
                let handle = handle.clone();
                tokio::spawn(async move {
                    let seen = handle(socket).await;
                    sink.lock().await.push(seen);
                });
            }
        });

        Self {
            url: format!("http://{addr}"),
            accepts,
            received,
        }
    }

    /// How many connections the backend has accepted.
    pub(crate) fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    /// Everything the backend was sent, joined.
    pub(crate) async fn received(&self) -> String {
        let seen = self.received.lock().await;
        String::from_utf8_lossy(&seen.concat()).into_owned()
    }
}

/// Read until the end of an HTTP head, plus whatever body arrived with it.
async fn read_head(socket: &mut TcpStream, into: &mut Vec<u8>) -> std::io::Result<()> {
    let mut buf = [0u8; 4096];
    loop {
        let n = socket.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        into.extend_from_slice(&buf[..n]);
        if into.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(());
        }
    }
}

/// Send one request through a connect-side listener and return the raw
/// response.
///
/// Speaks HTTP by hand rather than using a client, so that what is asserted
/// is the bytes on the wire and not a client library's interpretation.
pub(crate) async fn request(
    base_url: &str,
    path: &str,
    auth: Option<&str>,
) -> std::io::Result<String> {
    let authority = base_url
        .trim_start_matches("http://")
        .split('/')
        .next()
        .expect("authority");
    let mut socket = TcpStream::connect(authority).await?;

    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(value) = auth {
        let _ = write!(req, "Authorization: {value}\r\n");
    }
    req.push_str("\r\n");
    socket.write_all(req.as_bytes()).await?;
    socket.flush().await?;

    let mut seen = Vec::new();
    socket.read_to_end(&mut seen).await?;
    Ok(String::from_utf8_lossy(&seen).into_owned())
}

/// Wrap an await so a hung pipe fails the test rather than the suite.
pub(crate) async fn within<F: Future>(why: &str, future: F) -> F::Output {
    tokio::time::timeout(std::time::Duration::from_secs(20), future)
        .await
        .unwrap_or_else(|_| panic!("{why}"))
}
