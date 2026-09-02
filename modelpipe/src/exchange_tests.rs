//! Tests for [`super`] — the authentication edge, end to end.
//!
//! Split out via `#[path]` so `exchange.rs` stays inside the file-size
//! budget.
//!
//! Every test here runs over `tokio::io::duplex()`. There is no socket, no
//! port and no peer, which is the whole reason this module is generic over
//! its streams — the security-critical path is fully exercised before the
//! transport exists.
//!
//! The backend is hand-written and counts how often it is asked for a
//! connection. That counter is the point: a 401 proves the client was
//! refused, and only the counter proves the backend never heard about it.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use super::*;
use crate::credential::TokenPolicy;

const TOKEN: &str = "sk-zzq-the-credential";
const OK_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";

/// A backend that records how often it was connected to and what arrived.
///
/// Modelled on the counting stub gglib uses for the same job: a status code
/// says the request was refused, and only a counter says the work never
/// happened. Those are different promises and this crate sells the second.
struct CountingBackend {
    connects: Arc<AtomicUsize>,
    response: Vec<u8>,
    received: Arc<Mutex<Vec<JoinHandle<Vec<u8>>>>>,
}

impl CountingBackend {
    fn new(response: &[u8]) -> Self {
        Self {
            connects: Arc::new(AtomicUsize::new(0)),
            response: response.to_vec(),
            received: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn connects(&self) -> usize {
        self.connects.load(Ordering::SeqCst)
    }

    /// Everything the backend was sent, once the exchange has finished and
    /// dropped its end.
    async fn received(&self) -> Vec<u8> {
        // The guard is released before awaiting the tasks: holding a lock
        // across an await that waits on something which might want it is how
        // a test deadlocks intermittently.
        let taken: Vec<_> = self.received.lock().await.drain(..).collect();
        let mut out = Vec::new();
        for handle in taken {
            out.extend_from_slice(&handle.await.expect("backend task"));
        }
        out
    }
}

impl Backend for CountingBackend {
    type Stream = DuplexStream;

    fn authority(&self) -> &'static str {
        "127.0.0.1:11434"
    }

    async fn connect(&self) -> std::io::Result<DuplexStream> {
        self.connects.fetch_add(1, Ordering::SeqCst);
        let (mine, mut theirs) = duplex(64 * 1024);
        let response = self.response.clone();
        let handle = tokio::spawn(async move {
            // Written before reading: the duplex is buffered, so this sits
            // there until the edge asks for it, and nothing deadlocks.
            let _ = theirs.write_all(&response).await;
            let _ = theirs.flush().await;
            let mut seen = Vec::new();
            let _ = theirs.read_to_end(&mut seen).await;
            seen
        });
        self.received.lock().await.push(handle);
        Ok(mine)
    }
}

/// A backend that hands over one prepared stream, for the case where the
/// test needs to drive the backend side by hand. Declared at module scope
/// because an item after a statement inside a test body is a clippy error.
struct Fixed(Mutex<Option<DuplexStream>>);

impl Backend for Fixed {
    type Stream = DuplexStream;

    fn authority(&self) -> &'static str {
        "127.0.0.1:11434"
    }

    async fn connect(&self) -> std::io::Result<DuplexStream> {
        Ok(self.0.lock().await.take().expect("connected once"))
    }
}

/// Run one exchange against a fresh client stream, returning what the
/// client saw.
async fn exchange(
    request: &[u8],
    policy: &TokenPolicy,
    backend: &CountingBackend,
) -> (Outcome, Vec<u8>) {
    let (mut client, mut edge) = duplex(64 * 1024);
    client.write_all(request).await.unwrap();
    client.shutdown().await.unwrap();

    let (credential, _) = Credential::new(policy);
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        serve_exchange(&mut edge, &credential, backend),
    )
    .await
    .expect("the exchange must not hang")
    .expect("no transport failure");

    drop(edge);
    let mut seen = Vec::new();
    client.read_to_end(&mut seen).await.unwrap();
    (outcome, seen)
}

fn get(auth: Option<&str>) -> Vec<u8> {
    let mut req = b"GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n".to_vec();
    if let Some(value) = auth {
        req.extend_from_slice(format!("Authorization: {value}\r\n").as_bytes());
    }
    req.extend_from_slice(b"\r\n");
    req
}

fn supplied() -> TokenPolicy {
    TokenPolicy::Supplied(TOKEN.to_owned())
}

// ── Admitted ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_authorized_request_reaches_the_backend_and_the_response_comes_back() {
    let backend = CountingBackend::new(OK_RESPONSE);
    let (outcome, seen) = exchange(
        &get(Some(&format!("Bearer {TOKEN}"))),
        &supplied(),
        &backend,
    )
    .await;

    assert_eq!(outcome, Outcome::Forwarded);
    assert_eq!(backend.connects(), 1);
    assert!(
        String::from_utf8_lossy(&seen).starts_with("HTTP/1.1 200 OK"),
        "the backend's response reaches the client: {}",
        String::from_utf8_lossy(&seen)
    );
}

/// Serving open is a configuration, not the absence of a check.
#[tokio::test]
async fn serving_open_forwards_a_request_with_no_credential() {
    let backend = CountingBackend::new(OK_RESPONSE);
    let (outcome, _) = exchange(&get(None), &TokenPolicy::InsecureNoAuth, &backend).await;
    assert_eq!(outcome, Outcome::Forwarded);
    assert_eq!(backend.connects(), 1);
}

// ── Refused, with the backend untouched ──────────────────────────────────

/// The assertion this whole module is shaped around.
///
/// "Returned 401" and "the backend never saw it" are different promises,
/// and only the second is what `lib.rs` means by "before a byte reaches
/// your backend". A status code cannot tell them apart; the counter can.
#[tokio::test]
async fn a_rejected_request_opens_no_backend_connection_at_all() {
    let backend = CountingBackend::new(OK_RESPONSE);
    let wrong = [
        None,
        Some("Bearer wrong-token"),
        Some(TOKEN),
        Some(&format!("Bearer {TOKEN}x")),
        Some(&format!("Basic {TOKEN}")),
    ];
    for (i, auth) in wrong.iter().enumerate() {
        let (outcome, seen) = exchange(&get(auth.as_deref()), &supplied(), &backend).await;
        assert_eq!(outcome, Outcome::Unauthorized, "case {i}");
        assert!(
            String::from_utf8_lossy(&seen).starts_with("HTTP/1.1 401"),
            "case {i} must be refused"
        );
    }
    assert_eq!(
        backend.connects(),
        0,
        "after {} unauthorized requests the backend was never contacted",
        wrong.len()
    );
    assert!(backend.received().await.is_empty(), "and sent nothing");
}

/// A 401 produced here cannot be confused with anything upstream said,
/// because upstream has not been spoken to.
#[tokio::test]
async fn the_401_is_synthesized_locally_and_advertises_the_scheme() {
    let backend = CountingBackend::new(OK_RESPONSE);
    let (_, seen) = exchange(&get(None), &supplied(), &backend).await;
    let text = String::from_utf8_lossy(&seen);

    assert!(text.starts_with("HTTP/1.1 401 Unauthorized"));
    assert!(text.contains("WWW-Authenticate: Bearer"));
    assert!(text.contains("invalid_api_key"));
    assert_eq!(backend.connects(), 0);
}

/// An ambiguously framed request is refused before the credential is even
/// consulted, and so also before the backend exists.
#[tokio::test]
async fn an_ambiguously_framed_request_is_refused_without_a_backend_connection() {
    let backend = CountingBackend::new(OK_RESPONSE);
    let smuggle = b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";

    let (outcome, seen) = exchange(smuggle, &supplied(), &backend).await;
    assert_eq!(outcome, Outcome::BadRequest);
    assert!(String::from_utf8_lossy(&seen).starts_with("HTTP/1.1 400"));
    assert_eq!(backend.connects(), 0, "smuggling never reaches the backend");
}

/// Even carrying a valid credential. Framing is checked first because a
/// request the edge cannot read unambiguously is one it must not forward,
/// whoever sent it.
#[tokio::test]
async fn framing_is_refused_before_the_credential_is_consulted() {
    let backend = CountingBackend::new(OK_RESPONSE);
    let mut smuggle = b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\n".to_vec();
    smuggle.extend_from_slice(format!("Authorization: Bearer {TOKEN}\r\n").as_bytes());
    smuggle.extend_from_slice(b"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");

    let (outcome, _) = exchange(&smuggle, &supplied(), &backend).await;
    assert_eq!(outcome, Outcome::BadRequest);
    assert_eq!(backend.connects(), 0);
}

#[tokio::test]
async fn a_head_that_is_not_http_is_refused_without_a_backend_connection() {
    let backend = CountingBackend::new(OK_RESPONSE);
    let (outcome, seen) = exchange(b"this is not http\r\n\r\n", &supplied(), &backend).await;
    assert_eq!(outcome, Outcome::BadRequest);
    assert!(String::from_utf8_lossy(&seen).starts_with("HTTP/1.1 400"));
    assert_eq!(backend.connects(), 0);
}

// ── What the backend receives ────────────────────────────────────────────

/// Connection-scoped headers stop at the edge; the message survives.
/// `Authorization` is forwarded on purpose — that is what lets a `Supplied`
/// embedder's own backend check the same credential a second time.
#[tokio::test]
async fn the_backend_receives_the_message_headers_and_not_the_connection_ones() {
    let backend = CountingBackend::new(OK_RESPONSE);
    let mut req = b"GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n".to_vec();
    req.extend_from_slice(format!("Authorization: Bearer {TOKEN}\r\n").as_bytes());
    req.extend_from_slice(b"Connection: keep-alive, X-Hop\r\nX-Hop: 1\r\n");
    req.extend_from_slice(b"X-Forwarded-For: 203.0.113.1\r\nAccept: */*\r\n\r\n");

    let (outcome, _) = exchange(&req, &supplied(), &backend).await;
    assert_eq!(outcome, Outcome::Forwarded);

    let sent = String::from_utf8(backend.received().await).expect("ascii");
    let lower = sent.to_ascii_lowercase();
    assert!(
        sent.contains("Host: 127.0.0.1:11434"),
        "the backend's own authority: {sent}"
    );
    assert!(!sent.contains("127.0.0.1:8080"), "not the client's: {sent}");
    assert!(
        lower.contains("authorization: bearer"),
        "forwarded for the second check"
    );
    assert!(
        !lower.contains("x-hop"),
        "a nominated hop-by-hop header: {sent}"
    );
    assert!(!lower.contains("connection:"), "hop-by-hop: {sent}");
    assert!(
        !lower.contains("x-forwarded-for"),
        "a forwarding chain: {sent}"
    );
    assert!(lower.contains("accept: */*"), "a message header survives");
}

/// A length-framed body arrives intact and is not truncated by the head
/// read having over-read into it.
#[tokio::test]
async fn a_request_body_reaches_the_backend_byte_for_byte() {
    let backend = CountingBackend::new(OK_RESPONSE);
    let payload = r#"{"model":"llama","messages":[{"role":"user","content":"hi"}]}"#;
    let mut req = b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\n".to_vec();
    req.extend_from_slice(format!("Authorization: Bearer {TOKEN}\r\n").as_bytes());
    req.extend_from_slice(format!("Content-Length: {}\r\n\r\n", payload.len()).as_bytes());
    req.extend_from_slice(payload.as_bytes());

    let (outcome, _) = exchange(&req, &supplied(), &backend).await;
    assert_eq!(outcome, Outcome::Forwarded);
    assert!(
        String::from_utf8(backend.received().await)
            .expect("ascii")
            .ends_with(payload),
        "the body must arrive unaltered"
    );
}

// ── Streaming ────────────────────────────────────────────────────────────

/// The product is a token stream, and a `collect` anywhere in the response
/// path would still return 200 with the right bytes. This asserts the
/// frames leave the edge as they arrive.
#[tokio::test]
async fn a_streaming_response_reaches_the_client_frame_by_frame() {
    let backend = CountingBackend::new(OK_RESPONSE);
    let (mut client, mut edge) = duplex(64 * 1024);
    client
        .write_all(&get(Some(&format!("Bearer {TOKEN}"))))
        .await
        .unwrap();

    // A backend that sends a head, then one frame, then waits before the
    // last. If the edge buffers, the first read below times out.
    let (mine, mut theirs) = duplex(64 * 1024);
    let released = Arc::new(tokio::sync::Notify::new());
    let wait = released.clone();
    tokio::spawn(async move {
        theirs
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
            .await
            .unwrap();
        theirs.write_all(b"data: first\n\n").await.unwrap();
        theirs.flush().await.unwrap();
        wait.notified().await;
        theirs.write_all(b"data: [DONE]\n\n").await.unwrap();
    });

    let fixed = Fixed(Mutex::new(Some(mine)));
    let (credential, _) = Credential::new(&supplied());
    let pump = tokio::spawn(async move {
        serve_exchange(&mut edge, &credential, &fixed)
            .await
            .unwrap()
    });

    let mut seen = vec![0u8; 65];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.read_exact(&mut seen),
    )
    .await
    .expect("the head and first frame must arrive before the backend finishes")
    .expect("read");
    let text = String::from_utf8_lossy(&seen);
    assert!(text.contains("200 OK"), "{text}");
    assert!(
        text.contains("data: first"),
        "the first frame arrived early: {text}"
    );

    released.notify_one();
    assert_eq!(pump.await.unwrap(), Outcome::Forwarded);
    let _ = backend.connects();
}
