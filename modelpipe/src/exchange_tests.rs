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

    let (credential, _) = Credential::new(policy).expect("a usable policy");
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
    // The client's `Connection` is gone; the edge's own is in its place.
    // Not a survival: this connection carries one exchange and the edge
    // drops it afterwards, so saying so is what keeps a keep-alive backend
    // from holding an `UntilClose` response open forever.
    assert!(
        !lower.contains("connection: keep-alive"),
        "the client's connection header must not survive: {sent}"
    );
    assert_eq!(
        lower.matches("connection:").count(),
        1,
        "exactly one, and it is the edge's: {sent}"
    );
    assert!(
        lower.contains("connection: close"),
        "the backend is told this connection carries one exchange: {sent}"
    );
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
    let (credential, _) = Credential::new(&supplied()).expect("a usable token");
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

// ── The backend's half of the framing rules ──────────────────────────────

/// A backend whose response head is written by hand, so a test can say
/// exactly what came back. Distinct from `Fixed` in taking the bytes rather
/// than a prepared stream, and in never closing: a real keep-alive backend
/// holds the socket open after answering, which is the condition under
/// which every framing mistake below becomes a hang rather than a wrong
/// answer.
struct KeepAlive(Mutex<Option<DuplexStream>>);

impl KeepAlive {
    fn new(response: &'static str) -> Self {
        let (mine, mut theirs) = duplex(64 * 1024);
        tokio::spawn(async move {
            let mut sink = Vec::new();
            // Answer, then hold the connection open exactly as Ollama and
            // llama-server do. Nothing here ever writes EOF.
            let _ = theirs.write_all(response.as_bytes()).await;
            let _ = theirs.flush().await;
            let _ = theirs.read_to_end(&mut sink).await;
        });
        Self(Mutex::new(Some(mine)))
    }
}

impl Backend for KeepAlive {
    type Stream = DuplexStream;

    fn authority(&self) -> &'static str {
        "127.0.0.1:11434"
    }

    async fn connect(&self) -> std::io::Result<DuplexStream> {
        Ok(self.0.lock().await.take().expect("connected once"))
    }
}

/// Drive one exchange against a keep-alive backend, failing rather than
/// hanging. The deadline is the assertion: every case below completes in
/// microseconds when the framing is right and never completes when it is
/// not.
async fn against_keepalive(request: &[u8], response: &'static str) -> (Outcome, String) {
    let backend = KeepAlive::new(response);
    let (mut client, mut edge) = duplex(64 * 1024);
    client.write_all(request).await.unwrap();

    let (credential, _) = Credential::new(&supplied()).expect("a usable token");
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        serve_exchange(&mut edge, &credential, &backend),
    )
    .await
    .expect("a keep-alive backend must not hang the exchange")
    .expect("no transport failure");

    drop(edge);
    let mut seen = Vec::new();
    client.read_to_end(&mut seen).await.unwrap();
    (outcome, String::from_utf8_lossy(&seen).into_owned())
}

fn authed(method: &str) -> Vec<u8> {
    format!("{method} /v1/models HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {TOKEN}\r\n\r\n")
        .into_bytes()
}

/// RFC 9112 §6.3: the status code settles this before any header does.
/// Reading it from the headers alone is not a wrong answer, it is a hang —
/// `204` declares no framing, so the old rule resolved it to `UntilClose`
/// and waited for a close a keep-alive backend never sends.
#[tokio::test]
async fn a_bodyless_status_is_framed_by_its_status_and_not_by_its_headers() {
    for response in [
        "HTTP/1.1 204 No Content\r\n\r\n",
        "HTTP/1.1 304 Not Modified\r\nContent-Length: 42\r\n\r\n",
    ] {
        let (outcome, seen) = against_keepalive(&authed("GET"), response).await;
        assert_eq!(outcome, Outcome::Forwarded, "{response:?}");
        assert!(
            seen.starts_with("HTTP/1.1 3") || seen.starts_with("HTTP/1.1 2"),
            "{seen}"
        );
    }
}

/// The same rule from the request's side: a response to `HEAD` carries the
/// length a `GET` would have returned, and no body. Waiting for that many
/// bytes is a wait that cannot end.
#[tokio::test]
async fn a_head_response_is_not_a_body_to_wait_for() {
    let (outcome, seen) = against_keepalive(
        &authed("HEAD"),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n",
    )
    .await;
    assert_eq!(outcome, Outcome::Forwarded);
    assert!(seen.starts_with("HTTP/1.1 200"), "{seen}");
    assert!(
        seen.to_ascii_lowercase().contains("content-length: 4096"),
        "the declared length still describes what a GET would return: {seen}"
    );
}

/// An interim response is a head that precedes the real one. Delivered as
/// final it was not merely the wrong status: a `1xx` declares no framing,
/// so what followed was `UntilClose` and the client waited forever.
#[tokio::test]
async fn an_interim_response_is_skipped_and_the_real_one_forwarded() {
    let (outcome, seen) = against_keepalive(
        &authed("GET"),
        "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
    )
    .await;
    assert_eq!(outcome, Outcome::Forwarded);
    assert!(
        seen.starts_with("HTTP/1.1 200"),
        "the interim head must not be the answer: {seen}"
    );
    assert!(seen.ends_with("{}"), "and the real body arrives: {seen}");
}

/// The rule the request path enforces, applied to the backend. A response
/// carrying both `Content-Length` and `Transfer-Encoding` is the
/// request-smuggling shape; refusing it inbound and resolving it outbound
/// is one rule applied on one side of the pipe only.
#[tokio::test]
async fn an_ambiguously_framed_backend_response_is_refused_rather_than_resolved() {
    let (outcome, seen) = against_keepalive(
        &authed("GET"),
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
    )
    .await;
    assert_eq!(outcome, Outcome::BadGateway);
    assert!(
        seen.starts_with("HTTP/1.1 502"),
        "the client did nothing wrong, and the backend's answer is unreadable: {seen}"
    );
}

/// A backend that will not take the connection owes the client an answer.
/// Before this the stream simply died: no status, no malformed response, no
/// bytes at all — indistinguishable from the tunnel being gone.
#[tokio::test]
async fn a_backend_that_refuses_the_connection_is_reported_as_a_gateway_failure() {
    struct Refusing;
    impl Backend for Refusing {
        type Stream = DuplexStream;
        fn authority(&self) -> &'static str {
            "127.0.0.1:11434"
        }
        async fn connect(&self) -> std::io::Result<DuplexStream> {
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "nothing is listening",
            ))
        }
    }

    let (mut client, mut edge) = duplex(64 * 1024);
    client.write_all(&authed("GET")).await.unwrap();
    client.shutdown().await.unwrap();

    let (credential, _) = Credential::new(&supplied()).expect("a usable token");
    let outcome = serve_exchange(&mut edge, &credential, &Refusing)
        .await
        .expect("a refused backend is an answer, not a transport failure");
    assert_eq!(outcome, Outcome::BadGateway);

    drop(edge);
    let mut seen = Vec::new();
    client.read_to_end(&mut seen).await.unwrap();
    let text = String::from_utf8_lossy(&seen);
    assert!(text.starts_with("HTTP/1.1 502"), "got: {text}");
}

// ── The backend that answers before it has finished listening ────────────

/// A backend that replies as soon as it has the head and then stops
/// reading, exactly as a server rejecting an oversized payload does. Its
/// buffer is small so the edge's write blocks well before the body is
/// through — which is the whole point: the answer is available while the
/// request is still going out.
struct AnswersEarly(Mutex<Option<DuplexStream>>);

impl AnswersEarly {
    fn new(response: &'static str) -> Self {
        let (mine, mut theirs) = duplex(1024);
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let mut seen = Vec::new();
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                match theirs.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => seen.extend_from_slice(&buf[..n]),
                }
            }
            let _ = theirs.write_all(response.as_bytes()).await;
            let _ = theirs.flush().await;
            // And now it stops reading. The edge is mid-body.
            std::future::pending::<()>().await;
        });
        Self(Mutex::new(Some(mine)))
    }
}

impl Backend for AnswersEarly {
    type Stream = DuplexStream;

    fn authority(&self) -> &'static str {
        "127.0.0.1:11434"
    }

    async fn connect(&self) -> std::io::Result<DuplexStream> {
        Ok(self.0.lock().await.take().expect("connected once"))
    }
}

/// A backend that answers before it has read the request must not cost the
/// client the answer.
///
/// This is the shape of every `413` on an oversized payload, every `400` on
/// bad JSON, every `429` — and SECURITY.md names multi-MiB vision payloads
/// as the expected traffic. Written sequentially, the edge was still inside
/// `write_all` when the backend stopped draining, so the write blocked
/// forever here and, against a real socket, died with `ECONNRESET` and took
/// the already-delivered response with it.
#[tokio::test]
async fn a_backend_that_answers_before_reading_the_body_is_still_heard() {
    let backend =
        AnswersEarly::new("HTTP/1.1 413 Payload Too Large\r\nContent-Length: 2\r\n\r\nno");
    let (mut client, mut edge) = duplex(256 * 1024);

    // A body far larger than the backend's buffer, so the pump cannot
    // finish and the answer is only reachable by reading while it stalls.
    let body = "x".repeat(64 * 1024);
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\n\
         Authorization: Bearer {TOKEN}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    client.write_all(request.as_bytes()).await.unwrap();

    let (credential, _) = Credential::new(&supplied()).expect("a usable token");
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        serve_exchange(&mut edge, &credential, &backend),
    )
    .await
    .expect("the answer is already in hand; waiting on the body is waiting forever")
    .expect("no transport failure");
    assert_eq!(outcome, Outcome::Forwarded);

    drop(edge);
    let mut seen = Vec::new();
    client.read_to_end(&mut seen).await.unwrap();
    let text = String::from_utf8_lossy(&seen);
    assert!(
        text.starts_with("HTTP/1.1 413"),
        "the backend's answer must reach the client: {text}"
    );
    assert!(text.ends_with("no"), "body included: {text}");
}
