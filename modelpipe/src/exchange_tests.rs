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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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

    // Read until the frame appears rather than a fixed number of bytes.
    // What is under test is that it arrives while the backend is still
    // producing; a hardcoded length additionally asserts the response head's
    // size, which breaks the moment a header is added to it.
    let mut text = String::new();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut buf = [0u8; 512];
        loop {
            let n = client.read(&mut buf).await.expect("read");
            assert!(n > 0, "the stream ended early: {text}");
            text.push_str(&String::from_utf8_lossy(&buf[..n]));
            if text.contains("data: first") {
                return;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the first frame must arrive before the backend finishes: {text}"));
    assert!(text.contains("200 OK"), "{text}");

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

    /// The same shape, except it hangs up after answering instead of
    /// stalling — the real-socket version, where the close arrives as an
    /// RST because the receive queue is not empty.
    ///
    /// Written out rather than folded into [`new`](Self::new) with a flag:
    /// that constructor is the fixture of the test that guards the
    /// overlapping read, and leaving it untouched is worth more than the
    /// dozen lines it saves.
    fn hanging_up(response: &'static str) -> Self {
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
            drop(theirs);
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

// ── Bounds before authentication ─────────────────────────────────────────

/// A stream opened and then left silent must not hold a task forever. This
/// is the third bound on what a leaked ticket is worth before it
/// authenticates, alongside the head's size and the per-peer stream cap.
#[tokio::test(start_paused = true)]
async fn a_peer_that_never_finishes_asking_is_timed_out() {
    let backend = CountingBackend::new(OK_RESPONSE);
    let (mut client, mut edge) = duplex(64 * 1024);

    // A head that begins and never ends: valid so far, so the parser keeps
    // asking for more.
    client
        .write_all(b"GET /v1/models HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();

    let (credential, _) = Credential::new(&supplied()).expect("a usable token");
    // `start_paused` advances the clock only when everything is idle, so
    // this resolves the moment the timeout is the only thing left to wait
    // on — no real thirty seconds pass.
    let outcome = serve_exchange(&mut edge, &credential, &backend)
        .await
        .expect("a timeout is not a transport failure");

    assert_eq!(outcome, Outcome::TimedOut);
    assert_eq!(backend.connects(), 0, "and the backend never heard of it");

    drop(edge);
    let mut seen = Vec::new();
    client.read_to_end(&mut seen).await.unwrap();
    assert!(
        seen.is_empty(),
        "a peer that never finished asking is owed no answer: {seen:?}"
    );
}

/// The timeout bounds the *head*, not the request. An admitted inference
/// call may run for many minutes, which is the product.
#[tokio::test(start_paused = true)]
async fn a_slow_head_that_arrives_in_time_is_served_normally() {
    let backend = CountingBackend::new(OK_RESPONSE);
    let (mut client, mut edge) = duplex(64 * 1024);
    let auth = format!("Bearer {TOKEN}");

    tokio::spawn(async move {
        client
            .write_all(b"GET /v1/models HTTP/1.1\r\nHost: x\r\n")
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        client
            .write_all(format!("Authorization: {auth}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        // Held open so the response has somewhere to go. Not a round
        // minute, which clippy reads as a unit that wants rewriting.
        tokio::time::sleep(std::time::Duration::from_secs(45)).await;
    });

    let (credential, _) = Credential::new(&supplied()).expect("a usable token");
    let outcome = serve_exchange(&mut edge, &credential, &backend)
        .await
        .expect("no transport failure");
    assert_eq!(outcome, Outcome::Forwarded);
    assert_eq!(backend.connects(), 1);
}

// ── The client that stops mid-body ───────────────────────────────────────

/// A complete 200, as text, for the stubs below that take one.
const OK_TEXT: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                       Content-Length: 2\r\n\r\n{}";

/// A backend that reads the whole declared body before it answers — what
/// every real inference server does, and what no other stub in this file
/// does. `CountingBackend`, `KeepAlive` and `AnswersEarly` all write first
/// and read afterwards, which is precisely why none of them could reproduce
/// a client that stops mid-body: the edge got its answer regardless.
///
/// `saw_eof` is the mechanism assertion. Over a duplex it can only become
/// true if the edge actually called `poll_shutdown` on its write half, so a
/// test asserting it cannot pass by the exchange having ended some other
/// way.
struct ReadsWholeBody {
    stream: Mutex<Option<DuplexStream>>,
    saw_eof: Arc<AtomicBool>,
}

/// What a [`ReadsWholeBody`] does when the body stops before its declared
/// end. Three real server behaviours, and the edge owes a different answer
/// to none of them — which is the point of testing all three.
#[derive(Clone, Copy)]
enum OnEarlyEnd {
    /// Close without a word. What most servers do once their read comes up
    /// short and their parser rejects what arrived.
    HangUp,
    /// Answer anyway, from what it did receive.
    Answer(&'static str),
    /// Say nothing and hold the socket open — the case the half-close alone
    /// cannot fix.
    Hold,
}

impl ReadsWholeBody {
    /// Answers `response` once the whole declared body has arrived, and
    /// does `after_eof` if it never does.
    fn new(response: &'static str, after_eof: OnEarlyEnd) -> Self {
        let (mine, mut theirs) = duplex(256 * 1024);
        let saw_eof = Arc::new(AtomicBool::new(false));
        let flag = saw_eof.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let mut seen = Vec::new();
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                match theirs.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => seen.extend_from_slice(&buf[..n]),
                }
            }
            let head_end = seen
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .expect("head ends")
                + 4;
            while !body_complete(&seen, head_end) {
                match theirs.read(&mut buf).await {
                    Ok(0) => {
                        flag.store(true, Ordering::SeqCst);
                        match after_eof {
                            OnEarlyEnd::HangUp => {}
                            OnEarlyEnd::Answer(text) => {
                                let _ = theirs.write_all(text.as_bytes()).await;
                                let _ = theirs.flush().await;
                            }
                            // Holds the stream open by never returning, so
                            // the edge sees neither an answer nor an end.
                            OnEarlyEnd::Hold => std::future::pending::<()>().await,
                        }
                        return;
                    }
                    Err(_) => return,
                    Ok(n) => seen.extend_from_slice(&buf[..n]),
                }
            }
            let _ = theirs.write_all(response.as_bytes()).await;
            let _ = theirs.flush().await;
        });
        Self {
            stream: Mutex::new(Some(mine)),
            saw_eof,
        }
    }

    /// Whether the backend was ever told the body had stopped.
    fn saw_eof(&self) -> bool {
        self.saw_eof.load(Ordering::SeqCst)
    }
}

impl Backend for ReadsWholeBody {
    type Stream = DuplexStream;

    fn authority(&self) -> &'static str {
        "127.0.0.1:11434"
    }

    async fn connect(&self) -> std::io::Result<DuplexStream> {
        Ok(self.stream.lock().await.take().expect("connected once"))
    }
}

/// Whether everything the head promised has arrived, by whichever framing
/// it declared. Deliberately a hand-rolled read of the two cases rather
/// than a call into `framing`: a stub that shared the code under test could
/// agree with it about a body neither had read correctly.
fn body_complete(seen: &[u8], head_end: usize) -> bool {
    let head = String::from_utf8_lossy(&seen[..head_end]).to_ascii_lowercase();
    if head.contains("transfer-encoding: chunked") {
        return seen[head_end..].windows(5).any(|w| w == b"0\r\n\r\n");
    }
    let declared = head
        .split("content-length:")
        .nth(1)
        .and_then(|rest| rest.split("\r\n").next())
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    seen.len() - head_end >= declared
}

/// A backend that takes the head and then vanishes without answering.
///
/// Its buffer is small on purpose, so the edge is still writing the body
/// when the peer goes — which is what makes the write, rather than the
/// read, the first thing to fail.
struct Vanishing(Mutex<Option<DuplexStream>>);

impl Vanishing {
    fn new() -> Self {
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
            drop(theirs);
        });
        Self(Mutex::new(Some(mine)))
    }
}

impl Backend for Vanishing {
    type Stream = DuplexStream;

    fn authority(&self) -> &'static str {
        "127.0.0.1:11434"
    }

    async fn connect(&self) -> std::io::Result<DuplexStream> {
        Ok(self.0.lock().await.take().expect("connected once"))
    }
}

/// Drive one exchange against a backend of any shape, returning what the
/// client saw.
///
/// `hang_up` closes the client's send half, which is the difference between
/// an aborted upload and a slow one — and the reason it is a parameter is
/// that the distinction is the subject of half the tests below.
///
/// `patience` bounds the whole exchange. It is a parameter rather than a
/// constant because a test of something that is *meant* to take time would
/// otherwise fail against its own subject: under `start_paused` the clock
/// jumps to whichever timer is nearest, and a fixed five seconds is always
/// nearer than a ten-second grace.
async fn drive<B: Backend + Sync>(
    request: &[u8],
    backend: &B,
    hang_up: bool,
    patience: std::time::Duration,
) -> (Outcome, String) {
    let (mut client, mut edge) = duplex(256 * 1024);
    client.write_all(request).await.unwrap();
    if hang_up {
        client.shutdown().await.unwrap();
    }

    let (credential, _) = Credential::new(&supplied()).expect("a usable token");
    let outcome = tokio::time::timeout(patience, serve_exchange(&mut edge, &credential, backend))
        .await
        .expect("the exchange must not hang")
        .expect("no transport failure");

    drop(edge);
    let mut seen = Vec::new();
    client.read_to_end(&mut seen).await.unwrap();
    (outcome, String::from_utf8_lossy(&seen).into_owned())
}

/// [`drive`] with the patience every test that is not about time wants.
async fn against<B: Backend + Sync>(
    request: &[u8],
    backend: &B,
    hang_up: bool,
) -> (Outcome, String) {
    drive(request, backend, hang_up, std::time::Duration::from_secs(5)).await
}

/// A POST whose head declares `declared` bytes and whose body carries
/// `body`. When the two disagree the request is a truncated upload.
fn post(declared: usize, body: &str) -> Vec<u8> {
    format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\n\
         Authorization: Bearer {TOKEN}\r\nContent-Length: {declared}\r\n\r\n{body}"
    )
    .into_bytes()
}

/// The bug, at the edge. A client that declares a length, sends less and
/// hangs up used to leave the exchange waiting forever on a response the
/// backend could not send: its head was already upstream, so the backend
/// sat blocked against a length that would never arrive, and nothing shut
/// the write half to tell it otherwise.
///
/// Measured, before the halves were told apart: the client got nothing at
/// all, and because the exchange never returned it held its in-flight
/// guard, so `ServeHandle::shutdown` never returned either — the first
/// Ctrl-C on `modelpipe serve` hung past twenty seconds where ordinary
/// traffic took one.
#[tokio::test]
async fn a_truncated_request_body_is_answered_rather_than_waited_on() {
    let backend = ReadsWholeBody::new(OK_TEXT, OnEarlyEnd::HangUp);

    let (outcome, seen) = against(&post(1000, "{\"model\":\""), &backend, true).await;

    assert_eq!(outcome, Outcome::Unfinished);
    assert!(seen.starts_with("HTTP/1.1 400"), "got: {seen}");
    assert!(seen.contains("incomplete_request"), "got: {seen}");
    assert!(
        backend.saw_eof(),
        "the backend must be told where the body stopped, not merely abandoned"
    );
}

/// The control for the test above. The same backend, the same route, a body
/// that arrives whole — so the 400 cannot be this stub simply never
/// answering anything.
#[tokio::test]
async fn a_complete_request_body_reaches_the_same_backend_that_hangs_on_a_short_one() {
    let backend = ReadsWholeBody::new(OK_TEXT, OnEarlyEnd::HangUp);
    let body = "{\"model\":\"m\"}";

    let (outcome, seen) = against(&post(body.len(), body), &backend, true).await;

    assert_eq!(outcome, Outcome::Forwarded);
    assert!(seen.starts_with("HTTP/1.1 200"), "got: {seen}");
    assert!(!backend.saw_eof(), "a complete body is not an early end");
}

/// A backend that answers the short body anyway must be heard. The
/// synthesized 400 is what this edge says when there is nothing to relay,
/// never something it says over the top of a real answer.
#[tokio::test]
async fn a_backend_that_answers_the_short_body_is_heard_rather_than_overridden() {
    let backend = ReadsWholeBody::new(
        OK_TEXT,
        OnEarlyEnd::Answer("HTTP/1.1 400 Bad Request\r\nContent-Length: 9\r\n\r\ntruncated"),
    );

    let (outcome, seen) = against(&post(1000, "{\"model\":\""), &backend, true).await;

    assert_eq!(outcome, Outcome::Forwarded);
    assert!(
        seen.ends_with("truncated"),
        "the backend's own words, not ours: {seen}"
    );
}

/// The trap, and the reason the fault only decides what happens when
/// nothing came back. A backend that answers and *then* hangs up makes the
/// edge's next write fail — so a fix that charged any failed pump to the
/// client would answer 400 while a perfectly good 413 sat unread in the
/// buffer. That is the size-dependent phantom the overlapping read was
/// written for in the first place, and this is the test that would catch
/// its return.
#[tokio::test]
async fn an_answer_followed_by_a_hangup_is_relayed_rather_than_charged_to_the_client() {
    let backend =
        AnswersEarly::hanging_up("HTTP/1.1 413 Payload Too Large\r\nContent-Length: 2\r\n\r\nno");
    let body = "x".repeat(64 * 1024);

    let (outcome, seen) = against(&post(body.len(), &body), &backend, false).await;

    assert_eq!(outcome, Outcome::Forwarded);
    assert!(seen.starts_with("HTTP/1.1 413"), "got: {seen}");
}

/// The control for the fault verdict itself: not every failed pump is the
/// client's. A backend that goes away mid-body is a gateway failure, and
/// reporting it as a 400 would send whoever is debugging it to the wrong
/// machine entirely.
#[tokio::test]
async fn a_backend_that_hangs_up_mid_body_is_a_gateway_failure_rather_than_a_client_one() {
    let backend = Vanishing::new();
    let body = "x".repeat(64 * 1024);

    let (outcome, seen) = against(&post(body.len(), &body), &backend, false).await;

    assert_eq!(outcome, Outcome::BadGateway);
    assert!(seen.starts_with("HTTP/1.1 502"), "got: {seen}");
}

/// The other way a body stops, and the one where the client is still
/// there. An unreadable chunk size is not a hang-up — the socket is open
/// and the client is waiting — so the answer it is owed actually reaches
/// it. `body::forward` reports this as `ErrorKind::Other`, which is what a
/// sink failure would look like too; only watching the sink tells them
/// apart.
#[tokio::test]
async fn a_chunked_body_with_an_unreadable_size_is_refused_rather_than_relayed_on() {
    let backend = ReadsWholeBody::new(OK_TEXT, OnEarlyEnd::HangUp);
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\n\
         Authorization: Bearer {TOKEN}\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"
    );

    let (outcome, seen) = against(request.as_bytes(), &backend, false).await;

    assert_eq!(outcome, Outcome::Unfinished);
    assert!(seen.starts_with("HTTP/1.1 400"), "got: {seen}");
    assert!(backend.saw_eof(), "the backend is told here too");
}

/// The control for the test above: a well-formed chunked body still gets
/// through. Nothing else in this file exercises chunked at the exchange
/// level, so without this the refusal could be the edge rejecting every
/// chunked request.
#[tokio::test]
async fn a_well_formed_chunked_body_is_forwarded_rather_than_refused() {
    let backend = ReadsWholeBody::new(OK_TEXT, OnEarlyEnd::HangUp);
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\n\
         Authorization: Bearer {TOKEN}\r\nTransfer-Encoding: chunked\r\n\r\n\
         a\r\n0123456789\r\n0\r\n\r\n"
    );

    let (outcome, seen) = against(request.as_bytes(), &backend, false).await;

    assert_eq!(outcome, Outcome::Forwarded);
    assert!(seen.starts_with("HTTP/1.1 200"), "got: {seen}");
}

/// The half-close is most of the answer, and this is the rest of it. A
/// backend that is told the body stopped and neither answers nor closes put
/// the exchange straight back where it started — waiting forever on a
/// response that was never coming, holding the in-flight guard that
/// `ServeHandle::shutdown` drains against, so one misbehaving server could
/// hold a teardown open indefinitely.
///
/// Measured against a real server blocked in `read`: the client got
/// nothing and `serve` would not shut down, with the half-close working
/// perfectly. Being told is not the same as acting on it.
///
/// Virtual time, so the ten-second grace costs the suite nothing.
#[tokio::test(start_paused = true)]
async fn a_backend_that_neither_answers_nor_closes_is_not_waited_on_forever() {
    let backend = ReadsWholeBody::new(OK_TEXT, OnEarlyEnd::Hold);

    let (outcome, seen) = drive(
        &post(1000, "{\"model\":\""),
        &backend,
        true,
        crate::request_body::ANSWER_GRACE * 100,
    )
    .await;

    assert_eq!(outcome, Outcome::Unfinished);
    assert!(seen.starts_with("HTTP/1.1 400"), "got: {seen}");
    assert!(backend.saw_eof(), "it was told, it simply did nothing");
}

/// The control for the grace, and the promise that it is not a request
/// timeout wearing a different name: a body that arrived whole leaves it
/// disarmed, so a backend taking far longer than the grace to think is
/// waited on exactly as before. Without this, shortening `ANSWER_GRACE` to
/// nothing would still pass every other test in this file.
#[tokio::test(start_paused = true)]
async fn a_slow_answer_to_a_complete_body_is_waited_for_however_long_it_takes() {
    let backend = Deliberating::new(OK_TEXT, crate::request_body::ANSWER_GRACE * 100);
    let body = "{\"model\":\"m\"}";

    let (outcome, seen) = drive(
        &post(body.len(), body),
        &backend,
        true,
        crate::request_body::ANSWER_GRACE * 1000,
    )
    .await;

    assert_eq!(outcome, Outcome::Forwarded);
    assert!(seen.starts_with("HTTP/1.1 200"), "got: {seen}");
}

/// A backend that reads the whole body and then thinks for a long time —
/// an inference call, which is the product.
struct Deliberating(Mutex<Option<DuplexStream>>);

impl Deliberating {
    fn new(response: &'static str, think_for: std::time::Duration) -> Self {
        let (mine, mut theirs) = duplex(256 * 1024);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let mut seen = Vec::new();
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                match theirs.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => seen.extend_from_slice(&buf[..n]),
                }
            }
            let head_end = seen
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .expect("head ends")
                + 4;
            while !body_complete(&seen, head_end) {
                match theirs.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => seen.extend_from_slice(&buf[..n]),
                }
            }
            tokio::time::sleep(think_for).await;
            let _ = theirs.write_all(response.as_bytes()).await;
            let _ = theirs.flush().await;
        });
        Self(Mutex::new(Some(mine)))
    }
}

impl Backend for Deliberating {
    type Stream = DuplexStream;

    fn authority(&self) -> &'static str {
        "127.0.0.1:11434"
    }

    async fn connect(&self) -> std::io::Result<DuplexStream> {
        Ok(self.0.lock().await.take().expect("connected once"))
    }
}
