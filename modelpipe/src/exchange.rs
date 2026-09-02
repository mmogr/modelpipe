//! One HTTP exchange across the tunnel edge.
//!
//! Generic over [`AsyncRead`] + [`AsyncWrite`], and over where the backend
//! comes from. It cannot name an iroh type **because it cannot** — which is
//! a stronger guarantee than a lint or a boundary script gives, and is what
//! lets the entire authentication edge be tested over
//! `tokio::io::duplex()` before a socket exists anywhere in the crate.
//!
//! The order below is the security property, not a style:
//!
//! ```text
//! read head → refuse ambiguous framing → check the credential
//!                                      → *only then* open the backend
//! ```
//!
//! Every refusal *the client can cause* happens with the backend untouched.
//! That is the difference between "returned 401" and "the backend never saw
//! it", and only the second is what the README sells — so it is asserted
//! with a connection counter rather than a status code. The one refusal
//! written after contact is the 502, which by definition reports what
//! happened at the backend and could not be produced before reaching it.

use std::future::Future;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::body::{self, Buffered};
use crate::credential::Credential;
use crate::framing::{self, Framing};
use crate::head_read;
use crate::headers;
use crate::http_head::{self, HeadError};

/// How long a peer may take to send a complete request head.
///
/// The third of the three bounds on what a ticket-holder can cost before
/// authenticating — the other two being the head's size and the number of
/// streams one peer may have in flight. A stream that is opened and then
/// left silent holds a task and a buffer indefinitely otherwise, and it
/// costs an attacker nothing to open thousands.
///
/// Generous by design: this is not a request timeout. A slow phone on a
/// slow network sends a few hundred bytes well inside it, and a request
/// that has been *admitted* is never cut by it — an inference call may run
/// for many minutes, which is the whole product.
const HEAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
use crate::refusal;

/// Where the serve side gets a connection to the backend.
///
/// A trait rather than a concrete socket so the tests can supply one that
/// counts how often it is asked — and can therefore prove that a rejected
/// request never asks at all.
pub(crate) trait Backend {
    /// The connection type. Not an iroh type and not necessarily a socket.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;

    /// What to put in the outbound `Host` header.
    fn authority(&self) -> &str;

    /// Open a connection. Called at most once per exchange, and never
    /// before the credential has been checked.
    fn connect(&self) -> impl Future<Output = std::io::Result<Self::Stream>> + Send;
}

/// What happened to one exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Admitted, and carried to the backend and back.
    Forwarded,
    /// Refused on the credential. The backend was not contacted.
    Unauthorized,
    /// Refused on the head — unparseable, oversized, or framed
    /// ambiguously. The backend was not contacted.
    BadRequest,
    /// The peer opened a stream and never finished asking. Nothing was
    /// written back, and the backend was not contacted.
    TimedOut,
    /// The backend was contacted and the exchange failed there — it would
    /// not take the connection, or answered with something this edge
    /// cannot read. The client was told so; distinct from
    /// [`Forwarded`](Self::Forwarded) because nothing came back.
    BadGateway,
}

/// Serve one exchange on `stream`.
pub(crate) async fn serve_exchange<S, B>(
    stream: &mut S,
    credential: &Credential,
    backend: &B,
) -> std::io::Result<Outcome>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    // `Sync`, not merely `Backend`: a `&B` is held across every await here,
    // so without it this future is not `Send` — and the listener spawns one
    // task per stream. The bound is the difference between compiling and
    // discovering at the call site that the whole edge cannot be spawned.
    B: Backend + Sync,
{
    // 1. The head, bounded. A ticket-holder can open a stream and type
    //    headers; without a bound that is an unbounded allocation for the
    //    price of a connection.
    let asked = tokio::time::timeout(HEAD_TIMEOUT, head_read::request(stream, Vec::new())).await;
    let Ok(asked) = asked else {
        // Nothing is written back. A peer that never finished asking is not
        // owed an answer, and a reply would only confirm that something is
        // listening here.
        return Ok(Outcome::TimedOut);
    };
    let Ok((mut head, leftover)) = asked? else {
        return refuse(stream, refusal::bad_request(), Outcome::BadRequest).await;
    };

    // 2. Framing, before anything else looks at the body. An ambiguously
    //    framed request is refused rather than resolved: resolving it is
    //    what makes a proxy exploitable, because the next hop resolves it
    //    the other way.
    // Every framing refusal is a 400; the variants exist so a test can say
    // which rule fired, not so the edge answers them differently.
    let Ok(request_framing) = framing::framing(&head.headers, false) else {
        return refuse(stream, refusal::bad_request(), Outcome::BadRequest).await;
    };

    // 3. The credential. Still nothing has been sent anywhere.
    if !credential.admits(http_head::authorization(&head.headers)) {
        return refuse(stream, refusal::unauthorized(), Outcome::Unauthorized).await;
    }

    // 4. Admitted. Only now does a backend connection exist.
    let method = head.method.clone();
    http_head::rewrite_for_backend(&mut head, backend.authority());
    // A backend that will not take the connection is a gateway failure with
    // an answer, not a stream that dies silently. Without this the client
    // received nothing at all — not a status, not a malformed response, no
    // bytes — for a backend that was simply down.
    let Ok(upstream) = backend.connect().await else {
        return refuse(stream, refusal::bad_gateway(), Outcome::BadGateway).await;
    };

    // Split so the request body and the response can be in flight at once.
    // They have to be: see `pump_and_read`.
    let (mut up_read, mut up_write) = tokio::io::split(upstream);
    up_write
        .write_all(&http_head::serialize_request(&head, request_framing))
        .await?;
    up_write.flush().await?;

    // 5. The request body out and the response head back, together. The
    //    response is then forwarded frame by frame: `UntilClose` is the
    //    streaming case and the one that matters, because an SSE response
    //    has to leave this edge as it arrives rather than once it has
    //    finished.
    // A backend response this edge cannot read is a gateway failure, not a
    // client error, and is reported as one rather than passed through as
    // though the client had erred.
    let read = pump_and_read(
        stream,
        leftover,
        request_framing,
        &mut up_write,
        &mut up_read,
    )
    .await;
    let Ok((mut response, response_leftover)) = read? else {
        return refuse(stream, refusal::bad_gateway(), Outcome::BadGateway).await;
    };
    // The status and the method decide this before any header does, and an
    // ambiguously framed backend response is refused on the way out for the
    // same reason an ambiguously framed request is refused on the way in.
    let Ok(response_framing) =
        framing::response_framing(response.status, &method, &response.headers)
    else {
        return refuse(stream, refusal::bad_gateway(), Outcome::BadGateway).await;
    };
    headers::strip_hop_by_hop(&mut response.headers);
    // One bi-stream carries one exchange, so the client must not put a
    // second request on the same local connection: that stream is finished
    // and nobody is reading it, and the request would hang until the
    // client's own timeout.
    //
    // Every OpenAI client pools connections by default, so this is not an
    // edge case — it is what the first SDK to point at modelpipe does. The
    // header is added after the hop-by-hop strip, which removes whatever
    // the backend said about its own connection; what is being described
    // here is *this* hop, which is over.
    response
        .headers
        .push(("Connection".to_owned(), "close".to_owned()));

    stream
        .write_all(&http_head::serialize_response(&response, response_framing))
        .await?;
    stream.flush().await?;

    let mut from_backend = Buffered::new(&mut up_read, response_leftover);
    body::forward(&mut from_backend, stream, response_framing).await?;

    Ok(Outcome::Forwarded)
}

/// Forward the request body while watching for the response, and return the
/// response head.
///
/// The two have to overlap, and the reason is not throughput. A backend may
/// answer before it has finished reading — a `413` on an oversized payload,
/// a `400` on bad JSON, a `429` — and then stop draining. Its close then
/// arrives as an RST, because the receive queue is not empty, and an RST
/// makes the kernel discard what it had already delivered. Written
/// sequentially, this edge was still inside `write_all` at that moment: the
/// write died with `ECONNRESET`, the error propagated, and the answer the
/// backend had already sent was gone. The client got a cleanly closed
/// stream with zero bytes in it — no status, no 502, nothing — for every
/// request whose body outran the backend's socket buffer. Under it, the
/// same request worked, so it presented as a size-dependent phantom.
///
/// The pump is polled first, so a backend that answers only after reading —
/// every well-behaved one — behaves exactly as before and the response is
/// read afterwards. When the head arrives first the pump is abandoned,
/// which is correct: the backend has committed to an answer and the rest of
/// the body cannot change it.
///
/// A pump failure is deliberately not propagated. It is the symptom this
/// function exists for, and the response is the thing worth having.
async fn pump_and_read<S, R, W>(
    stream: &mut S,
    leftover: Vec<u8>,
    framing: Framing,
    to_backend: &mut W,
    from_backend: &mut R,
) -> std::io::Result<Result<(http_head::ResponseHead, Vec<u8>), HeadError>>
where
    S: AsyncRead + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut from_client = Buffered::new(stream, leftover);
    let mut pump = std::pin::pin!(body::forward(&mut from_client, to_backend, framing));
    let mut reading = std::pin::pin!(final_response(from_backend));
    let mut pumping = true;
    loop {
        tokio::select! {
            // Biased, and the pump first: a backend that reads before it
            // answers must see the whole body, and on a buffered stream the
            // pump completes before the response is ever polled.
            biased;
            outcome = &mut pump, if pumping => {
                pumping = false;
                let _ = outcome;
            }
            head = &mut reading => return head,
        }
    }
}

/// Write a locally synthesized response and return without touching the
/// backend.
async fn refuse<S: AsyncWrite + Unpin>(
    stream: &mut S,
    response: Vec<u8>,
    outcome: Outcome,
) -> std::io::Result<Outcome> {
    stream.write_all(&response).await?;
    stream.flush().await?;
    Ok(outcome)
}

/// The backend's *final* response head, with any interim ones skipped.
///
/// A `1xx` is a complete head that is not a response: the client asked for
/// it (`Expect: 100-continue`) or the backend volunteered it, and the real
/// answer is the next head on the stream. Returning the first head made the
/// interim one the final one — and since a `1xx` carries neither
/// `Content-Length` nor `Transfer-Encoding`, the framing that followed was
/// `UntilClose`, so the client waited on a close a keep-alive backend never
/// sends. An interim head arrived as a hang, not as a wrong status.
///
/// The bytes that came in with the interim head are the start of the head
/// after it, which is why the reader takes a prefix.
async fn final_response<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> head_read::Read<http_head::ResponseHead> {
    let mut prefix = Vec::new();
    loop {
        let head = head_read::response(stream, prefix).await?;
        let Ok((response, rest)) = head else {
            return Ok(head);
        };
        if !framing::is_interim(response.status) {
            return Ok(Ok((response, rest)));
        }
        prefix = rest;
    }
}

#[cfg(test)]
#[path = "exchange_tests.rs"]
mod exchange_tests;
