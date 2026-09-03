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
//! with a connection counter rather than a status code. Two refusals are
//! written after contact, and neither could have been produced before it:
//! the 502, which by definition reports what happened at the backend, and
//! the 400 for a request body that stopped short — a body can only fail
//! once its head has already gone upstream, which is exactly why that
//! refusal cannot be the `bad_request` the other client errors use.

use std::future::Future;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::body::{self, Buffered};
use crate::credential::Credential;
use crate::framing;
use crate::head_read;
use crate::headers;
use crate::http_head;
use crate::request_body::{self, Carried};

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
    /// The request body stopped before its declared end — truncated, or
    /// framed so this edge could not go on reading it — and the backend,
    /// told by a half-close where it stopped, answered nothing this edge
    /// could relay.
    ///
    /// Not [`BadRequest`](Self::BadRequest), which promises the backend was
    /// never contacted: by the time a body can fail, its head is already
    /// upstream. Not [`BadGateway`](Self::BadGateway) either — the backend
    /// did nothing wrong, and reporting it there sends whoever is debugging
    /// to the far side of a tunnel that was working.
    Unfinished,
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
    // They have to be: see [`crate::request_body`].
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
    // though the client had erred. A body that stopped short is the mirror
    // image — the client's failure, not the backend's — and the two are
    // told apart in `request_body` rather than here, because only the code
    // holding both streams can see which half gave out.
    let carried = request_body::carry(
        stream,
        leftover,
        request_framing,
        &mut up_write,
        &mut up_read,
    )
    .await;
    let (mut response, response_leftover) = match carried {
        Carried::Answered(response, rest) => (response, rest),
        Carried::Unreadable => {
            return refuse(stream, refusal::bad_gateway(), Outcome::BadGateway).await;
        }
        Carried::Unfinished => {
            return refuse(stream, refusal::incomplete_request(), Outcome::Unfinished).await;
        }
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

#[cfg(test)]
#[path = "exchange_tests.rs"]
mod exchange_tests;
