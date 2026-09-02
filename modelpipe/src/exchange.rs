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
//! Every refusal happens with the backend untouched. That is the difference
//! between "returned 401" and "the backend never saw it", and only the
//! second is what the README sells — so it is asserted with a connection
//! counter rather than a status code.

use std::future::Future;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::body::{self, Buffered};
use crate::credential::Credential;
use crate::headers;
use crate::http_head::{self, Framing, HeadError, MAX_HEAD_BYTES};
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
    let Ok((mut head, leftover)) = read_head(stream).await? else {
        return refuse(stream, refusal::bad_request(), Outcome::BadRequest).await;
    };

    // 2. Framing, before anything else looks at the body. An ambiguously
    //    framed request is refused rather than resolved: resolving it is
    //    what makes a proxy exploitable, because the next hop resolves it
    //    the other way.
    // Every framing refusal is a 400; the variants exist so a test can say
    // which rule fired, not so the edge answers them differently.
    let Ok(request_framing) = http_head::framing(&head.headers, false) else {
        return refuse(stream, refusal::bad_request(), Outcome::BadRequest).await;
    };

    // 3. The credential. Still nothing has been sent anywhere.
    if !credential.admits(http_head::authorization(&head.headers)) {
        return refuse(stream, refusal::unauthorized(), Outcome::Unauthorized).await;
    }

    // 4. Admitted. Only now does a backend connection exist.
    http_head::rewrite_for_backend(&mut head, backend.authority());
    let mut upstream = backend.connect().await?;

    upstream
        .write_all(&http_head::serialize_request(&head, request_framing))
        .await?;
    upstream.flush().await?;

    let mut from_client = Buffered::new(stream, leftover);
    body::forward(&mut from_client, &mut upstream, request_framing).await?;

    // 5. The response, forwarded frame by frame. `UntilClose` is the
    //    streaming case and the one that matters: an SSE response has to
    //    leave this edge as it arrives, not once it has finished.
    // A backend response this edge cannot read is a gateway failure, not a
    // client error, and is reported as one rather than passed through as
    // though the client had erred.
    let Ok((mut response, response_leftover)) = read_response_head(&mut upstream).await? else {
        return refuse(stream, refusal::bad_gateway(), Outcome::Forwarded).await;
    };
    let response_framing =
        http_head::framing(&response.headers, true).unwrap_or(Framing::UntilClose);
    headers::strip_hop_by_hop(&mut response.headers);

    stream
        .write_all(&http_head::serialize_response(&response, response_framing))
        .await?;
    stream.flush().await?;

    let mut from_backend = Buffered::new(&mut upstream, response_leftover);
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

/// Read until the request head is complete, or the bound is reached.
///
/// The outer `Result` is transport failure; the inner one is a head this
/// edge refuses. They are different things: one means the stream broke,
/// the other means the peer sent something it should not have.
async fn read_head<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> std::io::Result<Result<(http_head::RequestHead, Vec<u8>), HeadError>> {
    let mut buf = Vec::new();
    loop {
        match http_head::parse_request(&buf) {
            Ok(Some((head, consumed))) => return Ok(Ok((head, buf[consumed..].to_vec()))),
            Ok(None) => {}
            Err(e) => return Ok(Err(e)),
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Ok(Err(HeadError::TooLarge));
        }
        let mut next = [0u8; 4096];
        let n = stream.read(&mut next).await?;
        if n == 0 {
            // The peer stopped mid-head. Nothing to answer, and nothing to
            // forward.
            return Ok(Err(HeadError::Malformed));
        }
        buf.extend_from_slice(&next[..n]);
    }
}

/// The response twin of [`read_head`].
async fn read_response_head<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> std::io::Result<Result<(http_head::ResponseHead, Vec<u8>), HeadError>> {
    let mut buf = Vec::new();
    loop {
        match http_head::parse_response(&buf) {
            Ok(Some((head, consumed))) => return Ok(Ok((head, buf[consumed..].to_vec()))),
            Ok(None) => {}
            Err(e) => return Ok(Err(e)),
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Ok(Err(HeadError::TooLarge));
        }
        let mut next = [0u8; 4096];
        let n = stream.read(&mut next).await?;
        if n == 0 {
            return Ok(Err(HeadError::Malformed));
        }
        buf.extend_from_slice(&next[..n]);
    }
}

#[cfg(test)]
#[path = "exchange_tests.rs"]
mod exchange_tests;
