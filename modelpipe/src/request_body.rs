//! Carrying the request body upstream while the answer is already on its
//! way back.
//!
//! Split from [`crate::exchange`] because it answers a different question.
//! That module decides what a request *means* — how it is framed, whether
//! the credential admits it, whether the backend is contacted at all. This
//! one decides nothing: it moves a body one way, watches for a head coming
//! the other, and reports which of the two halves gave out first. They have
//! to overlap, and the reason is not throughput — a backend may answer
//! before it has finished reading, and an edge still inside `write_all` at
//! that moment loses the answer it already had.
//!
//! The two failures kept apart here are the whole of it. A body that stops
//! short is the *client's*: the head is already upstream, so the backend is
//! blocked reading against a length that will never arrive, and nothing but
//! a half-close will move it. A write that fails is the *backend's*: it has
//! stopped taking bytes, usually because it has already answered, and that
//! answer is still the thing worth having. Told apart they are a 400 and a
//! 502. Confused, the first of them is not a wrong status but a hang — the
//! edge waits for a response that cannot exist, on a stream no timeout
//! covers, holding the in-flight guard `ServeHandle::shutdown` drains
//! against.
//!
//! Measured, before the halves were told apart: a client that declared
//! `Content-Length: 1000`, sent ten bytes and hung up got nothing back,
//! ever, and the first Ctrl-C on `modelpipe serve` never returned. With
//! only ordinary traffic in flight the same shutdown took a second.
//!
//! The half-close is most of the answer but not all of it, because it
//! depends on the backend doing something with what it is told. One that
//! holds its socket open after the end of the stream — measured, against a
//! server blocked in `read` that neither answers nor closes — put the
//! exchange straight back where it was. [`ANSWER_GRACE`] is the floor under
//! that, and it is armed only by a pump that has already failed, which is
//! what keeps it from ever becoming the request timeout this crate is right
//! not to have.
//!
//! Generic over its streams like everything above the transport, so the
//! half-close is a FIN on a socket and `tokio::io::duplex()`'s peer seeing
//! `Ok(0)` in the tests — which is why every case below is exercised
//! without one.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::body::{self, Buffered};
use crate::fault::{Fault, Watched};
use crate::framing::{self, Framing};
use crate::head_read;
use crate::http_head;

/// How long the backend has to answer a request whose body never arrived.
///
/// **Not a request timeout, and it cannot become one.** It is armed only
/// once the pump has *failed*, which means the backend never received the
/// whole request — so no inference is running, and nobody is waiting on a
/// result. A legitimate call that takes forty minutes has a pump that
/// succeeded, leaves this disarmed, and is never cut by it. That
/// distinction is the whole reason the bound can exist here at all when
/// `exchange`'s own docs rightly refuse to put one on an admitted request.
///
/// The half-close tells a blocked backend the body stopped; this covers the
/// backend that is told and still says nothing. Measured against one that
/// holds its socket open after the end of the stream: without this the
/// exchange never returned, so it never released its in-flight guard, and
/// `ServeHandle::shutdown` — documented as draining rather than cutting —
/// waited on it forever. One misbehaving backend could hold a teardown
/// open indefinitely.
///
/// Generous, because the client may still be there: an unreadable chunk
/// size leaves the socket open and the client waiting, and a backend that
/// is going to answer the end of a body answers it promptly.
pub(crate) const ANSWER_GRACE: Duration = Duration::from_secs(10);

/// What came back, once the request body had been carried as far as it
/// could go.
pub(crate) enum Carried {
    /// The backend's final response head, and the bytes that arrived with
    /// it.
    Answered(http_head::ResponseHead, Vec<u8>),
    /// Nothing this edge can read came back, and the request body was not
    /// the reason. A gateway failure.
    Unreadable,
    /// The body never arrived whole, and the backend — told by a half-close
    /// where it stopped — answered nothing either.
    Unfinished,
}

/// Forward the body, and half-close upstream if it could not be finished.
///
/// The half-close is the liveness fix and it is why this is one function
/// rather than two: [`carry`]'s pinned future holds the write half for its
/// whole scope, so nothing outside can touch it once the pump is running.
/// Folding the forward and the shutdown together is what hands the borrow
/// back.
///
/// A body that arrives whole leaves the write open. That is not symmetry
/// for its own sake: the backend then has exactly the bytes the head
/// declared and knows where the message ends, and a half-close there reads
/// to some servers as an abort of a request that was fine. It is also what
/// makes "could this truncate a slow upload?" answerable — slowness is
/// `Poll::Pending`, never `Err`, so the shutdown below is unreachable for
/// it.
async fn send<R, W>(
    from_client: &mut Buffered<'_, R>,
    to_backend: &mut W,
    framing: Framing,
) -> Option<Fault>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut sink = Watched::new(to_backend);
    if body::forward(from_client, &mut sink, framing).await.is_ok() {
        return None;
    }
    // Before the shutdown, never after. See `Watched::fault`.
    let fault = sink.fault();
    // Ignored: it fails only when the backend is already gone, which is
    // the same answer as success for the purpose of unblocking it.
    let _ = sink.shutdown().await;
    Some(fault)
}

/// Carry the request body to the backend while watching for its answer.
///
/// The pump is polled first, so a backend that answers only after reading —
/// every well-behaved one — sees the whole body and the response is read
/// afterwards. When a head arrives first the pump is abandoned, which is
/// correct: the backend has committed to an answer and the rest of the body
/// cannot change it.
///
/// **The backend's answer always wins, even over a failed pump.** That is
/// the case the discarded-error version of this function was written for,
/// and it is a real one rather than a hypothetical: a backend may answer
/// `413` on an oversized payload, `400` on bad JSON or `429`, and then stop
/// draining. Its close arrives as an RST because the receive queue is not
/// empty, the RST makes the kernel discard what it had already delivered,
/// and an edge still inside `write_all` at that moment loses a response it
/// had already been sent. The client got a cleanly closed stream with zero
/// bytes in it — no status, no 502 — for every request whose body outran
/// the backend's socket buffer, which presented as a size-dependent
/// phantom. Charging a pump failure to the client *before* reading is how
/// that bug comes back, so the fault only decides what happens when
/// nothing readable came back at all.
pub(crate) async fn carry<S, R, W>(
    stream: &mut S,
    leftover: Vec<u8>,
    framing: Framing,
    to_backend: &mut W,
    from_backend: &mut R,
) -> Carried
where
    S: AsyncRead + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut from_client = Buffered::new(stream, leftover);
    let mut pump = std::pin::pin!(send(&mut from_client, to_backend, framing));
    let mut reading = std::pin::pin!(final_response(from_backend));
    // Disarmed until a pump failure arms it, so its duration here is never
    // waited on. See `ANSWER_GRACE` for why arming it cannot cut a real
    // request short.
    let grace = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(grace);
    let mut fault = None;
    let mut pumping = true;
    let mut waiting = false;
    loop {
        tokio::select! {
            // Biased, and the pump first: a backend that reads before it
            // answers must see the whole body, and on a buffered stream the
            // pump completes before the response is ever polled.
            biased;
            outcome = &mut pump, if pumping => {
                pumping = false;
                fault = outcome;
                if fault.is_some() {
                    grace.as_mut().reset(tokio::time::Instant::now() + ANSWER_GRACE);
                    waiting = true;
                }
            }
            // The backend was told the body stopped and said nothing back.
            // Charged the same way a closed connection would be, because it
            // is the same event as far as anyone downstream can tell.
            () = &mut grace, if waiting => {
                return match fault {
                    Some(Fault::Client) => Carried::Unfinished,
                    Some(Fault::Backend) | None => Carried::Unreadable,
                };
            }
            head = &mut reading => {
                return match head {
                    Ok(Ok((response, rest))) => Carried::Answered(response, rest),
                    // Nothing readable came back, so the fault decides. A
                    // transport error reading the head is folded in here
                    // rather than propagated: a client that truncated its
                    // upload is owed an answer, and returning `Err` to the
                    // edge dropped the stream with zero bytes in it — the
                    // very shape this module exists to stop producing.
                    Ok(Err(_)) | Err(_) => match fault {
                        Some(Fault::Client) => Carried::Unfinished,
                        Some(Fault::Backend) | None => Carried::Unreadable,
                    },
                };
            }
        }
    }
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
#[path = "request_body_tests.rs"]
mod request_body_tests;
