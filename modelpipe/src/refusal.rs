//! What the edge says when it will not forward.
//!
//! Pure: each of these is a complete HTTP/1.1 response as bytes, built here
//! and never obtained from anywhere else. That is the property worth having
//! a module for — a refusal produced locally cannot be confused with
//! something the backend said.
//!
//! For [`unauthorized`] and [`bad_request`] the stronger statement holds:
//! at the point they are written the backend has not been contacted at all.
//! The three written *after* contact are the deliberate exceptions, and
//! each has to be. [`bad_gateway`] and [`backend_unreachable`] report what
//! happened at the backend, so neither can be produced before reaching for
//! one. [`incomplete_request`] reports a request body that stopped short,
//! and a body can only stop short after its head has already gone upstream
//! — which is precisely why it is not [`bad_request`], whose promise it
//! would break. [`tunnel_unavailable`] is the odd one out in a different
//! way: it is written by the *connect* side, which never had a backend to
//! reach. All five are still synthesized here rather than relayed, which
//! is what keeps them distinguishable from a status the backend itself
//! sent.
//!
//! Every one closes the connection. A stream carries exactly one exchange
//! and a refused exchange is over.
//!
//! # Why there are three 502s
//!
//! There used to be one, and its sentence — "the backend sent a response
//! this tunnel could not read" — was written at five call sites of which it
//! described exactly one. A backend that was never reached sent no
//! response; a tunnel with no peer has no backend at either end. Both said
//! so anyway, which sends the reader to the wrong machine: to the model
//! server, when the model server is fine and the far laptop is asleep.
//!
//! The status stays 502 for all three and [`Outcome`](crate::outcome::Outcome) stays
//! one variant, because the client's *recovery* is the same in each case
//! and that is what a status code is for. What differs is the sentence a
//! person reads, and the `code` a program matches on.

/// One refusal, in the shape they all share.
///
/// A status line, a JSON object naming a code a program can match and a
/// message a person can read, a `Content-Length` that matches what was
/// actually written, and `Connection: close`. Built in one place because
/// six copies of that shape is six chances for a declared length to
/// disagree with its body — which is the one mistake in this module that
/// hangs a client rather than merely annoying it.
///
/// `message` and `code` are literals at every call site, so nothing here
/// escapes them: there is no caller-supplied text in this module and the
/// tests below assert every refusal is still parseable. Interpolating the
/// backend's authority was considered and dropped — the client is on the
/// other machine and cannot act on an address it does not own, while the
/// serve side already logs it.
fn refusal(status_line: &str, extra: &[&str], code: &str, message: &str) -> Vec<u8> {
    let body = format!(r#"{{"error":{{"message":"{message}","code":"{code}"}}}}"#);
    let mut out = Vec::new();
    out.extend_from_slice(status_line.as_bytes());
    out.extend_from_slice(b"\r\n");
    for header in extra {
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Content-Type: application/json\r\n");
    out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(body.as_bytes());
    out
}

/// The 401 the edge writes itself.
///
/// Synthesized locally and never forwarded: the backend has not been
/// contacted at the point this is produced, so there is no upstream
/// response for it to be confused with.
pub(crate) fn unauthorized() -> Vec<u8> {
    refusal(
        "HTTP/1.1 401 Unauthorized",
        &["WWW-Authenticate: Bearer"],
        "invalid_api_key",
        "invalid or missing bearer token",
    )
}

/// The 400 for a head this edge refuses to interpret.
pub(crate) fn bad_request() -> Vec<u8> {
    refusal(
        "HTTP/1.1 400 Bad Request",
        &[],
        "bad_request",
        "malformed or ambiguous request",
    )
}

/// The 502 for a backend whose response this edge cannot read.
///
/// The narrow case, and the only one the single old 502 described: a
/// backend was reached, it answered, and the answer was something this edge
/// will not resolve — ambiguous framing, an unreadable head, or nothing at
/// all before the grace expired.
///
/// Distinct from [`bad_request`] on purpose: the client did nothing wrong,
/// and reporting a gateway failure as a client error would send whoever is
/// debugging it to the wrong side of the tunnel.
pub(crate) fn bad_gateway() -> Vec<u8> {
    refusal(
        "HTTP/1.1 502 Bad Gateway",
        &[],
        "bad_gateway",
        "the backend sent a response this tunnel could not read",
    )
}

/// The 502 for a backend that was never reached at all.
///
/// The most likely failure on a first run, and the one the old wording was
/// worst for: the tunnel is up, the serving side is running, and the model
/// server behind it is not — stopped, on a different port, or bound
/// somewhere this listener may not dial. Saying "the backend sent a
/// response" there is not merely imprecise, it is a claim about an event
/// that did not happen, and it points at the one component that is working.
pub(crate) fn backend_unreachable() -> Vec<u8> {
    refusal(
        "HTTP/1.1 502 Bad Gateway",
        &[],
        "backend_unreachable",
        "the serving side could not reach its backend",
    )
}

/// The 502 the *connect* side writes when it has no tunnel to use.
///
/// Nothing about this one involves a backend: the peer is away, or the
/// connection to it has died and `keep_connected` is looking for a
/// replacement. It is the only refusal in this module produced on the
/// machine that does not have the models, which is exactly why it must not
/// borrow either of the sentences above — the reader is sitting at the
/// client, and what they need to know is that the *other* machine is not
/// there.
pub(crate) fn tunnel_unavailable() -> Vec<u8> {
    refusal(
        "HTTP/1.1 502 Bad Gateway",
        &[],
        "tunnel_unavailable",
        "no tunnel to the serving side is connected right now",
    )
}

/// The 400 for a request body that never arrived whole.
///
/// A client error, and deliberately not [`bad_request`]: that one promises
/// the backend was never contacted, and this one can only be written after
/// the head has gone upstream. The distinction is not pedantry — it is the
/// difference between "your request was malformed" and "your request was
/// fine and your upload stopped", and only the second tells the operator to
/// look at the network rather than at their JSON.
///
/// 400 rather than 408: no timeout expired. Rather than 499, which is not a
/// status. The client is often gone by now — a truncated upload usually
/// means it hung up — but a body this edge could not go on *reading*, an
/// unreadable chunk-size line, leaves it there and owed an answer.
pub(crate) fn incomplete_request() -> Vec<u8> {
    refusal(
        "HTTP/1.1 400 Bad Request",
        &[],
        "incomplete_request",
        "the request body did not arrive complete",
    )
}

#[cfg(test)]
#[path = "refusal_tests.rs"]
mod refusal_tests;
