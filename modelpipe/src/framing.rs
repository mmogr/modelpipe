//! How a message body is delimited, and the refusals that keeps honest.
//!
//! Split from [`crate::http_head`] because it is the other half of what a
//! head is for. That module turns bytes into a head and a head back into
//! bytes; this one answers the question the head exists to settle — where
//! does the body end — and it is the question request smuggling is built
//! out of, so it is worth being able to read on its own.
//!
//! Pure and synchronous, like its neighbour. Every rule here is decided
//! from values already in hand: a header list, a status code, a method.

use crate::http_head::HeadError;

/// How to find the end of a message body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Framing {
    /// No body at all.
    Empty,
    /// Exactly this many bytes.
    Length(u64),
    /// Chunked transfer coding; the body ends at its terminal chunk.
    Chunked,
    /// The body ends when the peer closes. Responses only — a request
    /// framed this way could never be answered, because the server would
    /// have to wait for a close that means "I am done asking".
    UntilClose,
}

/// Decide how a body is framed, refusing every combination that two
/// implementations could read differently.
///
/// This is the request-smuggling check, and it refuses rather than
/// resolves. RFC 9112 does say `Transfer-Encoding` overrides
/// `Content-Length`, and a proxy that follows that rule is correct and
/// still exploitable: the attack works precisely because the *next* hop
/// resolves the same ambiguity the other way. An edge that refuses cannot
/// disagree with anybody.
///
/// `assume_close` is true for responses, which may legitimately be framed
/// by the connection closing; a request may not be, because a server
/// cannot distinguish "I have finished asking" from "I have gone away".
pub(crate) fn framing(
    fields: &[(String, String)],
    assume_close: bool,
) -> Result<Framing, HeadError> {
    let mut lengths = fields
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim());
    let mut codings = fields
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
        .peekable();

    let chunked = codings.peek().is_some();
    if chunked {
        // Any transfer coding at all rules out Content-Length. Both present
        // is the classic smuggling shape and is refused outright.
        if lengths.next().is_some() {
            return Err(HeadError::ConflictingFraming);
        }
        // `chunked` must be the final coding, and it is the only one this
        // edge implements. A coding it cannot apply is not something to
        // pass through blind.
        let all: Vec<String> = codings
            .flat_map(|(_, value)| value.split(','))
            .map(|token| token.trim().to_ascii_lowercase())
            .filter(|token| !token.is_empty())
            .collect();
        if all.last().map(String::as_str) != Some("chunked") || all.len() != 1 {
            return Err(HeadError::UnsupportedTransferCoding);
        }
        return Ok(Framing::Chunked);
    }

    let Some(first) = lengths.next() else {
        return Ok(if assume_close {
            Framing::UntilClose
        } else {
            Framing::Empty
        });
    };
    // Repeated Content-Length is legal only when every value agrees; two
    // that disagree are the same ambiguity by another route.
    for other in lengths {
        if other != first {
            return Err(HeadError::ConflictingFraming);
        }
    }
    // Digits and nothing else, checked before parsing. RFC 9112 §6.2 makes
    // a `Content-Length` `1*DIGIT`, and `u64::from_str` is more generous
    // than that: it accepts a leading `+`, so `Content-Length: +5` framed a
    // five-byte body here and was forwarded verbatim to a backend whose
    // parser may well read it as no length at all. That is exactly the
    // "two implementations could read this differently" shape this function
    // exists to refuse, and refusing it costs one line.
    if first.is_empty() || !first.bytes().all(|b| b.is_ascii_digit()) {
        return Err(HeadError::ConflictingFraming);
    }
    let length = first
        .parse::<u64>()
        .map_err(|_| HeadError::ConflictingFraming)?;
    Ok(Framing::Length(length))
}

/// How a *response* body is framed, which the headers alone cannot say.
///
/// RFC 9112 §6.3 puts the status code and the request method ahead of every
/// header: a `1xx`, `204` or `304` has no body whatever it declares, and
/// neither does any response to `HEAD` — where `Content-Length` describes
/// what a `GET` would have returned, not what follows.
///
/// Reading those from the headers alone is not a wrong answer, it is a
/// hang. `Length(n)` waits for `n` bytes that will never come and
/// `UntilClose` waits for a close the edge never asked for, both on a
/// socket no timeout covers — so the exchange parks forever holding its
/// stream slot and its drain guard.
///
/// The error case stays an error rather than resolving, which is the whole
/// difference from the previous rule here: a backend answering with both
/// `Content-Length` and `Transfer-Encoding` is the request-smuggling shape
/// [`framing`] refuses on the way in, and refusing it on the way out is the
/// same rule rather than a new one.
pub(crate) fn response_framing(
    status: u16,
    method: &str,
    fields: &[(String, String)],
) -> Result<Framing, HeadError> {
    if is_interim(status) || status == 204 || status == 304 || method.eq_ignore_ascii_case("head") {
        return Ok(Framing::Empty);
    }
    framing(fields, true)
}

/// Whether a status code is informational — a head that precedes the real
/// response rather than being one.
pub(crate) const fn is_interim(status: u16) -> bool {
    status >= 100 && status < 200
}
