//! Request and response heads: parsing them, deciding how a body is
//! framed, and writing them back out.
//!
//! Pure and synchronous. Nothing here reads a socket — it is handed bytes
//! and returns a decision — which is what lets the framing rules, the ones
//! request smuggling is built out of, be tested without a network, a
//! runtime, or a peer.
//!
//! Only the head is parsed. Bodies are forwarded as bytes under whatever
//! framing was declared, because one QUIC stream carries exactly one
//! exchange: there is no second request on this connection for a framing
//! disagreement to desynchronize, which is the property that makes an
//! opaque body safe here and would not make it safe on a shared socket.

use crate::headers;

/// The most head a peer may send before being cut off.
///
/// A ticket-holder can open a stream and start typing headers; without a
/// bound, that is an unbounded allocation for the cost of a connection.
/// 64 KiB is far past any real client — an OpenAI-compatible request head
/// is a few hundred bytes — and far below anything that matters.
pub(crate) const MAX_HEAD_BYTES: usize = 64 * 1024;

/// The most header fields a head may carry, bounding the parse itself.
const MAX_HEADER_FIELDS: usize = 128;

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

/// Why a head was refused. Every variant is a 400 to the client; they are
/// separate so a test can say which rule fired rather than only that one
/// did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeadError {
    /// Not HTTP, or not HTTP this edge speaks.
    Malformed,
    /// Longer than [`MAX_HEAD_BYTES`], or more fields than allowed.
    TooLarge,
    /// `Content-Length` and `Transfer-Encoding` both present, or two
    /// `Content-Length` headers that disagree, or a length that is not a
    /// number. The request-smuggling family.
    ConflictingFraming,
    /// A transfer coding this edge does not implement.
    UnsupportedTransferCoding,
}

/// A parsed request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestHead {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) headers: Vec<(String, String)>,
}

/// A parsed response head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResponseHead {
    pub(crate) status: u16,
    pub(crate) reason: String,
    pub(crate) headers: Vec<(String, String)>,
}

/// Parse a request head. `Ok(None)` means the bytes so far are a valid
/// prefix and more are needed; the returned `usize` is where the body
/// begins.
pub(crate) fn parse_request(buf: &[u8]) -> Result<Option<(RequestHead, usize)>, HeadError> {
    if buf.len() > MAX_HEAD_BYTES {
        return Err(HeadError::TooLarge);
    }
    let mut fields = [httparse::EMPTY_HEADER; MAX_HEADER_FIELDS];
    let mut req = httparse::Request::new(&mut fields);
    match req.parse(buf) {
        Ok(httparse::Status::Complete(consumed)) => {
            let head = RequestHead {
                method: req.method.ok_or(HeadError::Malformed)?.to_owned(),
                target: req.path.ok_or(HeadError::Malformed)?.to_owned(),
                headers: collect(req.headers)?,
            };
            Ok(Some((head, consumed)))
        }
        Ok(httparse::Status::Partial) => Ok(None),
        Err(httparse::Error::TooManyHeaders) => Err(HeadError::TooLarge),
        Err(_) => Err(HeadError::Malformed),
    }
}

/// Parse a response head. Same contract as [`parse_request`].
pub(crate) fn parse_response(buf: &[u8]) -> Result<Option<(ResponseHead, usize)>, HeadError> {
    if buf.len() > MAX_HEAD_BYTES {
        return Err(HeadError::TooLarge);
    }
    let mut fields = [httparse::EMPTY_HEADER; MAX_HEADER_FIELDS];
    let mut res = httparse::Response::new(&mut fields);
    match res.parse(buf) {
        Ok(httparse::Status::Complete(consumed)) => {
            let head = ResponseHead {
                status: res.code.ok_or(HeadError::Malformed)?,
                reason: res.reason.unwrap_or("").to_owned(),
                headers: collect(res.headers)?,
            };
            Ok(Some((head, consumed)))
        }
        Ok(httparse::Status::Partial) => Ok(None),
        Err(httparse::Error::TooManyHeaders) => Err(HeadError::TooLarge),
        Err(_) => Err(HeadError::Malformed),
    }
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
    let length = first
        .parse::<u64>()
        .map_err(|_| HeadError::ConflictingFraming)?;
    Ok(Framing::Length(length))
}

/// Serialize a request head, re-declaring chunked framing when that is how
/// the body will be forwarded.
///
/// `Transfer-Encoding` is hop-by-hop and has already been stripped, so a
/// chunked body would otherwise arrive at the backend with nothing left to
/// say how it is framed. Each hop declares its own.
pub(crate) fn serialize_request(head: &RequestHead, framing: Framing) -> Vec<u8> {
    let mut out = format!("{} {} HTTP/1.1\r\n", head.method, head.target).into_bytes();
    write_fields(&mut out, &head.headers, framing);
    out
}

/// Serialize a response head. Same chunked re-declaration as requests.
pub(crate) fn serialize_response(head: &ResponseHead, framing: Framing) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {} {}\r\n", head.status, head.reason).into_bytes();
    write_fields(&mut out, &head.headers, framing);
    out
}

fn write_fields(out: &mut Vec<u8>, fields: &[(String, String)], framing: Framing) {
    for (name, value) in fields {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if framing == Framing::Chunked {
        out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    }
    out.extend_from_slice(b"\r\n");
}

/// The value of the first `Authorization` header, if any.
pub(crate) fn authorization(fields: &[(String, String)]) -> Option<&[u8]> {
    fields
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.as_bytes())
}

/// Apply the edge's header rules in the order they must happen.
pub(crate) fn rewrite_for_backend(head: &mut RequestHead, authority: &str) {
    headers::strip_hop_by_hop(&mut head.headers);
    headers::strip_inbound_forwarded(&mut head.headers);
    headers::set_host(&mut head.headers, authority);
}

fn collect(fields: &[httparse::Header<'_>]) -> Result<Vec<(String, String)>, HeadError> {
    fields
        .iter()
        .map(|h| {
            // A header value that is not UTF-8 is refused rather than
            // lossily converted: forwarding bytes the edge could not read is
            // how a value means one thing here and another downstream.
            let value = std::str::from_utf8(h.value).map_err(|_| HeadError::Malformed)?;
            Ok((h.name.to_owned(), value.to_owned()))
        })
        .collect()
}

#[cfg(test)]
#[path = "http_head_tests.rs"]
mod http_head_tests;
