//! The pairing exchange's bytes, from the connect side: the request a device
//! sends through its own local port, and how the answer is read.
//!
//! Apart from [`pair`](fn@crate::pair), the call an embedder makes, and the
//! errors it answers with. These are the parts a test drives without a pipe.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use crate::http_head;
use crate::invite::PAIR_PATH;
use crate::pair::PairError;
use crate::peer_id::PeerId;

/// The most of an answer this reads. A pairing answer is a few hundred bytes.
const MAX_ANSWER: u64 = 64 * 1024;

/// The most of a label this sends, cut at a character boundary. The edge
/// keeps sixty-four characters of it.
const MAX_LABEL_BYTES: usize = 4096;

/// Send `request` to this side's local port, and read the whole answer.
pub(crate) async fn exchange(local: SocketAddr, request: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut socket = TcpStream::connect(local).await?;
    socket.write_all(request).await?;
    socket.flush().await?;
    let mut answer = Vec::new();
    socket.take(MAX_ANSWER).read_to_end(&mut answer).await?;
    Ok(answer)
}

/// The pairing request, with `label` cut to at most [`MAX_LABEL_BYTES`] at a
/// character boundary.
pub(crate) fn redeem_request(authority: SocketAddr, code: &str, label: &str) -> Vec<u8> {
    let mut end = label.len().min(MAX_LABEL_BYTES);
    while !label.is_char_boundary(end) {
        end -= 1;
    }
    let body = &label[..end];
    format!(
        "POST {PAIR_PATH} HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Bearer {code}\r\n\
         Content-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// The key and device name a pairing answer carries, checked against the
/// endpoint the ticket named.
pub(crate) fn redeemed(answer: &[u8], serving: PeerId) -> Result<(String, String), PairError> {
    let (head, consumed) = match http_head::parse_response(answer) {
        Ok(Some(parsed)) => parsed,
        // No bytes, or the start of a head and no end to it: the pipe gave out
        // under the answer, maybe after the edge had spent the code.
        Ok(None) => return Err(answer_lost()),
        Err(_) => return Err(PairError::Unexpected("no HTTP response head")),
    };
    match head.status {
        200 => {}
        401 => return Err(PairError::Refused),
        // This side's own answer when the pipe dropped under the request, so
        // nothing reached the edge.
        502 => {
            return Err(PairError::Exchange(std::io::Error::other(
                "the pipe to the serve side dropped before the code arrived",
            )));
        }
        // Carried as a number, not a sentence, so an embedder matches the
        // status rather than prose. A serve side too old to know this path
        // answers here.
        other => return Err(PairError::UnexpectedStatus { status: other }),
    }
    let declared = head
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok());
    if declared.is_some_and(|length| answer.len() - consumed < length) {
        return Err(answer_lost());
    }
    let body = std::str::from_utf8(&answer[consumed..])
        .map_err(|_| PairError::Unexpected("a body that is not UTF-8"))?;
    let api_key = field(body, "api_key")?;
    let device = field(body, "device_id")?;
    let peer: PeerId = field(body, "peer")?
        .parse()
        .map_err(|_| PairError::Unexpected("a peer that is not an endpoint id"))?;
    if peer != serving {
        return Err(PairError::Unexpected(
            "a peer other than the endpoint the ticket named",
        ));
    }
    if api_key.is_empty() || device.is_empty() {
        return Err(PairError::Unexpected("an empty key or device"));
    }
    Ok((api_key, device))
}

/// The pipe gave out before the answer was whole, maybe after the edge had
/// spent the code.
fn answer_lost() -> PairError {
    PairError::Exchange(std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "the answer stopped before it was whole",
    ))
}

/// The string value of `name` in a flat JSON object whose values need no
/// escaping, as a pairing answer's do. A value with a backslash in it is
/// refused rather than unescaped.
fn field(body: &str, name: &str) -> Result<String, PairError> {
    let key = format!("\"{name}\":\"");
    let start = body
        .find(&key)
        .ok_or(PairError::Unexpected("a field is missing"))?
        + key.len();
    let len = body[start..]
        .find('"')
        .ok_or(PairError::Unexpected("a field is not closed"))?;
    let value = &body[start..start + len];
    if value.contains('\\') {
        return Err(PairError::Unexpected("an escaped value"));
    }
    // A minted key is base32, a device name is a token name, and a peer is
    // hex. Anything else, a terminal's control characters above all, is not
    // an answer an edge wrote, and must not reach whoever prints the key.
    if !value.chars().all(|c| c.is_ascii_graphic()) {
        return Err(PairError::Unexpected(
            "a value with characters a key or a name never has",
        ));
    }
    Ok(value.to_owned())
}

#[cfg(test)]
#[path = "pair_wire_tests.rs"]
mod pair_wire_tests;
