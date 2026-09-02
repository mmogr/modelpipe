//! Reading a message head off a stream, under the bound the edge enforces.
//!
//! Split from [`crate::exchange`] because it answers a different question.
//! The edge decides what a head *means* — how the body is framed, whether
//! the credential admits, whether the backend is contacted at all. This
//! decides only when there is a head to look at, and refuses one that is
//! too large to be worth buffering.
//!
//! Generic over [`AsyncRead`], so nothing here learns where the bytes came
//! from. The request and response readers were written twice and were the
//! same loop both times; they are one loop now, and the caller supplies the
//! parser.

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::http_head::{self, HeadError, MAX_HEAD_BYTES, RequestHead, ResponseHead};

/// One pull from the stream. Small on purpose: a head is a few hundred
/// bytes and this is re-parsed from the start on every fill.
const PULL: usize = 4096;

/// What a head reader hands back: the head, and the bytes that arrived
/// after it. Named because the two readers and the loop behind them all
/// spell it, and spelling it three times is what the lint is objecting to.
pub(crate) type Read<H> = std::io::Result<Result<(H, Vec<u8>), HeadError>>;

/// A head parser, as [`read`] consumes one. `Ok(None)` means "a valid
/// prefix, send more".
type Parse<H> = fn(&[u8]) -> Result<Option<(H, usize)>, HeadError>;

/// Read until the request head is complete, or the bound is reached.
///
/// `prefix` is bytes already taken off the stream that belong to this head.
/// The returned `Vec` is the tail — whatever arrived after the head, which
/// is usually the start of the body.
///
/// The outer `Result` is transport failure; the inner one is a head this
/// edge refuses. They are different things: one means the stream broke, the
/// other means the peer sent something it should not have.
pub(crate) async fn request<S: AsyncRead + Unpin>(
    stream: &mut S,
    prefix: Vec<u8>,
) -> Read<RequestHead> {
    read(stream, prefix, http_head::parse_request).await
}

/// The response twin of [`request`].
///
/// `prefix` earns its place here rather than being an artefact of sharing
/// the loop: an interim (`1xx`) response is a complete head followed
/// immediately by another, and the bytes that arrived with the interim one
/// are the start of the head after it.
pub(crate) async fn response<S: AsyncRead + Unpin>(
    stream: &mut S,
    prefix: Vec<u8>,
) -> Read<ResponseHead> {
    read(stream, prefix, http_head::parse_response).await
}

/// The loop both readers are.
async fn read<S, H>(stream: &mut S, prefix: Vec<u8>, parse: Parse<H>) -> Read<H>
where
    S: AsyncRead + Unpin,
{
    let mut buf = prefix;
    loop {
        match parse(&buf) {
            Ok(Some((head, consumed))) => return Ok(Ok((head, buf[consumed..].to_vec()))),
            Ok(None) => {}
            Err(e) => return Ok(Err(e)),
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Ok(Err(HeadError::TooLarge));
        }
        let mut next = [0u8; PULL];
        let n = stream.read(&mut next).await?;
        if n == 0 {
            // The peer stopped mid-head. Nothing to answer, and nothing to
            // forward.
            return Ok(Err(HeadError::Malformed));
        }
        buf.extend_from_slice(&next[..n]);
    }
}
