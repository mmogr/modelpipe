//! Moving a message body from one stream to another under a known framing.
//!
//! Generic over [`AsyncRead`] and [`AsyncWrite`], so every case here is
//! exercised over `tokio::io::duplex()` with no socket, no port and no
//! peer. Nothing in this module knows what iroh is.
//!
//! Each frame is written and flushed as it arrives rather than collected
//! and forwarded at the end. That is not an optimization: the product is a
//! token stream, and a `read_to_end` anywhere in this file would turn
//! per-token delivery into one blob that still returns 200 and still passes
//! any test that only checks the bytes.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::framing::Framing;
use crate::headers;

/// Read size for one pull from the source.
const CHUNK: usize = 16 * 1024;

/// The longest chunk-size line a peer may send. A chunked body announces
/// each chunk's size on its own line; without a bound, a peer that sends an
/// endless line of digits is an unbounded allocation.
const MAX_CHUNK_LINE: usize = 1024;

/// A source with bytes already read from it — the tail of the head read,
/// which is usually the start of the body.
pub(crate) struct Buffered<'a, R> {
    src: &'a mut R,
    buf: Vec<u8>,
    pos: usize,
}

impl<'a, R: AsyncRead + Unpin> Buffered<'a, R> {
    pub(crate) const fn new(src: &'a mut R, leftover: Vec<u8>) -> Self {
        Self {
            src,
            buf: leftover,
            pos: 0,
        }
    }

    fn available(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn consume(&mut self, n: usize) {
        self.pos += n;
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        }
    }

    /// Pull more bytes. `Ok(false)` at end of stream.
    async fn fill(&mut self) -> std::io::Result<bool> {
        let mut next = vec![0u8; CHUNK];
        let n = self.src.read(&mut next).await?;
        if n == 0 {
            return Ok(false);
        }
        next.truncate(n);
        // Compact rather than growing forever: what has been consumed is
        // gone, and a long body would otherwise retain every byte of it.
        self.buf.drain(..self.pos);
        self.pos = 0;
        self.buf.extend_from_slice(&next);
        Ok(true)
    }

    /// Read up to and including the next CRLF, returning the line without
    /// it.
    async fn read_line(&mut self) -> std::io::Result<Vec<u8>> {
        loop {
            if let Some(end) = find_crlf(self.available()) {
                let line = self.available()[..end].to_vec();
                self.consume(end + 2);
                return Ok(line);
            }
            if self.available().len() > MAX_CHUNK_LINE {
                return Err(std::io::Error::other("chunk line is too long"));
            }
            if !self.fill().await? {
                return Err(unexpected_eof());
            }
        }
    }
}

/// Forward a body of the given framing from `src` to `dst`.
///
/// Returns the number of body bytes forwarded.
pub(crate) async fn forward<R, W>(
    src: &mut Buffered<'_, R>,
    dst: &mut W,
    framing: Framing,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match framing {
        Framing::Empty => Ok(0),
        Framing::Length(n) => forward_exact(src, dst, n).await,
        Framing::Chunked => forward_chunked(src, dst).await,
        Framing::UntilClose => forward_to_close(src, dst).await,
    }
}

async fn forward_exact<R, W>(
    src: &mut Buffered<'_, R>,
    dst: &mut W,
    mut remaining: u64,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let total = remaining;
    while remaining > 0 {
        if src.available().is_empty() && !src.fill().await? {
            // Fewer bytes than the head promised. Refused rather than
            // forwarded short: a truncated body delivered as if complete is
            // a request the backend answers on partial input.
            return Err(unexpected_eof());
        }
        let take = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(src.available().len());
        dst.write_all(&src.available()[..take]).await?;
        dst.flush().await?;
        src.consume(take);
        remaining -= take as u64;
    }
    Ok(total)
}

/// Forward a chunked body, re-emitting the chunked framing verbatim.
///
/// The sizes are parsed — they have to be, to know where the body ends —
/// but each chunk's bytes pass through untouched, so this neither decodes
/// nor re-encodes. Trailers after the terminal chunk are forwarded as they
/// arrive.
async fn forward_chunked<R, W>(src: &mut Buffered<'_, R>, dst: &mut W) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    loop {
        let line = src.read_line().await?;
        // Chunk extensions follow a `;` and are not ours to interpret.
        let size_text = line.split(|&b| b == b';').next().unwrap_or(&[]);
        let size_text = std::str::from_utf8(size_text)
            .map_err(|_| std::io::Error::other("chunk size is not ASCII"))?
            .trim();
        let size = u64::from_str_radix(size_text, 16)
            .map_err(|_| std::io::Error::other("chunk size is not hexadecimal"))?;

        dst.write_all(&line).await?;
        dst.write_all(b"\r\n").await?;

        if size == 0 {
            // Trailers, then the blank line that ends the body.
            //
            // Filtered by the same rule the head is, because a trailer is a
            // header field that arrives late and nothing else. Forwarding
            // them verbatim let a peer restate anything the head strip had
            // just removed — a client putting back its own
            // `X-Forwarded-For`, a backend putting back `Connection` or a
            // second `Content-Length` — with the edge's own header rules
            // applied and then undone a few hundred bytes later.
            loop {
                let trailer = src.read_line().await?;
                if trailer.is_empty() {
                    dst.write_all(b"\r\n").await?;
                    break;
                }
                if !dropped(&trailer) {
                    dst.write_all(&trailer).await?;
                    dst.write_all(b"\r\n").await?;
                }
            }
            dst.flush().await?;
            return Ok(total);
        }

        total += forward_exact(src, dst, size).await?;
        // The CRLF that terminates the chunk data.
        let terminator = src.read_line().await?;
        if !terminator.is_empty() {
            return Err(std::io::Error::other("chunk data is not CRLF-terminated"));
        }
        dst.write_all(b"\r\n").await?;
        dst.flush().await?;
    }
}

async fn forward_to_close<R, W>(src: &mut Buffered<'_, R>, dst: &mut W) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    loop {
        if src.available().is_empty() && !src.fill().await? {
            dst.flush().await?;
            return Ok(total);
        }
        let n = src.available().len();
        dst.write_all(src.available()).await?;
        // Flushed per read, not per body: this is the streaming path, and a
        // response that arrives a token at a time has to leave the same way.
        dst.flush().await?;
        src.consume(n);
        total += n as u64;
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// Whether a trailer line names a field the edge strips from a head.
///
/// A line with no colon is not a field at all; it is dropped, because
/// passing bytes onward that this edge could not read is how a value means
/// one thing here and another downstream — the rule `http_head::collect`
/// already applies to header values.
fn dropped(line: &[u8]) -> bool {
    line.iter()
        .position(|&b| b == b':')
        .is_none_or(|colon| std::str::from_utf8(&line[..colon]).is_ok_and(headers::is_stripped))
}

fn unexpected_eof() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "the body ended before its declared length",
    )
}

#[cfg(test)]
#[path = "body_tests.rs"]
mod body_tests;
