//! The chunked body, driven through the edge and read back by httparse.
//!
//! Shared by the property tests and the fuzz targets, which check the same
//! rule: whatever chunked body the edge forwards, httparse, an independent
//! and long-fuzzed parser, reads it with the same boundaries.

use tokio::io::{AsyncWriteExt, duplex};

use crate::body::{Buffered, forward};
use crate::framing::Framing;

/// Forward `input` as a chunked body, `split` bytes of it already in hand
/// as the head read's leftover.
pub(crate) fn forward_chunked(input: &[u8], split: usize) -> (std::io::Result<u64>, Vec<u8>) {
    let split = split.min(input.len());
    let (leftover, rest) = input.split_at(split);
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime")
        .block_on(async {
            let (mut tx, mut rx) = duplex(64 * 1024);
            tx.write_all(rest)
                .await
                .expect("the source takes the input");
            drop(tx);
            let mut out = Vec::new();
            let mut src = Buffered::new(&mut rx, leftover.to_vec());
            let n = forward(&mut src, &mut out, Framing::Chunked).await;
            (n, out)
        })
}

/// A chunked body as httparse reads it: the data, or `None` where it cannot
/// read one that ends exactly at the end of `bytes`.
pub(crate) fn chunked(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut data = Vec::new();
    let mut at = 0;
    loop {
        let httparse::Status::Complete((line, size)) =
            httparse::parse_chunk_size(&bytes[at..]).ok()?
        else {
            return None;
        };
        at += line;
        if size == 0 {
            break;
        }
        let end = at.checked_add(usize::try_from(size).ok()?)?;
        data.extend_from_slice(bytes.get(at..end)?);
        if bytes.get(end..end + 2)? != b"\r\n" {
            return None;
        }
        at = end + 2;
    }
    // Trailer lines, then the blank line that ends the body, then nothing.
    loop {
        let rest = &bytes[at..];
        let end = rest.windows(2).position(|w| w == b"\r\n")?;
        at += end + 2;
        if end == 0 {
            return (at == bytes.len()).then_some(data);
        }
    }
}
