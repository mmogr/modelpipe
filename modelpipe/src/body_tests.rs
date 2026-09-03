//! Tests for [`super`] — body forwarding under each framing.
//!
//! Split out via `#[path]` so `body.rs` stays inside the file-size budget.
//!
//! Every case runs over `tokio::io::duplex()`: no socket, no port, no peer.
//! That is the payoff of keeping this module generic over `AsyncRead` and
//! `AsyncWrite` — the whole body path is exercised before the transport
//! exists.

use super::*;
use tokio::io::duplex;

/// Forward `input` under `framing`, with `leftover` standing in for bytes
/// already read while parsing the head.
async fn run(leftover: &[u8], input: &[u8], framing: Framing) -> std::io::Result<(u64, Vec<u8>)> {
    let (mut src_tx, mut src_rx) = duplex(64 * 1024);
    src_tx.write_all(input).await.unwrap();
    drop(src_tx); // the source ends here, which is what UntilClose needs

    let mut out = Vec::new();
    let mut buffered = Buffered::new(&mut src_rx, leftover.to_vec());
    let n = forward(&mut buffered, &mut out, framing).await?;
    Ok((n, out))
}

// ── Length-framed ────────────────────────────────────────────────────────

#[tokio::test]
async fn a_length_framed_body_forwards_exactly_its_declared_size() {
    let (n, out) = run(b"", b"abcdefghij", Framing::Length(10)).await.unwrap();
    assert_eq!(n, 10);
    assert_eq!(out, b"abcdefghij");
}

/// The head read almost always over-reads into the body, so the leftover
/// path is the common case rather than an edge one.
#[tokio::test]
async fn bytes_already_read_with_the_head_are_forwarded_first() {
    let (n, out) = run(b"abc", b"defghij", Framing::Length(10)).await.unwrap();
    assert_eq!(n, 10);
    assert_eq!(out, b"abcdefghij");
}

/// Everything may already be in hand, in which case the source is never
/// read at all.
#[tokio::test]
async fn a_body_entirely_in_the_leftover_needs_no_read() {
    let (n, out) = run(b"abcdefghij", b"", Framing::Length(10)).await.unwrap();
    assert_eq!(n, 10);
    assert_eq!(out, b"abcdefghij");
}

/// Only the declared body is taken. Anything after it belongs to whatever
/// comes next and must not be swept up.
#[tokio::test]
async fn nothing_past_the_declared_length_is_forwarded() {
    let (n, out) = run(b"", b"abcdeSURPLUS", Framing::Length(5)).await.unwrap();
    assert_eq!(n, 5);
    assert_eq!(out, b"abcde");
}

/// A body shorter than promised is refused rather than forwarded short: a
/// truncated request delivered as complete is one the backend answers on
/// partial input.
#[tokio::test]
async fn a_body_shorter_than_its_declared_length_is_an_error() {
    let err = run(b"", b"abc", Framing::Length(10)).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn an_empty_framing_forwards_nothing() {
    let (n, out) = run(b"ignored", b"also ignored", Framing::Empty)
        .await
        .unwrap();
    assert_eq!(n, 0);
    assert!(out.is_empty());
}

// ── Chunked ──────────────────────────────────────────────────────────────

/// The chunked framing is re-emitted verbatim: sizes are parsed, because
/// the body's end has to be found, but the bytes pass through untouched.
#[tokio::test]
async fn a_chunked_body_is_forwarded_with_its_framing_intact() {
    let input = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    let (n, out) = run(b"", input, Framing::Chunked).await.unwrap();
    assert_eq!(n, 11, "the payload bytes, not the framing overhead");
    assert_eq!(out, input, "byte for byte, framing included");
}

#[tokio::test]
async fn a_chunked_body_with_no_chunks_is_forwarded() {
    let (n, out) = run(b"", b"0\r\n\r\n", Framing::Chunked).await.unwrap();
    assert_eq!(n, 0);
    assert_eq!(out, b"0\r\n\r\n");
}

/// Trailers follow the terminal chunk and are part of the body.
#[tokio::test]
async fn trailers_after_the_terminal_chunk_are_forwarded() {
    let input = b"3\r\nabc\r\n0\r\nX-Checksum: 1\r\n\r\n";
    let (_, out) = run(b"", input, Framing::Chunked).await.unwrap();
    assert_eq!(out, input);
}

/// A trailer is a header field that arrives after the body, so the edge's
/// header rules apply to it. Without this a peer could restate anything the
/// head strip had just removed — the strip applied and then undone a few
/// hundred bytes later, on the one part of the message nothing was
/// filtering.
#[tokio::test]
async fn a_trailer_cannot_restate_a_header_the_head_strip_removes() {
    let input = b"3\r\nabc\r\n0\r\n\
                  X-Forwarded-For: 203.0.113.9\r\n\
                  Connection: keep-alive\r\n\
                  Transfer-Encoding: chunked\r\n\
                  Content-Length: 99\r\n\
                  Host: elsewhere.example\r\n\
                  X-Checksum: 1\r\n\r\n";
    let (_, out) = run(b"", input, Framing::Chunked).await.unwrap();
    let text = String::from_utf8(out).expect("ascii");
    assert!(
        !text.contains("203.0.113.9"),
        "a forwarding chain reached the far side through the trailers: {text}"
    );
    // `Content-Length` and `Host` are the two this test did not cover and
    // the filter did not catch: neither is hop-by-hop and neither is a
    // forwarding header, so `is_stripped` passed them straight through
    // while the comment above the filter named `Content-Length` as an
    // example of what it stopped. A second length arriving after the body,
    // on a message already framed as chunked, is the framing confusion the
    // whole strip exists to avoid creating.
    for stripped in [
        "Connection:",
        "Transfer-Encoding:",
        "Content-Length:",
        "Host:",
    ] {
        assert!(!text.contains(stripped), "{stripped} survived: {text}");
    }
    // The point is a filter, not a deletion: an ordinary trailer is still
    // the peer's to send.
    assert!(text.contains("X-Checksum: 1"), "{text}");
    assert!(text.ends_with("\r\n\r\n"), "the body still ends: {text:?}");
}

/// A trailer line the edge cannot read as a field is not forwarded, on the
/// rule `http_head::collect` already applies to header values: passing on
/// bytes this edge could not parse is how a value means one thing here and
/// another downstream.
#[tokio::test]
async fn a_trailer_that_is_not_a_field_is_dropped() {
    let input = b"0\r\nnot a header line\r\nX-Kept: 1\r\n\r\n";
    let (_, out) = run(b"", input, Framing::Chunked).await.unwrap();
    let text = String::from_utf8(out).expect("ascii");
    assert!(!text.contains("not a header line"), "{text}");
    assert!(text.contains("X-Kept: 1"), "{text}");
}

/// Chunk extensions are not this edge's to interpret, and must survive.
#[tokio::test]
async fn chunk_extensions_pass_through_uninterpreted() {
    let input = b"3;name=value\r\nabc\r\n0\r\n\r\n";
    let (n, out) = run(b"", input, Framing::Chunked).await.unwrap();
    assert_eq!(n, 3);
    assert_eq!(out, input);
}

#[tokio::test]
async fn a_chunk_size_that_is_not_hexadecimal_is_an_error() {
    for input in [
        &b"zz\r\nabc\r\n0\r\n\r\n"[..],
        &b"-1\r\nabc\r\n0\r\n\r\n"[..],
        &b" \r\n"[..],
    ] {
        assert!(
            run(b"", input, Framing::Chunked).await.is_err(),
            "{input:?} is not a chunk size"
        );
    }
}

/// A chunk whose data is not followed by CRLF is a desynchronized stream,
/// and continuing to read it would mean guessing where the next size line
/// begins.
#[tokio::test]
async fn a_chunk_not_terminated_by_crlf_is_an_error() {
    assert!(
        run(b"", b"3\r\nabcXX\r\n0\r\n\r\n", Framing::Chunked)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_chunked_body_that_ends_before_its_terminal_chunk_is_an_error() {
    let err = run(b"", b"5\r\nhello\r\n", Framing::Chunked)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

/// An unbounded size line is an unbounded allocation for the price of one
/// connection.
#[tokio::test]
async fn an_over_long_chunk_size_line_is_refused() {
    let input = vec![b'0'; MAX_CHUNK_LINE + 64];
    assert!(run(b"", &input, Framing::Chunked).await.is_err());
}

// ── Until close ──────────────────────────────────────────────────────────

#[tokio::test]
async fn a_close_framed_body_forwards_everything_until_the_source_ends() {
    let (n, out) = run(b"lead", b"ing and trailing", Framing::UntilClose)
        .await
        .unwrap();
    assert_eq!(n, 20);
    assert_eq!(out, b"leading and trailing");
}

#[tokio::test]
async fn a_close_framed_body_may_be_empty() {
    let (n, out) = run(b"", b"", Framing::UntilClose).await.unwrap();
    assert_eq!(n, 0);
    assert!(out.is_empty());
}

// ── Streaming ────────────────────────────────────────────────────────────

/// The highest-value assertion in this file. A `read_to_end` anywhere in
/// the forward path would turn per-token delivery into one blob, and every
/// test above would still pass — they only check the bytes. This one checks
/// *when*: the first frame must reach the destination while the source is
/// still open and has not written its last.
#[tokio::test]
async fn a_frame_reaches_the_destination_before_the_source_has_finished() {
    let (mut src_tx, mut src_rx) = duplex(64 * 1024);
    let (mut dst_tx, mut dst_rx) = duplex(64 * 1024);

    let pump = tokio::spawn(async move {
        let mut buffered = Buffered::new(&mut src_rx, Vec::new());
        forward(&mut buffered, &mut dst_tx, Framing::UntilClose).await
    });

    src_tx.write_all(b"data: first\n\n").await.unwrap();
    src_tx.flush().await.unwrap();

    // Read the first frame back while the source is still open. If the
    // implementation buffered, this times out and the test fails loudly
    // rather than hanging the suite.
    let mut seen = [0u8; 13];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        dst_rx.read_exact(&mut seen),
    )
    .await
    .expect("the first frame must arrive before the source closes")
    .expect("read");
    assert_eq!(&seen, b"data: first\n\n");

    src_tx.write_all(b"data: [DONE]\n\n").await.unwrap();
    drop(src_tx);
    let forwarded = pump.await.unwrap().unwrap();
    assert_eq!(forwarded, 27);
}

/// A trailer line may not carry an embedded line terminator.
///
/// `read_line` ends a line at CRLF, and `dropped` inspects only the field
/// name before the first colon. So a *bare LF* inside a trailer is not a
/// line ending here and is not looked past: everything after it rides
/// through on the strength of the name in front of it. A recipient that
/// treats a bare LF as a terminator — many do — then reads a second field
/// this edge never filtered, which is the whole shape of request smuggling
/// and precisely what the trailer filter exists to prevent.
#[tokio::test]
async fn a_trailer_cannot_smuggle_a_second_field_behind_a_bare_lf() {
    let input = b"0\r\nX-Ok: 1\nContent-Length: 99\r\n\r\n";
    let (_, out) = run(b"", input, Framing::Chunked).await.unwrap();
    let text = String::from_utf8(out).expect("ascii");
    assert!(
        !text.contains("Content-Length"),
        "a second field rode through behind a bare LF: {text:?}"
    );
}

/// The negative control for the bare-LF refusal: an ordinary trailer, on a
/// line with no embedded terminator, is still the peer's to send.
///
/// Without this the fix could be "drop every trailer", which would satisfy
/// the test above and silently discard the checksums this edge is supposed
/// to forward.
#[tokio::test]
async fn an_ordinary_trailer_still_survives_the_terminator_check() {
    let input = b"3\r\nabc\r\n0\r\nX-Checksum: 1\r\nX-Other: 2\r\n\r\n";
    let (_, out) = run(b"", input, Framing::Chunked).await.unwrap();
    let text = String::from_utf8(out).expect("ascii");
    assert!(text.contains("X-Checksum: 1"), "{text:?}");
    assert!(text.contains("X-Other: 2"), "{text:?}");
}

/// A chunk size is `1*HEXDIG` (RFC 9112 §7.1), and `from_str_radix` is more
/// generous than that.
///
/// The same laxness `framing` refuses in a `Content-Length`, on the other
/// half of the same job: `+a` framed a ten-byte chunk while the size line
/// went to the next hop verbatim, for it to read its own way.
#[tokio::test]
async fn a_chunk_size_that_is_not_plain_hexadecimal_is_refused() {
    for bad in ["+a\r\nabcdefghij\r\n0\r\n\r\n", "-1\r\n\r\n0\r\n\r\n"] {
        let err = run(b"", bad.as_bytes(), Framing::Chunked)
            .await
            .expect_err("must be refused");
        assert!(
            err.to_string().contains("hexadecimal"),
            "{bad:?} gave {err}"
        );
    }
}

/// The negative control: ordinary hex sizes, in either case, still frame.
#[tokio::test]
async fn an_ordinary_chunk_size_is_still_hexadecimal() {
    for (input, body) in [
        ("3\r\nabc\r\n0\r\n\r\n", "abc"),
        ("A\r\n0123456789\r\n0\r\n\r\n", "0123456789"),
        ("a\r\n0123456789\r\n0\r\n\r\n", "0123456789"),
    ] {
        let (n, out) = run(b"", input.as_bytes(), Framing::Chunked)
            .await
            .unwrap_or_else(|e| panic!("{input:?} must frame: {e}"));
        assert_eq!(n, body.len() as u64, "{input:?}");
        assert!(String::from_utf8(out).unwrap().contains(body), "{input:?}");
    }
}
