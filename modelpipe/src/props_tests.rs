//! The edge's framing rules, held against input nobody wrote by hand.
//!
//! The other tests name the inputs that broke something once. These
//! generate them: valid chunked bodies cut at any point, the same bodies
//! with bytes mutated, and header lists built from the fields framing is
//! decided by. The chunked properties use httparse as the oracle. It is an
//! independent and long-fuzzed parser, so whatever this edge forwards, a
//! strict next hop has to read it with the same boundaries. That is the
//! smuggling property, stated as a test.

use proptest::prelude::*;
use tokio::io::{AsyncWriteExt, duplex};

use crate::body::{Buffered, forward};
use crate::framing::{Framing, framing};
use crate::http_head::{parse_request, parse_response};

/// Forward `input` as a chunked body, `split` bytes of it already in hand
/// as the head read's leftover.
fn forward_chunked(input: &[u8], split: usize) -> (std::io::Result<u64>, Vec<u8>) {
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
fn oracle(bytes: &[u8]) -> Option<Vec<u8>> {
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

/// One chunk's data, and the extension its size line carries, if any.
fn chunk() -> impl Strategy<Value = (Vec<u8>, Option<String>)> {
    (
        prop::collection::vec(any::<u8>(), 1..64),
        prop::option::of(prop::sample::select(vec![
            ";a".to_owned(),
            ";name=value".to_owned(),
            ";x=\"quoted\"".to_owned(),
            " ;padded".to_owned(),
        ])),
    )
}

/// Trailers the edge forwards, beside ones it must drop.
fn trailers() -> impl Strategy<Value = Vec<&'static str>> {
    prop::collection::vec(
        prop::sample::select(vec![
            "X-Checksum: 1",
            "Server-Timing: total;dur=5",
            "Content-Length: 99",
            "Authorization: Bearer stolen",
            "X-Forwarded-For: 10.0.0.1",
        ]),
        0..4,
    )
}

/// Encode `chunks` and `trailers` as a chunked body.
fn encode(chunks: &[(Vec<u8>, Option<String>)], trailers: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for (data, ext) in chunks {
        out.extend_from_slice(format!("{:x}", data.len()).as_bytes());
        if let Some(ext) = ext {
            out.extend_from_slice(ext.as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(data);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n");
    for trailer in trailers {
        out.extend_from_slice(trailer.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// The bytes most likely to change what a chunked body means.
const SHARP: &[u8] = b"0123456789abcdefABCDEF;=\" \t\r\n:+-xX\x00\x7f";

/// One edit to a body: replace, insert or delete at a position, with a
/// byte from [`SHARP`] or any byte at all.
fn mutation() -> impl Strategy<Value = (u8, usize, u8)> {
    (
        0..3u8,
        any::<usize>(),
        prop_oneof![prop::sample::select(SHARP.to_vec()), any::<u8>()],
    )
}

/// A chunk whose size line is spelled any of the ways a parser can be
/// lenient about: a sign, leading zeros, padding on either side, an
/// extension with a control byte or a no-break space, a bare LF. The data
/// is always the declared length, so the size line is the only question.
fn spelled_chunk() -> impl Strategy<Value = Vec<u8>> {
    (
        prop::collection::vec(any::<u8>(), 1..48),
        prop::sample::select(vec!["", "+", "-", " ", "\t", "0", "00", "0x"]),
        prop::sample::select(vec![
            "",
            " ",
            "\t",
            ";a",
            " ;a",
            "\t;a",
            ";a=\"b;c\"",
            ";a\0",
            ";a\x7f",
            ";a\x1b",
            "\u{a0}",
            " \u{a0};a",
        ]),
        prop::sample::select(vec!["\r\n", "\n", "\r\r\n", "\r"]),
        any::<bool>(),
    )
        .prop_map(|(data, prefix, suffix, end, upper)| {
            let size = if upper {
                format!("{:X}", data.len())
            } else {
                format!("{:x}", data.len())
            };
            let mut out = format!("{prefix}{size}{suffix}{end}").into_bytes();
            out.extend_from_slice(&data);
            out.extend_from_slice(b"\r\n");
            out
        })
}

fn mutate(mut bytes: Vec<u8>, edits: &[(u8, usize, u8)]) -> Vec<u8> {
    for &(kind, at, byte) in edits {
        if bytes.is_empty() {
            bytes.push(byte);
            continue;
        }
        let at = at % bytes.len();
        match kind {
            0 => bytes[at] = byte,
            1 => bytes.insert(at, byte),
            _ => {
                bytes.remove(at);
            }
        }
    }
    bytes
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// The same property over size lines spelled every lenient way, which
    /// random edits reach too rarely to rely on.
    #[test]
    fn however_a_size_line_is_spelled_httparse_reads_what_the_edge_forwards(
        chunks in prop::collection::vec(spelled_chunk(), 1..4),
        split in any::<usize>(),
    ) {
        let mut input: Vec<u8> = chunks.concat();
        input.extend_from_slice(b"0\r\n\r\n");
        let (n, out) = forward_chunked(&input, split % (input.len() + 1));
        if let Ok(n) = n {
            let read = oracle(&out);
            prop_assert!(read.is_some(), "httparse cannot read what the edge forwarded: {:?}", out);
            prop_assert_eq!(read.map(|data| data.len() as u64), Some(n));
        }
    }

    /// A valid chunked body arrives whole, wherever the head read cut it:
    /// the data is what was sent, and the trailers the edge drops are gone.
    #[test]
    fn a_valid_chunked_body_is_forwarded_whole(
        chunks in prop::collection::vec(chunk(), 0..6),
        trailers in trailers(),
        split in any::<usize>(),
    ) {
        let input = encode(&chunks, &trailers);
        let (n, out) = forward_chunked(&input, split % (input.len() + 1));
        let sent: Vec<u8> = chunks.iter().flat_map(|(data, _)| data.clone()).collect();
        prop_assert_eq!(n.expect("a valid body is forwarded"), sent.len() as u64);
        prop_assert_eq!(oracle(&out), Some(sent));
        let text = String::from_utf8_lossy(&out);
        for dropped in ["Content-Length", "Authorization", "X-Forwarded-For"] {
            prop_assert!(!text.contains(dropped), "{} crossed the edge: {}", dropped, text);
        }
    }

    /// Whatever the edge accepts, httparse reads with the same boundaries.
    ///
    /// The input is a valid body with up to four bytes edited, which is
    /// what reaches the parser's corners: a size padded or signed, an
    /// extension with a control byte, a lone CR or LF, data that overruns
    /// its size. The edge may refuse any of them. What it may not do is
    /// accept one and forward something a strict next hop reads as a
    /// different body, or as more than one.
    #[test]
    fn whatever_the_edge_forwards_httparse_reads_the_same_body(
        chunks in prop::collection::vec(chunk(), 1..4),
        trailers in trailers(),
        edits in prop::collection::vec(mutation(), 1..5),
        split in any::<usize>(),
    ) {
        let input = mutate(encode(&chunks, &trailers), &edits);
        let (n, out) = forward_chunked(&input, split % (input.len() + 1));
        if let Ok(n) = n {
            let read = oracle(&out);
            prop_assert!(read.is_some(), "httparse cannot read what the edge forwarded: {:?}", out);
            prop_assert_eq!(read.map(|data| data.len() as u64), Some(n));
        }
    }

    /// Framing over any mix of the two fields it is decided by: never a
    /// panic, a length only when every `Content-Length` is the same digits,
    /// and chunked only with no `Content-Length` beside it.
    #[test]
    fn framing_is_one_reading_of_its_fields_or_a_refusal(
        fields in prop::collection::vec(
            (
                prop::sample::select(vec![
                    "Content-Length", "content-length", "Transfer-Encoding",
                    "transfer-encoding", "X-Other",
                ]),
                prop_oneof![
                    prop::sample::select(vec![
                        "0", "5", "05", "+5", " 5 ", "5,5", "chunked", "Chunked",
                        "gzip, chunked", "chunked, gzip", "", "\u{a0}5", "18446744073709551616",
                    ]).prop_map(str::to_owned),
                    (0u32..1000).prop_map(|n| n.to_string()),
                ],
            ),
            0..4,
        ),
        response in any::<bool>(),
    ) {
        let fields: Vec<(String, String)> =
            fields.into_iter().map(|(name, value)| (name.to_owned(), value)).collect();
        let lengths: Vec<&str> = fields
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.as_str())
            .collect();
        match framing(&fields, response) {
            Ok(Framing::Length(n)) => {
                prop_assert!(!lengths.is_empty());
                for value in &lengths {
                    let digits = value.trim_matches([' ', '\t']);
                    prop_assert!(digits.bytes().all(|b| b.is_ascii_digit()), "{:?}", value);
                    prop_assert_eq!(digits.parse::<u64>().ok(), Some(n));
                }
            }
            Ok(Framing::Chunked) => prop_assert!(lengths.is_empty(), "{:?}", fields),
            Ok(Framing::Empty | Framing::UntilClose) => prop_assert!(lengths.is_empty()),
            Err(_) => {}
        }
    }

    /// Any bytes at all parse to a head, a request for more, or a refusal,
    /// and never a panic.
    #[test]
    fn any_bytes_parse_or_are_refused(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_request(&bytes);
        let _ = parse_response(&bytes);
    }

    /// Every strict prefix of a valid head asks for more rather than being
    /// refused, so a head that arrives a byte at a time is still read.
    #[test]
    fn a_prefix_of_a_valid_head_asks_for_more(cut in any::<usize>()) {
        let head = b"POST /v1/chat/completions HTTP/1.1\r\nHost: pipe\r\n\
                     Authorization: Bearer sk\r\nContent-Length: 2\r\n\r\n";
        let cut = cut % head.len();
        prop_assert_eq!(parse_request(&head[..cut]).map(|parsed| parsed.is_none()), Ok(true));
        prop_assert!(matches!(parse_request(head), Ok(Some(_))));
    }
}
