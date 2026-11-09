//! The edge's framing rules, held against input nobody wrote by hand.
//!
//! The other tests name the inputs that broke something once. These
//! generate them: valid chunked bodies cut at any point, and header lists
//! built from the fields framing is decided by. A forwarded body is read
//! back with httparse, an independent and long-fuzzed parser, rather than
//! with anything of this crate's own.

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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

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
