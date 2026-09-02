//! Tests for [`super`] — head parsing and body framing.
//!
//! Split out via `#[path]` so `http_head.rs` stays inside the file-size
//! budget.
//!
//! The framing tests are the security-relevant ones. Request smuggling is
//! not a parser bug; it is two correct parsers disagreeing about where a
//! body ends, so what is asserted here is that this edge refuses to be one
//! of the two rather than that it resolves the ambiguity some particular
//! way.

use super::*;

fn fields(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect()
}

const POST: &[u8] =
    b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc";

// ── Parsing ──────────────────────────────────────────────────────────────

#[test]
fn a_request_head_parses_into_its_parts() {
    let (head, consumed) = parse_request(POST).expect("valid").expect("complete");
    assert_eq!(head.method, "POST");
    assert_eq!(head.target, "/v1/chat/completions");
    assert_eq!(
        head.headers,
        fields(&[("Host", "x"), ("Content-Length", "3")])
    );
    assert_eq!(&POST[consumed..], b"abc", "the body starts where it says");
}

#[test]
fn a_response_head_parses_into_its_parts() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: hi\n\n";
    let (head, consumed) = parse_response(raw).expect("valid").expect("complete");
    assert_eq!(head.status, 200);
    assert_eq!(head.reason, "OK");
    assert_eq!(
        head.headers,
        fields(&[("Content-Type", "text/event-stream")])
    );
    assert_eq!(&raw[consumed..], b"data: hi\n\n");
}

/// A head arriving in pieces is the normal case on a stream, and must not
/// be mistaken for a malformed one.
#[test]
fn an_incomplete_head_asks_for_more_rather_than_failing() {
    for cut in 1..POST.len() - 3 {
        assert_eq!(
            parse_request(&POST[..cut]),
            Ok(None),
            "a {cut}-byte prefix is incomplete, not malformed"
        );
    }
}

#[test]
fn a_head_that_is_not_http_is_malformed() {
    for raw in [
        &b"not http at all\r\n\r\n"[..],
        &b"GET\r\n\r\n"[..],
        &b"\0\0\0\0"[..],
    ] {
        assert_eq!(parse_request(raw), Err(HeadError::Malformed), "{raw:?}");
    }
}

#[test]
fn an_over_long_head_is_refused_rather_than_buffered() {
    let mut raw = b"GET / HTTP/1.1\r\n".to_vec();
    raw.resize(MAX_HEAD_BYTES + 1, b'x');
    assert_eq!(parse_request(&raw), Err(HeadError::TooLarge));
}

#[test]
fn too_many_header_fields_is_refused() {
    let mut raw = b"GET / HTTP/1.1\r\n".to_vec();
    for i in 0..MAX_HEADER_FIELDS + 10 {
        raw.extend_from_slice(format!("X-H{i}: v\r\n").as_bytes());
    }
    raw.extend_from_slice(b"\r\n");
    assert_eq!(parse_request(&raw), Err(HeadError::TooLarge));
}

/// Forwarding bytes the edge itself could not read is how a header means
/// one thing here and another downstream.
#[test]
fn a_header_value_that_is_not_utf8_is_malformed() {
    let raw = b"GET / HTTP/1.1\r\nX-Bad: \xff\xfe\r\n\r\n";
    assert_eq!(parse_request(raw), Err(HeadError::Malformed));
}

// ── Framing that is accepted ─────────────────────────────────────────────

#[test]
fn a_content_length_frames_a_body_of_that_size() {
    assert_eq!(
        framing(&fields(&[("Content-Length", "42")]), false),
        Ok(Framing::Length(42))
    );
    assert_eq!(
        framing(&fields(&[("content-length", " 42 ")]), false),
        Ok(Framing::Length(42)),
        "the name is case-insensitive and the value is trimmed"
    );
}

#[test]
fn chunked_frames_a_body_ending_at_its_terminal_chunk() {
    assert_eq!(
        framing(&fields(&[("Transfer-Encoding", "chunked")]), false),
        Ok(Framing::Chunked)
    );
    assert_eq!(
        framing(&fields(&[("transfer-encoding", "CHUNKED")]), false),
        Ok(Framing::Chunked)
    );
}

/// Repeated `Content-Length` is legal when the values agree. Only a
/// disagreement is ambiguous.
#[test]
fn repeated_agreeing_content_lengths_are_accepted() {
    assert_eq!(
        framing(
            &fields(&[("Content-Length", "7"), ("Content-Length", "7")]),
            false
        ),
        Ok(Framing::Length(7))
    );
}

/// A request with no framing headers has no body; a response with none is
/// framed by the connection closing. The asymmetry is real: a server cannot
/// tell "I have finished asking" from "I have gone away".
#[test]
fn an_unframed_request_is_empty_and_an_unframed_response_runs_to_close() {
    assert_eq!(
        framing(&fields(&[("Host", "x")]), false),
        Ok(Framing::Empty)
    );
    assert_eq!(
        framing(&fields(&[("Content-Type", "text/plain")]), true),
        Ok(Framing::UntilClose)
    );
}

// ── Framing that is refused ──────────────────────────────────────────────

/// The classic smuggling shape. RFC 9112 says Transfer-Encoding wins, and a
/// proxy that follows that rule is correct *and* still exploitable — the
/// attack works because the next hop resolves the same ambiguity the other
/// way. An edge that refuses cannot disagree with anybody.
#[test]
fn content_length_and_transfer_encoding_together_are_refused() {
    for pairs in [
        &[("Content-Length", "6"), ("Transfer-Encoding", "chunked")][..],
        &[("Transfer-Encoding", "chunked"), ("Content-Length", "6")][..],
        &[("content-length", "0"), ("TRANSFER-ENCODING", "chunked")][..],
    ] {
        assert_eq!(
            framing(&fields(pairs), false),
            Err(HeadError::ConflictingFraming),
            "{pairs:?}"
        );
    }
}

/// The same ambiguity by another route.
#[test]
fn two_content_lengths_that_disagree_are_refused() {
    assert_eq!(
        framing(
            &fields(&[("Content-Length", "6"), ("Content-Length", "7")]),
            false
        ),
        Err(HeadError::ConflictingFraming)
    );
}

#[test]
fn a_content_length_that_is_not_a_number_is_refused() {
    for value in ["", "abc", "-1", "6, 7", "0x10", "6 7", "１２"] {
        assert_eq!(
            framing(&fields(&[("Content-Length", value)]), false),
            Err(HeadError::ConflictingFraming),
            "{value:?} is not a length"
        );
    }
}

/// A coding the edge cannot apply is not something to pass through blind:
/// forwarding a body it did not decode, under framing it did not
/// understand, is exactly the disagreement being avoided.
#[test]
fn a_transfer_coding_this_edge_cannot_apply_is_refused() {
    for value in [
        "gzip",
        "gzip, chunked",
        "chunked, gzip",
        "chunked, chunked",
        "",
    ] {
        assert_eq!(
            framing(&fields(&[("Transfer-Encoding", value)]), false),
            Err(HeadError::UnsupportedTransferCoding),
            "{value:?}"
        );
    }
}

// ── Serialization ────────────────────────────────────────────────────────

/// `Transfer-Encoding` is hop-by-hop and stripped on the way through, so a
/// chunked body would otherwise reach the backend with nothing left to say
/// how it is framed. Each hop declares its own.
#[test]
fn a_chunked_body_is_re_declared_on_the_outbound_head() {
    let head = RequestHead {
        method: "POST".to_owned(),
        target: "/v1/chat/completions".to_owned(),
        headers: fields(&[("Host", "127.0.0.1:11434")]),
    };
    let out = serialize_request(&head, Framing::Chunked);
    let text = String::from_utf8(out).expect("ascii");

    assert!(text.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
    assert!(
        text.contains("Transfer-Encoding: chunked\r\n"),
        "the framing must survive the hop: {text}"
    );
    assert!(text.ends_with("\r\n\r\n"));
}

#[test]
fn a_length_framed_body_gains_no_transfer_encoding() {
    let head = RequestHead {
        method: "POST".to_owned(),
        target: "/".to_owned(),
        headers: fields(&[("Content-Length", "3")]),
    };
    let text = String::from_utf8(serialize_request(&head, Framing::Length(3))).unwrap();
    assert!(!text.to_ascii_lowercase().contains("transfer-encoding"));
}

/// A serialized head must parse back to what it came from, or the edge and
/// the backend are reading different messages.
#[test]
fn a_serialized_head_round_trips() {
    let head = RequestHead {
        method: "POST".to_owned(),
        target: "/v1/models".to_owned(),
        headers: fields(&[("Host", "b"), ("Accept", "*/*")]),
    };
    let bytes = serialize_request(&head, Framing::Empty);
    let (parsed, consumed) = parse_request(&bytes).unwrap().unwrap();
    assert_eq!(parsed, head);
    assert_eq!(consumed, bytes.len(), "nothing left over");
}

// ── Helpers ──────────────────────────────────────────────────────────────

#[test]
fn the_authorization_header_is_found_whatever_its_case() {
    assert_eq!(
        authorization(&fields(&[("AUTHORIZATION", "Bearer x")])),
        Some(&b"Bearer x"[..])
    );
    assert_eq!(authorization(&fields(&[("Accept", "*/*")])), None);
}

/// The three header rules applied in the order the edge applies them,
/// pinned once as a combination.
#[test]
fn rewriting_for_the_backend_drops_the_connection_and_keeps_the_message() {
    let mut head = RequestHead {
        method: "POST".to_owned(),
        target: "/".to_owned(),
        headers: fields(&[
            ("Host", "127.0.0.1:8080"),
            ("Connection", "keep-alive"),
            ("X-Forwarded-For", "203.0.113.1"),
            ("Transfer-Encoding", "chunked"),
            ("Authorization", "Bearer secret"),
            ("Content-Type", "application/json"),
        ]),
    };
    rewrite_for_backend(&mut head, "127.0.0.1:11434");

    let names: Vec<String> = head
        .headers
        .iter()
        .map(|(n, _)| n.to_ascii_lowercase())
        .collect();
    assert_eq!(names, ["host", "authorization", "content-type"]);
    assert_eq!(head.headers[0].1, "127.0.0.1:11434");
}
