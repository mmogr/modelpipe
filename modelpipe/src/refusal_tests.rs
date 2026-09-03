//! Tests for [`super`] — every refusal, and what tells them apart.
//!
//! Split out via `#[path]` so `refusal.rs` stays inside the file-size
//! budget once there are six of them.

use super::*;
use crate::framing::{Framing, framing};
use crate::http_head::parse_response;

/// Each refusal must be a well-formed response whose declared length
/// matches the body actually written — a wrong length here would hang
/// the client waiting for bytes that never come.
#[test]
fn every_refusal_is_well_formed_and_declares_its_own_length() {
    for (name, bytes, status) in [
        ("unauthorized", unauthorized(), 401),
        ("bad request", bad_request(), 400),
        ("bad gateway", bad_gateway(), 502),
        ("backend unreachable", backend_unreachable(), 502),
        ("tunnel unavailable", tunnel_unavailable(), 502),
        ("incomplete request", incomplete_request(), 400),
    ] {
        let (head, consumed) = parse_response(&bytes)
            .unwrap_or_else(|e| panic!("{name} must parse: {e:?}"))
            .unwrap_or_else(|| panic!("{name} must be complete"));
        assert_eq!(head.status, status, "{name}");
        assert_eq!(
            framing(&head.headers, true),
            Ok(Framing::Length((bytes.len() - consumed) as u64)),
            "{name} declares the body it wrote"
        );
    }
}

/// A 401 that does not say how to authenticate is a 401 a client cannot
/// act on.
#[test]
fn the_unauthorized_response_advertises_the_scheme() {
    let bytes = unauthorized();
    let (head, _) = parse_response(&bytes).unwrap().unwrap();
    assert!(
        head.headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("www-authenticate") && v.contains("Bearer"))
    );
}

/// A backend failure reported as a client error sends whoever is
/// debugging it to the wrong side of the tunnel.
#[test]
fn a_backend_failure_is_not_reported_as_a_client_error() {
    let (head, _) = parse_response(&bad_gateway()).unwrap().unwrap();
    assert!((500..600).contains(&head.status), "5xx, not 4xx");
}

/// The mirror of the test above, and the reason both exist: an upload
/// that stopped is the client's, so reporting it as a gateway failure
/// would send the same person to the same wrong side of the tunnel —
/// hunting a backend that was working the whole time.
#[test]
fn a_client_failure_is_not_reported_as_a_backend_error() {
    let (head, _) = parse_response(&incomplete_request()).unwrap().unwrap();
    assert!((400..500).contains(&head.status), "4xx, not 5xx");
}

/// The three 502s must be three, not one sentence written three times.
///
/// This is the whole point of the split. A single 502 body was written at
/// five call sites and described one of them; the failure it produced was
/// not a wrong status but a wrong *instruction* — "the backend sent a
/// response this tunnel could not read", for a backend that was never
/// contacted and for a tunnel with no peer at either end, sending whoever
/// read it to the one component that was working.
#[test]
fn the_three_gateway_failures_say_three_different_things() {
    let bodies = [
        ("bad_gateway", bad_gateway()),
        ("backend_unreachable", backend_unreachable()),
        ("tunnel_unavailable", tunnel_unavailable()),
    ];
    let mut messages = Vec::new();
    for (code, bytes) in &bodies {
        let text = String::from_utf8(bytes.clone()).expect("ascii");
        assert!(
            text.contains(&format!(r#""code":"{code}""#)),
            "{code} must name itself so a program can match on it: {text}"
        );
        let (head, consumed) = parse_response(bytes).unwrap().unwrap();
        assert_eq!(head.status, 502, "{code}");
        messages.push(String::from_utf8(bytes[consumed..].to_vec()).expect("ascii"));
    }
    messages.sort();
    let distinct = {
        let mut m = messages.clone();
        m.dedup();
        m.len()
    };
    assert_eq!(distinct, 3, "two of the three still say the same thing");
}

/// The negative control for the test above, and the property that makes the
/// split safe: a client's *recovery* is identical in all three cases, so
/// the status code — which is what a program acts on — stays the same.
///
/// Without this, "make them distinct" could be satisfied by giving them
/// different statuses, which would be a protocol change dressed up as a
/// wording fix.
#[test]
fn telling_them_apart_did_not_change_what_a_client_does() {
    for bytes in [bad_gateway(), backend_unreachable(), tunnel_unavailable()] {
        let (head, _) = parse_response(&bytes).unwrap().unwrap();
        assert_eq!(head.status, 502);
        let text = String::from_utf8(bytes).expect("ascii");
        assert!(text.contains("Connection: close"), "{text}");
        assert!(text.contains("Content-Type: application/json"), "{text}");
    }
}

/// A refusal names a backend the client cannot see, or it does not.
///
/// The serving side's backend address is the operator's, on the other
/// machine; a client told `127.0.0.1:11434` learns the address of a
/// loopback port that is not its own. It is in the serve side's log, which
/// is where the person who can act on it is sitting.
#[test]
fn no_refusal_names_an_address() {
    for bytes in [
        unauthorized(),
        bad_request(),
        bad_gateway(),
        backend_unreachable(),
        tunnel_unavailable(),
        incomplete_request(),
    ] {
        let text = String::from_utf8(bytes).expect("ascii");
        for leak in ["127.0.0.1", "localhost", "http://", ":11434"] {
            assert!(!text.contains(leak), "{leak} appears in: {text}");
        }
    }
}
