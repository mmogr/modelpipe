//! Tests for [`super`] — which headers cross the tunnel edge.
//!
//! Split out via `#[path]` so `headers.rs` stays inside the file-size
//! budget.

use super::*;

fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect()
}

fn names(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
        .map(|(n, _)| n.to_ascii_lowercase())
        .collect()
}

// ── Hop-by-hop ───────────────────────────────────────────────────────────

/// Both halves in one body: the connection-scoped headers go and the
/// message headers stay. A test asserting only the first would pass on an
/// implementation that emptied the list.
#[test]
fn hop_by_hop_headers_are_stripped_and_message_headers_are_not() {
    let mut h = headers(&[
        ("Host", "127.0.0.1:11434"),
        ("Connection", "keep-alive"),
        ("Keep-Alive", "timeout=5"),
        ("Proxy-Authenticate", "Basic"),
        ("Proxy-Authorization", "Basic abc"),
        ("TE", "trailers"),
        ("Trailer", "Expires"),
        ("Transfer-Encoding", "chunked"),
        ("Upgrade", "websocket"),
        ("Authorization", "Bearer secret"),
        ("Content-Type", "application/json"),
    ]);
    strip_hop_by_hop(&mut h);

    assert_eq!(
        names(&h),
        ["host", "authorization", "content-type"],
        "only the connection-scoped headers should go"
    );
}

/// Header names are case-insensitive, so a deny-list that only matched the
/// canonical spelling would be trivially bypassed.
#[test]
fn the_deny_list_is_case_insensitive() {
    let mut h = headers(&[
        ("TRANSFER-ENCODING", "chunked"),
        ("cOnNeCtIoN", "close"),
        ("Content-Type", "application/json"),
    ]);
    strip_hop_by_hop(&mut h);
    assert_eq!(names(&h), ["content-type"]);
}

/// `Connection` may nominate further headers as connection-scoped, and
/// honouring that is not optional: a header a peer marked as not for anyone
/// else must not be handed to anyone else.
#[test]
fn a_connection_header_strips_the_names_it_lists() {
    let mut h = headers(&[
        ("Connection", "close, X-Internal-Hop, X-Another"),
        ("X-Internal-Hop", "1"),
        ("X-Another", "2"),
        ("X-Kept", "3"),
    ]);
    strip_hop_by_hop(&mut h);
    assert_eq!(names(&h), ["x-kept"]);
}

/// The nomination cannot reach a field that describes the message.
///
/// `Content-Length` is the one with teeth: framing is decided from the
/// headers as they arrived and the strip runs afterwards, so a honoured
/// `Connection: content-length` would leave the edge forwarding a body
/// under a head that declares none — a peer rewriting what its own message
/// means, using a header that is only supposed to describe the hop.
#[test]
fn a_message_level_field_cannot_be_nominated_away() {
    for field in ["Content-Length", "Host", "Transfer-Encoding", "Connection"] {
        let mut h = headers(&[
            ("Connection", &field.to_ascii_lowercase()),
            (field, "9"),
            ("X-Kept", "1"),
        ]);
        strip_hop_by_hop(&mut h);
        // `Connection` and `Transfer-Encoding` are hop-by-hop in their own
        // right and go regardless; what must survive is everything the
        // nomination alone would have taken.
        let expected: &[&str] = match field {
            "Content-Length" => &["content-length", "x-kept"],
            "Host" => &["host", "x-kept"],
            _ => &["x-kept"],
        };
        assert_eq!(names(&h), expected, "nominating {field}");
    }
}

/// The exclusion is narrow: an ordinary header is still nominable, so the
/// test above cannot pass because the whole mechanism stopped working.
#[test]
fn an_ordinary_field_is_still_nominable_alongside_a_refused_one() {
    let mut h = headers(&[
        ("Connection", "content-length, X-Hop"),
        ("Content-Length", "9"),
        ("X-Hop", "1"),
        ("X-Kept", "2"),
    ]);
    strip_hop_by_hop(&mut h);
    assert_eq!(names(&h), ["content-length", "x-kept"]);
}

/// Whitespace and case inside the `Connection` value are as variable as
/// anywhere else in HTTP.
#[test]
fn nominated_names_are_trimmed_and_case_folded() {
    let mut h = headers(&[
        ("Connection", "  X-One ,x-TWO,   , X-Three  "),
        ("X-One", "a"),
        ("X-Two", "b"),
        ("X-Three", "c"),
        ("X-Four", "d"),
    ]);
    strip_hop_by_hop(&mut h);
    assert_eq!(names(&h), ["x-four"]);
}

/// A request may carry several `Connection` headers; every list counts.
#[test]
fn several_connection_headers_all_contribute_their_names() {
    let mut h = headers(&[
        ("Connection", "X-One"),
        ("Connection", "X-Two"),
        ("X-One", "a"),
        ("X-Two", "b"),
        ("X-Three", "c"),
    ]);
    strip_hop_by_hop(&mut h);
    assert_eq!(names(&h), ["x-three"]);
}

/// Repeated headers are legitimate and order is observable, which is why
/// this is a list and not a map.
#[test]
fn repeated_headers_survive_in_order() {
    let mut h = headers(&[
        ("Set-Cookie", "a=1"),
        ("Connection", "close"),
        ("Set-Cookie", "b=2"),
    ]);
    strip_hop_by_hop(&mut h);
    assert_eq!(
        h,
        headers(&[("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")]),
        "both cookies, in the order they arrived"
    );
}

/// The empty case, which a `retain` over an empty nomination list could
/// plausibly get wrong.
#[test]
fn a_message_with_nothing_to_strip_is_left_alone() {
    let original = headers(&[("Host", "x"), ("Content-Type", "application/json")]);
    let mut h = original.clone();
    strip_hop_by_hop(&mut h);
    assert_eq!(h, original);
}

// ── Forwarding chain ─────────────────────────────────────────────────────

/// modelpipe is a private tunnel, not a reverse proxy in front of a fleet.
/// A client-supplied chain would let anyone claim any origin address they
/// like to whatever reads the backend's logs.
#[test]
fn an_inbound_forwarded_chain_is_removed_and_none_is_added() {
    let mut h = headers(&[
        ("Forwarded", "for=203.0.113.1"),
        ("X-Forwarded-For", "203.0.113.1"),
        ("X-Forwarded-Host", "evil.example"),
        ("X-Forwarded-Proto", "https"),
        ("X-Real-IP", "203.0.113.1"),
        ("Content-Type", "application/json"),
    ]);
    strip_inbound_forwarded(&mut h);

    assert_eq!(names(&h), ["content-type"]);
    assert!(
        !names(&h)
            .iter()
            .any(|n| n.contains("forwarded") || n.contains("real-ip")),
        "and nothing is added back"
    );
}

#[test]
fn the_forwarding_deny_list_is_case_insensitive() {
    let mut h = headers(&[("X-FORWARDED-FOR", "203.0.113.1"), ("Accept", "*/*")]);
    strip_inbound_forwarded(&mut h);
    assert_eq!(names(&h), ["accept"]);
}

// ── Host ─────────────────────────────────────────────────────────────────

/// The client's `Host` names the local listener, which the backend has
/// never heard of.
#[test]
fn the_host_header_names_the_backend_not_the_client() {
    let mut h = headers(&[
        ("Host", "127.0.0.1:8080"),
        ("Content-Type", "application/json"),
    ]);
    set_host(&mut h, "127.0.0.1:11434");

    assert_eq!(
        h[0],
        ("Host".to_owned(), "127.0.0.1:11434".to_owned()),
        "the backend's authority, first"
    );
    assert_eq!(names(&h), ["host", "content-type"]);
}

/// A request carrying two `Host` headers is ambiguous; resolving it by
/// appending a third would be worse than picking one.
#[test]
fn every_existing_host_is_replaced_rather_than_appended_to() {
    let mut h = headers(&[
        ("Host", "first.example"),
        ("HOST", "second.example"),
        ("Accept", "*/*"),
    ]);
    set_host(&mut h, "127.0.0.1:11434");

    assert_eq!(names(&h), ["host", "accept"], "exactly one Host survives");
    assert_eq!(h[0].1, "127.0.0.1:11434");
}

#[test]
fn a_request_with_no_host_gains_one() {
    let mut h = headers(&[("Accept", "*/*")]);
    set_host(&mut h, "127.0.0.1:11434");
    assert_eq!(names(&h), ["host", "accept"]);
}

// ── Composition ──────────────────────────────────────────────────────────

/// The order the edge applies these in, checked once so that the
/// combination is pinned and not just the parts. `Authorization` survives
/// all three, which it must: it is what the tunnel edge checks, and
/// forwarding it is what lets an embedder's backend check it again.
#[test]
fn the_edge_transform_keeps_the_message_and_drops_the_connection() {
    let mut h = headers(&[
        ("Host", "127.0.0.1:8080"),
        ("Connection", "keep-alive, X-Hop"),
        ("X-Hop", "1"),
        ("X-Forwarded-For", "203.0.113.1"),
        ("Transfer-Encoding", "chunked"),
        ("Authorization", "Bearer secret"),
        ("Content-Type", "application/json"),
    ]);
    strip_hop_by_hop(&mut h);
    strip_inbound_forwarded(&mut h);
    set_host(&mut h, "127.0.0.1:11434");

    assert_eq!(names(&h), ["host", "authorization", "content-type"]);
    assert_eq!(h[0].1, "127.0.0.1:11434");
}
