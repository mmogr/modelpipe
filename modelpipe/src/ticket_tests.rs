//! Conformance and refusal tests for [`super`].
//!
//! Split out via `#[path]` so `ticket.rs` stays inside the file-size budget.
//!
//! The vectors below are **hard-coded**, copied from
//! `docs/ticket-format-v0.md` rather than generated. That is the point: if
//! these were produced by running `scripts/ticket_vectors.py`, agreement
//! would prove only that one implementation agrees with itself. Typed out,
//! the Rust codec is an independent third party, and three parties — the
//! spec page, the Python reference, and this file — have to agree before
//! anything ships.

use super::*;
use crate::base32;
use crate::ticket_string::{KIND, MAX_TICKET_CHARS};

/// RFC 8032 §7.1 TEST 1. A real, citable ed25519 public key, so the vectors
/// rest on a published value rather than on random bytes someone chose.
const ENDPOINT_ID_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

const V1_BYTES: &str =
    "00d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a0000a1d6fd34";
const V1_TICKET: &str = "pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaaauhlp2na";

const V2_BYTES: &str = "00d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a0200001a68747470733a2f2f72656c61792e6578616d706c652e636f6d2f010006c0a80107115100c5fdbc79";
const V2_TICKET: &str = "pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaqaaangq5duobztulzpojswyylzfzsxqylnobwgkltdn5ws6aiaa3akqaihcfiqbrp5xr4q";

const V3_BYTES: &str = "00d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a0102001220010db80000000000000000000000011f9000032990f6";
const V3_TICKET: &str = "pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaicaajcaainxaaaaaaaaaaaaaaaaaaach4qaabstehw";

/// Vector 4 carries tag `0x7f`, which v0 has no meaning for. It is
/// decode-only on purpose: there is deliberately no way to *construct* an
/// unknown address through this API, so the bytes are the only way to prove
/// a parser skips one.
const V4_BYTES: &str = "00d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a02010006c0a8010711517f0004deadbeef00046ac5b0";
const V4_TICKET: &str =
    "pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaqbaadmbkaba4ivc7yaatpk3pxpaacgvrnq";

/// Every component of this URL is something a URL library rewrites.
const V5_URL: &str = "https://Relay.Example.COM.:443/%7Efoo";
const V5_BYTES: &str = "00d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a0100002568747470733a2f2f52656c61792e4578616d706c652e434f4d2e3a3434332f253745666f6f00d76d87c7";
const V5_TICKET: &str = "pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaiaaaswq5duobztulzpkjswyylzfzcxqylnobwgklsdj5gs4orugqzs6jjxivtg63ya25wypry";

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex must be whole bytes");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn endpoint_id() -> [u8; ENDPOINT_ID_LEN] {
    hex(ENDPOINT_ID_HEX).try_into().expect("32 bytes")
}

fn relay(url: &str) -> TicketAddr {
    TicketAddr::Relay(url.to_owned())
}

fn v4(s: &str) -> TicketAddr {
    TicketAddr::V4(s.parse().expect("socket addr"))
}

fn v6(s: &str) -> TicketAddr {
    TicketAddr::V6(s.parse().expect("socket addr"))
}

fn ticket(addrs: Vec<TicketAddr>) -> Ticket {
    Ticket::new(endpoint_id(), addrs, BackendHint::OpenAiCompatible)
}

// ── Conformance ──────────────────────────────────────────────────────────

/// The four constructible vectors, encoded from their parts. Byte-for-byte,
/// because a wire format that is only nearly right is a wire format that
/// fails in someone else's language.
#[test]
fn the_normative_vectors_encode_byte_for_byte() {
    let cases = [
        ("1 minimal", ticket(vec![]), V1_BYTES),
        (
            "2 relay + IPv4",
            ticket(vec![
                relay("https://relay.example.com/"),
                v4("192.168.1.7:4433"),
            ]),
            V2_BYTES,
        ),
        ("3 IPv6", ticket(vec![v6("[2001:db8::1]:8080")]), V3_BYTES),
        ("5 verbatim relay", ticket(vec![relay(V5_URL)]), V5_BYTES),
    ];
    for (name, t, want) in cases {
        assert_eq!(hex_of(&t.encode()), want, "vector {name} bytes");
    }
}

fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// The other half: the string a ticket renders to.
#[test]
fn the_normative_vectors_render_their_ticket_strings() {
    let cases = [
        (ticket(vec![]), V1_TICKET),
        (
            ticket(vec![
                relay("https://relay.example.com/"),
                v4("192.168.1.7:4433"),
            ]),
            V2_TICKET,
        ),
        (ticket(vec![v6("[2001:db8::1]:8080")]), V3_TICKET),
        (ticket(vec![relay(V5_URL)]), V5_TICKET),
    ];
    for (t, want) in cases {
        assert_eq!(t.to_string(), want);
    }
}

/// Parsing is the inverse, and the bytes each vector claims are the bytes
/// its string decodes to.
#[test]
fn the_normative_vectors_parse_back_to_their_bytes() {
    for (s, bytes) in [
        (V1_TICKET, V1_BYTES),
        (V2_TICKET, V2_BYTES),
        (V3_TICKET, V3_BYTES),
        (V4_TICKET, V4_BYTES),
        (V5_TICKET, V5_BYTES),
    ] {
        let parsed: Ticket = s.parse().expect("vector must parse");
        // Vector 4 loses its unknown address on the way in, so its re-encode
        // is deliberately shorter than its source bytes; the rest round-trip
        // byte-for-byte.
        if s == V4_TICKET {
            assert_ne!(hex_of(&parsed.encode()), bytes);
        } else {
            assert_eq!(hex_of(&parsed.encode()), bytes, "{s}");
        }
    }
}

/// The QR path. A display layer may upcase a whole ticket to fit
/// alphanumeric mode, and the scan of that code has to come back the same
/// ticket.
#[test]
fn every_vector_round_trips_through_its_uppercase_form() {
    for s in [V1_TICKET, V2_TICKET, V3_TICKET, V4_TICKET, V5_TICKET] {
        let lower: Ticket = s.parse().expect("lowercase parses");
        let upper: Ticket = s.to_ascii_uppercase().parse().expect("uppercase parses");
        assert_eq!(lower, upper, "{s} must survive being upcased");
    }
    // And a mixed case, which is what a careless copy produces.
    let mixed: String = V2_TICKET
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i.is_multiple_of(2) {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    assert_eq!(
        mixed.parse::<Ticket>().expect("mixed case parses"),
        V2_TICKET.parse::<Ticket>().unwrap()
    );
}

/// `Display` is canonicalizing, which is worth pinning because it means
/// parse-then-print is not always the identity.
#[test]
fn display_emits_the_canonical_form_whatever_order_came_in() {
    let forward = ticket(vec![
        relay("https://relay.example.com/"),
        v4("192.168.1.7:4433"),
    ]);
    let reversed = ticket(vec![
        v4("192.168.1.7:4433"),
        relay("https://relay.example.com/"),
    ]);
    assert_eq!(forward.to_string(), reversed.to_string());
    assert_eq!(forward.to_string(), V2_TICKET);
}

#[test]
fn duplicate_addresses_collapse() {
    let once = ticket(vec![v4("192.168.1.7:4433")]);
    let thrice = ticket(vec![
        v4("192.168.1.7:4433"),
        v4("192.168.1.7:4433"),
        v4("192.168.1.7:4433"),
    ]);
    assert_eq!(once, thrice);
    assert_eq!(once.addrs.len(), 1);
}

/// The payoff of length-prefixing every body, checked end to end from a
/// real ticket string rather than from a hand-built address.
#[test]
fn an_unknown_address_tag_is_skipped_rather_than_fatal() {
    let parsed: Ticket = V4_TICKET.parse().expect("an unknown tag must not be fatal");
    assert_eq!(
        parsed.addrs,
        vec![v4("192.168.1.7:4433")],
        "the known address survives and the unknown one is gone"
    );
}

/// A hint, not a contract: a newer serve side stays pairable from this
/// build.
#[test]
fn an_unknown_backend_hint_parses_rather_than_failing() {
    let t = Ticket::new(endpoint_id(), vec![], BackendHint::Unknown(0x42));
    let parsed: Ticket = t.to_string().parse().expect("an unknown hint must parse");
    assert_eq!(parsed.backend, BackendHint::Unknown(0x42));
    assert_eq!(parsed, t, "and survives the round trip unchanged");
}

/// "Carried verbatim" is normative, and every part of this URL is something
/// a URL library would quietly rewrite.
#[test]
fn a_relay_url_survives_a_round_trip_verbatim() {
    let parsed: Ticket = V5_TICKET.parse().expect("vector 5 parses");
    assert_eq!(parsed.addrs, vec![relay(V5_URL)]);
}

/// The encoder obligation from the spec: a ticket that would exceed the cap
/// sheds addresses rather than being minted unreadable. Relays are shed
/// last, because a direct address is an optimization and the relay is what
/// connects at all.
#[test]
fn an_oversize_address_set_is_trimmed_rather_than_minted_unreadable() {
    let many: Vec<TicketAddr> = (0..250)
        .map(|i| v6(&format!("[2001:db8::{i:x}]:8080")))
        .chain(std::iter::once(relay("https://relay.example.com/")))
        .collect();
    let t = ticket(many);
    let encoded = t.encode();

    assert!(
        encoded.len() <= MAX_TICKET_BYTES,
        "minted {} bytes, over the cap",
        encoded.len()
    );
    assert!(t.addrs.len() < 251, "some addresses must have been shed");
    assert!(
        t.addrs.contains(&relay("https://relay.example.com/")),
        "the relay is shed last, not first"
    );
    // And what survives is still a valid ticket.
    assert_eq!(t.to_string().parse::<Ticket>().expect("still parses"), t);
}

/// The redaction invariant, which until now was guarded by a comment.
#[test]
fn a_debug_rendering_never_contains_the_ticket_string() {
    let t = ticket(vec![relay("https://relay.example.com/")]);
    let rendered = format!("{t:?}");
    let displayed = t.to_string();

    assert!(
        !rendered.contains(&displayed),
        "Debug leaked the whole ticket: {rendered}"
    );
    // The base32 body, minus the prefix every ticket shares, must not appear
    // even in part — a Debug that printed a prefix would still be a leak.
    assert!(
        !rendered.contains(&displayed[KIND.len()..KIND.len() + 16]),
        "Debug leaked part of the ticket body: {rendered}"
    );
    assert!(
        rendered.contains(&t.fingerprint()),
        "Debug must still identify the ticket: {rendered}"
    );
}

#[test]
fn a_fingerprint_is_short_and_is_not_the_whole_key() {
    let f = ticket(vec![]).fingerprint();
    assert_eq!(f.len(), FINGERPRINT_BYTES * 2);
    assert!(f.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(
        ENDPOINT_ID_HEX.starts_with(&f) && f.len() < ENDPOINT_ID_HEX.len(),
        "a prefix of the key, and only a prefix"
    );
}

// ── Refusals ─────────────────────────────────────────────────────────────
//
// Kept apart from the conformance tests above, and from each other by
// verdict: a single table asserting "these all fail somehow" would pass just
// as happily if every one of them failed for the wrong reason.

/// Everything the format routes to "re-copy it".
#[test]
fn the_re_copy_it_failures_are_all_malformed() {
    let good = V1_TICKET;
    let cases: Vec<(&str, String)> = vec![
        (
            "the wrong kind prefix",
            format!("note{}", &good[KIND.len()..]),
        ),
        ("no prefix at all", good[KIND.len()..].to_owned()),
        ("an empty payload", KIND.to_owned()),
        (
            "a character outside the alphabet",
            format!("{}1", &good[..good.len() - 1]),
        ),
        ("an impossible length class", format!("{good}a")),
        ("non-zero bits in the final group", "pipeab".to_owned()),
        ("truncation", good[..good.len() / 2].to_owned()),
        ("a corrupted checksum", flip_last_byte(good)),
        ("a corrupted endpoint id", flip_body_byte(good)),
    ];
    for (label, input) in cases {
        assert_eq!(
            input.parse::<Ticket>(),
            Err(TicketParseError::Malformed),
            "{label} must be malformed"
        );
    }
}

/// Distinct from malformed because the advice differs: upgrade, not
/// re-copy. Nothing else in the taxonomy produces this.
#[test]
fn a_newer_format_version_is_unsupported_rather_than_malformed() {
    let mut bytes = hex(V1_BYTES);
    bytes[0] = 0x01;
    // The CRC is version-owned, so it is not recomputed: a parser cannot
    // check it for a version it does not speak, which is exactly why a
    // strike on the version byte reads as "upgrade".
    let s = format!("{KIND}{}", base32::encode(&bytes).to_ascii_lowercase());
    assert_eq!(
        s.parse::<Ticket>(),
        Err(TicketParseError::UnsupportedVersion(1))
    );
}

/// Under full Unicode folding U+212A KELVIN SIGN lowercases to `k`, so a
/// folding parser accepts a ticket an ASCII one rejects. The reference
/// implementation had this bug in Python; this is the test that says Rust
/// does not.
#[test]
fn a_kelvin_sign_is_not_a_k() {
    let with_kelvin = V1_TICKET.replacen('k', "\u{212A}", 1);
    assert_ne!(
        with_kelvin, V1_TICKET,
        "the vector must contain a k to swap"
    );
    assert_eq!(
        with_kelvin.parse::<Ticket>(),
        Err(TicketParseError::Malformed),
        "a ticket is ASCII"
    );
}

/// The cap is stated on decoded bytes, but a parser that only checks it
/// afterwards allocates the whole hostile input first — twice, counting the
/// canonicality check.
#[test]
fn an_over_long_string_is_rejected_before_it_is_decoded() {
    let huge = format!("{KIND}{}", "a".repeat(500_000));
    assert_eq!(huge.parse::<Ticket>(), Err(TicketParseError::Malformed));

    // The bound itself, checked at the edge rather than by magnitude.
    let at_bound = format!("{KIND}{}", "a".repeat(MAX_TICKET_CHARS));
    assert_eq!(at_bound.parse::<Ticket>(), Err(TicketParseError::Malformed));
}

/// Bytes past the end of the declared structure are corruption, not
/// forward-compatible padding — `addr_count` says exactly where the backend
/// hint and checksum sit.
#[test]
fn trailing_bytes_after_the_structure_are_malformed() {
    let mut bytes = hex(V1_BYTES);
    let body_len = bytes.len() - CRC_LEN;
    let mut body = bytes[..body_len].to_vec();
    body.push(0x00); // one byte the structure does not account for
    let crc = crc32c(&body);
    body.extend_from_slice(&crc.to_be_bytes());
    bytes = body;

    let s = format!("{KIND}{}", base32::encode(&bytes).to_ascii_lowercase());
    assert_eq!(s.parse::<Ticket>(), Err(TicketParseError::Malformed));
}

fn flip_last_byte(s: &str) -> String {
    let mut bytes = hex(V1_BYTES);
    let _ = s;
    *bytes.last_mut().expect("non-empty") ^= 0xFF;
    format!("{KIND}{}", base32::encode(&bytes).to_ascii_lowercase())
}

fn flip_body_byte(s: &str) -> String {
    let mut bytes = hex(V1_BYTES);
    let _ = s;
    bytes[5] ^= 0xFF; // inside the endpoint id, so the CRC no longer matches
    format!("{KIND}{}", base32::encode(&bytes).to_ascii_lowercase())
}
