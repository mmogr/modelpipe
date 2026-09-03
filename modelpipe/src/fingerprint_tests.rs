//! Tests for [`super`] — one naming rule, applied to two things.
//!
//! Split out via `#[path]` so `fingerprint.rs` stays inside the file-size
//! budget.

use super::of;
use crate::ticket::{BackendHint, Ticket};

/// RFC 8032 §7.1 TEST 1, the same published key `ticket_tests` builds its
/// vectors on. Reused deliberately: the cross-check at the bottom of this
/// file is only worth anything if both sides are looking at the same bytes.
const KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

/// The rule, stated as a value rather than as a description of one.
#[test]
fn a_fingerprint_is_the_first_six_bytes_in_hex() {
    assert_eq!(of(&KEY), "d75a980182b1");
}

/// The negative control for the test above, and the one that matters: a
/// function returning a hard-coded string would pass it.
///
/// Two keys differing in their *first* byte must differ, and a key differing
/// only past byte six must not — which is the truncation being real rather
/// than incidental, and is the documented limit of what a fingerprint can
/// tell you.
#[test]
fn a_fingerprint_reads_the_leading_bytes_and_only_those() {
    let mut early = KEY;
    early[0] ^= 0xff;
    assert_ne!(of(&early), of(&KEY), "a change inside the prefix must show");

    let mut late = KEY;
    late[6] ^= 0xff;
    assert_eq!(
        of(&late),
        of(&KEY),
        "a change past the prefix cannot show — that is what truncation means"
    );
}

/// A diagnostic that panics is worse than a short one.
///
/// Nothing in this crate passes a short id today; this is about the day
/// something does. The assertion is both halves — no panic, *and* the bytes
/// that were there — because a function that returned `String::new()` for
/// every short input would not panic either.
#[test]
fn an_id_shorter_than_the_prefix_is_rendered_whole() {
    assert_eq!(of(&KEY[..2]), "d75a");
    assert_eq!(of(&[]), "");
}

/// The invariant this module exists for.
///
/// The serve side names a peer from the endpoint id on its connection; a
/// ticket names the same kind of thing from the id it carries. If those two
/// ever stop agreeing, an operator comparing a log line against the ticket
/// they handed out is comparing two different alphabets — and would have no
/// way to know.
#[test]
fn a_ticket_names_itself_by_the_same_rule() {
    let ticket = Ticket::new(KEY, vec![], BackendHint::OpenAiCompatible);
    assert_eq!(ticket.fingerprint(), of(&KEY));
}

/// The negative control for that cross-check: it would pass if both sides
/// returned the empty string, so pin that neither does.
#[test]
fn the_shared_rule_actually_renders_something() {
    let ticket = Ticket::new(KEY, vec![], BackendHint::OpenAiCompatible);
    assert_eq!(ticket.fingerprint().len(), 12);
    assert!(ticket.fingerprint().chars().all(|c| c.is_ascii_hexdigit()));
}
