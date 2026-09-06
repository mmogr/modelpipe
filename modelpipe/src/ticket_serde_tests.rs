//! Tests for the `serde` feature — a ticket as its canonical string, and
//! the two status types as the identifiers `as_str` already froze.

use crate::status::{PeerView, PipeStatus};
use crate::ticket::Ticket;

/// A ticket from the format spec's own vectors.
const VECTOR: &str = "pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaaauhlp2na";

#[test]
fn a_ticket_serializes_as_its_canonical_string() {
    let ticket: Ticket = VECTOR.parse().expect("a normative vector");
    let json = serde_json::to_string(&ticket).expect("serializes");
    assert_eq!(json, format!("\"{VECTOR}\""));
}

#[test]
fn a_ticket_round_trips_and_a_scanned_upper_case_one_parses() {
    let ticket: Ticket = VECTOR.parse().expect("a normative vector");
    let back: Ticket = serde_json::from_str(&serde_json::to_string(&ticket).unwrap()).unwrap();
    assert_eq!(back, ticket);

    let upper = format!("\"{}\"", VECTOR.to_uppercase());
    let scanned: Ticket = serde_json::from_str(&upper).expect("case-insensitive, like FromStr");
    assert_eq!(scanned, ticket);
}

/// The deserialization error is the parser's one-line advice, and it does
/// not echo the input — which may be most of a real ticket.
#[test]
fn a_malformed_ticket_fails_with_the_parsers_advice_and_not_the_input() {
    let bad = "\"pipe-not-a-ticket-at-all-but-long-enough-to-matter\"";
    let err = serde_json::from_str::<Ticket>(bad).expect_err("must not parse");
    let message = err.to_string();
    assert!(message.contains("re-copy"), "{message}");
    assert!(
        !message.contains("not-a-ticket"),
        "the input leaked: {message}"
    );
}

#[test]
fn a_status_serializes_as_the_identifier_as_str_reports() {
    for status in [
        PipeStatus::Idle,
        PipeStatus::Direct,
        PipeStatus::Relayed,
        PipeStatus::Closed,
    ] {
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, format!("\"{}\"", status.as_str()));
        let back: PipeStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, status);
    }
}

#[test]
fn a_peer_view_round_trips_as_a_plain_object() {
    let view = PeerView {
        fingerprint: "3ca82708b995".to_owned(),
        path: PipeStatus::Relayed,
        rtt_ms: Some(91),
    };
    let json = serde_json::to_string(&view).unwrap();
    assert_eq!(
        json,
        r#"{"fingerprint":"3ca82708b995","path":"relayed","rtt_ms":91}"#
    );
    let back: PeerView = serde_json::from_str(&json).unwrap();
    assert_eq!(back, view);
}

/// The reason the round-trip time is milliseconds rather than a
/// `Duration`: this struct is the DTO a status page renders, and a
/// `Duration` would land in it as a two-field object of seconds and
/// nanoseconds. A path with nothing measured yet is `null` rather than a
/// zero that reads as an impossibly fast link.
#[test]
fn a_peer_view_carries_its_round_trip_time_as_one_number_or_null() {
    let unmeasured = PeerView {
        fingerprint: "3ca82708b995".to_owned(),
        path: PipeStatus::Relayed,
        rtt_ms: None,
    };
    let json = serde_json::to_string(&unmeasured).unwrap();
    assert_eq!(
        json,
        r#"{"fingerprint":"3ca82708b995","path":"relayed","rtt_ms":null}"#
    );
    let back: PeerView = serde_json::from_str(&json).unwrap();
    assert_eq!(back, unmeasured);
}

/// A `PeerView` written by 0.3.0 — before `rtt_ms` existed — still parses,
/// and parses as "not measured" rather than as an error.
///
/// The compatibility property the field's arrival rested on, and the one the
/// test above does *not* check: that one round-trips a `null` this crate
/// wrote itself, which an absent key is not. serde supplies `None` for a
/// missing `Option` field, so this holds — but "holds" and "is pinned" are
/// different claims, and the second was made without the first. A stored
/// status page, a cached DTO, or a peer still on the older release all send
/// the two-field object below, and this is what says they keep working.
#[test]
fn a_peer_view_written_before_the_round_trip_time_existed_still_parses() {
    let older = r#"{"fingerprint":"3ca82708b995","path":"relayed"}"#;
    let parsed: PeerView = serde_json::from_str(older).expect("0.3.0 wrote exactly this");
    assert_eq!(
        parsed,
        PeerView {
            fingerprint: "3ca82708b995".to_owned(),
            path: PipeStatus::Relayed,
            rtt_ms: None,
        },
        "an absent key means unmeasured, which is what `null` means too"
    );
}
