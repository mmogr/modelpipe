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
    };
    let json = serde_json::to_string(&view).unwrap();
    assert_eq!(json, r#"{"fingerprint":"3ca82708b995","path":"relayed"}"#);
    let back: PeerView = serde_json::from_str(&json).unwrap();
    assert_eq!(back, view);
}
