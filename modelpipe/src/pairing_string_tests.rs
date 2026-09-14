//! Conformance and refusal tests for [`super`].
//!
//! Split out via `#[path]` so `pairing_string.rs` stays inside the file-size
//! budget.
//!
//! The vectors are **hard-coded**, copied from `docs/pairing-v0.md` rather
//! than generated, for the reason `ticket_tests.rs` gives: typed out, this
//! parser is a third party that the spec page and
//! `scripts/pairing_vectors.py` both have to agree with.

use std::error::Error as _;

use super::*;

const V1_TICKET: &str = "pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaaauhlp2na";
const V2_TICKET: &str = "pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaqaaangq5duobztulzpojswyylzfzsxqylnobwgkltdn5ws6aiaa3akqaihcfiqbrp5xr4q";
const V3_TICKET: &str = "pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaicaajcaainxaaaaaaaaaaaaaaaaaaach4qaabstehw";

/// The ticket format's vector 1 with its version byte set to `0x01`.
const NEWER_TICKET: &str = "pipeahlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaaauhlp2na";

/// A pairing string's ticket and code as strings, or its refusal.
fn parse(s: &str) -> Result<(String, Option<String>), PairingStringError> {
    s.parse::<PairingString>().map(|p| {
        (
            p.ticket().to_string(),
            p.code().map(|c| c.as_str().to_owned()),
        )
    })
}

/// The spec's accepted vectors: input, then the ticket and code it yields.
fn accepted() -> Vec<(String, &'static str, Option<&'static str>)> {
    vec![
        (V1_TICKET.to_owned(), V1_TICKET, None),
        (format!("{V1_TICKET}-483920"), V1_TICKET, Some("483920")),
        (format!("{V3_TICKET}-000417"), V3_TICKET, Some("000417")),
        (
            format!("{V2_TICKET}-017284").to_ascii_uppercase(),
            V2_TICKET,
            Some("017284"),
        ),
        (
            format!(" \t{V1_TICKET}-483920\r\n"),
            V1_TICKET,
            Some("483920"),
        ),
    ]
}

#[test]
fn every_accepted_vector_parses_to_its_ticket_and_code() {
    for (input, ticket, code) in accepted() {
        let got = parse(&input).unwrap_or_else(|e| panic!("{input:?} was refused: {e:?}"));
        assert_eq!(
            got,
            (ticket.to_owned(), code.map(str::to_owned)),
            "{input:?}"
        );
    }
}

#[test]
fn a_parsed_string_prints_back_as_ticket_and_code_with_no_whitespace() {
    for (input, ticket, code) in accepted() {
        let printed = input
            .parse::<PairingString>()
            .expect("accepted")
            .to_string();
        let want = code.map_or_else(|| ticket.to_owned(), |code| format!("{ticket}-{code}"));
        assert_eq!(printed, want, "{input:?}");
    }
}

/// Upper case is what a QR code carries, and a scan of it has to come back
/// as the value that made it.
#[test]
fn the_string_for_a_qr_code_is_upper_case_and_parses_back_to_the_same_value() {
    for (input, _, _) in accepted() {
        let pairing = input.parse::<PairingString>().expect("accepted");
        let qr = pairing.to_qr_string();
        assert_eq!(qr, qr.to_ascii_uppercase());
        assert_eq!(
            qr.parse::<PairingString>().expect("the scan parses"),
            pairing
        );
    }
}

#[test]
fn every_refusal_in_the_spec_gets_its_verdict() {
    use PairingStringError::{Code, Empty, Ticket};
    use TicketParseError::{Malformed, UnsupportedVersion};

    let cases = [
        (" \t\r\n".to_owned(), Empty),
        (format!("{V1_TICKET}-"), Code),
        (format!("{V1_TICKET}-48392"), Code),
        (format!("{V1_TICKET}-4839201"), Code),
        (format!("{V1_TICKET}-48392a"), Code),
        (
            format!("{V1_TICKET}-\u{ff14}\u{ff18}\u{ff13}\u{ff19}\u{ff12}\u{ff10}"),
            Code,
        ),
        (format!("{V1_TICKET}-483920\u{a0}"), Code),
        ("not-a-ticket-4839".to_owned(), Code),
        (format!("{V1_TICKET}-483920-483920"), Ticket(Malformed)),
        (format!("{V1_TICKET} -483920"), Ticket(Malformed)),
        ("-483920".to_owned(), Ticket(Malformed)),
        ("not-a-ticket-483920".to_owned(), Ticket(Malformed)),
        (
            format!("{NEWER_TICKET}-483920"),
            Ticket(UnsupportedVersion(1)),
        ),
    ];
    for (input, want) in cases {
        assert_eq!(parse(&input), Err(want), "{input:?}");
    }
}

/// Not a spec row, because it is the row above it with nothing to trim.
#[test]
fn the_empty_string_is_empty() {
    assert_eq!(parse(""), Err(PairingStringError::Empty));
}

#[test]
fn a_code_is_six_ascii_digits_and_nothing_else() {
    for code in ["000000", "999999", "483920"] {
        assert_eq!(code.parse::<PairingCode>().expect(code).as_str(), code);
    }
    for code in [
        "",
        "48392",
        "4839201",
        "+48392",
        " 48392",
        "483920\n",
        "４８３９２０",
        "4839２0",
    ] {
        assert_eq!(
            code.parse::<PairingCode>(),
            Err(PairingStringError::Code),
            "{code:?}"
        );
    }
}

#[test]
fn a_minted_code_is_six_ascii_digits_that_parse_back() {
    let codes: Vec<PairingCode> = (0..2_000).map(|_| PairingCode::mint()).collect();
    for code in &codes {
        assert_eq!(code.as_str().parse::<PairingCode>().as_ref(), Ok(code));
    }
    // Not a test of the generator, which is the operating system's: a test
    // that `mint` draws at all rather than returning one value.
    assert!(codes.iter().any(|code| code != &codes[0]));
}

/// A live code is worth a credential, and `Debug` is what panics and
/// `tracing` fields print.
#[test]
fn neither_debug_shows_the_code() {
    let pairing: PairingString = format!("{V1_TICKET}-483920").parse().expect("accepted");

    assert_eq!(
        format!("{:?}", pairing.code().expect("has a code")),
        "PairingCode(<redacted>)"
    );
    let debug = format!("{pairing:?}");
    assert!(!debug.contains("483920"), "{debug}");
    assert!(debug.contains(&pairing.ticket().fingerprint()), "{debug}");
    assert!(!debug.contains(V1_TICKET), "{debug}");
}

/// The ticket's error is the source, so a caller printing the chain sees
/// its advice once.
#[test]
fn a_ticket_refusal_carries_the_tickets_error_as_its_source_and_not_in_its_message() {
    // No `-` in it, or it would be refused for its code before the ticket.
    let refused = "notaticket".parse::<PairingString>().unwrap_err();
    let source = refused.source().expect("a ticket refusal has a source");

    assert_eq!(
        source.downcast_ref::<TicketParseError>(),
        Some(&TicketParseError::Malformed)
    );
    assert!(
        !refused.to_string().contains(&source.to_string()),
        "{refused}"
    );
    assert!(PairingStringError::Code.source().is_none());
    assert!(PairingStringError::Empty.source().is_none());
}

#[test]
fn into_parts_hands_back_what_new_was_given() {
    let ticket: Ticket = V1_TICKET.parse().expect("vector 1");
    let code: PairingCode = "000417".parse().expect("a code");

    let (got_ticket, got_code) =
        PairingString::new(ticket.clone(), Some(code.clone())).into_parts();
    assert_eq!((got_ticket, got_code), (ticket.clone(), Some(code)));
    assert_eq!(PairingString::new(ticket, None).code(), None);
}
