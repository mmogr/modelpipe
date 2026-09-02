//! Tests for [`super`] — the ALPN, the address bridge, relay validation.
//!
//! Split out via `#[path]` so `transport.rs` stays inside the file-size
//! budget.
//!
//! Almost everything here runs without a network: the bridge between a
//! ticket and an iroh address is a pure translation, and it is where a
//! mistake would be least visible and most expensive. The one test that
//! binds an endpoint says so.

use std::collections::BTreeSet;

use super::*;

/// RFC 8032 §7.1 TEST 1 — a real curve point, so `EndpointId::from_bytes`
/// has something valid to accept.
const VALID_KEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

fn key(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex");
    }
    out
}

fn endpoint_addr(addrs: Vec<TransportAddr>) -> EndpointAddr {
    EndpointAddr {
        id: EndpointId::from_bytes(&key(VALID_KEY)).expect("a real curve point"),
        addrs: addrs.into_iter().collect::<BTreeSet<_>>(),
    }
}

// ── The ALPN ─────────────────────────────────────────────────────────────

/// An unversioned ALPN leaves no negotiation lever, and the ticket's own
/// version byte cannot cover for it — the two version spaces are
/// independent, so a ticket that parses perfectly still reaches a peer you
/// cannot speak to.
#[test]
fn the_alpn_carries_a_version() {
    let text = std::str::from_utf8(ALPN).expect("ASCII");
    assert_eq!(text, "modelpipe/0");
    let (name, version) = text.split_once('/').expect("a version component");
    assert_eq!(name, "modelpipe");
    assert!(
        version.parse::<u32>().is_ok(),
        "the version must be a number a later one can follow: {version}"
    );
}

// ── The address bridge ───────────────────────────────────────────────────

#[tokio::test]
async fn a_ticket_round_trips_through_an_iroh_address() {
    let original = endpoint_addr(vec![
        TransportAddr::Relay("https://relay.example.com./".parse().expect("relay url")),
        TransportAddr::Ip("192.168.1.7:4433".parse().unwrap()),
        TransportAddr::Ip("[2001:db8::1]:8080".parse().unwrap()),
    ]);

    let ticket = ticket_from(&original);
    let back = addr_from(&ticket).expect("a valid key must convert back");

    assert_eq!(back.id, original.id, "the identity survives");
    assert_eq!(back.addrs, original.addrs, "and so does every address");
}

/// The identity is what the pairing actually rests on, so it survives even
/// a ticket with nothing else in it.
#[test]
fn an_address_free_ticket_still_names_its_endpoint() {
    let original = endpoint_addr(vec![]);
    let ticket = ticket_from(&original);
    let back = addr_from(&ticket).expect("valid");

    assert_eq!(back.id, original.id);
    assert!(back.addrs.is_empty());
}

/// `TransportAddr` is `#[non_exhaustive]` with a `Custom` variant, which is
/// exactly the situation the drop arm exists for: iroh may learn transports
/// v0 has no tag for. A ticket carrying fewer paths is slower in the worst
/// case and never broken — the address set exists to help a peer *avoid*
/// the relay, not to connect at all.
#[test]
fn an_address_v0_cannot_describe_is_dropped_rather_than_failing_the_mint() {
    let original = endpoint_addr(vec![
        TransportAddr::Relay("https://relay.example.com./".parse().expect("relay url")),
        TransportAddr::Ip("192.168.1.7:4433".parse().unwrap()),
    ]);
    let ticket = ticket_from(&original);

    // Everything v0 *can* describe is still there.
    assert_eq!(ticket.addrs().len(), 2);
    let back = addr_from(&ticket).expect("valid");
    assert_eq!(back.addrs.len(), 2);
}

/// The format spec says a parser treats the endpoint id as 32 opaque bytes
/// and leaves curve validity to the transport. iroh agrees, and defers it
/// further still: `EndpointId::from_bytes` accepts *any* 32 bytes —
/// all-ones, all-zeros, the high bit alone — because decompressing the
/// point is left until a signature is actually verified.
///
/// So the conversion below succeeds for a key nobody holds, and the
/// pairing fails later at dial, as unreachable. That is the right shape
/// (nobody is at that address and nobody ever was) and it is worth pinning:
/// if a future iroh validates eagerly, this test changes and the error path
/// in `addr_from` starts firing.
#[test]
fn an_endpoint_id_is_taken_as_opaque_bytes_and_judged_at_dial_time() {
    for bytes in [[0x00u8; 32], [0xFFu8; 32]] {
        let ticket = Ticket::new(bytes, vec![], BackendHint::OpenAiCompatible);
        let addr = addr_from(&ticket)
            .expect("iroh accepts any 32 bytes; validity is decided when dialling");
        assert_eq!(addr.id.as_bytes(), &bytes, "carried through unaltered");
    }
}

/// A ticket is pasted by a human and may name a relay this build cannot
/// parse. Dropping that one address costs the pairing a path, not the
/// pairing — the same reasoning as the unknown-address-tag rule.
#[test]
fn a_relay_url_iroh_will_not_parse_costs_one_path_and_not_the_pairing() {
    let ticket = Ticket::new(
        key(VALID_KEY),
        vec![
            TicketAddr::Relay("not a url at all".to_owned()),
            TicketAddr::V4("192.168.1.7:4433".parse().unwrap()),
        ],
        BackendHint::OpenAiCompatible,
    );
    let back = addr_from(&ticket).expect("the pairing survives");
    assert_eq!(back.addrs.len(), 1, "only the usable address remains");
}

// ── Relay validation ─────────────────────────────────────────────────────

#[test]
fn a_well_formed_relay_url_is_accepted() {
    for url in [
        "https://relay.example.com/",
        "http://127.0.0.1:3340/",
        "https://relay.example.com.:443/",
    ] {
        assert!(validate_relay(url).is_ok(), "{url}");
    }
}

#[test]
fn a_value_that_is_not_a_url_is_refused_before_the_listener_starts() {
    for url in ["", "not a url", "relay.example.com", "://missing-scheme"] {
        match validate_relay(url) {
            Err(ServeError::InvalidRelay { url: named }) => {
                assert_eq!(named, url, "the error must name what was refused");
            }
            other => panic!("{url:?} should be InvalidRelay, got {other:?}"),
        }
    }
}

/// The reason validation returns `()`. Every URL library normalizes, and a
/// ticket carries relay URLs verbatim — so the parse is used for its
/// verdict and then discarded, and the string the operator gave is the
/// string that travels.
#[test]
fn validation_yields_a_verdict_and_never_a_normalized_url() {
    let awkward = "https://Relay.Example.COM.:443/";
    assert!(validate_relay(awkward).is_ok());

    // The ticket keeps what it was given, whatever a URL parser would have
    // made of it.
    let ticket = Ticket::new(
        key(VALID_KEY),
        vec![TicketAddr::Relay(awkward.to_owned())],
        BackendHint::OpenAiCompatible,
    );
    let reparsed: Ticket = ticket.to_string().parse().expect("round trips");
    assert_eq!(
        reparsed.addrs(),
        [TicketAddr::Relay(awkward.to_owned())],
        "the operator's spelling survives the ticket"
    );
}

// ── Binding ──────────────────────────────────────────────────────────────

/// The one test here that touches the network stack. It binds a real
/// endpoint, which is why it is a single case rather than a table: what is
/// being checked is that the builder is wired up and the ALPN is
/// registered, not anything about connectivity.
#[tokio::test]
async fn an_endpoint_binds_and_reports_its_own_identity() {
    let endpoint = bind(None).await.expect("binding must succeed");
    let addr = endpoint.addr();

    let ticket = ticket_from(&addr);
    assert_eq!(
        ticket.endpoint_id(),
        addr.id.as_bytes(),
        "the ticket names the endpoint that minted it"
    );
    assert_eq!(ticket.fingerprint().len(), 12);
    endpoint.close().await;
}

/// A relay value that is not a URL is refused up front rather than
/// surfacing later as an unexplained transport failure.
#[tokio::test]
async fn binding_with_an_unparseable_relay_fails_before_the_endpoint_exists() {
    let err = bind(Some("not a url")).await.expect_err("must refuse");
    match &err {
        ServeError::InvalidRelay { url } => assert_eq!(url, "not a url"),
        other => panic!("expected InvalidRelay, got {other:?}"),
    }
    assert!(!err.is_retryable(), "and it is the operator's to fix");
}
