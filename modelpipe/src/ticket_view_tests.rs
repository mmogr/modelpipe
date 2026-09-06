//! Tests for [`super`] — what a ticket says about where it points.
//!
//! Split out via `#[path]` so `ticket_view.rs` stays inside the file-size
//! budget, the same way every other module in the crate does it.
//!
//! Driven from the **normative vectors** in `docs/ticket-format-v0.md`
//! rather than from tickets built here. A ticket built in this file would
//! be one built by the same code the accessors read back, and would prove
//! only that the crate agrees with itself; the vectors are asserted
//! identical by three independent implementations on every CI run, so
//! reading them is reading a value nobody in this file chose.

use super::*;

/// Vector 1: the minimal ticket. An endpoint id, no addresses at all.
const V1: &str = "pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaaauhlp2na";

/// Vector 2: one relay and one IPv4 address — the ordinary case.
const V2: &str = "pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaqaaangq5duobztulzpojswyylzfzsxqylnobwgkltdn5ws6aiaa3akqaihcfiqbrp5xr4q";

/// Vector 3: one IPv6 address and no relay.
const V3: &str = "pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaicaajcaainxaaaaaaaaaaaaaaaaaaach4qaabstehw";

/// Vector 5: a relay URL whose every component a URL library rewrites.
const V5: &str = "pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaiaaaswq5duobztulzpkjswyylzfzcxqylnobwgklsdj5gs4orugqzs6jjxivtg63ya25wypry";

/// What vector 5 carries, character for character.
const V5_URL: &str = "https://Relay.Example.COM.:443/%7Efoo";

fn ticket(s: &str) -> Ticket {
    s.parse().expect("a normative vector must parse")
}

/// The question these accessors exist for, and the one an embedder printing
/// a ticket had no way to ask: is there a relay in it?
#[test]
fn a_ticket_with_no_relay_says_so_rather_than_leaving_it_to_be_guessed() {
    assert!(
        ticket(V1).relay_urls().is_empty(),
        "the minimal ticket names nowhere at all"
    );
    assert!(
        ticket(V3).relay_urls().is_empty(),
        "a direct-only ticket is reachable on a LAN and nowhere else"
    );
    assert_eq!(
        ticket(V2).relay_urls(),
        ["https://relay.example.com/"],
        "and a ticket that has one hands it back"
    );
}

/// **Verbatim** is the whole reason a relay comes back as a `String`. Every
/// component of this URL is one a URL library rewrites — the host case, the
/// trailing dot, the explicitly written default port, the percent-encoding
/// — and the format spec makes carrying it unchanged normative.
#[test]
fn a_relay_url_is_handed_back_exactly_as_the_serve_side_wrote_it() {
    assert_eq!(ticket(V5).relay_urls(), [V5_URL]);
}

/// The other half: the direct addresses, as `std` values, both families.
#[test]
fn the_direct_addresses_come_back_as_socket_addresses() {
    assert_eq!(
        ticket(V2).direct_addrs(),
        ["192.168.1.7:4433".parse::<SocketAddr>().unwrap()],
        "the LAN address the fast path exists for"
    );
    assert_eq!(
        ticket(V3).direct_addrs(),
        ["[2001:db8::1]:8080".parse::<SocketAddr>().unwrap()]
    );
    assert!(
        ticket(V1).direct_addrs().is_empty(),
        "an id-only ticket is resolved through address lookup, not an address"
    );
}

/// Neither accessor may report the other's addresses. Its own test because
/// the two are one `filter_map` apart, and a mistake there is the kind that
/// reads correctly: a ticket carrying both would answer both questions with
/// the same list and look entirely plausible doing it.
#[test]
fn each_accessor_reports_its_own_kind_of_address_and_no_other() {
    let both = ticket(V2);
    assert_eq!(both.relay_urls().len(), 1);
    assert_eq!(both.direct_addrs().len(), 1);
    assert!(
        both.relay_urls()[0].starts_with("https://"),
        "a relay body is a URL, not an address"
    );
}

/// The order is the ticket's canonical one, so a ticket that has been
/// through a parse and a re-encode reports the same lists in the same
/// order — which is what makes two readings of one ticket comparable.
#[test]
fn the_order_survives_a_round_trip_through_the_string_form() {
    for vector in [V1, V2, V3, V5] {
        let once = ticket(vector);
        let twice = ticket(&once.to_string());
        assert_eq!(once.relay_urls(), twice.relay_urls(), "{vector}");
        assert_eq!(once.direct_addrs(), twice.direct_addrs(), "{vector}");
    }
}
