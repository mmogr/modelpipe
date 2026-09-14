//! Tests for [`super`].
//!
//! Split out via `#[path]`, as every module in the crate does it.

use super::*;

/// RFC 8032 §7.1 TEST 1's public key, which the ticket vectors use too.
const PRINTED: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

#[test]
fn a_peer_id_prints_as_sixty_four_lower_case_hex_and_parses_back() {
    let id: PeerId = PRINTED.parse().expect("hex");
    assert_eq!(id.to_string(), PRINTED);
    assert_eq!(PRINTED.to_ascii_uppercase().parse::<PeerId>(), Ok(id));
    assert_eq!(id.to_bytes()[0], 0xd7);
    assert_eq!(id.to_bytes()[31], 0x1a);
    assert_eq!(PeerId::from_bytes(id.to_bytes()), id);
}

/// The fingerprint is the listener's rule over the same bytes, and the
/// front of the printed id, which is what lets a person match the two.
#[test]
fn the_fingerprint_is_the_front_of_the_printed_id() {
    let id: PeerId = PRINTED.parse().expect("hex");
    assert_eq!(id.fingerprint(), &PRINTED[..12]);
    assert_eq!(id.fingerprint(), fingerprint::of(&id.to_bytes()));
}

#[test]
fn debug_is_the_fingerprint() {
    let id: PeerId = PRINTED.parse().expect("hex");
    assert_eq!(format!("{id:?}"), format!("PeerId({:?})", &PRINTED[..12]));
}

#[test]
fn anything_but_sixty_four_hex_characters_is_refused() {
    let cases = [
        String::new(),
        PRINTED[..63].to_owned(),
        format!("{PRINTED}0"),
        format!("{}g", &PRINTED[..63]),
        format!(" {}", &PRINTED[..63]),
        format!("0x{}", &PRINTED[..62]),
        // Sixty-four bytes, but the last two are one character that is not
        // a hex digit: the length is counted in bytes and still refused.
        format!("{}\u{e9}", &PRINTED[..62]),
    ];
    for case in cases {
        assert_eq!(
            case.parse::<PeerId>(),
            Err(PeerIdParseError(())),
            "{case:?}"
        );
    }
    assert!(!PeerIdParseError(()).to_string().is_empty());
}

#[cfg(feature = "serde")]
#[test]
fn serde_carries_a_peer_id_as_its_printed_form() {
    let id: PeerId = PRINTED.parse().expect("hex");
    let json = serde_json::to_string(&id).expect("serializes");
    assert_eq!(json, format!("\"{PRINTED}\""));
    assert_eq!(
        serde_json::from_str::<PeerId>(&json).expect("deserializes"),
        id
    );
    assert!(serde_json::from_str::<PeerId>("\"d75a\"").is_err());
}
