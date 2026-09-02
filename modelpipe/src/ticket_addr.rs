//! One transport address, as a ticket spells it.
//!
//! Owns the tagged, length-prefixed encoding of a single address and
//! nothing else: it does not know how many addresses a ticket holds, in
//! what order, or what to do with one. Whether an address is *reachable*,
//! or *allowed*, is not asked here either — this module answers only how an
//! address is written down and read back.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use crate::ticket::TicketParseError;

/// Tag for a relay URL.
const TAG_RELAY: u8 = 0x00;
/// Tag for an IPv4 socket address.
const TAG_V4: u8 = 0x01;
/// Tag for an IPv6 socket address.
const TAG_V6: u8 = 0x02;

/// Bytes in the `u16` that prefixes every body.
const LEN_PREFIX: usize = 2;
/// Bytes in an IPv4 address.
const V4_ADDR: usize = 4;
/// Bytes in an IPv6 address.
const V6_ADDR: usize = 16;
/// Bytes in a port.
const PORT: usize = 2;

/// The exact body length of an IPv4 address, derived rather than written.
const V4_BODY: usize = V4_ADDR + PORT;
/// The exact body length of an IPv6 address, derived rather than written.
const V6_BODY: usize = V6_ADDR + PORT;

/// A transport address a ticket can carry.
///
/// Relay URLs are carried verbatim — no case folding, no percent-decoding,
/// no trailing-dot removal, no default-port elision. That is normative in
/// the format spec, and the reason this holds a `String` rather than a
/// parsed URL type: every URL library normalizes, and a value that went
/// through one is no longer the value that was written down.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum TicketAddr {
    /// A relay URL, exactly as the serve side wrote it.
    Relay(String),
    /// A direct IPv4 socket address.
    V4(SocketAddrV4),
    /// A direct IPv6 socket address.
    V6(SocketAddrV6),
}

impl TicketAddr {
    /// This address in its wire form: `tag || u16 length || body`.
    ///
    /// Returns `None` for a relay URL too long to describe in the `u16`
    /// length. The caller's size obligation is broader than this — a ticket
    /// has a total cap far below what the length field admits — but a body
    /// that cannot be *framed* fails here, closer to the cause.
    pub(crate) fn encoded(&self) -> Option<Vec<u8>> {
        let (tag, body) = match self {
            Self::Relay(url) => (TAG_RELAY, url.as_bytes().to_vec()),
            Self::V4(addr) => {
                let mut body = addr.ip().octets().to_vec();
                body.extend_from_slice(&addr.port().to_be_bytes());
                (TAG_V4, body)
            }
            Self::V6(addr) => {
                let mut body = addr.ip().octets().to_vec();
                body.extend_from_slice(&addr.port().to_be_bytes());
                (TAG_V6, body)
            }
        };
        let len = u16::try_from(body.len()).ok()?;

        let mut out = Vec::with_capacity(1 + LEN_PREFIX + body.len());
        out.push(tag);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&body);
        Some(out)
    }

    /// Read one address from `buf` at `pos`, advancing `pos` past it.
    ///
    /// `Ok(None)` means the tag is one this version does not know: its
    /// length was read, `pos` advanced past its body, and the address
    /// dropped. That is the entire payoff of length-prefixing every body —
    /// a client meeting a transport added after it was written skips that
    /// address and keeps the rest of the ticket, instead of failing the
    /// parse and being unable to pair at all.
    pub(crate) fn read(buf: &[u8], pos: &mut usize) -> Result<Option<Self>, TicketParseError> {
        let tag = take(buf, pos, 1)?[0];
        let len_bytes = take(buf, pos, LEN_PREFIX)?;
        let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
        let body = take(buf, pos, len)?;

        match tag {
            TAG_RELAY => {
                // Invalid UTF-8 is malformed rather than skipped: the tag is
                // one we claim to understand, so a body we cannot read is a
                // corrupt ticket, not a future feature.
                let url = std::str::from_utf8(body)
                    .map_err(|_| TicketParseError::Malformed)?
                    .to_owned();
                Ok(Some(Self::Relay(url)))
            }
            TAG_V4 => {
                if body.len() != V4_BODY {
                    return Err(TicketParseError::Malformed);
                }
                let octets: [u8; V4_ADDR] = body[..V4_ADDR].try_into().expect("length checked");
                let port = u16::from_be_bytes([body[V4_ADDR], body[V4_ADDR + 1]]);
                Ok(Some(Self::V4(SocketAddrV4::new(
                    Ipv4Addr::from(octets),
                    port,
                ))))
            }
            TAG_V6 => {
                if body.len() != V6_BODY {
                    return Err(TicketParseError::Malformed);
                }
                let octets: [u8; V6_ADDR] = body[..V6_ADDR].try_into().expect("length checked");
                let port = u16::from_be_bytes([body[V6_ADDR], body[V6_ADDR + 1]]);
                // Flow info and scope id are not carried: they are local
                // facts about one machine's interfaces, meaningless to the
                // peer that reads this ticket.
                Ok(Some(Self::V6(SocketAddrV6::new(
                    Ipv6Addr::from(octets),
                    port,
                    0,
                    0,
                ))))
            }
            _ => Ok(None),
        }
    }
}

/// Take `n` bytes from `buf` at `pos`, advancing it. Running off the end is
/// a truncated ticket.
fn take<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], TicketParseError> {
    let end = pos.checked_add(n).ok_or(TicketParseError::Malformed)?;
    let slice = buf.get(*pos..end).ok_or(TicketParseError::Malformed)?;
    *pos = end;
    Ok(slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(addr: &TicketAddr) -> Option<TicketAddr> {
        let bytes = addr.encoded().expect("encodable");
        let mut pos = 0;
        let parsed = TicketAddr::read(&bytes, &mut pos).expect("well-formed");
        assert_eq!(pos, bytes.len(), "read must consume exactly what it wrote");
        parsed
    }

    #[test]
    fn every_address_kind_round_trips() {
        for addr in [
            TicketAddr::Relay("https://relay.example.com/".to_owned()),
            TicketAddr::V4("192.168.1.7:4433".parse().unwrap()),
            TicketAddr::V6("[2001:db8::1]:8080".parse().unwrap()),
        ] {
            assert_eq!(round_trip(&addr).as_ref(), Some(&addr));
        }
    }

    /// The bodies are fixed-width and their lengths therefore redundant.
    /// Pinned because the redundancy is deliberate and someone will
    /// eventually wonder whether it can be dropped: it cannot, and the test
    /// above it explains why.
    #[test]
    fn the_ip_bodies_carry_their_redundant_length() {
        let v4 = TicketAddr::V4("192.168.1.7:4433".parse().unwrap())
            .encoded()
            .unwrap();
        assert_eq!(&v4[..3], &[TAG_V4, 0x00, u8::try_from(V4_BODY).unwrap()]);

        let v6 = TicketAddr::V6("[2001:db8::1]:8080".parse().unwrap())
            .encoded()
            .unwrap();
        assert_eq!(&v6[..3], &[TAG_V6, 0x00, u8::try_from(V6_BODY).unwrap()]);
    }

    /// The graceful degrade, which is the whole reason every body is
    /// length-prefixed.
    #[test]
    fn an_unknown_tag_is_skipped_and_its_body_stepped_over() {
        let mut bytes = vec![0x7F, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        let tail = TicketAddr::V4("192.168.1.7:4433".parse().unwrap())
            .encoded()
            .unwrap();
        bytes.extend_from_slice(&tail);

        let mut pos = 0;
        assert_eq!(
            TicketAddr::read(&bytes, &mut pos),
            Ok(None),
            "an unknown tag is skipped, not fatal"
        );
        assert_eq!(pos, 7, "and its body is stepped over exactly");

        // The address after it must still be readable, which is the property
        // that makes adding a transport a graceful degrade.
        let next = TicketAddr::read(&bytes, &mut pos).expect("well-formed");
        assert_eq!(
            next,
            Some(TicketAddr::V4("192.168.1.7:4433".parse().unwrap()))
        );
    }

    /// A relay URL that every URL library rewrites. Held as a `String` for
    /// exactly this reason.
    #[test]
    fn a_relay_url_survives_verbatim() {
        let url = "https://Relay.Example.COM.:443/%7Efoo";
        let addr = TicketAddr::Relay(url.to_owned());
        match round_trip(&addr) {
            Some(TicketAddr::Relay(got)) => assert_eq!(got, url),
            other => panic!("expected the relay back unchanged, got {other:?}"),
        }
    }

    // ── Refusals ─────────────────────────────────────────────────────────

    #[test]
    fn a_truncated_address_is_malformed() {
        for bytes in [
            vec![],                         // no tag
            vec![TAG_V4],                   // no length
            vec![TAG_V4, 0x00],             // half a length
            vec![TAG_V4, 0x00, 0x06, 0xC0], // body shorter than its length
            vec![0x7F, 0x00, 0x04, 0xDE],   // an unknown tag is not exempt
        ] {
            let mut pos = 0;
            assert_eq!(
                TicketAddr::read(&bytes, &mut pos),
                Err(TicketParseError::Malformed),
                "{bytes:?} is truncated"
            );
        }
    }

    /// A known tag whose body is the wrong size is corruption, not a future
    /// feature — the distinction an unknown tag gets and this does not.
    #[test]
    fn a_known_tag_with_a_wrong_sized_body_is_malformed() {
        for bytes in [
            vec![TAG_V4, 0x00, 0x05, 1, 2, 3, 4, 5],
            vec![TAG_V6, 0x00, 0x06, 1, 2, 3, 4, 5, 6],
        ] {
            let mut pos = 0;
            assert_eq!(
                TicketAddr::read(&bytes, &mut pos),
                Err(TicketParseError::Malformed),
                "{bytes:?} has a body the tag cannot mean"
            );
        }
    }

    #[test]
    fn a_relay_body_that_is_not_utf8_is_malformed() {
        let bytes = vec![TAG_RELAY, 0x00, 0x02, 0xFF, 0xFE];
        let mut pos = 0;
        assert_eq!(
            TicketAddr::read(&bytes, &mut pos),
            Err(TicketParseError::Malformed)
        );
    }
}
