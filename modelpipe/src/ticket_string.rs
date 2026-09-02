//! How a ticket is spelled: the string form and its decoding order.
//!
//! The spec divides itself the same way — "String form" and "Byte layout"
//! are separate sections — and the two answer different questions. This
//! module owns the envelope: the kind prefix, base32, the bounds that apply
//! before any structure is read, and the order those checks happen in.
//! What the bytes inside *mean* is [`crate::ticket`]'s.
//!
//! The order is normative, not incidental. It is what decides whether a
//! given corruption tells the user to re-copy the ticket or to upgrade
//! their build, and those are the only two pieces of advice the format
//! offers.

use std::fmt;
use std::str::FromStr;

use crate::base32;
use crate::crc32c::crc32c;
use crate::ticket::{CRC_LEN, MAX_TICKET_BYTES, MIN_V0, Ticket, TicketParseError, VERSION_V0};

/// The string form's kind prefix.
pub(crate) const KIND: &str = "pipe";

/// The bound on the *string*, checked before decoding.
///
/// The byte cap is stated on decoded bytes, but enforcing it only after
/// decoding means a hostile megabyte-long input is fully allocated before
/// the guard it exists for ever fires. Base32 carries five bits per
/// character, so this is `ceil(MAX_TICKET_BYTES * 8 / 5)` plus the prefix.
pub(crate) const MAX_TICKET_CHARS: usize = KIND.len() + (MAX_TICKET_BYTES * 8).div_ceil(5);

impl fmt::Display for Ticket {
    /// The canonical string form, lowercase.
    ///
    /// Canonicalizing, which is worth knowing at a call site: parsing a
    /// ticket and printing it again may not reproduce the input. Addresses
    /// come back sorted and deduplicated, the whole string comes back
    /// lowercase whatever case arrived, and an address whose tag this build
    /// does not know is gone — it was skipped on the way in and there is
    /// nothing left to write out.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(KIND)?;
        f.write_str(&base32::encode(&self.encode()).to_ascii_lowercase())
    }
}

impl FromStr for Ticket {
    type Err = TicketParseError;

    /// The spec's decoding order, exactly: ASCII, the character bound, the
    /// kind prefix, strict base32, the byte cap, and a version byte to read
    /// — every failure among these is [`Malformed`](TicketParseError::Malformed)
    /// — then version dispatch, and only then the fields this version owns.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // ASCII first, and as a refusal rather than a coercion. Under full
        // Unicode folding U+212A KELVIN SIGN lowercases to `k`, so a folding
        // parser would accept a ticket that an ASCII one rejects — an
        // interoperability split with no upside. The spec says ASCII.
        if !s.is_ascii() || s.len() > MAX_TICKET_CHARS {
            return Err(TicketParseError::Malformed);
        }
        let rest = s
            .get(..KIND.len())
            .filter(|p| p.eq_ignore_ascii_case(KIND))
            .and_then(|_| s.get(KIND.len()..))
            .ok_or(TicketParseError::Malformed)?;

        let bytes =
            base32::decode(&rest.to_ascii_uppercase()).ok_or(TicketParseError::Malformed)?;
        if bytes.len() > MAX_TICKET_BYTES {
            return Err(TicketParseError::Malformed);
        }

        // Before the version dispatch, because there is no version to
        // dispatch on. `UnsupportedVersion` carries a `u8` and has nothing to
        // put in it here: "cannot read the version byte" is a framing
        // failure, not a newer format.
        let &version = bytes.first().ok_or(TicketParseError::Malformed)?;
        if version != VERSION_V0 {
            return Err(TicketParseError::UnsupportedVersion(version));
        }

        // Everything from here is owned by v0, including the checksum —
        // which is why a strike on the version byte surfaces as "upgrade"
        // rather than "re-copy", the one corruption this cannot catch.
        if bytes.len() < MIN_V0 {
            return Err(TicketParseError::Malformed);
        }
        let (body, crc) = bytes.split_at(bytes.len() - CRC_LEN);
        let crc = u32::from_be_bytes(crc.try_into().expect("CRC_LEN bytes"));
        if crc32c(body) != crc {
            return Err(TicketParseError::Malformed);
        }

        Self::decode(&bytes)
    }
}
