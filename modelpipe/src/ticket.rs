//! The pairing ticket and its parse errors.
//!
//! Pure: this module never touches the network. It owns what a ticket
//! *contains* — the fields, their widths, and how they are laid out as
//! bytes. How those bytes are spelled as a string, and the order a parser
//! checks things in, is [`crate::ticket_string`]'s. What is done with the
//! endpoint a ticket names belongs to the transport, and is neither's.
//!
//! The normative contract is `docs/ticket-format-v0.md`, which ships in
//! this crate's published tarball. Everything here implements that page;
//! where the two could disagree, the page wins, and
//! `scripts/ticket_vectors.py --check` plus the hard-coded vectors in
//! `ticket_tests.rs` are what keep them from drifting.

use std::fmt;

use crate::crc32c::crc32c;
use crate::ticket_addr::TicketAddr;

/// The only format version this build speaks.
pub(crate) const VERSION_V0: u8 = 0x00;

/// `openai-compatible`, the only backend hint assigned in v0.
const BACKEND_OPENAI_COMPATIBLE: u8 = 0x00;

// Field widths. Every bound below is a sum of these rather than a literal,
// so the arithmetic is checkable by reading it and a field that changes
// width cannot leave a stale constant behind.
const VERSION_LEN: usize = 1;
const ENDPOINT_ID_LEN: usize = 32;
const ADDR_COUNT_LEN: usize = 1;
const BACKEND_LEN: usize = 1;
pub(crate) const CRC_LEN: usize = 4;

/// The smallest possible v0 ticket: the fixed fields with no addresses.
pub(crate) const MIN_V0: usize =
    VERSION_LEN + ENDPOINT_ID_LEN + ADDR_COUNT_LEN + BACKEND_LEN + CRC_LEN;

/// The decoded-size cap, a denial-of-service guard independent of version.
pub(crate) const MAX_TICKET_BYTES: usize = 1024;

/// What kind of server sits behind a ticket's endpoint.
///
/// A hint, not a contract: v0 assigns one value and a parser must accept
/// any other rather than failing, so that a newer serve side stays pairable
/// from an older client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum BackendHint {
    /// The only value v0 assigns.
    OpenAiCompatible,
    /// A value assigned after this build was written. Carried so the byte
    /// survives a round trip; v0 defines no accessor, so nothing consumes it.
    Unknown(u8),
}

impl BackendHint {
    /// The wire byte.
    const fn as_byte(self) -> u8 {
        match self {
            Self::OpenAiCompatible => BACKEND_OPENAI_COMPATIBLE,
            Self::Unknown(b) => b,
        }
    }

    /// Never fails: an unrecognised hint is carried, not refused.
    const fn from_byte(b: u8) -> Self {
        if b == BACKEND_OPENAI_COMPATIBLE {
            Self::OpenAiCompatible
        } else {
            Self::Unknown(b)
        }
    }
}

/// A pairing ticket: how one machine finds and authenticates another's
/// listener.
///
/// Base32 on the wire so it survives terminals, being read aloud, and —
/// with the case rule the README's format section records — QR codes.
///
/// Contains the serve side's endpoint identity (endpoint id plus a set of
/// transport addresses) and a backend-kind hint — and deliberately *not*
/// the bearer token, which travels separately so that a leaked ticket
/// alone cannot make a request. The format is versioned; the byte-level
/// contract, test vectors and refusal taxonomy included, is
/// `docs/ticket-format-v0.md`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Ticket {
    // Field layout is private; docs/ticket-format-v0.md is the public
    // contract.
    endpoint_id: [u8; ENDPOINT_ID_LEN],
    /// Canonical at all times: sorted by encoded bytes, no duplicates, and
    /// short enough that the whole ticket fits the cap. [`Ticket::new`]
    /// is the only thing that builds this, and it establishes all three —
    /// which is what lets [`Ticket::encode`] be infallible.
    addrs: Vec<TicketAddr>,
    backend: BackendHint,
}

impl Ticket {
    /// Build a ticket, canonicalizing and size-bounding its addresses.
    ///
    /// Infallible by construction. The spec makes staying under the cap an
    /// *encoder* obligation — the field widths admit far more than any
    /// parser accepts — and says an encoder drops lowest-priority addresses
    /// rather than minting a ticket nobody can read. That is what this does,
    /// and it cannot run out of things to drop: an address-free ticket is
    /// `MIN_V0` bytes, far inside the cap.
    ///
    /// "Lowest priority" falls out of the canonical order rather than being
    /// a second rule to remember. Sorting by encoded bytes groups relays
    /// (tag `0x00`) before IPv4 (`0x01`) before IPv6 (`0x02`), so dropping
    /// from the end sheds direct addresses first and keeps relays longest —
    /// which is the right way round: a direct address is an optimization,
    /// while the relay is what connects at all under a NAT that refuses to
    /// hole-punch.
    pub(crate) fn new(
        endpoint_id: [u8; ENDPOINT_ID_LEN],
        addrs: Vec<TicketAddr>,
        backend: BackendHint,
    ) -> Self {
        let mut encoded: Vec<(Vec<u8>, TicketAddr)> = addrs
            .into_iter()
            // An address too long to frame is dropped rather than fatal: it
            // is unusable either way, and a ticket without it still pairs.
            .filter_map(|a| a.encoded().map(|bytes| (bytes, a)))
            .collect();
        encoded.sort_by(|a, b| a.0.cmp(&b.0));
        encoded.dedup_by(|a, b| a.0 == b.0);

        // `addr_count` is a u8, so the count is bounded before the bytes are.
        encoded.truncate(u8::MAX as usize);

        let mut total = MIN_V0 + encoded.iter().map(|(b, _)| b.len()).sum::<usize>();
        while total > MAX_TICKET_BYTES {
            let (bytes, _) = encoded.pop().expect("MIN_V0 alone is inside the cap");
            total -= bytes.len();
        }

        Self {
            endpoint_id,
            addrs: encoded.into_iter().map(|(_, a)| a).collect(),
            backend,
        }
    }

    /// The serve side's endpoint identity, as raw bytes.
    ///
    /// `pub(crate)`: the transport needs it to dial, and nobody outside
    /// this crate has anything to do with a raw key.
    pub(crate) const fn endpoint_id(&self) -> &[u8; ENDPOINT_ID_LEN] {
        &self.endpoint_id
    }

    /// The transport addresses this ticket carries, in canonical order.
    pub(crate) fn addrs(&self) -> &[TicketAddr] {
        &self.addrs
    }

    /// Short fingerprint of the serve side's identity: enough to compare
    /// two tickets by eye, or to name one in a log line, without putting
    /// ninety-six characters there. Never the full key.
    ///
    /// This is what [`Debug`](fmt::Debug) renders instead of the ticket
    /// string, which is the reason it is not merely a convenience — see
    /// that impl for why a ticket must not land in a panic message whole.
    pub fn fingerprint(&self) -> String {
        crate::fingerprint::of(&self.endpoint_id)
    }

    /// The ticket's bytes, per the format spec.
    ///
    /// Infallible: [`Ticket::new`] is the only constructor and it
    /// establishes the invariants — canonical addresses, inside the cap —
    /// that would otherwise make this fallible. A ticket that exists is a
    /// ticket that encodes.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(MIN_V0);
        body.push(VERSION_V0);
        body.extend_from_slice(&self.endpoint_id);
        body.push(u8::try_from(self.addrs.len()).expect("new() bounds the count"));
        for addr in &self.addrs {
            body.extend_from_slice(&addr.encoded().expect("new() dropped unframeable addresses"));
        }
        body.push(self.backend.as_byte());

        let crc = crc32c(&body);
        body.extend_from_slice(&crc.to_be_bytes());
        debug_assert!(body.len() <= MAX_TICKET_BYTES, "new() bounds the total");
        body
    }

    /// Parse verified ticket bytes into a ticket.
    ///
    /// Assumes the caller has already checked everything the format spec
    /// puts before the structure — version, minimum length, checksum — and
    /// enforces what it puts after: exact consumption, and no bytes left
    /// between the structure's end and the checksum.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, TicketParseError> {
        let body = &bytes[..bytes.len() - CRC_LEN];
        let mut pos = VERSION_LEN;

        let endpoint_id: [u8; ENDPOINT_ID_LEN] = body
            .get(pos..pos + ENDPOINT_ID_LEN)
            .ok_or(TicketParseError::Malformed)?
            .try_into()
            .expect("slice length checked");
        pos += ENDPOINT_ID_LEN;

        let count = *body.get(pos).ok_or(TicketParseError::Malformed)?;
        pos += ADDR_COUNT_LEN;

        let mut addrs = Vec::with_capacity(count as usize);
        for _ in 0..count {
            // `None` is a tag this version does not know: already stepped
            // over, and deliberately absent from the result. The parsed list
            // is therefore allowed to be shorter than `count`.
            if let Some(addr) = TicketAddr::read(body, &mut pos)? {
                addrs.push(addr);
            }
        }

        let backend = BackendHint::from_byte(*body.get(pos).ok_or(TicketParseError::Malformed)?);
        pos += BACKEND_LEN;

        if pos != body.len() {
            return Err(TicketParseError::Malformed);
        }
        // Through `new`, never a struct literal. The spec says a decoder
        // accepts addresses in any order and that "a duplicated address
        // collapses — the parsed result is a set", and that an encoder emits
        // them sorted "so equal tickets compare equal as strings".
        // `Display` is an encoder, so building the fields directly here made
        // parse-then-print reproduce whatever order arrived, and made two
        // tickets naming one pairing compare unequal.
        //
        // `new` also collapses duplicates by encoded bytes, which is the key
        // its sort already uses; the loop above did it by `PartialEq`, a
        // second and subtly different rule for the same job.
        Ok(Self::new(endpoint_id, addrs, backend))
    }
}

impl fmt::Debug for Ticket {
    // Hand-written, never derived: `Display` emits the full ticket (that
    // is its job — the CLI prints it), so a derived `Debug` over the real
    // fields would copy pairing credentials into every downstream panic
    // message and `tracing` line. The fingerprint is the only part of a
    // ticket a log should ever see.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ticket").field(&self.fingerprint()).finish()
    }
}

/// Why a ticket string failed to parse. Deliberately coarse: a ticket is
/// pasted or scanned, so the advice is one line — re-copy it, or, when
/// the format is newer than this build, upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TicketParseError {
    /// Bad base32, truncated, checksum failure — any of the re-copy-it
    /// failures the format spec routes here.
    Malformed,
    /// Parsed, but a format version this build doesn't speak.
    UnsupportedVersion(u8),
}

impl fmt::Display for TicketParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => write!(f, "ticket is malformed — re-copy it from the serve side"),
            Self::UnsupportedVersion(v) => write!(f, "ticket format v{v} is newer than this build"),
        }
    }
}

impl std::error::Error for TicketParseError {}

#[cfg(test)]
#[path = "ticket_tests.rs"]
mod ticket_tests;
