//! The pairing ticket and its parse errors.
//!
//! Pure: this module never touches the network. It owns how a ticket is
//! spelled, checked and rendered, and nothing about what is done with the
//! endpoint it names — resolving that endpoint and dialing it belong to
//! the transport.

use std::fmt;
use std::str::FromStr;

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
#[derive(Clone)]
pub struct Ticket {
    // Field layout is private; docs/ticket-format-v0.md is the public
    // contract.
    _private: (),
}

impl Ticket {
    /// Short fingerprint of the serve side's identity, for `status`
    /// output and eyeball comparison. Never the full key.
    pub fn fingerprint(&self) -> String {
        todo!()
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

impl fmt::Display for Ticket {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl FromStr for Ticket {
    type Err = TicketParseError;

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

/// Why a ticket string failed to parse. Deliberately coarse: a ticket is
/// pasted or scanned, so the advice is one line — re-copy it, or, when
/// the format is newer than this build, upgrade.
#[derive(Debug)]
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
