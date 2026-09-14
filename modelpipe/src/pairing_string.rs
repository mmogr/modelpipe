//! The string that pairs one machine with another: a ticket, and the first
//! time a one-time code after it.
//!
//! A ticket says where a listener is. The first pairing needs one thing more,
//! a short code spent once to hand a device a credential of its own, and the
//! two travel as one string so that a person carries one thing by hand, or
//! scans one QR code. Later sessions carry the ticket alone.
//!
//! The normative contract is `docs/pairing-v0.md`. The hard-coded vectors in
//! `pairing_string_tests.rs`, that page and `scripts/pairing_vectors.py` have
//! to agree, which `scripts/pairing_vectors.py --check` asserts in CI.
//!
//! Pure: no I/O and no async, like [`crate::ticket`], which owns the ticket
//! half.

use std::fmt;
use std::str::FromStr;

use crate::ticket::{Ticket, TicketParseError};

/// What separates the ticket from the code. A ticket's string form is `pipe`
/// and base32, which has no `-` in it, so the last `-` is always this.
const SEPARATOR: char = '-';

/// How many ASCII digits a pairing code has.
const CODE_DIGITS: usize = 6;

/// A one-time pairing code: exactly six ASCII digits.
///
/// Worth as much as a device's credential for as long as it is live, so its
/// `Debug` never shows the digits and it has no `Display`: the one way to them
/// is [`as_str`](Self::as_str), which a caller writes on purpose.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingCode(String);

impl PairingCode {
    /// A fresh code from the operating system's CSPRNG, uniform over all one
    /// million.
    ///
    /// Uniform because a draw at or above the largest multiple of a million a
    /// `u32` holds is drawn again, rather than folded in by a remainder that
    /// would make the low codes likelier.
    ///
    /// # Panics
    ///
    /// If the operating system's CSPRNG cannot produce bytes. A guessable code
    /// is worse than none, so there is no weaker fallback.
    #[must_use]
    pub fn mint() -> Self {
        const LIMIT: u32 = u32::MAX - u32::MAX % 1_000_000;
        loop {
            let mut bytes = [0u8; 4];
            getrandom::fill(&mut bytes).expect("the OS CSPRNG must be available");
            let draw = u32::from_le_bytes(bytes);
            if draw < LIMIT {
                return Self(format!("{:06}", draw % 1_000_000));
            }
        }
    }

    /// The six digits.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for PairingCode {
    type Err = PairingStringError;

    /// Exactly six ASCII digits and nothing else: no sign, no space, and no
    /// full-width or other-script digit, because the far side compares bytes.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() == CODE_DIGITS && s.bytes().all(|b| b.is_ascii_digit()) {
            Ok(Self(s.to_owned()))
        } else {
            Err(PairingStringError::Code)
        }
    }
}

impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingCode(<redacted>)")
    }
}

/// A pairing string taken apart: who to dial, and, for a first pairing, the
/// code to redeem.
///
/// Parsing trims ASCII whitespace from both ends, splits on the last `-`,
/// checks the code, and then parses the ticket, in that order;
/// `docs/pairing-v0.md` gives the refusal for each step.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingString {
    ticket: Ticket,
    code: Option<PairingCode>,
}

impl PairingString {
    /// A pairing string for `ticket`, carrying `code` for a first pairing.
    #[must_use]
    pub const fn new(ticket: Ticket, code: Option<PairingCode>) -> Self {
        Self { ticket, code }
    }

    /// Who to dial.
    #[must_use]
    pub const fn ticket(&self) -> &Ticket {
        &self.ticket
    }

    /// The code to redeem, when this is a first pairing.
    #[must_use]
    pub const fn code(&self) -> Option<&PairingCode> {
        self.code.as_ref()
    }

    /// The ticket and the code, by value.
    #[must_use]
    pub fn into_parts(self) -> (Ticket, Option<PairingCode>) {
        (self.ticket, self.code)
    }

    /// The whole string upper-cased, for a QR code.
    ///
    /// QR alphanumeric mode encodes only upper case, and a code made from it is
    /// materially smaller and easier for a camera to read. Parsing takes the
    /// ticket case-insensitively and the code is digits, so a scan of the
    /// result parses back to this value.
    #[must_use]
    pub fn to_qr_string(&self) -> String {
        self.to_string().to_ascii_uppercase()
    }
}

impl fmt::Display for PairingString {
    /// `<ticket>` or `<ticket>-<code>`, with the ticket in its canonical
    /// lower-case form.
    ///
    /// This prints the code: it is the string a person is shown to carry to the
    /// other machine, which is its whole purpose. Do not log it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.code {
            Some(code) => write!(f, "{}{SEPARATOR}{}", self.ticket, code.0),
            None => write!(f, "{}", self.ticket),
        }
    }
}

impl fmt::Debug for PairingString {
    /// The ticket's fingerprint, and whether there is a code, never the code.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingString")
            .field("ticket", &self.ticket)
            .field("code", &self.code)
            .finish()
    }
}

impl FromStr for PairingString {
    type Err = PairingStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim_matches(|c: char| c.is_ascii_whitespace());
        if s.is_empty() {
            return Err(PairingStringError::Empty);
        }
        // The code is checked before the ticket, so a string whose code and
        // ticket are both wrong is refused for its code: the end of a paste
        // is where one stops short.
        let (ticket, code) = match s.rsplit_once(SEPARATOR) {
            Some((ticket, code)) => (ticket, Some(code.parse::<PairingCode>()?)),
            None => (s, None),
        };
        let ticket = ticket
            .parse::<Ticket>()
            .map_err(PairingStringError::Ticket)?;
        Ok(Self { ticket, code })
    }
}

/// Why a string is not a pairing string.
///
/// Three answers a person can act on: they pasted nothing, the end of the
/// paste is not a code, or the ticket is not one, in which case the ticket's
/// own error says whether to copy it again or upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PairingStringError {
    /// Nothing but whitespace.
    Empty,
    /// There is a `-`, and what follows the last one is not six ASCII digits.
    Code,
    /// The ticket half is not a ticket.
    Ticket(TicketParseError),
}

impl fmt::Display for PairingStringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => {
                f.write_str("a pairing string is a ticket, or a ticket, a '-' and a six-digit code")
            }
            Self::Code => f.write_str("the part after the last '-' should be the six-digit code"),
            // Not interpolated: the ticket's error is the source, and a caller
            // printing the chain would otherwise see it twice.
            Self::Ticket(_) => f.write_str("the part before the code is not a ticket"),
        }
    }
}

impl std::error::Error for PairingStringError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ticket(e) => Some(e),
            Self::Empty | Self::Code => None,
        }
    }
}

#[cfg(test)]
#[path = "pairing_string_tests.rs"]
mod pairing_string_tests;
