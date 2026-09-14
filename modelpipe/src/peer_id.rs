//! An endpoint's identity, as a value an embedder can keep.
//!
//! A fingerprint names a peer for a person to read: twelve hex characters of
//! a thirty-two byte key, enough to tell two devices apart by eye. A serve
//! side that records which machine paired, or admits a credential from one
//! machine only, needs the whole key, and this is it.

use std::fmt;
use std::str::FromStr;

use crate::fingerprint;

/// Bytes in an endpoint id, which is an ed25519 public key.
const ID_BYTES: usize = 32;

/// Who an endpoint is: its public key.
///
/// What a connect side dials out as, and what a serve side sees on every
/// connection it accepts. Not a secret: a serve side's is in every ticket it
/// hands out.
///
/// Prints as sixty-four lower-case hex characters, and parses from them in
/// either case. The first twelve are its [`fingerprint`](Self::fingerprint),
/// the form log lines and the `X-Modelpipe-Peer` header carry, so a
/// fingerprint someone wrote down can be checked against a stored id by eye.
/// `Debug` shows the fingerprint alone, to keep log lines short.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId([u8; ID_BYTES]);

impl PeerId {
    /// The peer id whose public key is `bytes`.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// The public key's bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; ID_BYTES] {
        self.0
    }

    /// The twelve-character form every log line and header uses.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        fingerprint::of(&self.0)
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PeerId").field(&self.fingerprint()).finish()
    }
}

impl FromStr for PeerId {
    type Err = PeerIdParseError;

    /// Exactly sixty-four ASCII hex digits, in either case, and nothing else:
    /// no prefix, no separator and no surrounding space.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let digits = s.as_bytes();
        if digits.len() != ID_BYTES * 2 {
            return Err(PeerIdParseError(()));
        }
        let mut bytes = [0u8; ID_BYTES];
        for (byte, pair) in bytes.iter_mut().zip(digits.chunks_exact(2)) {
            *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(Self(bytes))
    }
}

/// One hex digit's value.
const fn nibble(digit: u8) -> Result<u8, PeerIdParseError> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        b'A'..=b'F' => Ok(digit - b'A' + 10),
        _ => Err(PeerIdParseError(())),
    }
}

/// Why a string is not a [`PeerId`]: it is not sixty-four hex characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdParseError(());

impl fmt::Display for PeerIdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a peer id is sixty-four hex characters")
    }
}

impl std::error::Error for PeerIdParseError {}

// As its printed form, the way a ticket is carried: one string a person can
// also read, and the parse's own error when it is not one.
#[cfg(feature = "serde")]
impl serde::Serialize for PeerId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PeerId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[path = "peer_id_tests.rs"]
mod peer_id_tests;
