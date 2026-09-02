//! RFC 4648 base32 without padding, decoded strictly.
//!
//! Pure, and hand-rolled rather than taken as a dependency for the same
//! reason [`crate::crc32c`] is: it is the one place in the crate that needs
//! base32, it is short, and a non-Rust implementer reading the ticket format
//! can read this as pseudocode for what their own decoder has to reject.
//!
//! "Strictly" is the whole point of the module. A permissive base32 decoder
//! accepts several distinct strings for one byte sequence, which would make
//! ticket equality a question about spelling rather than about identity. The
//! three ways that happens are all refused here: a character outside the
//! alphabet, a character count that no whole number of bytes can produce,
//! and non-zero bits left over in the final partial group.
//!
//! Case is *not* this module's business. The ticket format is
//! case-insensitive over the whole string, so a caller upper-cases before
//! decoding; what this module guarantees is that within one case, exactly
//! one string decodes to any given byte sequence.

/// RFC 4648 §6, uppercase. Digits `0`, `1`, `8` and `9` are absent on
/// purpose — they are the ones a human confuses with `O`, `I`, `B` and `g`
/// when reading a ticket aloud or off a screen.
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Bits carried by one base32 character.
const BITS_PER_CHAR: u32 = 5;

/// Bits in a byte. Named so the arithmetic below reads as what it is rather
/// than as a magic 8.
const BITS_PER_BYTE: u32 = 8;

/// Encode `data` as base32 without padding, in the alphabet's own case.
///
/// The ticket's string form lower-cases the whole result afterwards; doing
/// it there rather than here keeps this module a faithful RFC 4648 encoder.
pub(crate) fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        acc = (acc << BITS_PER_BYTE) | u32::from(byte);
        bits += BITS_PER_BYTE;
        while bits >= BITS_PER_CHAR {
            bits -= BITS_PER_CHAR;
            let index = (acc >> bits) & 0x1F;
            out.push(ALPHABET[index as usize] as char);
        }
    }
    if bits > 0 {
        // The final partial group is padded with zero bits on the right,
        // which is what the decoder below insists on finding.
        let index = (acc << (BITS_PER_CHAR - bits)) & 0x1F;
        out.push(ALPHABET[index as usize] as char);
    }
    out
}

/// Decode `s` strictly. `None` for anything that is not the unique encoding
/// of some byte sequence.
///
/// Expects the alphabet's own case; the caller has already folded. Returns
/// `None` rather than an error type because the caller has exactly one
/// verdict for every failure here — the ticket format routes all of them to
/// its malformed case — and inventing a richer error would be discarded at
/// the only call site.
pub(crate) fn decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;

    for &c in bytes {
        let value = decode_char(c)?;
        acc = (acc << BITS_PER_CHAR) | u32::from(value);
        bits += BITS_PER_CHAR;
        if bits >= BITS_PER_BYTE {
            bits -= BITS_PER_BYTE;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }

    // Two refusals in one check, and they are different failures wearing the
    // same shape.
    //
    // Five or more leftover bits mean an impossible character count — a
    // length whose modulo 8 is 1, 3 or 6, which no byte sequence encodes to.
    // Fewer than five leftover bits are legitimate padding, but they must be
    // zero: a decoder that ignored them would accept up to sixteen distinct
    // strings for one byte sequence, and two of them naming one ticket is
    // precisely what this module exists to prevent.
    if bits >= BITS_PER_CHAR {
        return None;
    }
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }

    Some(out)
}

/// The alphabet's inverse, by search rather than by table. Thirty-two
/// comparisons on a string that is at most 1643 characters, once per
/// pairing — a lookup table would be more code for time nobody spends.
fn decode_char(c: u8) -> Option<u8> {
    ALPHABET
        .iter()
        .position(|&a| a == c)
        .and_then(|i| u8::try_from(i).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 §10's own test vectors, which is the point of citing a
    /// standard rather than inventing an encoding.
    #[test]
    fn the_rfc_4648_vectors_round_trip() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(encode(plain.as_bytes()), encoded, "encoding {plain:?}");
            assert_eq!(
                decode(encoded).as_deref(),
                Some(plain.as_bytes()),
                "decoding {encoded:?}"
            );
        }
    }

    #[test]
    fn every_byte_value_survives_a_round_trip() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&all)), Some(all));
    }

    /// The lengths modulo 8 that no byte sequence can produce. A decoder
    /// that accepted them would be inventing bytes.
    #[test]
    fn an_impossible_character_count_is_rejected() {
        for s in ["A", "AAA", "AAAAAA", "MZXW6YTBOIA"] {
            assert_eq!(decode(s), None, "{s} encodes no whole number of bytes");
        }
    }

    /// The subtle one, and the reason this module is hand-written rather
    /// than delegated: `MZ` and `MY` differ only in bits that carry no byte,
    /// so a permissive decoder yields "f" for both and two strings name one
    /// ticket.
    #[test]
    fn non_zero_bits_in_the_final_group_are_rejected() {
        assert_eq!(decode("MY").as_deref(), Some(&b"f"[..]));
        for s in ["MZ", "M6", "MZXW6YTBOJ"] {
            assert_eq!(decode(s), None, "{s} has rubbish in its final group");
        }
    }

    #[test]
    fn characters_outside_the_alphabet_are_rejected() {
        // `0`, `1`, `8` and `9` are the deliberate omissions; lowercase is
        // the caller's job to fold before arriving here.
        for s in [
            "MZXW6YT0", "MZXW6YT1", "MZXW6YT8", "MZXW6YT9", "mzxw6ytb", "MZXW-YTB",
        ] {
            assert_eq!(decode(s), None, "{s} is not in the alphabet");
        }
    }

    /// Encoding never emits padding, so a padded string is not something
    /// this codec produces and must not be something it accepts.
    #[test]
    fn padding_is_rejected_rather_than_tolerated() {
        assert!(!encode(b"f").contains('='));
        assert_eq!(decode("MY======"), None);
    }
}
