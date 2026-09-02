//! CRC-32C (Castagnoli), the ticket's transcription check.
//!
//! Pure, and small enough to be worth not taking a dependency for: this is
//! the bit-serial form, twelve lines, no lookup table. The ticket is the
//! only thing in the crate that needs a checksum and it is at most a
//! kilobyte, so a table-driven implementation would trade readability for
//! speed nobody can measure.
//!
//! What it is for, and is not: it catches a mistyped character or a misread
//! QR code. It is not a signature and does not resist tampering — anyone
//! able to alter a ticket in transit can recompute this trivially. The real
//! authentication is the endpoint key in the ticket plus the bearer token
//! that never rides in one.

/// The reflected form of polynomial `0x1EDC6F41`. Reflected because the
/// algorithm shifts right, which is what makes the bit-serial loop below
/// this short.
const POLY_REFLECTED: u32 = 0x82F6_3B78;

/// Both the initial value and the final XOR, per the CRC-32C definition.
const INIT_AND_XOROUT: u32 = 0xFFFF_FFFF;

/// CRC-32C of `data`.
///
/// `const` so the published check value can be asserted at compile time
/// rather than in a test that has to be run — see below.
pub(crate) const fn crc32c(data: &[u8]) -> u32 {
    let mut crc = INIT_AND_XOROUT;
    let mut i = 0;
    // `while` rather than `for`: iterators are not available in a const fn.
    while i < data.len() {
        crc ^= data[i] as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLY_REFLECTED
            } else {
                crc >> 1
            };
            bit += 1;
        }
        i += 1;
    }
    crc ^ INIT_AND_XOROUT
}

// The published CRC-32C check value, asserted at compile time. This is the
// one number that proves the implementation is the algorithm the spec names
// rather than merely *a* CRC — every conforming implementation in every
// language agrees on it, which is exactly the property a cross-language wire
// format needs. As a `const` assertion it cannot be skipped, filtered out of
// a test run, or left unexecuted: a wrong constant fails the build.
const _: () = assert!(crc32c(b"123456789") == 0xE306_9283);

#[cfg(test)]
mod tests {
    use super::*;

    /// The compile-time assertion above already guarantees this, so the
    /// test exists to state the value where someone reading the test suite
    /// will see it, and to fail loudly rather than cryptically if the
    /// assertion is ever weakened.
    #[test]
    fn the_published_check_value_holds() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn the_empty_input_has_a_defined_checksum() {
        assert_eq!(crc32c(b""), 0);
    }

    /// A checksum that ignored ordering would be useless against exactly the
    /// corruption this exists to catch — two characters swapped in a
    /// hand-copied ticket.
    #[test]
    fn transposed_bytes_change_the_checksum() {
        assert_ne!(crc32c(b"ab"), crc32c(b"ba"));
    }

    /// The single-bit case, which is the QR misread.
    #[test]
    fn a_one_bit_difference_changes_the_checksum() {
        assert_ne!(crc32c(&[0x00]), crc32c(&[0x01]));
    }
}
