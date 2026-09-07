//! Tests for [`super`] — what a minted token is made of.
//!
//! Moved here with the functions themselves, so the properties of a token
//! *value* are asserted beside the code that produces them rather than in
//! the credential's file.

use super::*;

/// Two mints must never collide, and the value must be something a person
/// can copy off a screen and paste into a shell without quoting.
#[test]
fn a_minted_token_is_unique_and_safe_to_paste() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..64 {
        let token = mint();
        // One base32 character per five bits, so ceil(bytes * 8 / 5) — not
        // whole 5-byte groups rounded up, which over-counts whenever the
        // input is not a multiple of five.
        assert_eq!(token.len(), (MINTED_ENTROPY_BYTES * 8).div_ceil(5));
        assert!(
            token
                .chars()
                .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)),
            "unambiguous, shell-safe, header-safe: {token}"
        );
        assert!(seen.insert(token), "two mints collided");
    }
}
