//! Making a token, and deciding whether one can be presented at all.
//!
//! Two questions about a token *value*, which are not the question
//! [`crate::credential`] answers about the token a listener *enforces*.
//! They moved here when the grace window arrived and that file reached its
//! budget: the cell, the comparison and the rotation are one responsibility
//! and this is another, so the gate picked the seam correctly.

use crate::base32;

/// Bytes of entropy in a generated token: 256 bits, which is not a number
/// anyone needs to reason about again.
const MINTED_ENTROPY_BYTES: usize = 32;

/// Whether a token is one a client could actually send.
///
/// The check is deliberately only "not empty after trimming". Anything more
/// — a byte-set rule, a minimum length — is a policy this crate has no
/// standing to impose on an embedder's existing API key. What it does have
/// standing to refuse is a value that makes the listener unusable.
pub(crate) fn presentable(token: &str) -> bool {
    !token.trim().is_empty()
}

/// A fresh token from the operating system's CSPRNG.
///
/// Base32 of 256 random bits, reusing the ticket's alphabet rather than
/// inventing a second one: it has no characters a person can confuse when
/// reading a token off a screen, it survives a shell without quoting, and it
/// is already a header-safe subset of ASCII.
pub(crate) fn mint() -> String {
    let mut bytes = [0u8; MINTED_ENTROPY_BYTES];
    // A CSPRNG that cannot produce bytes is not a condition to paper over
    // with a weaker source: serving with a guessable credential would be
    // worse than not serving.
    getrandom::fill(&mut bytes).expect("the OS CSPRNG must be available");
    base32::encode(&bytes)
}

#[cfg(test)]
#[path = "minting_tests.rs"]
mod minting_tests;
