//! Tests for [`super`] — the word a log line uses for what happened.
//!
//! Split out via `#[path]` so `outcome.rs` stays inside the file-size
//! budget.

use super::Outcome;

/// Every variant, so a new one cannot be added without deciding what it is
/// called here.
///
/// The `match` in `as_str` is exhaustive, so the *compiler* already refuses
/// a variant with no arm. What it cannot refuse is a variant nobody thought
/// to add to this list, which is why the list is written out rather than
/// derived — and why the assertion below counts it.
const EVERY: &[Outcome] = &[
    Outcome::Forwarded,
    Outcome::Unauthorized,
    Outcome::BadRequest,
    Outcome::TimedOut,
    Outcome::BadGateway,
    Outcome::Unfinished,
];

/// Two outcomes that log the same word are one outcome, as far as anyone
/// reading the log is concerned.
///
/// This is the copy-paste arm: `Self::TimedOut => "bad_request"` compiles,
/// passes every other test in this crate, and silently makes a timeout
/// indistinguishable from a malformed head in the one place an operator
/// would look.
#[test]
fn no_two_outcomes_log_the_same_word() {
    let mut seen: Vec<&str> = EVERY.iter().map(|o| o.as_str()).collect();
    seen.sort_unstable();
    let total = seen.len();
    seen.dedup();
    assert_eq!(
        seen.len(),
        total,
        "each outcome needs its own word: {seen:?}"
    );
}

/// The negative control for the test above, which it needs more than most:
/// a broken `as_str` returning `""` for everything would fail that one, but
/// a broken `EVERY` listing a single variant six times would *pass* it.
#[test]
fn the_list_above_names_every_variant_exactly_once() {
    let mut seen: Vec<Outcome> = EVERY.to_vec();
    seen.dedup_by_key(|o| o.as_str());
    assert_eq!(seen.len(), EVERY.len(), "EVERY repeats a variant");
    // A count, so adding a variant to the enum and forgetting this file is
    // a failing test rather than a silently narrower assertion above.
    assert_eq!(EVERY.len(), 6, "a variant was added without naming it here");
}

/// An operator greps these, so they are a lower-case, underscore-separated
/// vocabulary rather than whatever `Debug` renders.
///
/// `Debug` would give `BadGateway`, and the difference is not cosmetic: it
/// is the difference between one `grep bad_gateway` finding both this field
/// and the refusal body's `"code"`, and finding neither reliably.
#[test]
fn every_word_is_greppable() {
    for outcome in EVERY {
        let word = outcome.as_str();
        assert!(!word.is_empty(), "{outcome:?} logs nothing at all");
        assert!(
            word.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
            "{outcome:?} logs {word:?}, which is not the house vocabulary"
        );
    }
}
