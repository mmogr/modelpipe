//! Tests for [`super`] — the word a log line uses for what happened.
//!
//! Split out via `#[path]` so `outcome.rs` stays inside the file-size
//! budget.

use super::Outcome;

/// Every variant, listed by hand because nothing derives it.
///
/// The `match` in `as_str` is exhaustive, so the *compiler* already refuses
/// a variant with no arm there. What no compiler can check is whether this
/// list is complete — so the check is made a compile error instead, by
/// `a_new_variant_cannot_be_added_without_visiting_this_file` below.
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
fn the_list_above_repeats_no_variant() {
    let mut seen: Vec<Outcome> = EVERY.to_vec();
    seen.dedup_by_key(|o| o.as_str());
    assert_eq!(seen.len(), EVERY.len(), "EVERY repeats a variant");
}

/// Adding a variant to [`Outcome`] must stop this file compiling.
///
/// The match below is exhaustive with no wildcard arm, so a new variant is
/// a compile error *here* — which is the event that sends whoever added it
/// to `EVERY` above. That is the only mechanism available: nothing derives
/// the variant list, so no assertion executed at run time can notice a
/// variant missing from a hand-written const.
///
/// A length assertion cannot do this job, and the one that used to sit
/// here was worse than useless. `assert_eq!(EVERY.len(), 6)` is a property
/// of the literal rather than of the enum: it stayed silent in exactly the
/// case its message described — a variant added, `EVERY` left stale — and
/// fired only on somebody correctly extending the list. It alarmed on the
/// right state and passed on the wrong one.
#[test]
fn a_new_variant_cannot_be_added_without_visiting_this_file() {
    for outcome in EVERY {
        // No wildcard arm, deliberately. This is the whole test.
        match outcome {
            Outcome::Forwarded
            | Outcome::Unauthorized
            | Outcome::BadRequest
            | Outcome::TimedOut
            | Outcome::BadGateway
            | Outcome::Unfinished => {}
        }
    }
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
