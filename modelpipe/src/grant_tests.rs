//! Tests for [`super::Grants`] — a credential that admits once.

use std::time::Duration;

use super::*;

const CODE: &str = "483920";
const LONG: Duration = Duration::from_mins(1);

#[test]
fn a_grant_admits_exactly_once() {
    let grants = Grants::new();
    grants.add(CODE.to_owned(), LONG, None);
    assert!(
        grants.consume(CODE.as_bytes()),
        "the first presentation admits"
    );
    assert!(
        !grants.consume(CODE.as_bytes()),
        "the second finds nothing to consume"
    );
}

#[test]
fn a_grant_that_was_never_used_still_dies_at_its_deadline() {
    let grants = Grants::new();
    grants.add(CODE.to_owned(), Duration::ZERO, None);
    assert_eq!(grants.count(), 0, "already past its deadline");
    assert!(!grants.consume(CODE.as_bytes()));
}

#[test]
fn a_wrong_value_consumes_nothing() {
    let grants = Grants::new();
    grants.add(CODE.to_owned(), LONG, None);
    for wrong in ["483921", "48392", "4839200", "", "Bearer 483920"] {
        assert!(
            !grants.consume(wrong.as_bytes()),
            "{wrong:?} must not admit"
        );
    }
    assert_eq!(grants.count(), 1, "and the real one is still waiting");
}

#[test]
fn two_grants_are_two_admissions() {
    let grants = Grants::new();
    grants.add("first".to_owned(), LONG, None);
    grants.add("second".to_owned(), LONG, None);
    assert!(grants.consume(b"second"));
    assert!(grants.consume(b"first"));
    assert_eq!(grants.count(), 0);
}

#[test]
fn the_count_reports_only_live_grants() {
    let grants = Grants::new();
    grants.add("live".to_owned(), LONG, None);
    grants.add("dead".to_owned(), Duration::ZERO, None);
    assert_eq!(grants.count(), 1);
}

// ── Burning ──────────────────────────────────────────────────────────────

const THREE: NonZeroU8 = NonZeroU8::new(3).expect("three is not zero");
const ONE: NonZeroU8 = NonZeroU8::new(1).expect("one is not zero");

#[test]
fn the_third_wrong_presentation_burns_a_bounded_grant() {
    let grants = Grants::new();
    grants.add(CODE.to_owned(), LONG, Some(THREE));
    assert!(!grants.consume(b"000000"));
    assert!(!grants.consume(b"000001"));
    assert_eq!(grants.count(), 1, "two wrong, and it is still waiting");
    assert!(!grants.consume(b"000002"));
    assert_eq!(grants.count(), 0, "the third wrong one burned it");
    assert!(
        !grants.consume(CODE.as_bytes()),
        "and the real code is now worth nothing"
    );
}

#[test]
fn an_unbounded_grant_survives_any_number_of_wrong_presentations() {
    let grants = Grants::new();
    grants.add(CODE.to_owned(), LONG, None);
    for wrong in 0..10 {
        assert!(!grants.consume(format!("{wrong:06}").as_bytes()));
    }
    assert_eq!(grants.count(), 1, "nothing but its deadline ends it");
    assert!(grants.consume(CODE.as_bytes()));
}

/// The edge cannot tell which grant a guess was aimed at, so it does not
/// try: one wrong value is one wrong value for every grant that counts.
#[test]
fn a_wrong_presentation_counts_against_every_bounded_grant_at_once() {
    let grants = Grants::new();
    grants.add("first".to_owned(), LONG, Some(ONE));
    grants.add("second".to_owned(), LONG, Some(ONE));
    grants.add("lasting".to_owned(), LONG, None);
    assert!(!grants.consume(b"neither"));
    assert_eq!(
        grants.count(),
        1,
        "both bounded grants burned; the unbounded one stands"
    );
    assert!(grants.consume(b"lasting"));
}

/// Spending one grant is not a wrong presentation of the others.
#[test]
fn consuming_one_grant_does_not_count_against_another() {
    let grants = Grants::new();
    grants.add("first".to_owned(), LONG, Some(ONE));
    grants.add("second".to_owned(), LONG, Some(ONE));
    assert!(grants.consume(b"first"));
    assert_eq!(grants.count(), 1, "the second is untouched");
    assert!(grants.consume(b"second"));
}
