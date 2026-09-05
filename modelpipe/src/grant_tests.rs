//! Tests for [`super::Grants`] — a credential that admits once.

use std::time::Duration;

use super::*;

const CODE: &str = "483920";
const LONG: Duration = Duration::from_mins(1);

#[test]
fn a_grant_admits_exactly_once() {
    let grants = Grants::new();
    grants.add(CODE.to_owned(), LONG);
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
    grants.add(CODE.to_owned(), Duration::ZERO);
    assert_eq!(grants.count(), 0, "already past its deadline");
    assert!(!grants.consume(CODE.as_bytes()));
}

#[test]
fn a_wrong_value_consumes_nothing() {
    let grants = Grants::new();
    grants.add(CODE.to_owned(), LONG);
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
    grants.add("first".to_owned(), LONG);
    grants.add("second".to_owned(), LONG);
    assert!(grants.consume(b"second"));
    assert!(grants.consume(b"first"));
    assert_eq!(grants.count(), 0);
}

#[test]
fn the_count_reports_only_live_grants() {
    let grants = Grants::new();
    grants.add("live".to_owned(), LONG);
    grants.add("dead".to_owned(), Duration::ZERO);
    assert_eq!(grants.count(), 1);
}
