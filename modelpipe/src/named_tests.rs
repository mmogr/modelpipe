//! Tests for [`super::Named`] — one standing credential per name.

use super::*;

const LAPTOP: &str = "sk-zzq-the-laptops-key";
const PHONE: &str = "sk-zzq-the-phones-key";

/// An endpoint none of the tokens `holding` adds is pinned to.
const ANYONE: PeerId = PeerId::from_bytes([7; 32]);

/// The endpoint a pinned token below is pinned to.
const DESK: PeerId = PeerId::from_bytes([1; 32]);

/// The name `presented` admits under from an endpoint nothing is pinned to.
fn admitted(named: &Named, presented: &[u8]) -> Option<Arc<str>> {
    match named.admits(presented, ANYONE) {
        NamedMatch::Admits(name) => Some(name),
        NamedMatch::PinnedElsewhere | NamedMatch::Unknown => None,
    }
}

fn holding() -> Named {
    let named = Named::new();
    named
        .add("laptop", LAPTOP.to_owned(), None)
        .expect("a valid name and token");
    named
        .add("phone", PHONE.to_owned(), None)
        .expect("a valid name and token");
    named
}

// ── What admits ──────────────────────────────────────────────────────────

#[test]
fn each_token_admits_under_its_own_name() {
    let named = holding();
    assert_eq!(
        admitted(&named, LAPTOP.as_bytes()).as_deref(),
        Some("laptop")
    );
    assert_eq!(admitted(&named, PHONE.as_bytes()).as_deref(), Some("phone"));
    assert_eq!(named.count(), 2);
}

#[test]
fn a_wrong_value_names_nobody() {
    let named = holding();
    for wrong in [
        "",
        "sk-zzq-the-laptops-ke",
        "sk-zzq-the-laptops-keyy",
        "laptop",
    ] {
        assert!(
            admitted(&named, wrong.as_bytes()).is_none(),
            "{wrong:?} must not admit"
        );
    }
}

/// Admission is not consumption: a named token is a standing credential
/// and admits as often as it is presented.
#[test]
fn a_named_token_admits_every_time() {
    let named = holding();
    for _ in 0..3 {
        assert!(admitted(&named, LAPTOP.as_bytes()).is_some());
    }
}

// ── Removal ──────────────────────────────────────────────────────────────

/// The whole point: one device goes, the other is untouched.
#[test]
fn removing_one_name_refuses_only_that_token() {
    let named = holding();
    assert!(named.remove("phone"));
    assert!(
        admitted(&named, PHONE.as_bytes()).is_none(),
        "the phone is out"
    );
    assert_eq!(
        admitted(&named, LAPTOP.as_bytes()).as_deref(),
        Some("laptop"),
        "the laptop never noticed"
    );
    assert_eq!(named.names(), ["laptop"]);
}

#[test]
fn removing_a_name_nothing_is_held_under_is_not_an_error() {
    let named = holding();
    assert!(!named.remove("tablet"));
    assert_eq!(named.count(), 2, "and nothing else went with it");
}

// ── What add refuses ─────────────────────────────────────────────────────

#[test]
fn a_name_already_in_use_is_refused_rather_than_replaced() {
    let named = holding();
    assert_eq!(
        named.add("laptop", "sk-zzq-another-key".to_owned(), None),
        Err(AddRefused::NameTaken)
    );
    assert_eq!(
        admitted(&named, LAPTOP.as_bytes()).as_deref(),
        Some("laptop"),
        "the original still admits; nothing was rotated by accident"
    );
}

#[test]
fn a_token_already_held_under_another_name_is_refused() {
    let named = holding();
    assert_eq!(
        named.add("tablet", LAPTOP.to_owned(), None),
        Err(AddRefused::TokenTaken)
    );
    assert_eq!(named.names(), ["laptop", "phone"]);
}

#[test]
fn a_blank_token_is_refused_for_the_reason_the_primary_refuses_it() {
    let named = Named::new();
    for blank in ["", "   ", "\t"] {
        assert_eq!(
            named.add("tablet", blank.to_owned(), None),
            Err(AddRefused::UnpresentableToken)
        );
    }
    assert_eq!(named.count(), 0);
}

/// A name goes into a header value and a log line, so it is restricted to
/// what both carry unescaped.
#[test]
fn a_name_is_an_identifier_not_a_label() {
    for good in [
        "laptop",
        "c4d1a3f9b2e7",
        "matts-phone",
        "v2.iphone_15",
        &"a".repeat(64),
    ] {
        assert!(valid_name(good), "{good:?} should be accepted");
    }
    for bad in [
        "",
        " ",
        "Matt's iPhone",
        "laptop\r\nX-Injected: yes",
        "laptop:home",
        "café",
        &"a".repeat(65),
    ] {
        assert!(!valid_name(bad), "{bad:?} should be refused");
        assert_eq!(
            Named::new().add(bad, LAPTOP.to_owned(), None),
            Err(AddRefused::InvalidName)
        );
    }
}

// ── Pinned to one endpoint ───────────────────────────────────────────────

#[test]
fn a_pinned_token_admits_from_its_endpoint_and_no_other() {
    let named = Named::new();
    named
        .add("laptop", LAPTOP.to_owned(), Some(DESK))
        .expect("a valid name and token");
    assert_eq!(
        named.admits(LAPTOP.as_bytes(), DESK),
        NamedMatch::Admits(Arc::from("laptop"))
    );
    assert_eq!(
        named.admits(LAPTOP.as_bytes(), ANYONE),
        NamedMatch::PinnedElsewhere
    );
    assert_eq!(named.admits(PHONE.as_bytes(), DESK), NamedMatch::Unknown);
}

#[test]
fn an_unpinned_token_admits_from_any_endpoint() {
    let named = holding();
    for from in [DESK, ANYONE] {
        assert_eq!(
            named.admits(LAPTOP.as_bytes(), from),
            NamedMatch::Admits(Arc::from("laptop"))
        );
    }
}
