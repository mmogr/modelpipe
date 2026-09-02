//! Tests for [`super::Credential`] — the bearer check itself.
//!
//! Split out via `#[path]` so `credential.rs` stays inside the file-size
//! budget. The `TokenPolicy` rendering tests stay inline beside that type.
//!
//! These assert the *contract* of the comparison — agrees with equality,
//! refuses every near miss — and not its timing. A timing assertion is a
//! benchmark wearing a test's clothes: flaky under load, passing on a
//! machine that happens to be quiet, and proving nothing about the
//! optimizer that will compile the release build. The constant-time
//! property comes from `subtle` being used at all, which is a code review
//! rather than a test run.

use super::*;

const TOKEN: &str = "sk-zzq-a-known-credential";

fn enforcing(token: &str) -> Credential {
    let (cell, given) = Credential::new(&TokenPolicy::Supplied(token.to_owned()));
    assert_eq!(given.as_deref(), Some(token), "Supplied echoes its input");
    cell
}

/// Offer an `Authorization` value. `None` is a request carrying no such
/// header at all, which differs from one carrying an empty value — and
/// neither is ever accepted while a credential is enforced.
fn offers(cell: &Credential, value: Option<&str>) -> bool {
    cell.admits(value.map(str::as_bytes))
}

// ── What is admitted ─────────────────────────────────────────────────────

#[test]
fn the_expected_header_is_accepted() {
    let cell = enforcing(TOKEN);
    assert!(offers(&cell, Some(&format!("Bearer {TOKEN}"))));
}

/// Serving open is the one configuration with no credential, and the check
/// still runs — it just has nothing to refuse against.
#[test]
fn serving_open_admits_everything_including_nothing() {
    let (cell, token) = Credential::new(&TokenPolicy::InsecureNoAuth);
    assert_eq!(token, None, "there is no token to report");
    assert!(offers(&cell, None));
    assert!(offers(&cell, Some("Bearer anything")));
    assert!(offers(&cell, Some("")));
}

// ── What is refused ──────────────────────────────────────────────────────

/// Every shape of a wrong credential, including the two a lenient
/// comparison waves through: a prefix, and the raw token with no scheme.
#[test]
fn every_flavour_of_missing_or_wrong_credential_is_refused() {
    let cell = enforcing(TOKEN);
    let expected = format!("Bearer {TOKEN}");
    let cases: Vec<(&str, Option<String>)> = vec![
        ("no Authorization header at all", None),
        ("an empty header", Some(String::new())),
        ("a different token", Some("Bearer sk-zzq-not-it".to_owned())),
        (
            "the right token under the wrong scheme",
            Some(format!("Basic {TOKEN}")),
        ),
        ("the token with no scheme", Some(TOKEN.to_owned())),
        (
            "a prefix of the expected header",
            Some(expected[..expected.len() - 1].to_owned()),
        ),
        (
            "the expected header plus a suffix",
            Some(format!("{expected}x")),
        ),
        ("the scheme alone", Some("Bearer ".to_owned())),
        (
            "the scheme in the wrong case",
            Some(format!("bearer {TOKEN}")),
        ),
        ("leading whitespace", Some(format!(" {expected}"))),
        ("trailing whitespace", Some(format!("{expected} "))),
    ];
    for (description, offered) in cases {
        assert!(
            !offers(&cell, offered.as_deref()),
            "{description} must be refused"
        );
    }
}

/// The failure mode a naive `starts_with` would introduce, called out
/// separately because it is the one an implementation is most likely to
/// regress into.
#[test]
fn a_prefix_never_passes() {
    let cell = enforcing(TOKEN);
    let expected = format!("Bearer {TOKEN}");
    for cut in 1..expected.len() {
        assert!(
            !offers(&cell, Some(&expected[..cut])),
            "a {cut}-byte prefix must not pass"
        );
    }
}

// ── Rotation ─────────────────────────────────────────────────────────────

/// The credential gates admission, and a replacement takes effect for the
/// next request rather than at some later point.
#[test]
fn set_refuses_the_old_credential_immediately() {
    let cell = enforcing(TOKEN);
    let old = format!("Bearer {TOKEN}");
    assert!(offers(&cell, Some(&old)));

    cell.set("sk-zzq-the-replacement");
    assert!(!offers(&cell, Some(&old)), "the old value is dead");
    assert!(
        offers(&cell, Some("Bearer sk-zzq-the-replacement")),
        "and the new one works"
    );
    assert_eq!(cell.token().as_deref(), Some("sk-zzq-the-replacement"));
}

/// Single-token by design: there is no dual-accept window where both the
/// old and the new value pass, which is what makes rolling a replacement
/// out to several clients race their reconfiguration.
#[test]
fn there_is_no_window_where_both_credentials_pass() {
    let cell = enforcing(TOKEN);
    cell.set("sk-zzq-second");
    assert!(!offers(&cell, Some(&format!("Bearer {TOKEN}"))));
    assert!(offers(&cell, Some("Bearer sk-zzq-second")));
}

/// The recovery move for a leaked generated token.
#[test]
fn rotate_mints_a_fresh_token_and_enforces_it() {
    let (cell, first) = Credential::new(&TokenPolicy::Generate);
    let first = first.expect("Generate produces a token");
    assert!(offers(&cell, Some(&format!("Bearer {first}"))));

    let second = cell.rotate();
    assert_ne!(second, first, "rotation must actually change the value");
    assert!(!offers(&cell, Some(&format!("Bearer {first}"))));
    assert!(offers(&cell, Some(&format!("Bearer {second}"))));
    assert_eq!(cell.token().as_deref(), Some(second.as_str()));
}

/// `set_token` turns authentication *on* from that call forward, which is
/// why the check is always installed rather than decided at startup.
#[test]
fn set_turns_auth_on_when_serving_open() {
    let (cell, _) = Credential::new(&TokenPolicy::InsecureNoAuth);
    assert!(offers(&cell, None), "open to begin with");

    cell.set(TOKEN);
    assert!(!offers(&cell, None), "and closed afterwards");
    assert!(offers(&cell, Some(&format!("Bearer {TOKEN}"))));
}

// ── Minting ──────────────────────────────────────────────────────────────

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

// ── Redaction ────────────────────────────────────────────────────────────

/// The same rule `Debug for TokenPolicy` follows: a credential-bearing type
/// reports its state and never its secret.
#[test]
fn debug_reports_whether_a_credential_is_enforced_and_never_which() {
    let enforced = enforcing(TOKEN);
    let rendered = format!("{enforced:?}");
    assert!(!rendered.contains(TOKEN), "the token leaked: {rendered}");
    assert!(rendered.contains("enforced"), "but the state is legible");

    let (open, _) = Credential::new(&TokenPolicy::InsecureNoAuth);
    assert!(format!("{open:?}").contains("open"));
}
