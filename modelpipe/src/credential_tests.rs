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
use crate::ServeError;

const TOKEN: &str = "sk-zzq-a-known-credential";

fn enforcing(token: &str) -> Credential {
    let (cell, given) =
        Credential::new(&TokenPolicy::Supplied(token.to_owned())).expect("a usable token");
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
    let (cell, token) = Credential::new(&TokenPolicy::InsecureNoAuth).expect("a usable policy");
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
            "a scheme that only looks like the right one",
            Some(format!("Bearerx {TOKEN}")),
        ),
        (
            "the right case, the wrong token",
            Some("bearer sk-zzq-not-it".to_owned()),
        ),
        (
            "two spaces after the scheme",
            Some(format!("Bearer  {TOKEN}")),
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

    cell.set("sk-zzq-the-replacement".to_owned());
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
    cell.set("sk-zzq-second".to_owned());
    assert!(!offers(&cell, Some(&format!("Bearer {TOKEN}"))));
    assert!(offers(&cell, Some("Bearer sk-zzq-second")));
}

/// The recovery move for a leaked generated token.
#[test]
fn rotate_mints_a_fresh_token_and_enforces_it() {
    let (cell, first) = Credential::new(&TokenPolicy::Generate).expect("a usable policy");
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
    let (cell, _) = Credential::new(&TokenPolicy::InsecureNoAuth).expect("a usable policy");
    assert!(offers(&cell, None), "open to begin with");

    cell.set(TOKEN.to_owned());
    assert!(!offers(&cell, None), "and closed afterwards");
    assert!(offers(&cell, Some(&format!("Bearer {TOKEN}"))));
}

// ── Grants ───────────────────────────────────────────────────────────────

const CODE: &str = "483920";
const LONG: std::time::Duration = std::time::Duration::from_mins(1);

/// A grant is a credential that admits once: the second presentation of
/// the same value is a plain wrong token.
#[test]
fn a_grant_admits_one_request_and_then_is_a_wrong_token() {
    let cell = enforcing(TOKEN);
    assert!(
        cell.grant(CODE.to_owned(), LONG),
        "a presentable code takes"
    );
    let as_bearer = format!("Bearer {CODE}");
    assert!(
        offers(&cell, Some(&as_bearer)),
        "the first presentation admits"
    );
    assert!(
        !offers(&cell, Some(&as_bearer)),
        "the second is refused like any wrong token"
    );
}

/// Granting changes nothing about the token: it still admits, it is still
/// what the handle reports, and the grant is not it.
#[test]
fn a_grant_leaves_the_enforced_token_untouched() {
    let cell = enforcing(TOKEN);
    cell.grant(CODE.to_owned(), LONG);
    assert!(offers(&cell, Some(&format!("Bearer {TOKEN}"))));
    assert_eq!(cell.token().as_deref(), Some(TOKEN));
    assert!(
        offers(&cell, Some(&format!("Bearer {CODE}"))),
        "and the grant is still unspent — the token did not consume it"
    );
}

/// The grant follows the scheme rules the token follows: it is a bearer
/// credential, not a magic string that admits from anywhere in the header.
#[test]
fn a_grant_is_presented_as_a_bearer_or_not_at_all() {
    let cell = enforcing(TOKEN);
    cell.grant(CODE.to_owned(), LONG);
    assert!(!offers(&cell, Some(CODE)), "no scheme");
    assert!(
        !offers(&cell, Some(&format!("Basic {CODE}"))),
        "wrong scheme"
    );
    assert!(
        offers(&cell, Some(&format!("bearer {CODE}"))),
        "the scheme is case-insensitive"
    );
}

/// An unused grant dies at its deadline rather than lingering as a
/// standing credential nobody remembers issuing.
#[test]
fn an_unused_grant_expires() {
    let cell = enforcing(TOKEN);
    cell.grant(CODE.to_owned(), std::time::Duration::ZERO);
    assert!(!offers(&cell, Some(&format!("Bearer {CODE}"))));
}

/// A rotation neither spends nor extends a grant: the two are independent
/// credentials with independent lifetimes.
#[test]
fn rotating_the_token_does_not_disturb_a_live_grant() {
    let cell = enforcing(TOKEN);
    cell.grant(CODE.to_owned(), LONG);
    cell.set("sk-zzq-the-replacement".to_owned());
    assert!(offers(&cell, Some(&format!("Bearer {CODE}"))));
}

/// The value `set` refuses, `grant` refuses, and for the same reason.
#[test]
fn an_unpresentable_grant_is_refused() {
    let cell = enforcing(TOKEN);
    for blank in ["", " ", "\t\n"] {
        assert!(
            !cell.grant(blank.to_owned(), LONG),
            "{blank:?} must not become a grant"
        );
    }
}

/// Grants are counted in `Debug`, never shown.
#[test]
fn debug_counts_grants_and_never_shows_one() {
    let cell = enforcing(TOKEN);
    cell.grant(CODE.to_owned(), LONG);
    let rendered = format!("{cell:?}");
    assert!(!rendered.contains(CODE), "the grant leaked: {rendered}");
    assert!(
        rendered.contains("grants: 1"),
        "but the count is legible: {rendered}"
    );
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

    let (open, _) = Credential::new(&TokenPolicy::InsecureNoAuth).expect("a usable policy");
    assert!(format!("{open:?}").contains("open"));
}

// ── A credential nothing can present ─────────────────────────────────────

/// Refused at construction, not enforced.
///
/// `"Bearer "` with a trailing space is a header value no conforming client
/// can produce: HTTP parsers trim trailing whitespace, so what arrives is
/// `"Bearer"` and never matches. Enforcing it fails closed, which is the
/// safe direction and the worst version of it — the listener starts,
/// reports the token it was handed, and refuses every request afterwards
/// with nothing to say why.
#[test]
fn a_token_no_client_could_send_is_refused_rather_than_enforced() {
    for empty in ["", " ", "\t", "\n", "  \r\n "] {
        assert!(
            matches!(
                Credential::new(&TokenPolicy::Supplied(empty.to_owned())),
                Err(ServeError::InvalidToken)
            ),
            "{empty:?} must not become a credential"
        );
    }
}

/// The refusal is narrow. A token that merely *contains* whitespace, or is
/// short, is the embedder's business — this crate has no standing to impose
/// a shape on an API key it did not mint.
#[test]
fn an_unusual_but_presentable_token_is_still_accepted() {
    for odd in ["x", " padded ", "sk-with spaces", "🔑"] {
        let (cell, given) = Credential::new(&TokenPolicy::Supplied(odd.to_owned()))
            .expect("presentable, however odd");
        assert_eq!(given.as_deref(), Some(odd));
        assert!(offers(&cell, Some(&format!("Bearer {odd}"))));
    }
}

/// A rotation to an unpresentable value keeps the credential already in
/// force. Installing it would take a working listener down to one that
/// answers nothing, which is not a rotation — it is an outage.
#[test]
fn setting_an_unpresentable_token_changes_nothing() {
    let cell = enforcing(TOKEN);
    assert!(
        !cell.set(String::new()),
        "the caller is told it did not take"
    );
    assert!(
        offers(&cell, Some(&format!("Bearer {TOKEN}"))),
        "the credential in force must survive a refused rotation"
    );
}

/// RFC 9110 §11.1 makes the authentication scheme a token, and token
/// comparison is case-insensitive. This edge required `Bearer` exactly.
///
/// Measured before the fix, against the real binary over a live pipe:
/// `Bearer` returned 200 and `bearer`, `BEARER` and `BeArEr` all returned
/// 401 — with the correct key, and with nothing in the response pointing at
/// the capitalisation. That is the least actionable 401 available.
#[test]
fn the_scheme_is_matched_without_regard_to_case() {
    let cell = enforcing(TOKEN);
    for scheme in ["Bearer", "bearer", "BEARER", "BeArEr", "bEARER"] {
        assert!(
            offers(&cell, Some(&format!("{scheme} {TOKEN}"))),
            "{scheme} is the same scheme"
        );
    }
}

/// The negative control for the test above, and the property that makes it
/// safe: the *token* is still compared exactly, and still in constant time.
///
/// Without this, "case-insensitive" could have been applied to the whole
/// header — which would accept a token in any casing and turn a 256-bit
/// credential into a much smaller one.
#[test]
fn the_token_is_still_matched_exactly() {
    let cell = enforcing(TOKEN);
    let flipped: String = TOKEN
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    assert_ne!(flipped, TOKEN, "the sentinel must have letters to flip");
    assert!(
        !offers(&cell, Some(&format!("Bearer {flipped}"))),
        "the token is not a token comparison — case matters in the credential"
    );
    // And the scheme leniency does not extend past the single space.
    assert!(!offers(&cell, Some(&format!("bearer{TOKEN}"))));
    assert!(!offers(&cell, Some(&format!("bearer\t{TOKEN}"))));
}
