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
    cell.admits(value.map(str::as_bytes)).is_some()
}

/// Which credential admitted, for the tests that are about that.
fn admitted_by(cell: &Credential, value: &str) -> Option<Admitted> {
    cell.admits(Some(value.as_bytes()))
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

/// A plain `set` leaves no dual-accept window where both the old and the new
/// value pass, which is what makes rolling a replacement out to several
/// clients race their reconfiguration. `set_with_grace` is the form that does
/// open one, and `superseded_tests.rs` is where that is asserted — this test
/// is about the setter that deliberately does not.
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
        cell.grant(CODE.to_owned(), LONG, None),
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
    cell.grant(CODE.to_owned(), LONG, None);
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
    cell.grant(CODE.to_owned(), LONG, None);
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
    cell.grant(CODE.to_owned(), std::time::Duration::ZERO, None);
    assert!(!offers(&cell, Some(&format!("Bearer {CODE}"))));
}

/// A rotation neither spends nor extends a grant: the two are independent
/// credentials with independent lifetimes.
#[test]
fn rotating_the_token_does_not_disturb_a_live_grant() {
    let cell = enforcing(TOKEN);
    cell.grant(CODE.to_owned(), LONG, None);
    cell.set("sk-zzq-the-replacement".to_owned());
    assert!(offers(&cell, Some(&format!("Bearer {CODE}"))));
}

/// The value `set` refuses, `grant` refuses, and for the same reason.
#[test]
fn an_unpresentable_grant_is_refused() {
    let cell = enforcing(TOKEN);
    for blank in ["", " ", "\t\n"] {
        assert!(
            !cell.grant(blank.to_owned(), LONG, None),
            "{blank:?} must not become a grant"
        );
    }
}

/// Grants are counted in `Debug`, never shown.
#[test]
fn debug_counts_grants_and_never_shows_one() {
    let cell = enforcing(TOKEN);
    cell.grant(CODE.to_owned(), LONG, None);
    let rendered = format!("{cell:?}");
    assert!(!rendered.contains(CODE), "the grant leaked: {rendered}");
    assert!(
        rendered.contains("grants: 1"),
        "but the count is legible: {rendered}"
    );
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

// ── The grace window ─────────────────────────────────────────────────────
//
// `Superseded` is exercised on its own in `superseded_tests.rs`; what these
// assert is the *wiring* — that the key a graced rotation replaces reaches
// the comparison, that a plain rotation still leaves no window at all, and
// that the two new credentials do not interfere with the two that were
// already here.

const NEXT: &str = "sk-zzq-the-replacement";

/// The whole point: after a graced rotation the key it replaced still
/// admits, so a machine that has not been reconfigured yet is not refused
/// at the edge.
#[test]
fn the_key_a_graced_rotation_replaced_keeps_admitting() {
    let cell = enforcing(TOKEN);
    assert!(cell.set_with_grace(NEXT.to_owned(), LONG));

    assert!(
        offers(&cell, Some(&format!("Bearer {TOKEN}"))),
        "the replaced key must go on admitting inside the window"
    );
    assert!(
        offers(&cell, Some(&format!("Bearer {NEXT}"))),
        "and so must the new one"
    );
    assert_eq!(
        cell.token().as_deref(),
        Some(NEXT),
        "while the enforced token is unambiguously the new one"
    );
}

/// Not a grant. Several machines are holding the replaced key, so the
/// second one to reconnect must not be refused for being second.
#[test]
fn the_replaced_key_admits_every_machine_not_just_the_first() {
    let cell = enforcing(TOKEN);
    cell.set_with_grace(NEXT.to_owned(), LONG);
    let as_bearer = format!("Bearer {TOKEN}");
    for machine in 1..=4 {
        assert!(
            offers(&cell, Some(&as_bearer)),
            "machine {machine} was refused; the window is being spent like a grant"
        );
    }
}

/// The window closes on its own. Without this the method would be a way to
/// quietly accumulate standing credentials.
///
/// A real deadline rather than `ZERO`, so this pins the *expiry* and not
/// merely the refusal to hold a zero-width window.
#[test]
fn the_replaced_key_stops_admitting_once_the_grace_passes() {
    let cell = enforcing(TOKEN);
    cell.set_with_grace(NEXT.to_owned(), std::time::Duration::from_millis(1));
    std::thread::sleep(std::time::Duration::from_millis(20));
    assert!(
        !offers(&cell, Some(&format!("Bearer {TOKEN}"))),
        "the window closed and the replaced key is still admitting"
    );
    assert!(offers(&cell, Some(&format!("Bearer {NEXT}"))));
}

/// A rotation asked for no window at all leaves none, and does not park an
/// already-expired key waiting for something to sweep it.
#[test]
fn a_graced_rotation_with_no_grace_is_exactly_a_plain_one() {
    let cell = enforcing(TOKEN);
    cell.set_with_grace(NEXT.to_owned(), std::time::Duration::ZERO);
    assert!(!offers(&cell, Some(&format!("Bearer {TOKEN}"))));
    assert!(offers(&cell, Some(&format!("Bearer {NEXT}"))));
    let rendered = format!("{cell:?}");
    assert!(
        rendered.contains("grace: false"),
        "a zero window must not read as open: {rendered}"
    );
}

/// A `Duration` the clock cannot add fails closed instead of panicking
/// inside the enforced write lock — which would abandon the rotation and
/// poison the lock every later request reads through.
#[test]
fn an_absurd_grace_does_not_panic_or_leave_a_standing_second_key() {
    let cell = enforcing(TOKEN);
    assert!(cell.set_with_grace(NEXT.to_owned(), std::time::Duration::MAX));
    assert!(
        !offers(&cell, Some(&format!("Bearer {TOKEN}"))),
        "Duration::MAX must not become a permanent second credential"
    );
    assert!(
        offers(&cell, Some(&format!("Bearer {NEXT}"))),
        "and the rotation itself must still have happened"
    );
    assert_eq!(cell.token().as_deref(), Some(NEXT));
}

/// `set` is untouched by any of this: it leaves no window, which is the
/// contract every existing caller was written against.
#[test]
fn a_plain_rotation_still_leaves_no_window() {
    let cell = enforcing(TOKEN);
    cell.set(NEXT.to_owned());
    assert!(!offers(&cell, Some(&format!("Bearer {TOKEN}"))));
}

/// And `set` *shuts* an open one, which is how an embedder ends an overlap
/// early — and why calling it mid-window cannot leave a key admitting that
/// its own doc promises is dead.
#[test]
fn a_plain_rotation_shuts_an_open_window() {
    let cell = enforcing(TOKEN);
    cell.set_with_grace(NEXT.to_owned(), LONG);
    assert!(offers(&cell, Some(&format!("Bearer {TOKEN}"))));

    cell.set("sk-zzq-the-third".to_owned());
    assert!(
        !offers(&cell, Some(&format!("Bearer {TOKEN}"))),
        "the window was open and a plain rotation must close it"
    );
    assert!(
        !offers(&cell, Some(&format!("Bearer {NEXT}"))),
        "and the key it just replaced gets no window either"
    );
    assert!(offers(&cell, Some("Bearer sk-zzq-the-third")));
}

/// Windows do not chain: at most two values admit, ever.
#[test]
fn a_second_graced_rotation_retires_the_first_replaced_key() {
    let cell = enforcing(TOKEN);
    cell.set_with_grace(NEXT.to_owned(), LONG);
    cell.set_with_grace("sk-zzq-the-third".to_owned(), LONG);

    assert!(
        !offers(&cell, Some(&format!("Bearer {TOKEN}"))),
        "a key two rotations behind must not survive on the strength of the first window"
    );
    assert!(
        offers(&cell, Some(&format!("Bearer {NEXT}"))),
        "the key the newest rotation replaced is the one that is held"
    );
    assert!(offers(&cell, Some("Bearer sk-zzq-the-third")));
}

/// A refused rotation must not open a window either — an embedder told its
/// rotation failed would otherwise still be running an overlap it never
/// asked for.
#[test]
fn an_unpresentable_graced_rotation_changes_nothing() {
    let cell = enforcing(TOKEN);
    for blank in ["", " ", "\t\n"] {
        assert!(
            !cell.set_with_grace(blank.to_owned(), LONG),
            "{blank:?} must not become the enforced token"
        );
    }
    assert_eq!(cell.token().as_deref(), Some(TOKEN), "nothing was replaced");
    assert!(offers(&cell, Some(&format!("Bearer {TOKEN}"))));
    let rendered = format!("{cell:?}");
    assert!(
        rendered.contains("grace: false"),
        "and no window was opened: {rendered}"
    );
}

/// A refused rotation leaves an *open* window exactly as it was — neither
/// shut nor extended. The behaviour is right (a rotation that did not
/// happen must not change what admits) and it is why the public method's
/// `# Errors` section has to say so: mid-window, "nothing changed" and "no
/// old key is admitting" are different claims, and only the first is true.
#[test]
fn a_refused_rotation_neither_shuts_nor_extends_an_open_window() {
    let cell = enforcing(TOKEN);
    cell.set_with_grace(NEXT.to_owned(), LONG);
    assert!(offers(&cell, Some(&format!("Bearer {TOKEN}"))));

    assert!(!cell.set_with_grace(String::new(), LONG), "refused");
    assert!(
        offers(&cell, Some(&format!("Bearer {TOKEN}"))),
        "the window a refused call did not touch must still be open"
    );
    assert_eq!(cell.token().as_deref(), Some(NEXT), "and nothing rotated");
}

/// Serving open has no key to leave behind, so a graced rotation onto one
/// is exactly `set`: auth turns on, and nothing is grandfathered.
#[test]
fn a_graced_rotation_onto_an_open_listener_holds_nothing() {
    let (cell, _) = Credential::new(&TokenPolicy::InsecureNoAuth).expect("a usable policy");
    assert!(offers(&cell, None), "open to begin with");

    assert!(cell.set_with_grace(TOKEN.to_owned(), LONG));
    assert!(!offers(&cell, None), "and closed afterwards");
    assert!(!offers(&cell, Some("Bearer anything")));
    assert!(offers(&cell, Some(&format!("Bearer {TOKEN}"))));
}

/// The window is consulted before grants, and that order is the whole
/// reason this test exists: a value that is *both* an open window's key and
/// a live grant must be admitted by the window, which spends nothing,
/// leaving the grant's one admission still there to spend afterwards.
#[test]
fn a_key_the_window_already_admits_does_not_spend_a_grant() {
    let cell = enforcing(TOKEN);
    assert!(
        cell.grant(TOKEN.to_owned(), LONG, None),
        "the same value, granted"
    );
    cell.set_with_grace(NEXT.to_owned(), LONG);

    let as_bearer = format!("Bearer {TOKEN}");
    assert!(offers(&cell, Some(&as_bearer)), "admitted by the window");

    // Shut the window. If the presentation above had been answered by the
    // grant instead, there is nothing left here.
    cell.set("sk-zzq-the-third".to_owned());
    assert!(
        offers(&cell, Some(&as_bearer)),
        "the grant was spent by a request the window should have answered"
    );
    assert!(
        !offers(&cell, Some(&as_bearer)),
        "and now it really is spent"
    );
}

/// A graced rotation neither spends nor extends a grant, the promise a
/// plain rotation already makes.
#[test]
fn a_graced_rotation_does_not_disturb_a_live_grant() {
    let cell = enforcing(TOKEN);
    cell.grant(CODE.to_owned(), LONG, None);
    cell.set_with_grace(NEXT.to_owned(), LONG);
    assert!(offers(&cell, Some(&format!("Bearer {CODE}"))));
}

/// An open window is reported as open and never as the key it holds — the
/// rule the token and the grants already follow.
#[test]
fn debug_says_a_window_is_open_and_never_which_key() {
    let cell = enforcing(TOKEN);
    let shut = format!("{cell:?}");
    assert!(shut.contains("grace: false"), "shut to begin with: {shut}");

    cell.set_with_grace(NEXT.to_owned(), LONG);
    let open = format!("{cell:?}");
    assert!(
        !open.contains(TOKEN),
        "the superseded key leaked into Debug: {open}"
    );
    assert!(
        open.contains("grace: true"),
        "but the state is legible: {open}"
    );
}

// ── A grant that burns ───────────────────────────────────────────────────

const THREE: NonZeroU8 = NonZeroU8::new(3).expect("three is not zero");

/// The whole point of the bounded form: three wrong bearers through the
/// edge and the code is dead, without a byte reaching the handshake route
/// that used to be the only thing counting.
#[test]
fn three_wrong_bearers_burn_a_bounded_grant_at_the_edge() {
    let cell = enforcing(TOKEN);
    assert!(cell.grant(CODE.to_owned(), LONG, Some(THREE)));
    for wrong in ["000000", "000001", "000002"] {
        assert!(!offers(&cell, Some(&format!("Bearer {wrong}"))));
    }
    assert_eq!(cell.grants.count(), 0, "burned");
    assert!(
        !offers(&cell, Some(&format!("Bearer {CODE}"))),
        "the code itself is now a wrong token"
    );
    assert!(
        offers(&cell, Some(&format!("Bearer {TOKEN}"))),
        "and the enforced token was never in question"
    );
}

/// What does not count: the enforced token, presented as often as anyone
/// likes, and anything that is not a bearer at all. Neither is a guess at
/// the code, and a paired machine making requests during a pairing window
/// must not be the thing that closes it.
#[test]
fn only_a_wrong_bearer_counts_as_a_wrong_presentation() {
    let cell = enforcing(TOKEN);
    assert!(cell.grant(CODE.to_owned(), LONG, Some(THREE)));
    for _ in 0..5 {
        assert!(offers(&cell, Some(&format!("Bearer {TOKEN}"))));
    }
    for not_a_guess in [None, Some(""), Some("Basic dXNlcjpwYXNz"), Some("Bearer")] {
        assert!(!offers(&cell, not_a_guess));
    }
    assert_eq!(cell.grants.count(), 1, "still waiting for the device");
    assert!(offers(&cell, Some(&format!("Bearer {CODE}"))));
}

// ── Named tokens ─────────────────────────────────────────────────────────

const LAPTOP: &str = "sk-zzq-the-laptops-key";
const PHONE: &str = "sk-zzq-the-phones-key";

fn by_name(name: &str) -> Admitted {
    Admitted::Named(Arc::from(name))
}

/// The listener with no token of its own is closed until a name is added,
/// and never open — the state that used to be indistinguishable from
/// `InsecureNoAuth`.
#[test]
fn a_named_only_listener_is_closed_not_open() {
    let (cell, token) = Credential::new(&TokenPolicy::Named).expect("a usable policy");
    assert_eq!(token, None, "there is no primary to report");
    assert!(!offers(&cell, None));
    assert!(!offers(&cell, Some("Bearer anything")));
    assert!(!offers(&cell, Some("")));
    cell.add_named("laptop", LAPTOP.to_owned()).expect("held");
    assert_eq!(
        admitted_by(&cell, &format!("Bearer {LAPTOP}")),
        Some(by_name("laptop"))
    );
    assert_eq!(cell.token(), None, "still nothing of its own");
}

#[test]
fn a_named_token_admits_beside_the_primary_and_says_which() {
    let cell = enforcing(TOKEN);
    cell.add_named("laptop", LAPTOP.to_owned()).expect("held");
    assert_eq!(
        admitted_by(&cell, &format!("Bearer {TOKEN}")),
        Some(Admitted::Token)
    );
    assert_eq!(
        admitted_by(&cell, &format!("Bearer {LAPTOP}")),
        Some(by_name("laptop"))
    );
    assert_eq!(admitted_by(&cell, "Bearer neither"), None);
}

/// The whole reason names exist: one device goes and nothing else notices.
#[test]
fn removing_a_name_refuses_that_token_and_nothing_else() {
    let cell = enforcing(TOKEN);
    cell.add_named("laptop", LAPTOP.to_owned()).expect("held");
    cell.add_named("phone", PHONE.to_owned()).expect("held");
    cell.grant(CODE.to_owned(), LONG, None);
    assert!(cell.remove_named("phone"));
    assert!(!offers(&cell, Some(&format!("Bearer {PHONE}"))));
    assert!(offers(&cell, Some(&format!("Bearer {LAPTOP}"))));
    assert!(offers(&cell, Some(&format!("Bearer {TOKEN}"))));
    assert_eq!(cell.grants.count(), 1, "the grant is still waiting");
    assert_eq!(cell.named(), ["laptop"]);
}

/// A named token spends nothing, so it is asked before a grant: a value
/// that is both admits by name and leaves the grant live.
#[test]
fn a_value_that_is_both_a_named_token_and_a_grant_admits_by_name_and_spends_nothing() {
    let cell = enforcing(TOKEN);
    cell.add_named("laptop", LAPTOP.to_owned()).expect("held");
    cell.grant(LAPTOP.to_owned(), LONG, None);
    assert_eq!(
        admitted_by(&cell, &format!("Bearer {LAPTOP}")),
        Some(by_name("laptop"))
    );
    assert_eq!(cell.grants.count(), 1, "the grant was not spent");
}

#[test]
fn rotating_the_primary_does_not_disturb_a_named_token() {
    let cell = enforcing(TOKEN);
    cell.add_named("laptop", LAPTOP.to_owned()).expect("held");
    let fresh = cell.rotate();
    assert!(!offers(&cell, Some(&format!("Bearer {TOKEN}"))));
    assert!(offers(&cell, Some(&format!("Bearer {fresh}"))));
    assert_eq!(
        admitted_by(&cell, &format!("Bearer {LAPTOP}")),
        Some(by_name("laptop"))
    );
}

/// `set_token` on a named-only listener gives it a primary; the names stay.
#[test]
fn a_named_only_listener_can_be_given_a_primary_later() {
    let (cell, _) = Credential::new(&TokenPolicy::Named).expect("a usable policy");
    cell.add_named("laptop", LAPTOP.to_owned()).expect("held");
    assert!(cell.set(TOKEN.to_owned()));
    assert_eq!(cell.token().as_deref(), Some(TOKEN));
    assert_eq!(
        admitted_by(&cell, &format!("Bearer {TOKEN}")),
        Some(Admitted::Token)
    );
    assert_eq!(
        admitted_by(&cell, &format!("Bearer {LAPTOP}")),
        Some(by_name("laptop"))
    );
}

#[test]
fn debug_counts_named_tokens_and_never_shows_one() {
    let (cell, _) = Credential::new(&TokenPolicy::Named).expect("a usable policy");
    cell.add_named("laptop", LAPTOP.to_owned()).expect("held");
    let rendered = format!("{cell:?}");
    assert!(!rendered.contains(LAPTOP), "the token leaked: {rendered}");
    assert!(
        rendered.contains("state: \"named\"") && rendered.contains("named: 1"),
        "but the state and the count are legible: {rendered}"
    );
}
