//! Tests for [`super`] — what a bind address becomes, and who may be
//! dialled.
//!
//! Pure address arithmetic, so nothing here binds a socket. The one thing
//! these cannot check is that `serve` honours the permission; the
//! integration test does that.

use super::*;

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("an address")
}

// ── What a bind address becomes ──────────────────────────────────────────

/// A wildcard names no host, so it is dialled on loopback of its own
/// family — keeping the port, which is the whole point of rewriting rather
/// than guessing.
#[test]
fn a_wildcard_bind_is_dialled_on_loopback_of_its_own_family() {
    assert_eq!(
        BackendUrl::at(addr("0.0.0.0:11434")).url(),
        "http://127.0.0.1:11434"
    );
    assert_eq!(
        BackendUrl::at(addr("[::]:11434")).url(),
        "http://[::1]:11434"
    );
}

/// An IPv6 literal is bracketed, because a URL authority needs it and
/// modelpipe's own parser strips the brackets back off before resolving.
#[test]
fn an_ipv6_literal_is_bracketed() {
    assert_eq!(
        BackendUrl::at(addr("[::1]:8080")).url(),
        "http://[::1]:8080"
    );
}

/// Everything that is already a destination passes through untouched.
#[test]
fn an_ordinary_address_is_dialled_as_written() {
    assert_eq!(
        BackendUrl::at(addr("127.0.0.1:8080")).url(),
        "http://127.0.0.1:8080"
    );
    assert_eq!(
        BackendUrl::at(addr("192.168.1.5:8080")).url(),
        "http://192.168.1.5:8080"
    );
}

// ── Who may be dialled ───────────────────────────────────────────────────

/// A caller that owns the bind has already chosen the interface, so `at`
/// derives the permission its address needs.
#[test]
fn a_bind_on_the_operators_own_network_carries_its_own_permission() {
    assert!(BackendUrl::at(addr("192.168.1.5:8080")).permits_private());
    assert!(BackendUrl::at(addr("10.0.0.4:8080")).permits_private());
    assert!(BackendUrl::at(addr("[fd00::1]:8080")).permits_private());
}

/// Loopback needs no permission and is not given one — so a value built
/// for the ordinary case cannot later be read as "private was allowed".
#[test]
fn a_loopback_bind_permits_nothing_it_does_not_need() {
    assert!(!BackendUrl::at(addr("127.0.0.1:8080")).permits_private());
    assert!(!BackendUrl::at(addr("0.0.0.0:8080")).permits_private());
}

/// **The safety nuance, pinned.** A URL is never self-permitting, however
/// private it looks: `dial` is what a caller uses for an address it did
/// not choose, and for that caller the rule applies in full.
#[test]
fn a_private_url_is_not_permitted_merely_by_being_private() {
    assert!(!BackendUrl::dial("http://192.168.1.5:8080").permits_private());
    assert!(!BackendUrl::from("http://192.168.1.5:8080").permits_private());
    assert!(
        BackendUrl::dial("http://192.168.1.5:8080")
            .allow_private()
            .permits_private(),
        "and saying so out loud is what grants it"
    );
}

/// A link-local bind gets no permission from `at` either. Nothing grants
/// one — `serve` refuses the address whatever it is handed — but the flag
/// must not be set on the way there, or a later reader of this value would
/// conclude the operator had agreed to it.
///
/// `169.254.169.254` is the case the rule exists for: cloud instance
/// metadata, and a tunnel that dialled it on a stranger's behalf would be
/// a credential-exfiltration primitive.
#[test]
fn a_link_local_bind_is_never_permitted() {
    assert!(!BackendUrl::at(addr("169.254.169.254:80")).permits_private());
    assert!(!BackendUrl::at(addr("[fe80::1]:8080")).permits_private());
}

/// Nor is a public one, which is the other half of "this moves exactly one
/// class".
#[test]
fn a_public_bind_is_never_permitted() {
    assert!(!BackendUrl::at(addr("93.184.216.34:80")).permits_private());
}

// ── Conversions ──────────────────────────────────────────────────────────

/// `&str` and `String` convert as `dial` does, which is what keeps
/// `serve("http://127.0.0.1:11434", opts)` reading the way it always has.
#[test]
fn a_string_converts_as_a_plain_dial() {
    let owned = String::from("http://127.0.0.1:11434");
    let expected = BackendUrl::dial("http://127.0.0.1:11434");
    assert_eq!(BackendUrl::from("http://127.0.0.1:11434"), expected);
    assert_eq!(BackendUrl::from(owned.clone()), expected);
    assert_eq!(BackendUrl::from(&owned), expected);
}

// ── The shared rewrite ───────────────────────────────────────────────────

/// The helper the pairing exchange and the connect side's base URL share
/// with `at`, so the three cannot drift.
#[test]
fn the_shared_rewrite_moves_only_the_wildcard() {
    assert_eq!(dialable(addr("0.0.0.0:8080")), addr("127.0.0.1:8080"));
    assert_eq!(dialable(addr("[::]:8080")), addr("[::1]:8080"));
    assert_eq!(dialable(addr("192.168.1.5:8080")), addr("192.168.1.5:8080"));
    assert_eq!(dialable(addr("127.0.0.1:8080")), addr("127.0.0.1:8080"));
}
