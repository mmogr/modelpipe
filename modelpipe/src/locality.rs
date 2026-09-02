//! Whether an address is one this machine may reach on a caller's behalf.
//!
//! Pure: predicates over [`IpAddr`], no DNS, no sockets, no configuration.
//! It answers exactly one question — *may `serve` connect to this?* — and
//! deliberately not two neighbouring ones it would be easy to confuse it
//! with:
//!
//! * It does not resolve names. The rule is stated on resolved addresses
//!   precisely so a hostname cannot smuggle one past it, which means
//!   whoever resolves must screen every address they get and then connect
//!   to *that* address rather than re-resolving the name. Splitting resolve
//!   from connect is what re-opens the hole; the transport owns keeping
//!   them together.
//! * It does not decide whether the CLI should warn about a *bind* address.
//!   That looks like the same question and is the opposite one: this is a
//!   refusal about where traffic goes out, and the bind warning is a
//!   presentation decision about a case that is deliberately permitted.
//!
//! The rule this implements is stated for users on
//! [`ServeError::BackendNotLocal`](crate::ServeError::BackendNotLocal),
//! which is where someone hitting it will read it. This module is the
//! mechanism, and the two must agree.

// Scoped to the non-test build: the tests below are currently the only
// callers, so an unconditional expectation is itself unfulfilled when they
// compile. When the real caller lands this goes unfulfilled in turn, which
// is the reminder to delete it.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the backend dial screens addresses; until it exists only tests call these"
    )
)]

use std::net::IpAddr;

/// What kind of address this is, from the point of view of "may we dial it".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Locality {
    /// `127.0.0.0/8` or `::1`. The whole point of the product.
    Loopback,
    /// RFC 1918 or `fc00::/7`. The operator's own network — reachable, and
    /// a decision they have to make explicitly.
    Private,
    /// `169.254.0.0/16` or `fe80::/10`. Never admitted: cloud instance
    /// metadata lives at `169.254.169.254`, and a tunnel that would dial it
    /// on a stranger's behalf is a credential-exfiltration primitive.
    LinkLocal,
    /// Routable. modelpipe extends trust outward from this machine; it does
    /// not re-export someone else's server.
    Public,
    /// `0.0.0.0` or `::`. Names no host at all — and on Linux, connecting to
    /// it reaches loopback, so treating it as "not loopback, therefore
    /// public, therefore refused" happens to be right for the wrong reason.
    /// Refused deliberately instead.
    Unspecified,
}

/// Classify a resolved address.
///
/// IPv4-mapped IPv6 is canonicalized to IPv4 *first*, which is the whole
/// reason this is a function rather than a chain of `std` predicates:
/// `::ffff:169.254.169.254` is the metadata endpoint wearing an IPv6 hat,
/// and every per-family check answers "not link-local" about it because it
/// asks an `Ipv6Addr` a question only an `Ipv4Addr` can answer.
///
/// IPv4-*compatible* addresses (`::a.b.c.d`) are deliberately not unwrapped:
/// they are deprecated, and `to_ipv4` — which does unwrap them — would turn
/// `::1` into `0.0.0.1`, reclassifying loopback as unspecified.
pub(crate) fn classify(ip: IpAddr) -> Locality {
    match canonicalize(ip) {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                Locality::Loopback
            } else if v4.is_unspecified() {
                Locality::Unspecified
            } else if v4.is_link_local() {
                Locality::LinkLocal
            } else if v4.is_private() {
                Locality::Private
            } else {
                Locality::Public
            }
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            if v6.is_loopback() {
                Locality::Loopback
            } else if v6.is_unspecified() {
                Locality::Unspecified
            } else if first & 0xFFC0 == 0xFE80 {
                // fe80::/10. Matched by prefix rather than via
                // `is_unicast_link_local`, which is unstable — and which
                // would be the wrong shape anyway, since this needs the
                // whole /10 including the parts that are not unicast.
                Locality::LinkLocal
            } else if first & 0xFE00 == 0xFC00 {
                // fc00::/7, unique local.
                Locality::Private
            } else {
                Locality::Public
            }
        }
    }
}

/// Whether a classified address may be dialled, given the operator's choice
/// about private ranges.
///
/// A full match with no `_` arm: adding a `Locality` variant should be a
/// compile error here, because a new kind of address that silently inherits
/// some other kind's permission is exactly the mistake this file exists to
/// prevent.
pub(crate) const fn admits(locality: Locality, allow_private: bool) -> bool {
    match locality {
        // Always, and needing no flag: this is the product.
        Locality::Loopback => true,
        // The operator's explicit decision, and only theirs.
        Locality::Private => allow_private,
        // Never, whatever the flag says. `allow_private_backend` widens the
        // rule to the operator's own network; it is not a general "trust me"
        // switch, and reading it as one is how the metadata endpoint becomes
        // reachable.
        Locality::LinkLocal | Locality::Public | Locality::Unspecified => false,
    }
}

/// Unwrap an IPv4-mapped IPv6 address to the IPv4 address it is.
fn canonicalize(ip: IpAddr) -> IpAddr {
    match ip {
        // Both arms written out rather than one and a wildcard: a wildcard
        // here would silently absorb a family added to `IpAddr` later, and
        // an unclassified address family reaching the admission check as
        // "whatever the fallthrough said" is the failure this file exists
        // to prevent.
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test address")
    }

    // ── What is admitted ─────────────────────────────────────────────────

    /// The common case must need no configuration at all.
    #[test]
    fn loopback_is_admitted_without_any_flag() {
        for s in ["127.0.0.1", "127.0.0.2", "127.255.255.254", "::1"] {
            assert_eq!(classify(ip(s)), Locality::Loopback, "{s}");
            assert!(admits(classify(ip(s)), false), "{s} needs no flag");
        }
    }

    /// Both halves in one body: refused bare, admitted with the flag. A test
    /// asserting only one of them would pass on an implementation that
    /// ignored the flag entirely.
    #[test]
    fn the_private_ranges_need_the_flag_and_are_refused_without_it() {
        for s in [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.5",
            "fc00::1",
            "fd12:3456::1",
        ] {
            assert_eq!(classify(ip(s)), Locality::Private, "{s}");
            assert!(!admits(classify(ip(s)), false), "{s} must need the flag");
            assert!(
                admits(classify(ip(s)), true),
                "{s} must be admitted with it"
            );
        }
    }

    /// 172.16/12 has edges people get wrong in both directions.
    #[test]
    fn the_private_range_boundaries_are_where_rfc_1918_puts_them() {
        assert_eq!(classify(ip("172.15.255.255")), Locality::Public);
        assert_eq!(classify(ip("172.16.0.0")), Locality::Private);
        assert_eq!(classify(ip("172.31.255.255")), Locality::Private);
        assert_eq!(classify(ip("172.32.0.0")), Locality::Public);
    }

    // ── What is refused ──────────────────────────────────────────────────

    /// The flag widens the rule to the operator's own network. It is not a
    /// general "trust me" switch, so it is asserted against *both* values.
    #[test]
    fn link_local_is_refused_however_the_flag_is_set() {
        for s in ["169.254.1.1", "169.254.169.254", "fe80::1", "febf::1"] {
            assert_eq!(classify(ip(s)), Locality::LinkLocal, "{s}");
            assert!(!admits(classify(ip(s)), false), "{s}");
            assert!(!admits(classify(ip(s)), true), "{s} even with the flag");
        }
    }

    /// The one a per-family check waves through. `::ffff:169.254.169.254` is
    /// cloud instance metadata wearing an IPv6 hat, and asking an `Ipv6Addr`
    /// whether it is link-local answers "no" — correctly, and uselessly.
    #[test]
    fn an_ipv4_mapped_metadata_address_is_still_link_local() {
        let mapped = ip("::ffff:169.254.169.254");
        assert!(mapped.is_ipv6(), "the input really is an IPv6 address");
        assert_eq!(classify(mapped), Locality::LinkLocal);
        assert!(!admits(classify(mapped), true), "even with the flag set");

        // And the mapping is applied across the board, not special-cased for
        // the metadata address.
        assert_eq!(classify(ip("::ffff:127.0.0.1")), Locality::Loopback);
        assert_eq!(classify(ip("::ffff:192.168.1.5")), Locality::Private);
        assert_eq!(classify(ip("::ffff:8.8.8.8")), Locality::Public);
    }

    /// IPv4-compatible addresses are *not* unwrapped, and `::1` is the
    /// reason: `to_ipv4` would turn it into `0.0.0.1` and reclassify
    /// loopback as unspecified.
    #[test]
    fn an_ipv4_compatible_address_is_not_unwrapped() {
        assert_eq!(classify(ip("::1")), Locality::Loopback);
        assert_eq!(classify(ip("::2")), Locality::Public);
    }

    #[test]
    fn the_unspecified_address_names_nothing_and_is_refused() {
        for s in ["0.0.0.0", "::"] {
            assert_eq!(classify(ip(s)), Locality::Unspecified, "{s}");
            assert!(!admits(classify(ip(s)), false), "{s}");
            // Connecting to it reaches loopback on Linux, which would make
            // this an accidental bypass rather than a deliberate allowance.
            assert!(!admits(classify(ip(s)), true), "{s} even with the flag");
        }
    }

    #[test]
    fn a_public_address_is_refused_however_the_flag_is_set() {
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "203.0.113.1",
            "2606:4700:4700::1111",
            "2001:db8::1",
        ] {
            assert_eq!(classify(ip(s)), Locality::Public, "{s}");
            assert!(!admits(classify(ip(s)), false), "{s}");
            assert!(!admits(classify(ip(s)), true), "{s} even with the flag");
        }
    }

    /// The flag's entire effect, stated once: it moves exactly one class and
    /// touches nothing else.
    #[test]
    fn the_flag_moves_private_and_nothing_else() {
        for locality in [
            Locality::Loopback,
            Locality::Private,
            Locality::LinkLocal,
            Locality::Public,
            Locality::Unspecified,
        ] {
            let changed = admits(locality, true) != admits(locality, false);
            assert_eq!(
                changed,
                locality == Locality::Private,
                "{locality:?} must{} be affected by the flag",
                if locality == Locality::Private {
                    ""
                } else {
                    " not"
                }
            );
        }
    }
}
