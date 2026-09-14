//! Tests for [`super`].
//!
//! Split out via `#[path]` so `connect.rs` stays inside the file-size
//! budget.

use super::*;

#[test]
fn an_unreachable_peer_is_retryable() {
    assert!(ConnectError::PeerUnreachable.is_retryable());
}

/// The p2p endpoint is nobody's choice, so failing to bind it is a
/// machine condition — the same verdict `ServeError::Bind` gets for the
/// same socket.
#[test]
fn failing_to_bind_the_p2p_endpoint_is_retryable() {
    let e = ConnectError::Endpoint(std::io::Error::other("too many open files"));
    assert!(e.is_retryable(), "{e} should be retryable");
}

/// The one variant that is permanent, and the reason it is a variant of
/// its own: the caller named this port through `ConnectOptions::bind`,
/// so retrying the same value fails the same way forever. The p2p
/// endpoint's own bind failure is `Endpoint`, above.
#[test]
fn a_connect_bind_failure_is_not_retryable_because_the_caller_chose_the_address() {
    let e = ConnectError::Bind(std::io::Error::other("address in use"));
    assert!(!e.is_retryable(), "{e} should not be retryable");
}

/// The operator typed the relay, so no amount of waiting fixes it —
/// the same verdict the serve side gives the same value.
#[test]
fn an_unparseable_relay_is_permanent_and_names_the_value() {
    let e = ConnectError::InvalidRelay {
        url: "not a url".to_owned(),
    };
    assert!(!e.is_retryable());
    assert!(e.to_string().contains("not a url"));
    assert!(std::error::Error::source(&e).is_none());
}

/// The defaults are what every version before this one did.
#[test]
fn the_default_options_keep_every_network_contact_on() {
    let opts = ConnectOptions::default();
    assert!(opts.port_mapping);
    assert!(opts.discovery);
    assert!(opts.relay.is_none());
}

/// The operator named the file, so no amount of waiting fixes it: the
/// verdict the serve side gives the same file.
#[test]
fn an_unusable_identity_is_permanent_and_names_the_file() {
    let e = ConnectError::Identity {
        path: "/tmp/connect_identity".to_owned(),
        source: std::io::Error::other("readable by others"),
    };
    assert!(!e.is_retryable());
    assert!(e.to_string().contains("/tmp/connect_identity"));
    assert!(std::error::Error::source(&e).is_some());
}

/// No key on disk unless one is asked for: a fresh identity per process, as
/// every version before this one had.
#[test]
fn the_default_options_keep_no_identity() {
    assert!(ConnectOptions::default().identity.is_none());
}
