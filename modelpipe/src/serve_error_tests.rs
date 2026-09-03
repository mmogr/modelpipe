//! Tests for [`super`] — which failures a caller should retry.
//!
//! Split out via `#[path]` so `serve_error.rs` stays inside the file-size
//! budget, the same way every other module in the crate does it.
//!
//! The classification is the whole of what is checked, because it is the
//! whole of what the enum promises: `#[non_exhaustive]` means a downstream
//! `match` cannot compute it, so a variant landing in the wrong bucket here
//! is a supervisor giving up on a listener that would have come back.

use super::*;

/// Both are the operator's to fix, and no amount of waiting changes
/// either one.
#[test]
fn a_user_fixable_serve_error_is_not_retryable() {
    for e in [
        ServeError::InvalidBackendUrl {
            url: "https://127.0.0.1:11434".to_owned(),
        },
        ServeError::InvalidToken,
        ServeError::BackendNotLocal {
            url: "http://example.com".to_owned(),
        },
        ServeError::InvalidRelay {
            url: "not a url".to_owned(),
        },
    ] {
        assert!(!e.is_retryable(), "{e} should not be retryable");
    }
}

/// `serve` takes no bind option, so nothing here names an address the
/// caller chose — a failure describes the machine underneath.
#[test]
fn a_machine_serve_error_is_retryable() {
    for e in [
        ServeError::Bind(std::io::Error::other("no sockets left")),
        ServeError::BackendUnresolvable {
            url: "http://ollama.local:11434".to_owned(),
        },
    ] {
        assert!(e.is_retryable(), "{e} should be retryable");
    }
}
