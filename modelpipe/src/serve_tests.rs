//! Tests for [`super`] — what `serve` is given, and how it refuses.
//!
//! Split out via `#[path]` so `serve.rs` stays inside the file-size
//! budget, the same way every other module in the crate does it.

use super::*;

/// Distinct from the sentinel `credential.rs` uses, so a leak names
/// the type it escaped through.
const SUPPLIED: &str = "sk-zzq-serve-options-sentinel";

/// `ServeOptions` is the type an embedder is most likely to hold in a
/// struct of their own and derive `Debug` on, which is how a supplied
/// credential reaches a log without anyone deciding it should.
#[test]
fn debug_for_serve_options_never_renders_the_supplied_token() {
    // A struct literal rather than the `Default`-then-mutate dance an
    // out-of-crate embedder is forced into by `#[non_exhaustive]`:
    // inside the crate the literal is legal, and clippy rejects the
    // dance. What is under test is the `Debug` impl, which cannot tell
    // how the value was built.
    let opts = ServeOptions {
        auth: TokenPolicy::Supplied(SUPPLIED.to_owned()),
        relay: Some("https://relay.example.com/".to_owned()),
        ..Default::default()
    };
    let rendered = format!("{opts:?}");
    assert!(
        !rendered.contains(SUPPLIED),
        "the token leaked through ServeOptions: {rendered}"
    );
    assert!(
        rendered.contains("relay.example.com"),
        "the non-secret fields should still be visible: {rendered}"
    );
}

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
