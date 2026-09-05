//! The public surface, exercised the way a dependent sees it.
//!
//! This links `modelpipe` as an external crate, which is the whole point:
//! `#[cfg(test)]` modules inside the library can reach private items and so
//! cannot tell whether a type is genuinely exported, whether a
//! `#[non_exhaustive]` struct is constructible from outside, or whether a
//! doc's promised path is real. Everything here would still compile if the
//! crate's internal module layout changed completely — and would stop
//! compiling the moment the re-export block in `lib.rs` did.
//!
//! Most of this file earns its place at compile time, which is where a
//! facade is proved: the runtime assertions below are the few claims about
//! the surface that a signature cannot make on its own.
//!
//! Nothing here runs an exchange, binds a socket or starts a runtime, and
//! that is the division of labour rather than a gap —
//! `tests/integration_pipe.rs` is the binary that pairs two live sides.
//! What this one answers is the question a dependent asks: does the crate
//! export what it says it exports, in the shapes it says?

use std::error::Error;

use modelpipe::{
    ConnectError, ConnectHandle, ConnectOptions, PipeStatus, ServeError, ServeHandle, ServeOptions,
    Ticket, TicketParseError, TokenPolicy,
};

/// Every name the crate promises, reachable at the flat path it promises it
/// at. A module rename inside the crate must not reach this list.
#[test]
fn the_public_names_resolve_at_the_crate_root() {
    fn nameable<T>() {}
    // Declared alongside `nameable`: an item after a statement is a clippy
    // error, and both of these are items.
    fn takes_any<T>(_: T) {}

    nameable::<Ticket>();
    nameable::<TicketParseError>();
    nameable::<ServeError>();
    nameable::<ServeOptions>();
    nameable::<ServeHandle>();
    nameable::<ConnectError>();
    nameable::<ConnectOptions>();
    nameable::<ConnectHandle>();
    nameable::<TokenPolicy>();
    nameable::<PipeStatus>();

    // The two entry points. Passed as values rather than ascribed a type:
    // both are `async fn`, so their return is an opaque future no caller
    // can spell, which is itself part of the contract. Naming them here is
    // enough to fail if either path stops resolving.
    takes_any(modelpipe::serve);
    takes_any(modelpipe::connect);
}

/// `#[non_exhaustive]` forbids a struct literal across a crate boundary, so
/// `Default`-then-assign is the *only* legal construction — and it is what
/// `modelpipe-cli` does. If a future field lands without a `Default`, or the
/// attribute is dropped, this is where it shows.
#[test]
fn the_options_structs_are_constructible_from_outside() {
    let mut serve_opts = ServeOptions::default();
    serve_opts.auth = TokenPolicy::Supplied("a-token".to_owned());
    serve_opts.relay = Some("https://relay.example.com/".to_owned());
    serve_opts.allow_private_backend = true;

    serve_opts.port_mapping = false;
    serve_opts.discovery = false;

    let mut connect_opts = ConnectOptions::default();
    connect_opts.bind = Some("127.0.0.1:8080".parse().unwrap());
    connect_opts.relay = Some("https://relay.example.com/".to_owned());
    connect_opts.port_mapping = false;
    connect_opts.discovery = false;

    assert!(connect_opts.bind.is_some());
    assert!(serve_opts.allow_private_backend);
    assert!(!connect_opts.discovery && !serve_opts.discovery);
}

/// The defaults are what every version before this one did: every network
/// contact on. A dependent that upgrades and changes nothing contacts
/// exactly what it contacted before.
#[test]
fn the_default_options_keep_every_network_contact_on() {
    let serve_opts = ServeOptions::default();
    let connect_opts = ConnectOptions::default();
    assert!(serve_opts.port_mapping && serve_opts.discovery);
    assert!(connect_opts.port_mapping && connect_opts.discovery);
    assert!(connect_opts.relay.is_none());
}

/// The opacity promise from the crate docs: a caller can walk to the
/// machine's own error, and finds a `std` type rather than anything
/// belonging to iroh.
#[test]
fn a_machine_failure_exposes_its_cause_and_nothing_of_the_transport() {
    let e = ServeError::Bind(std::io::Error::other("no sockets left"));
    let cause = e.source().expect("Bind must expose its source");
    assert_eq!(cause.to_string(), "no sockets left");
    // And it is not also interpolated into Display: `anyhow` prints the
    // top-level Display and then the source chain, so a variant that does
    // both prints the OS error twice.
    assert!(
        !e.to_string().contains("no sockets left"),
        "the source must not be duplicated into Display: {e}"
    );

    // The user-fixable variants deliberately have no source: there is no
    // underlying failure, only a value the operator got wrong.
    let e = ServeError::BackendNotLocal {
        url: "http://example.com".to_owned(),
    };
    assert!(e.source().is_none());
}

/// Retry classification is public API, not an internal detail — this is the
/// call a dependent's backoff loop makes.
#[test]
fn a_dependent_can_classify_failures_without_matching_on_them() {
    assert!(
        !ServeError::BackendNotLocal {
            url: "http://example.com".to_owned()
        }
        .is_retryable()
    );
    assert!(ConnectError::PeerUnreachable.is_retryable());
}

/// `Copy` and `Eq` are promised at the derive and relied on by
/// `status_changed`'s snapshot comparison; a dependent holding a status in
/// its own state needs both.
#[test]
fn a_status_can_be_copied_compared_and_named() {
    let a = PipeStatus::Relayed;
    let b = a; // Copy, not a move — `a` stays usable below.
    assert_eq!(a, b);
    assert_ne!(a, PipeStatus::Direct);
    assert_eq!(a.as_str(), "relayed");
}

/// The redaction promise, checked from outside, because a dependent's own
/// `#[derive(Debug)]` is exactly how a credential reaches a log.
#[test]
fn a_dependents_debug_output_cannot_contain_the_supplied_token() {
    const SECRET: &str = "sk-zzq-external-consumer-sentinel";

    #[derive(Debug)]
    #[allow(dead_code)]
    struct EmbedderConfig {
        name: &'static str,
        opts: ServeOptions,
    }

    let mut opts = ServeOptions::default();
    opts.auth = TokenPolicy::Supplied(SECRET.to_owned());
    let cfg = EmbedderConfig {
        name: "daemon",
        opts,
    };

    let rendered = format!("{cfg:?}");
    assert!(
        !rendered.contains(SECRET),
        "the token leaked through a dependent's derived Debug: {rendered}"
    );
    assert!(rendered.contains("daemon"), "the rest must still render");
}

/// Both error types are `std::error::Error`, which is what lets them ride
/// through `anyhow` and `Box<dyn Error>` in a dependent's stack.
#[test]
fn both_error_types_are_std_errors_and_send_sync() {
    fn assert_error<T: Error + Send + Sync + 'static>() {}
    assert_error::<ServeError>();
    assert_error::<ConnectError>();
    assert_error::<TicketParseError>();

    let boxed: Box<dyn Error + Send + Sync> = Box::new(ConnectError::PeerUnreachable);
    assert!(boxed.to_string().contains("could not reach"));
}

/// A grant is refused the same way a rotation is, with the same variant,
/// and a dependent is likewise forced to look.
#[test]
fn a_dependent_cannot_ignore_a_grant_that_was_refused() {
    fn pair(handle: &ServeHandle, code: String) -> Result<(), ServeError> {
        handle.grant_once(code, std::time::Duration::from_mins(2))?;
        Ok(())
    }
    // Named so it cannot be dropped as dead code, and never called: there
    // is no live listener here, and the promise being checked is the type.
    let _ = pair;
}

/// Rotation reports refusal, and the type says so from outside the crate.
///
/// This is a signature test as much as a behaviour one: `set_token` is
/// frozen at 0.1.0, and turning a `()` into a `Result` afterwards is a
/// breaking change. Written here rather than only inside the crate because
/// what matters is that a *dependent* is forced to look — an embedder
/// rotating a key it read from a config file has to handle the case where
/// that file came back blank.
#[test]
fn a_dependent_cannot_ignore_a_rotation_that_was_refused() {
    fn rotate(handle: &ServeHandle, from_config: String) -> Result<(), ServeError> {
        // The `?` is the point: this does not compile against a `()`.
        handle.set_token(from_config)?;
        Ok(())
    }

    // Named so it cannot be dropped as dead code, and never called: there
    // is no live listener here, and the promise being checked is the type.
    let _ = rotate;

    // The variant a blank replacement produces is the same one `serve`
    // refuses at startup, so a dependent needs one arm rather than two.
    let refused = ServeError::InvalidToken;
    assert!(
        !refused.is_retryable(),
        "a blank credential does not become usable by waiting"
    );
    assert!(
        refused.to_string().contains("empty"),
        "and it says which value it means: {refused}"
    );
}
