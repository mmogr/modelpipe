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
//! Most of the library is still `todo!()`, so the runtime assertions cover
//! the parts that exist. The rest of the file earns its place at compile
//! time, which is where a facade is proved.

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

    let mut connect_opts = ConnectOptions::default();
    connect_opts.bind = Some("127.0.0.1:8080".parse().unwrap());

    assert!(connect_opts.bind.is_some());
    assert!(serve_opts.allow_private_backend);
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
