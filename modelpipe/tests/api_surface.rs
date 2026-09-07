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
use std::time::Duration;

use modelpipe::{
    CloseReason, ConnectError, ConnectHandle, ConnectOptions, NetworkMetrics, PeerView, PipeStatus,
    ServeError, ServeHandle, ServeOptions, Ticket, TicketParseError, TokenPolicy,
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
    nameable::<CloseReason>();
    nameable::<PeerView>();
    nameable::<NetworkMetrics>();

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
    serve_opts.relay_only = true;

    let mut connect_opts = ConnectOptions::default();
    connect_opts.bind = Some("127.0.0.1:8080".parse().unwrap());
    connect_opts.relay = Some("https://relay.example.com/".to_owned());
    connect_opts.port_mapping = false;
    connect_opts.discovery = false;
    connect_opts.relay_only = true;

    assert!(connect_opts.bind.is_some());
    assert!(serve_opts.allow_private_backend);
    assert!(!connect_opts.discovery && !serve_opts.discovery);
    assert!(connect_opts.relay_only && serve_opts.relay_only);
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
    // And the direct path stays available on both sides: `relay_only` is a
    // measuring switch, and a default that forced every pipe through a
    // relay would be a performance regression nobody asked for.
    assert!(!serve_opts.relay_only && !connect_opts.relay_only);
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

/// The distinction a status page cannot make on its own, exercised the way
/// a dependent makes it: `None` is a live pipe — idle-and-retrying
/// included — and a reason is a pipe that is over, with `Shutdown` and
/// `ListenerFailed` the difference between a success and a failure.
///
/// Written as a function over the handle because the promise is the
/// signature: `Option<CloseReason>`, on `ConnectHandle`, matchable from
/// outside the crate with a `_` arm for the `#[non_exhaustive]` future.
#[test]
fn a_dependent_can_tell_a_live_pipe_from_a_close_and_a_close_from_a_failure() {
    fn render(handle: &ConnectHandle) -> &'static str {
        match handle.close_reason() {
            None => "connecting",
            Some(CloseReason::ListenerFailed) => "the local port died",
            Some(_) => "disconnected",
        }
    }
    // Named so it cannot be dropped as dead code, and never called: there
    // is no live pipe here, and the promise being checked is the type.
    let _ = render;

    let a = CloseReason::ListenerFailed;
    let b = a; // Copy, not a move — `a` stays usable below.
    assert_eq!(a, b);
    assert_ne!(a, CloseReason::Shutdown);
    assert_eq!(a.as_str(), "listener_failed");
}

/// A peer view is readable field by field from outside, and `peers` is on
/// the handle — the shape a status page renders from.
///
/// The round-trip time is part of that shape: `relayed` on its own is a
/// label, and the number beside it is what makes a status page able to say
/// whether the relay is good enough to keep using. `Option<u64>` rather
/// than a `Duration` so the rendering is one multiplication and the JSON is
/// one field.
#[test]
fn a_peer_view_is_readable_from_outside() {
    fn render(handle: &ServeHandle) -> Vec<String> {
        handle
            .peers()
            .iter()
            .map(|peer: &PeerView| {
                // Ascribed rather than inferred: the promise being checked
                // is the field's type, and `Option<u64>` is what makes
                // rendering it one multiplication rather than a match on a
                // `Duration`'s two halves.
                let rtt: Option<u64> = peer.rtt_ms;
                let cost = rtt.map_or_else(String::new, |ms| format!(" {ms}ms"));
                format!("{} {}{cost}", peer.fingerprint, peer.path.as_str())
            })
            .collect()
    }
    // Named so it cannot be dropped as dead code, and never called: there
    // is no live listener here, and the promise being checked is the type.
    let _ = render;
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

/// With the feature on, a dependent's own derived `Serialize` over a struct
/// holding a ticket and a status emits the canonical string and the frozen
/// identifier — the shape a status DTO needs, and nothing of the layout.
#[cfg(feature = "serde")]
#[test]
fn a_dependents_dto_serializes_a_ticket_as_its_string() {
    #[derive(serde::Serialize)]
    struct StatusDto {
        ticket: Ticket,
        path: PipeStatus,
    }
    let ticket: Ticket = "pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaaauhlp2na"
        .parse()
        .expect("a normative vector");
    let json = serde_json::to_string(&StatusDto {
        ticket: ticket.clone(),
        path: PipeStatus::Direct,
    })
    .expect("serializes");
    assert_eq!(
        json,
        format!(r#"{{"ticket":"{ticket}","path":"direct"}}"#),
        "the ticket is its string and the status is its identifier"
    );
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

/// The graced rotation is reachable from outside, reports refusal the same
/// way, and takes its window as a plain `Duration`.
///
/// A signature test: `set_token` is frozen, and this lands beside it rather
/// than replacing it, so a dependent must be able to name both. The
/// `Duration` is `std`'s and not a newtype of this crate's — an embedder
/// reads a rollout window out of its own config as a number of seconds, and
/// should not have to learn a type to pass it.
#[test]
fn a_dependent_can_rotate_with_an_overlap_and_still_cannot_ignore_a_refusal() {
    // Declared before the first statement: an item after one is a clippy
    // error, and both of these are items.
    fn roll(handle: &ServeHandle, next: String, window: Duration) -> Result<(), ServeError> {
        // The `?` is the point: this does not compile against a `()`.
        handle.set_token_with_grace(next, window)?;
        Ok(())
    }
    // Ending an overlap early is the plain rotation, unchanged — which is
    // what makes this addition free for every existing caller.
    fn cut_short(handle: &ServeHandle, current: String) -> Result<(), ServeError> {
        handle.set_token(current)?;
        Ok(())
    }
    // Named so they cannot be dropped as dead code, and never called:
    // there is no live listener here, and the promise is the type.
    let _ = roll;
    let _ = cut_short;

    // Zero is a legal window and means "no overlap", so a dependent
    // computing one from config does not need a branch for the zero case.
    let none_at_all = Duration::ZERO;
    assert_eq!(none_at_all.as_nanos(), 0);
}

/// The accessor a language binding watches on, in the shape a binding uses
/// it: hand back the value that was rendered, and the sequence *ends*.
///
/// A signature test, and the signature is the promise. `Option` is what
/// makes the loop below terminate — with a bare `PipeStatus` there is no
/// `while let` to write, and the obvious `loop` spins on a closed pipe
/// because `Closed` is terminal and would be answered again immediately,
/// for ever, with no await in the path. Written against both handles
/// because a binding wraps both, and against a `_` arm nowhere: what a
/// caller has to handle here is the end, not a new variant.
#[test]
fn a_dependent_can_watch_a_status_from_its_own_snapshot_and_reach_an_end() {
    // The coalescing form is untouched and still returns a bare status —
    // an embedder already watching one is not asked to change. Declared
    // alongside the two below rather than beside its own `let`: an item
    // after a statement is a clippy error, and all three are items.
    async fn watch_the_old_way(handle: &ConnectHandle) -> PipeStatus {
        handle.status_changed().await
    }
    async fn watch_connect(handle: &ConnectHandle) -> Vec<String> {
        let mut held: PipeStatus = handle.status();
        let mut rendered = vec![held.as_str().to_owned()];
        while let Some(next) = handle.status_changed_since(held).await {
            rendered.push(next.as_str().to_owned());
            held = next;
        }
        rendered
    }
    async fn watch_serve(handle: &ServeHandle) -> Vec<String> {
        let mut held: PipeStatus = handle.status();
        let mut rendered = vec![held.as_str().to_owned()];
        while let Some(next) = handle.status_changed_since(held).await {
            rendered.push(next.as_str().to_owned());
            held = next;
        }
        rendered
    }
    // Named so they cannot be dropped as dead code, and never called:
    // there is no live pipe here, and the promise being checked is the
    // type.
    let _ = (watch_connect, watch_serve, watch_the_old_way);
}

/// The resume hook, in the shape a phone client calls it: no arguments, no
/// return, nothing of the transport in either.
///
/// The signature is the whole point. This wraps an endpoint method, and the
/// alternative — handing the endpoint out and letting the caller call it —
/// would put an iroh type in a public signature and make an iroh major
/// version the *dependent's* upgrade rather than this crate's. A generated
/// binding cannot name such a type at all.
#[test]
fn a_dependent_can_report_a_network_change_without_holding_a_transport() {
    async fn on_resume(serving: &ServeHandle, connected: &ConnectHandle) {
        // Both return `()`. A binding's resume handler is `async` and has
        // nothing to unwrap or match.
        let () = serving.notify_network_change().await;
        let () = connected.notify_network_change().await;
    }
    // Named so it cannot be dropped as dead code, and never called: there
    // is no live pipe here, and the promise being checked is the type.
    let _ = on_resume;
}

/// The metrics snapshot is a plain owned value from outside the crate:
/// constructible, `Copy`, comparable, and every field a `u64` that can be
/// read without touching anything of iroh's.
///
/// `Default` is what makes it constructible at all — `#[non_exhaustive]`
/// forbids a struct literal across a crate boundary — and it is also the
/// honest zero: a pipe that has reached nothing has reached nothing.
#[test]
fn a_metrics_snapshot_is_a_plain_value_a_dependent_owns() {
    // Declared before the first statement: an item after one is a clippy
    // error, and this is an item.
    fn read(serving: &ServeHandle, connected: &ConnectHandle) -> (NetworkMetrics, NetworkMetrics) {
        (serving.network_metrics(), connected.network_metrics())
    }
    // Named so it cannot be dropped as dead code, and never called: there
    // is no live pipe here, and the promise being checked is the type.
    let _ = read;

    let fresh = NetworkMetrics::default();
    // Ascribed rather than inferred: the promise being checked is that
    // every field is a plain integer, so rendering one is a format and not
    // a call into somebody's metrics crate.
    let ratelimited: u64 = fresh.relay_connections_ratelimited;
    let connections: u64 = fresh.relay_connections;
    let failed: u64 = fresh.relay_connections_failed;
    assert_eq!((ratelimited, connections, failed), (0, 0, 0));

    let copied = fresh; // Copy, not a move — `fresh` stays usable below.
    assert_eq!(copied, fresh, "two readings can be compared for sameness");
}

/// A ticket says what it carries, which is what lets an embedder find out
/// that the one it is about to print names no relay.
///
/// The relay comes back as a `String` and never as a parsed URL, because
/// the format spec makes carrying the body verbatim normative and every URL
/// library normalizes; the direct addresses come back as `std`'s own
/// `SocketAddr`, because there is nothing this crate could add to it. Both
/// halves are checked against a normative vector rather than a ticket built
/// here.
#[test]
fn a_dependent_can_ask_a_ticket_where_it_points() {
    // Vector 2 from docs/ticket-format-v0.md: one relay, one IPv4 address.
    let ticket: Ticket = "pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaqaaangq5duobztulzpojswyylzfzsxqylnobwgkltdn5ws6aiaa3akqaihcfiqbrp5xr4q"
        .parse()
        .expect("a normative vector");

    let relays: Vec<String> = ticket.relay_urls();
    assert_eq!(relays, ["https://relay.example.com/"]);
    let direct: Vec<std::net::SocketAddr> = ticket.direct_addrs();
    assert_eq!(
        direct,
        ["192.168.1.7:4433".parse::<std::net::SocketAddr>().unwrap()]
    );

    // Vector 1: the minimal ticket. Empty is the answer that matters, and
    // it is an empty list rather than an error — a ticket with no relay is
    // a valid ticket, just one that may reach nobody behind a strict NAT.
    let minimal: Ticket = "pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaaauhlp2na"
        .parse()
        .expect("a normative vector");
    assert!(minimal.relay_urls().is_empty());
    assert!(minimal.direct_addrs().is_empty());
}

/// The metrics snapshot serializes as the flat object a status DTO wants —
/// three named integers and no wrapper — under the same feature `PeerView`
/// is behind, for the same reason: an embedder rendering a status page opts
/// in with one line, and the CLI never pays for it.
#[cfg(feature = "serde")]
#[test]
fn a_dependents_dto_serializes_the_metrics_as_plain_numbers() {
    #[derive(serde::Serialize)]
    struct HealthDto {
        transport: NetworkMetrics,
    }
    let json = serde_json::to_string(&HealthDto {
        transport: NetworkMetrics::default(),
    })
    .expect("serializes");
    assert_eq!(
        json,
        r#"{"transport":{"relay_connections":0,"relay_connections_failed":0,"relay_connections_ratelimited":0}}"#,
        "the field names are the identifiers a dashboard keys on"
    );
}
