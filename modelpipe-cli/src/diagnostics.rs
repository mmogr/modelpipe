//! Turning `-v` into somewhere for the library's events to go.
//!
//! Split from `main.rs` the way `interrupt.rs` and `park.rs` were: that
//! file parses what the operator typed, and deciding what a verbosity count
//! means is a separate question with its own answer to defend.
//!
//! The library emits [`tracing`] events and installs no subscriber, which
//! leaves exactly one place in this workspace allowed to choose where they
//! go. This is it. Everything below is about two risks that pull against
//! each other: a `-v` that says nothing useful, and a `-v` that buries what
//! is useful under somebody else's internals.

use std::str::FromStr as _;

use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

/// Every event this workspace emits arrives under this one target.
///
/// One entry covers the library *and* this binary, which looks like a bug
/// and is not: the `[[bin]]` target here is named `modelpipe`, so `rustc`
/// compiles it with that crate name and `module_path!()` — which is what a
/// `tracing` target defaults to — says `modelpipe` for both. A second
/// `modelpipe_cli` entry would match nothing at all.
const OURS: &str = "modelpipe";

/// The transport, which is the only dependency worth naming.
///
/// It is also the loudest. iroh, and the hickory/h2/rustls stack under it,
/// instrument themselves thoroughly and at levels that assume somebody is
/// debugging *them* — so the default for this one is off, and turning it on
/// is a deliberate second and third `-v`.
const TRANSPORT: &str = "iroh";

/// What a verbosity count means.
///
/// Pure and separate from [`install`] so it can be tested, which is the same
/// reason `token_policy` in `main.rs` is a function: the interesting claim
/// is about the mapping, and checking it should not need a process or a
/// global subscriber.
///
/// The shape of the ladder is the argument. Level 0 is not silence — a
/// stream that fails mid-exchange is a real event with nobody else to
/// report it, and an operator who never passed a flag should still hear
/// about it. Level 1 is the access log: one line per request, one per peer
/// arriving and leaving, and nothing from the transport. Only at 2 does
/// anything below this workspace get a say, because the first question
/// `-vv` is asked is "why will it not pair", and that answer lives in iroh.
///
/// There is deliberately no level that turns the whole dependency graph to
/// `trace`. It is not a verbosity, it is a firehose — hickory and rustls at
/// `trace` produce thousands of lines before the first request — and
/// `RUST_LOG` is the escape hatch for anyone who genuinely wants it.
pub(crate) fn targets(verbosity: u8) -> Targets {
    match verbosity {
        0 => Targets::new().with_target(OURS, LevelFilter::WARN),
        1 => Targets::new().with_target(OURS, LevelFilter::INFO),
        2 => Targets::new()
            .with_target(OURS, LevelFilter::DEBUG)
            .with_target(TRANSPORT, LevelFilter::INFO),
        _ => Targets::new()
            .with_target(OURS, LevelFilter::TRACE)
            .with_target(TRANSPORT, LevelFilter::DEBUG),
    }
}

/// Whether a line names the target it came from.
///
/// Pure and separate for the same reason [`targets`] is: it is a decision
/// with an argument behind it, and the argument is checkable without a
/// process or a global subscriber.
///
/// The column is worth its width only when more than one target can appear.
/// That is the second `-v` — and *any* `RUST_LOG`, which is the case that
/// makes this a function rather than a comparison. `RUST_LOG` replaces the
/// ladder wholesale, and `Targets` accepts a bare level, so the ordinary
/// `RUST_LOG=debug` admits the entire dependency graph. Keying the column
/// off the `-v` count alone hid it in precisely the configuration with the
/// most targets to tell apart.
pub(crate) const fn shows_target(verbosity: u8, env_in_force: bool) -> bool {
    verbosity >= 2 || env_in_force
}

/// Install the subscriber for this run.
///
/// **stderr, not stdout**, and that is load-bearing rather than
/// conventional. `serve` prints the ticket and the token on stdout so they
/// can be piped somewhere; `modelpipe serve … | head -1` is a thing people
/// do, and a diagnostic on that stream corrupts the one output this program
/// has that another program reads. The same rule the ephemeral-identity
/// note in `main.rs` already follows, for the same reason.
///
/// `RUST_LOG` replaces the computed filter rather than adding to it: half a
/// filter from a flag and half from the environment is a filter nobody can
/// predict from either. A value that does not parse is reported and then
/// ignored — a typo in an environment variable should not stop a tunnel
/// coming up.
pub(crate) fn install(verbosity: u8) {
    // A value that does not parse is reported and then ignored: a typo in an
    // environment variable should not stop a tunnel coming up, and a silent
    // fallback would leave the operator wondering why their filter did
    // nothing.
    let from_env = std::env::var("RUST_LOG").ok().and_then(|raw| {
        Targets::from_str(&raw)
            .inspect_err(|e| eprintln!("warning: ignoring RUST_LOG, which does not parse: {e}"))
            .ok()
    });
    // Whether the ladder is in force at all decides the target column
    // below, so the two cannot drift apart.
    let env_in_force = from_env.is_some();
    let filter = from_env.unwrap_or_else(|| targets(verbosity));

    // No ANSI: these lines may be going to a file or a pipe as readily as
    // to a terminal, and escape codes in a log file are what makes `grep`
    // miss.
    //
    // See `shows_target` for when the target column earns its width.
    let layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_target(shows_target(verbosity, env_in_force));

    tracing_subscriber::registry()
        .with(layer)
        .with(filter)
        .init();
}

#[cfg(test)]
#[path = "diagnostics_tests.rs"]
mod diagnostics_tests;
