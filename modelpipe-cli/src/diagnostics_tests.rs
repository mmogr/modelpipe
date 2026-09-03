//! Tests for [`super`] — what a verbosity count lets through.
//!
//! Split out via `#[path]` so `diagnostics.rs` stays inside the file-size
//! budget.
//!
//! [`super::install`] is deliberately untested here. It sets a *global*
//! subscriber, which is a once-per-process act: a test that called it would
//! be the only test in the binary allowed to, and would make every other
//! test's outcome depend on running order. The mapping is where the
//! decisions are, and the mapping is a pure function.

use tracing::Level;

use super::targets;

/// The claim of level 0: quieter than a flag, but not silent.
///
/// A stream that fails mid-exchange is reported by the library at `warn`
/// and by nothing else anywhere — the listener discards the error, because
/// the peer it would have told is the thing that went away. If level 0
/// filtered that out, the default install would be strictly worse than the
/// `eprintln!`s it sits beside.
#[test]
fn the_default_hears_warnings_and_nothing_below_them() {
    let filter = targets(0);
    assert!(filter.would_enable("modelpipe", &Level::WARN));
    assert!(!filter.would_enable("modelpipe", &Level::INFO));
}

/// The claim of `-v`: one line per request.
///
/// The negative control is the level *below* it. A filter that enabled
/// `debug` here would drown the access log in per-connection detail from
/// the same crate, which is exactly what `-vv` is for.
#[test]
fn one_v_is_the_access_log_and_not_more() {
    let filter = targets(1);
    assert!(filter.would_enable("modelpipe", &Level::INFO));
    assert!(!filter.would_enable("modelpipe", &Level::DEBUG));
}

/// The transport stays out of it until asked for twice.
///
/// iroh and the stack under it instrument themselves for whoever is
/// debugging *them*. Both halves are asserted: silent at 0 and 1, audible
/// at 2 — because a filter that simply never mentioned `iroh` would pass
/// the first half on its own.
#[test]
fn the_transport_is_silent_until_the_second_v() {
    for quiet in [0, 1] {
        assert!(
            !targets(quiet).would_enable("iroh", &Level::ERROR),
            "-{} must not turn the transport on",
            "v".repeat(quiet as usize)
        );
    }
    assert!(targets(2).would_enable("iroh", &Level::INFO));
    assert!(!targets(2).would_enable("iroh", &Level::DEBUG));
}

/// Each step admits strictly more than the one before it.
///
/// The property nobody checks by reading the `match`: a ladder with a rung
/// that goes *down* — a `-vvv` quieter than `-vv` for some target — is a
/// flag that lies, and it is one transposed line away at any time.
#[test]
fn every_step_admits_everything_the_step_below_it_did() {
    const LEVELS: [Level; 5] = [
        Level::ERROR,
        Level::WARN,
        Level::INFO,
        Level::DEBUG,
        Level::TRACE,
    ];
    for verbosity in 0..4u8 {
        let quieter = targets(verbosity);
        let louder = targets(verbosity + 1);
        for target in ["modelpipe", "iroh"] {
            for level in &LEVELS {
                assert!(
                    !quieter.would_enable(target, level) || louder.would_enable(target, level),
                    "-v x{} dropped {target} at {level} that -v x{verbosity} allowed",
                    verbosity + 1
                );
            }
        }
    }
}

/// Beyond the ladder it saturates rather than wrapping or panicking.
///
/// `u8` counts what the operator typed, and somebody will type twenty of
/// them.
#[test]
fn more_vs_than_the_ladder_has_is_the_top_of_the_ladder() {
    let top = targets(3);
    for absurd in [4u8, 20, u8::MAX] {
        for level in [Level::TRACE, Level::DEBUG] {
            assert_eq!(
                targets(absurd).would_enable("modelpipe", &level),
                top.would_enable("modelpipe", &level)
            );
        }
    }
}

/// Nothing outside this workspace and iroh is ever turned on by a flag.
///
/// `-vvv` on a graph this size is otherwise thousands of lines of TLS
/// handshake before the first request, and an operator who wanted that has
/// `RUST_LOG`.
#[test]
fn no_verbosity_turns_on_the_rest_of_the_graph() {
    for verbosity in 0..=5u8 {
        for stranger in ["rustls", "hickory_resolver", "h2", "hyper_util"] {
            assert!(
                !targets(verbosity).would_enable(stranger, &Level::ERROR),
                "-v x{verbosity} turned on {stranger}"
            );
        }
    }
}
