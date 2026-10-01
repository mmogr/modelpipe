//! The one way this crate's own code writes a status line to stderr.
//!
//! Stderr carries the lines a person reads rather than pipes: where the state
//! is kept, that a relay is being found, how an invite ended, a warning. A
//! write there can fail: the pipe a supervisor logs it through has gone, the
//! terminal has hung up, the disk it is redirected to is full. That failure
//! says nothing about the listener or the local port, so it must not end the
//! process, and `eprintln!` panics on it. `main.rs` denies `print_stderr` so
//! that every status line this crate's own code writes comes through here
//! instead, as every stdout line goes through [`crate::stdout::say`]. The
//! live status lines (`park.rs`), the serve window (`screen.rs`) and the
//! tracing layer (`diagnostics.rs`) write through writers of their own, and
//! drop a failed write too.

use std::io::Write;

/// Write `line` and a newline to stderr. A write that fails is dropped: the
/// line is lost and nothing else is.
pub(crate) fn say(line: &str) {
    say_to(&mut std::io::stderr().lock(), line);
}

/// [`say`], to `out`. Only the tests pass another writer.
fn say_to(out: &mut impl Write, line: &str) {
    let _ = writeln!(out, "{line}");
}

#[cfg(test)]
#[path = "stderr_tests.rs"]
mod stderr_tests;
