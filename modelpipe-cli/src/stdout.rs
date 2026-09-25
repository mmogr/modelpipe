//! The one way this crate's own code writes to stdout.
//!
//! Stdout carries the lines a person pipes or copies: the ticket, the token,
//! a pairing string, a QR code of the ticket or the pairing string, a base
//! URL and a key. Whatever reads them may be gone before they are written
//! (in `serve … | head -1`, `head` exits after the ticket and closes its end
//! of the pipe), and a write to a pipe whose reader has closed it fails.
//! That failure says nothing about the listener or the local port the line
//! describes, which are up and carrying requests, so it must not end the
//! process. `println!` panics on it; `main.rs` denies `print_stdout` so that
//! every stdout line this crate's own code writes comes through here
//! instead. Clap writes `--help`, `help` and `--version` to stdout itself.

use std::io::Write as _;

/// Write `line` and a newline to stdout, and say whether they got there.
///
/// `true` says stdout took the line, not that anything read it: a pipe
/// whose reader has not closed it can take a line nothing ever reads.
/// Flushed before returning. Std's stdout writes a line through at its
/// newline today, so the flush changes nothing now; it keeps a reader that
/// has gone noticed at this line, not at a later write, if stdout is ever
/// block-buffered. When this is `false` for the key `connect` redeems or a
/// token `serve` generates, the caller says so on stderr, without the
/// credential.
pub(crate) fn say(line: &str) -> bool {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}").and_then(|()| out.flush()).is_ok()
}
