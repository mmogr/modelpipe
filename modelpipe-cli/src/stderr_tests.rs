//! Tests for [`super`]: a status line is written whole, and a stderr that
//! cannot take it is not a panic.

use std::io::{self, Write};

use super::say_to;

/// A stderr whose reader has gone: every write fails, and each one is
/// counted, so a test can tell a write that failed from one never tried.
#[derive(Default)]
struct Gone {
    tried: usize,
}

impl Write for Gone {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        self.tried += 1;
        Err(io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::BrokenPipe.into())
    }
}

#[test]
fn a_status_line_is_written_with_its_newline() {
    let mut out = Vec::new();
    say_to(&mut out, "finding a relay…");
    assert_eq!(out, "finding a relay…\n".as_bytes());
}

/// `eprintln!` panics here. The helper tries the write, and returns.
#[test]
fn a_stderr_that_cannot_take_the_line_is_not_a_panic() {
    let mut gone = Gone::default();
    say_to(&mut gone, "finding a relay…");
    assert!(gone.tried > 0, "the line was never tried");
}
