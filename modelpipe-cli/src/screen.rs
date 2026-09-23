//! What the serve window shows while keys are on: lines as they come, and
//! one line at the bottom that is rewritten in place.
//!
//! The bottom line is the code on offer and how long it has left. It is
//! rewritten every second and cleared when the code is spent, so the
//! terminal never scrolls a stale countdown into its history; everything
//! else — a status change, a device pairing, a list — is a line printed
//! above it, and the footer is put back beneath.
//!
//! Stderr only, by construction: the one writer this is ever built over
//! is the one `serve` already used for every line but the ticket, so the
//! contract that stdout holds the ticket and nothing else survives keys
//! untouched.

use std::io::Write;

/// Clear the line the cursor is on, from its start.
const CLEAR_LINE: &str = "\r\x1b[K";

/// The window, over whatever it writes to.
pub(crate) struct Screen<W: Write> {
    out: W,
    footer: Option<String>,
}

impl<W: Write> Screen<W> {
    pub(crate) const fn new(out: W) -> Self {
        Self { out, footer: None }
    }

    /// Print `text` as its own line, above the footer if there is one.
    /// Several lines at once are fine; each ends where a line ends.
    pub(crate) fn say(&mut self, text: &str) {
        let _ = match &self.footer {
            Some(footer) => write!(self.out, "{CLEAR_LINE}{text}\n{footer}"),
            None => writeln!(self.out, "{text}"),
        };
        let _ = self.out.flush();
    }

    /// Set, replace or clear the bottom line, redrawing it in place.
    pub(crate) fn footer(&mut self, footer: Option<String>) {
        let _ = match (&self.footer, &footer) {
            (None, None) => Ok(()),
            (_, Some(next)) => write!(self.out, "{CLEAR_LINE}{next}"),
            (Some(_), None) => write!(self.out, "{CLEAR_LINE}"),
        };
        self.footer = footer;
        let _ = self.out.flush();
    }
}

impl<W: Write> Drop for Screen<W> {
    /// Leave the cursor at the start of a fresh line, with no footer under
    /// it, so the shell's prompt does not land beside a countdown.
    fn drop(&mut self) {
        if self.footer.take().is_some() {
            let _ = write!(self.out, "{CLEAR_LINE}");
            let _ = self.out.flush();
        }
    }
}

#[cfg(test)]
#[path = "screen_tests.rs"]
mod screen_tests;
