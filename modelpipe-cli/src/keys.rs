//! One key at a time from the terminal `serve` is running in.
//!
//! The window serve runs in is the one place a person is already looking,
//! so it is where a device is invited, listed or forgotten while the pipe
//! is up. That takes a key per read rather than a line per read, which is
//! the terminal's *cbreak* mode: canonical input and echo off, everything
//! else — signals above all — left as it was. Ctrl-C stays a signal, so
//! the shutdown path is the one every other run takes; and the mode is put
//! back on every way out but SIGKILL, by a guard `main` holds, so a
//! `kill` from another window does not leave the shell without echo.
//!
//! The read blocks, so it runs on a thread of its own, and the two sides
//! take turns: the loop asks for a key, the thread reads one and hands it
//! over, and it reads nothing more until asked again. That handshake is
//! what lets the loop ask for a whole *line* — a device to forget — with the
//! terminal back in its ordinary mode and nobody else reading from it.
//!
//! Only when both stdin and stderr are terminals. Piped, supervised, or
//! under CI with stdin closed, nothing here runs and serve behaves exactly
//! as it did before keys existed.

use std::io::{self, IsTerminal as _};

use tokio::sync::mpsc;

/// What the loop asks of the reader thread.
enum Ask {
    /// One key, in cbreak.
    Key,
    /// One line, echoed, with the terminal cooked for the duration.
    Line,
}

/// What the reader thread hands back.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    all(not(unix), not(test)),
    expect(dead_code, reason = "only the Unix reader thread constructs these")
)]
pub(crate) enum Got {
    /// A key was pressed.
    Key(char),
    /// The line typed, without its newline.
    Line(String),
    /// Stdin closed, or a read failed: keys are over for this run.
    Closed,
}

/// The keyboard, while serve runs. Dropping it puts the terminal back.
pub(crate) struct Keys {
    asks: std::sync::mpsc::Sender<Ask>,
    got: mpsc::Receiver<Got>,
    /// Whether a key has been asked for and not yet received, so a `next`
    /// dropped by a `select!` does not ask twice.
    asked: bool,
    #[cfg(unix)]
    _restore: Option<Restore>,
}

impl Keys {
    /// The keyboard, when there is one: stdin and stderr are both
    /// terminals, and the mode could be set. `None` otherwise, and serve
    /// runs as it always has.
    pub(crate) fn open() -> Option<Self> {
        if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
            return None;
        }
        Self::attach()
    }

    #[cfg(unix)]
    fn attach() -> Option<Self> {
        let original = rustix::termios::tcgetattr(io::stdin()).ok()?;
        let (asks, asked_for) = std::sync::mpsc::channel::<Ask>();
        let (give, got) = mpsc::channel::<Got>(1);
        // A plain thread rather than `spawn_blocking`: tokio's blocking pool
        // is waited on at shutdown, and a thread parked in `read` on a
        // keyboard nobody is touching would hold the exit for its timeout.
        // The OS ends this one with the process.
        let restore = Restore {
            original: original.clone(),
        };
        std::thread::spawn(move || {
            let mode = Mode { original };
            while let Ok(ask) = asked_for.recv() {
                let got = match ask {
                    Ask::Key => mode.cbreak().and_then(|()| read_key()),
                    Ask::Line => mode.cooked().and_then(|()| read_line()),
                };
                let got = got.unwrap_or(Got::Closed);
                let over = matches!(got, Got::Closed);
                if give.blocking_send(got).is_err() || over {
                    break;
                }
            }
            let _ = mode.cooked();
        });
        Some(Self {
            asks,
            got,
            asked: false,
            _restore: Some(restore),
        })
    }

    #[cfg(not(unix))]
    fn attach() -> Option<Self> {
        None
    }

    /// A keyboard that presses `script` in order, for the tests, and then
    /// resolves `done` the moment the loop asks for a key it does not have,
    /// which is after the last one was acted on: the loop asks for the next
    /// key only once it is finished with the last.
    #[cfg(test)]
    pub(crate) fn scripted(script: &[Got], done: tokio::sync::oneshot::Sender<()>) -> Self {
        let mut script: std::collections::VecDeque<Got> = script.iter().map(Got::clone).collect();
        let (asks, asked_for) = std::sync::mpsc::channel::<Ask>();
        let (give, got) = mpsc::channel::<Got>(1);
        std::thread::spawn(move || {
            let mut done = Some(done);
            while asked_for.recv().is_ok() {
                let Some(next) = script.pop_front() else {
                    if let Some(done) = done.take() {
                        let _ = done.send(());
                    }
                    let _ = give.blocking_send(Got::Closed);
                    return;
                };
                if give.blocking_send(next).is_err() {
                    return;
                }
            }
        });
        Self {
            asks,
            got,
            asked: false,
            #[cfg(unix)]
            _restore: None,
        }
    }

    /// The next key, or the line asked for. `None` once the keyboard is
    /// gone, after which it stays gone.
    ///
    /// Cancel-safe: a call dropped before it resolves has still asked, and
    /// the next call collects the answer rather than asking again.
    pub(crate) async fn next(&mut self) -> Option<Got> {
        if !self.asked {
            self.asks.send(Ask::Key).ok()?;
            self.asked = true;
        }
        let got = self.got.recv().await;
        self.asked = false;
        got
    }

    /// One line, typed with the terminal cooked and echo on. `None` once
    /// the keyboard is gone. Only between keys: never while a `next` is
    /// pending, which the loop's own shape guarantees.
    pub(crate) async fn line(&mut self) -> Option<String> {
        self.asks.send(Ask::Line).ok()?;
        match self.got.recv().await? {
            Got::Line(line) => Some(line),
            Got::Key(_) | Got::Closed => None,
        }
    }
}

/// The terminal's mode, set for one read at a time on the reader thread.
#[cfg(unix)]
struct Mode {
    original: rustix::termios::Termios,
}

#[cfg(unix)]
impl Mode {
    /// A key per read, unechoed. Signals stay on.
    fn cbreak(&self) -> io::Result<()> {
        use rustix::termios::{LocalModes, OptionalActions, SpecialCodeIndex, tcsetattr};
        let mut mode = self.original.clone();
        mode.local_modes
            .remove(LocalModes::ICANON | LocalModes::ECHO);
        mode.special_codes[SpecialCodeIndex::VMIN] = 1;
        mode.special_codes[SpecialCodeIndex::VTIME] = 0;
        tcsetattr(io::stdin(), OptionalActions::Now, &mode).map_err(io::Error::from)
    }

    /// As the shell left it.
    fn cooked(&self) -> io::Result<()> {
        use rustix::termios::{OptionalActions, tcsetattr};
        tcsetattr(io::stdin(), OptionalActions::Now, &self.original).map_err(io::Error::from)
    }
}

/// Puts the terminal back when serve ends, however it ends. The reader
/// thread may be parked in a read under cbreak at that moment, and a
/// process exit does not undo `tcsetattr`; this does.
#[cfg(unix)]
struct Restore {
    original: rustix::termios::Termios,
}

#[cfg(unix)]
impl Drop for Restore {
    fn drop(&mut self) {
        use rustix::termios::{OptionalActions, tcsetattr};
        let _ = tcsetattr(io::stdin(), OptionalActions::Now, &self.original);
    }
}

/// One byte, as the key it is. Anything past ASCII — an arrow, a
/// multi-byte character — arrives as bytes this reports one at a time,
/// and none of them is a key the loop acts on.
#[cfg(unix)]
fn read_key() -> io::Result<Got> {
    use std::io::Read as _;
    let mut byte = [0u8; 1];
    let read = io::stdin().lock().read(&mut byte)?;
    match read {
        0 => Ok(Got::Closed),
        _ => Ok(Got::Key(char::from(byte[0]))),
    }
}

/// One line, without its newline.
#[cfg(unix)]
fn read_line() -> io::Result<Got> {
    use std::io::BufRead as _;
    let mut line = String::new();
    let read = io::stdin().lock().read_line(&mut line)?;
    match read {
        0 => Ok(Got::Closed),
        _ => Ok(Got::Line(line.trim_end_matches(['\r', '\n']).to_owned())),
    }
}
