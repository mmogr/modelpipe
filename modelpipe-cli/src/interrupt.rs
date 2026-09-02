//! Ctrl-C handling, which is the one place this CLI is platform code.
//!
//! Its own module because it is the only thing here that differs between
//! Unix and Windows, and because `main.rs` should read as argument parsing
//! and printing — which is what it claims to be.

/// A Ctrl-C listener that outlives `park`.
///
/// tokio installs its handler on first use and documents that it stays
/// installed for the life of the process — "even if this `Signal` instance
/// is dropped, subsequent SIGINT deliveries will end up captured by Tokio,
/// and the default platform behavior will NOT be reset". So a `park` that
/// created its own listener and returned left every later Ctrl-C going
/// nowhere: the first one entered `shutdown`, and if that took a while the
/// operator's only remaining option was `kill` from another terminal.
/// Keeping one listener alive across both phases is what makes the second
/// interrupt mean something.
///
/// The two platform types are the same idea under different names — a
/// stream that yields once per interrupt — which is why the whole
/// difference fits in the field and the constructor. What is *not*
/// interchangeable is `tokio::signal::ctrl_c()`: it is a one-shot future,
/// and the second Ctrl-C is the one that matters here.
pub(crate) struct Interrupt(
    #[cfg(unix)] tokio::signal::unix::Signal,
    #[cfg(windows)] tokio::signal::windows::CtrlC,
);

impl Interrupt {
    #[cfg(unix)]
    pub(crate) fn new() -> anyhow::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self(signal(SignalKind::interrupt())?))
    }

    #[cfg(windows)]
    pub(crate) fn new() -> anyhow::Result<Self> {
        Ok(Self(tokio::signal::windows::ctrl_c()?))
    }

    pub(crate) async fn next(&mut self) -> anyhow::Result<()> {
        self.0.recv().await;
        Ok(())
    }
}
