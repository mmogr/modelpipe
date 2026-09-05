//! Shutdown-signal handling, which is the one place this CLI is platform
//! code.
//!
//! Its own module because it is the only thing here that differs between
//! Unix and Windows, and because `main.rs` should read as argument parsing
//! and printing — which is what it claims to be.

/// A shutdown-signal listener that outlives `park`.
///
/// tokio installs its handler on first use and documents that it stays
/// installed for the life of the process — "even if this `Signal` instance
/// is dropped, subsequent SIGINT deliveries will end up captured by Tokio,
/// and the default platform behavior will NOT be reset". So a `park` that
/// created its own listener and returned left every later signal going
/// nowhere: the first one entered `shutdown`, and if that took a while the
/// operator's only remaining option was `kill -9` from another terminal.
/// Keeping one listener alive across both phases is what makes the second
/// signal mean something.
///
/// **On Unix that means SIGINT and SIGTERM alike.** Ctrl-C is what a person
/// at a terminal sends; SIGTERM is what everything else sends — `kill` with
/// no argument, systemd stopping a unit, Docker stopping a container. Both
/// mean "stop", so both get the drain that lets an admitted request finish.
/// Handling only the first left the case that matters most under a service
/// manager taking the default disposition instead: immediate death, every
/// in-flight response cut mid-body. The two arrive as separate streams and
/// are merged here, so which one was sent never reaches the rest of the CLI
/// — the phase an interrupt lands in is what decides its meaning, not its
/// number.
///
/// The platform types are the same idea under different names — a stream
/// that yields once per signal — which is why the whole difference fits in
/// the fields and the constructor. What is *not* interchangeable is
/// `tokio::signal::ctrl_c()`: it is a one-shot future, and the second
/// signal is the one that matters here.
pub(crate) struct Interrupt {
    #[cfg(unix)]
    sigint: tokio::signal::unix::Signal,
    #[cfg(unix)]
    sigterm: tokio::signal::unix::Signal,
    #[cfg(windows)]
    ctrl_c: tokio::signal::windows::CtrlC,
}

impl Interrupt {
    #[cfg(unix)]
    pub(crate) fn new() -> anyhow::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            sigint: signal(SignalKind::interrupt())?,
            sigterm: signal(SignalKind::terminate())?,
        })
    }

    #[cfg(windows)]
    pub(crate) fn new() -> anyhow::Result<Self> {
        Ok(Self {
            ctrl_c: tokio::signal::windows::ctrl_c()?,
        })
    }

    /// Resolve when either signal arrives.
    ///
    /// `Signal::recv` is cancel-safe, which is what lets this be one arm of
    /// a larger `select!` in `park` and be dropped un-resolved every time
    /// the status arm wins: a signal delivered to a dropped `recv` is still
    /// waiting on the next call rather than lost.
    #[cfg(unix)]
    pub(crate) async fn next(&mut self) -> anyhow::Result<()> {
        tokio::select! {
            _ = self.sigint.recv() => {}
            _ = self.sigterm.recv() => {}
        }
        Ok(())
    }

    /// Resolve when Ctrl-C arrives. There is no SIGTERM here: Windows
    /// console applications are stopped through control events, and the
    /// close and shutdown ones are a separate question from this change.
    #[cfg(windows)]
    pub(crate) async fn next(&mut self) -> anyhow::Result<()> {
        self.ctrl_c.recv().await;
        Ok(())
    }
}
