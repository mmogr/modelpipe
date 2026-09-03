//! Waiting on a live pipe, and letting go of it.
//!
//! Split from `main.rs` when the file-size gate said it was holding two
//! things: parsing what the operator typed, and then sitting on the result
//! until they ask for it back. This is the second. `interrupt.rs` beside it
//! owns hearing the ask; this owns what happens either side of it.
//!
//! Both halves of the CLI end up here, which is why the trait exists at
//! all — the two handles deliberately share none, and inventing a public
//! one in the library to save a few lines in a CLI would put it on a
//! surface that has to live with it.

use std::future::Future;

use modelpipe::PipeStatus;

use crate::interrupt::Interrupt;

/// Park until Ctrl-C, reporting the transport path and every change to it.
///
/// `Relayed` is worth surfacing: it explains latency, and a user who does
/// not know their traffic is going through a relay has no way to guess why
/// the pipe feels slow. `Idle` on the connect side is worth more — it is
/// the only thing that says the far end has gone away and this side is
/// looking for it.
///
/// The starting value is printed rather than waited for, which is not
/// belt-and-braces. `status_changed` compares against the status at the
/// moment it is called, so a pipe that reached `Direct` before this
/// function was first polled has nothing left to report — and that race is
/// real: the connect side publishes its path before the first accept, and
/// its `status:` line appeared in two runs out of three.
pub(crate) async fn park(
    mut status: impl AsyncStatus,
    interrupt: &mut Interrupt,
) -> anyhow::Result<()> {
    eprintln!("status: {}", status.current().as_str());
    loop {
        tokio::select! {
            r = interrupt.next() => {
                r?;
                return Ok(());
            }
            next = status.changed() => {
                eprintln!("status: {}", next.as_str());
                if next == PipeStatus::Closed {
                    return Ok(());
                }
            }
        }
    }
}

/// Shut down gracefully, unless the operator asks again.
///
/// The graceful path can legitimately take a while — it is waiting for
/// admitted requests to finish, which is the whole promise — so the second
/// Ctrl-C has to be able to stop waiting. Dropping the handle is the cut,
/// and returning from here does exactly that.
pub(crate) async fn shut_down(handle: impl Future<Output = ()>, interrupt: &mut Interrupt) {
    tokio::select! {
        () = handle => {}
        _ = interrupt.next() => {
            eprintln!("interrupted again — cutting rather than waiting");
        }
    }
}

/// The one thing `park` needs from either handle.
///
/// A trait here rather than in the library: the two handles deliberately
/// share none, and inventing a public one to save a few lines in a CLI
/// would put it on a surface that has to live with it.
pub(crate) trait AsyncStatus {
    fn current(&self) -> PipeStatus;
    fn changed(&mut self) -> impl Future<Output = PipeStatus>;
}

impl AsyncStatus for modelpipe::ServeHandle {
    fn current(&self) -> PipeStatus {
        self.status()
    }

    async fn changed(&mut self) -> PipeStatus {
        self.status_changed().await
    }
}

impl AsyncStatus for modelpipe::ConnectHandle {
    fn current(&self) -> PipeStatus {
        self.status()
    }

    async fn changed(&mut self) -> PipeStatus {
        self.status_changed().await
    }
}

impl<T: AsyncStatus> AsyncStatus for &mut T {
    fn current(&self) -> PipeStatus {
        (**self).current()
    }

    async fn changed(&mut self) -> PipeStatus {
        (**self).changed().await
    }
}
