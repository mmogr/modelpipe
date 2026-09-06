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
use std::time::Duration;

use modelpipe::PipeStatus;

use crate::interrupt::Interrupt;

/// How long a fresh connect side may sit at `Idle` before this command
/// gives up on the serve side.
///
/// Not a library default, and deliberately not one. `connect` returns as
/// soon as the local port is bound and then keeps trying for as long as the
/// handle lives, because a sleeping laptop, a dead one and a serve side
/// five seconds from starting look identical from down there — so the
/// deadline belongs to whoever is willing to give up, which for an
/// interactive command is this one.
///
/// Longer than the thirty-odd seconds iroh spends giving up on a peer that
/// is not there. Under that, this would report an absent peer while the
/// first dial was still in flight, which is a worse answer than the slow
/// one it replaced.
pub(crate) const FIRST_CONTACT: Duration = Duration::from_secs(40);

/// Park until a shutdown signal, reporting the transport path and every
/// change to it.
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

/// Wait for the pipe to reach the serve side, or say that it could not.
///
/// This is the sentence `connect` used to produce. It blocked until the
/// first dial landed and reported an absent peer through its `Result`;
/// it now returns with the local port bound and the dial still running, so
/// the wait — and the deadline it needs — moved out here rather than
/// disappearing. The wording is the one `ConnectError::PeerUnreachable`
/// printed, because it is the same fact reported from one step further out.
///
/// Nothing is printed on the way to stdout until this returns `Ok`, which
/// is the other half of not regressing: a script capturing the URL gets one
/// only for a pipe that actually reached its peer, exactly as before.
///
/// `grace` is [`FIRST_CONTACT`] everywhere but the tests, which pass a
/// short one so that checking the decision does not mean waiting out the
/// number.
pub(crate) async fn first_contact(
    mut status: impl AsyncStatus,
    grace: Duration,
) -> anyhow::Result<()> {
    let reached = tokio::time::timeout(grace, async {
        // The current value first. `changed` snapshots at the moment it is
        // polled, so a pipe that connected before this ran has nothing left
        // to report and waiting alone would sit here until the deadline.
        let mut now = status.current();
        while now == PipeStatus::Idle {
            now = status.changed().await;
        }
        now
    })
    .await;
    match reached {
        // A pipe that closed without ever connecting is the same news, and
        // there is nothing left to wait for either way.
        Ok(PipeStatus::Closed) | Err(_) => {
            anyhow::bail!("could not reach the serve side, directly or via a relay")
        }
        Ok(_) => Ok(()),
    }
}

/// Shut down gracefully, unless the operator asks again.
///
/// The graceful path can legitimately take a while — it is waiting for
/// admitted requests to finish, which is the whole promise — so a second
/// signal has to be able to stop waiting. Dropping the handle is the cut,
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

#[cfg(test)]
#[path = "park_tests.rs"]
mod park_tests;
