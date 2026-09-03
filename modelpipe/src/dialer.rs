//! The connect side, running.
//!
//! Holds one QUIC connection to the serve side and a local TCP listener in
//! front of it. Every local connection gets its own bi-stream, because one
//! stream carries exactly one HTTP exchange — the same rule the listener
//! enforces, seen from the other end.
//!
//! This side deliberately does not parse HTTP. It moves bytes between a
//! local socket and a stream, and the serve edge is where a request is
//! read, checked and framed. Two parsers in one path is how the two come to
//! disagree, which is the whole shape of request smuggling.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use crate::ConnectError;
use crate::lifecycle::Lifecycle;
use crate::peer::Peer;
use crate::refusal;
use crate::ticket::Ticket;

/// Everything a live connect side shares.
pub(crate) struct ConnectState {
    pub(crate) peer: Peer,
    pub(crate) local_addr: SocketAddr,
    pub(crate) lifecycle: Lifecycle,
}

/// Dial the ticket's endpoint and bind the local listener.
pub(crate) async fn dial(
    ticket: &Ticket,
    bind: Option<SocketAddr>,
) -> Result<(Arc<ConnectState>, TcpListener), ConnectError> {
    // The caller's own values first, which is the order `serve` states as a
    // rule: "checking the cheap, user-fixable things first means a typo is
    // reported as a typo rather than after a socket has been opened". This
    // side had it backwards, so an occupied `--bind` port plus an
    // unreachable peer spent thirty seconds dialling and then reported the
    // retryable `PeerUnreachable` — sending a supervisor into a
    // thirty-second-per-attempt spin over a port it could have been told
    // about immediately.
    //
    // Loopback by default. The local port is the one hop with no encryption
    // in front of it, so leaving this machine is a choice the caller makes
    // explicitly rather than one the default makes for them.
    let requested = bind.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
    let listener = TcpListener::bind(requested)
        .await
        .map_err(ConnectError::Bind)?;
    let local_addr = listener.local_addr().map_err(ConnectError::Bind)?;

    let peer = Peer::dial(ticket).await?;

    // Published here, before the handle exists, rather than from the accept
    // loop that used to own it. A spawned task has not necessarily run by
    // the time `connect` returns, so `status()` read on the next line was
    // `Idle` on a working pipe — which is the value this side uses to mean
    // "the peer is gone", so the one moment the answer was wrong it was
    // wrong in the most misleading direction available. Every change after
    // this is `keep_connected`'s.
    let lifecycle = Lifecycle::new();
    peer.publish_path(&lifecycle);

    Ok((
        Arc::new(ConnectState {
            peer,
            local_addr,
            lifecycle,
        }),
        listener,
    ))
}

/// Accept local connections and pair each with its own bi-stream.
pub(crate) async fn local_loop(state: Arc<ConnectState>, listener: TcpListener) {
    loop {
        let accepted = tokio::select! {
            // Biased so that teardown wins a tie: a `shutdown` racing an
            // incoming connection should stop accepting rather than take one
            // more.
            biased;
            () = state.lifecycle.wait_until_closed() => break,
            accepted = listener.accept() => accepted,
        };
        let local = match accepted {
            Ok((local, _)) => local,
            // A transient accept failure is not the end of the listener.
            // `ECONNABORTED` is a client that reset between SYN and accept
            // — routine on any open port — and `EMFILE`/`ENFILE` are a
            // process-wide condition that clears. Breaking here unbound the
            // advertised port while `local_addr` went on naming it, left
            // the status at `Idle` forever, and freed the port for any
            // local process to take, with the next request's bearer token
            // in it.
            Err(e) if transient(&e) => continue,
            Err(_) => break,
        };

        let state = state.clone();
        // Registered before the spawn, so a drain cannot observe zero while
        // this exchange is starting. `carry` owns it from here and releases
        // it early for a connection that turns out not to be an exchange.
        let guard = state.lifecycle.enter();
        tokio::spawn(async move {
            let _ = carry(&state, local, guard).await;
        });
    }

    // Dropped here, explicitly, before anything is told teardown finished.
    // The listener owns the port, so "shutdown returned" can only mean "the
    // port is free" if the value that holds it is gone first — which is the
    // whole reason `mark_torn_down` is separate from publishing `Closed`.
    drop(listener);
    // The loop can also end without anyone asking — a permanent accept
    // failure. The pipe is over either way, and a watcher that is never told
    // waits on a status that will not change again.
    state.lifecycle.close();
    state.lifecycle.mark_torn_down();
}

/// Whether an accept failure is worth retrying rather than ending the
/// listener over.
fn transient(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::{ConnectionAborted, Interrupted, OutOfMemory, WouldBlock};
    matches!(
        e.kind(),
        ConnectionAborted | Interrupted | WouldBlock | OutOfMemory
    ) || e.raw_os_error() == Some(24)  // EMFILE
        || e.raw_os_error() == Some(23) // ENFILE
}

/// Carry one local connection over one bi-stream.
///
/// `guard` is the in-flight registration taken at accept, and this function
/// is where it is decided whether that registration means anything. A
/// socket that has been accepted but has said nothing is not an exchange:
/// an SDK preconnect or a health probe is exactly that shape, and
/// `copy_bidirectional` never returns for one, so holding the guard made a
/// single silent connection wedge `shutdown`'s drain permanently.
async fn carry(
    state: &ConnectState,
    mut local: tokio::net::TcpStream,
    guard: crate::lifecycle::InFlight,
) -> std::io::Result<()> {
    // Wait for the client to say something, or for teardown, whichever
    // comes first. `peek` leaves the byte where it is for the copy below.
    let mut first = [0u8; 1];
    tokio::select! {
        biased;
        () = state.lifecycle.wait_until_closed() => return Ok(()),
        peeked = local.peek(&mut first) => {
            if peeked? == 0 {
                return Ok(());
            }
        }
    }
    // Only now is this an exchange the drain must wait for.
    let _guard = guard;

    let opened = match state.peer.current() {
        Some(connection) => connection.open_bi().await,
        // No connection at all right now — the peer is away and
        // `keep_connected` is looking for it. Same answer as a dead one,
        // for the same reason: this end owes the client a status rather
        // than a reset.
        None => return refuse_locally(&mut local).await,
    };
    let Ok((send, recv)) = opened else {
        // The serve edge answers a backend it cannot reach with a 502, and
        // this end owes a client whose tunnel is gone the same. The socket
        // used to be dropped unread, so an SDK saw a connection reset with
        // no status: "the tunnel is down" and "nothing is listening here"
        // were the same event. `open_bi` fails only when the connection is
        // dead — stream-budget exhaustion back-pressures instead — so this
        // arm is exactly that case.
        return refuse_locally(&mut local).await;
    };
    let mut remote = tokio::io::join(recv, send);

    // Opaque in both directions. `copy_bidirectional` finishes when both
    // halves have seen EOF, which for one exchange per stream is exactly
    // when the response is complete.
    tokio::io::copy_bidirectional(&mut local, &mut remote)
        .await
        .map(|_| ())
}

/// Answer a client this side cannot serve, and make sure it arrives.
///
/// The drain is not politeness, and leaving it out is how this refusal
/// silently became the thing it was written to replace. The request was
/// *peeked* rather than read — `carry` leaves the bytes where they are so
/// the copy below can forward them — so they are still sitting in this
/// socket's receive queue. Closing a socket with unread data in it sends an
/// RST rather than a FIN, and an RST makes the kernel discard whatever it
/// had already queued to send, refusal included.
///
/// Measured, before the drain: the client got `ECONNRESET` and no status at
/// all, which is exactly the "connection reset with nothing to say"
/// experience the 502 exists to end.
///
/// Shutting down the write half first is what makes the drain terminate: it
/// gives the client its EOF, so it stops reading, closes, and this side's
/// read returns zero. The deadline is for the client that does neither.
async fn refuse_locally(local: &mut tokio::net::TcpStream) -> std::io::Result<()> {
    local.write_all(&refusal::bad_gateway()).await?;
    local.flush().await?;
    let _ = local.shutdown().await;

    let mut discard = [0u8; 4096];
    let _ = tokio::time::timeout(REFUSAL_DRAIN, async {
        while matches!(local.read(&mut discard).await, Ok(n) if n > 0) {}
    })
    .await;
    Ok(())
}

/// How long to spend letting a refused client take its answer.
///
/// Short: nothing is being served here, the response is a hundred-odd
/// bytes, and the only thing being waited for is the client noticing the
/// end of the stream.
const REFUSAL_DRAIN: Duration = Duration::from_secs(5);

/// Stop accepting, drain, and release.
pub(crate) async fn shutdown(state: &ConnectState) {
    state.lifecycle.close();
    state.lifecycle.wait_until_drained().await;
    state.peer.close(b"shutdown");
    // Waits for the accept loop to notice the close and drop the listener.
    // Without this the port is still bound when this returns, and a caller
    // that rebinds immediately gets EADDRINUSE — which is not a theoretical
    // hazard: it is what the integration test caught.
    state.lifecycle.wait_until_torn_down().await;
}

/// [`shutdown`] with a deadline on the drain, reporting whether it was met.
///
/// The deadline covers the drain and nothing else. `mark_torn_down` is not
/// called here and must not be: `local_loop` still owns the `TcpListener`,
/// and it is the loop that knows when the port is free. Setting the latch
/// from outside returned `true` with the port still bound — and left the
/// latch set, so a later `shutdown` lost the same guarantee.
pub(crate) async fn shutdown_timeout(state: &ConnectState, grace: Duration) -> bool {
    state.lifecycle.close();
    let drained = tokio::time::timeout(grace, state.lifecycle.wait_until_drained())
        .await
        .is_ok();
    state.peer.close(b"shutdown");
    state.lifecycle.wait_until_torn_down().await;
    drained
}
