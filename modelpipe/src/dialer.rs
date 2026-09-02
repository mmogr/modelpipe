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

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use iroh::Endpoint;
use iroh::endpoint::Connection;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpListener;

use crate::ConnectError;
use crate::lifecycle::{Lifecycle, PeerPath, aggregate};
use crate::refusal;
use crate::ticket::Ticket;
use crate::transport;

/// Everything a live connect side shares.
pub(crate) struct ConnectState {
    /// Kept so the endpoint outlives the connection opened on it.
    _endpoint: Endpoint,
    pub(crate) connection: Connection,
    pub(crate) local_addr: SocketAddr,
    pub(crate) lifecycle: Lifecycle,
}

/// Dial the ticket's endpoint and bind the local listener.
pub(crate) async fn dial(
    ticket: &Ticket,
    bind: Option<SocketAddr>,
) -> Result<(Arc<ConnectState>, TcpListener), ConnectError> {
    let addr = transport::addr_from(ticket)?;
    let endpoint = transport::bind(None).await?;

    let connection = endpoint
        .connect(addr, transport::ALPN)
        .await
        // Everything a dial can fail with is retryable, and there is no
        // "rejected" case to tell apart: the endpoint key is ephemeral, so a
        // serve side that restarted is a different endpoint and this reaches
        // nobody rather than reaching someone who refuses.
        .map_err(|_| ConnectError::PeerUnreachable)?;

    // Loopback by default. The local port is the one hop with no encryption
    // in front of it, so leaving this machine is a choice the caller makes
    // explicitly rather than one the default makes for them.
    let requested = bind.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
    let listener = TcpListener::bind(requested)
        .await
        .map_err(ConnectError::Bind)?;
    let local_addr = listener.local_addr().map_err(ConnectError::Bind)?;

    Ok((
        Arc::new(ConnectState {
            _endpoint: endpoint,
            connection,
            local_addr,
            lifecycle: Lifecycle::new(),
        }),
        listener,
    ))
}

/// How this side is reaching the peer, read from the live connection.
///
/// The serve side has had this since it landed; this side published nothing
/// at all, so `status()` was permanently `Idle` on a working pipe and
/// `Direct`/`Relayed` were unreachable here however the traffic actually
/// flowed. Same snapshot semantics as the serve side, and the same honest
/// limit: a path that migrates after this is read is not followed yet.
fn peer_path(connection: &Connection) -> PeerPath {
    connection
        .paths()
        .iter()
        .find(iroh::endpoint::Path::is_selected)
        .map_or(PeerPath::Relayed, |p| {
            if p.remote_addr().is_relay() {
                PeerPath::Relayed
            } else {
                PeerPath::Direct
            }
        })
}

/// Accept local connections and pair each with its own bi-stream.
pub(crate) async fn local_loop(state: Arc<ConnectState>, listener: TcpListener) {
    // Published before the first accept, so a caller that reads `status()`
    // as soon as `connect` returns sees the path it actually has.
    state
        .lifecycle
        .set_status(aggregate(&[peer_path(&state.connection)]));
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

    let opened = state.connection.open_bi().await;
    let Ok((send, recv)) = opened else {
        // The serve edge answers a backend it cannot reach with a 502, and
        // this end owes a client whose tunnel is gone the same. The socket
        // used to be dropped unread, so an SDK saw a connection reset with
        // no status: "the tunnel is down" and "nothing is listening here"
        // were the same event. `open_bi` fails only when the connection is
        // dead — stream-budget exhaustion back-pressures instead — so this
        // arm is exactly that case.
        local.write_all(&refusal::bad_gateway()).await?;
        local.flush().await?;
        return Ok(());
    };
    let mut remote = tokio::io::join(recv, send);

    // Opaque in both directions. `copy_bidirectional` finishes when both
    // halves have seen EOF, which for one exchange per stream is exactly
    // when the response is complete.
    tokio::io::copy_bidirectional(&mut local, &mut remote)
        .await
        .map(|_| ())
}

/// Stop accepting, drain, and release.
pub(crate) async fn shutdown(state: &ConnectState) {
    state.lifecycle.close();
    state.lifecycle.wait_until_drained().await;
    state.connection.close(0u32.into(), b"shutdown");
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
pub(crate) async fn shutdown_timeout(state: &ConnectState, grace: std::time::Duration) -> bool {
    state.lifecycle.close();
    let drained = tokio::time::timeout(grace, state.lifecycle.wait_until_drained())
        .await
        .is_ok();
    state.connection.close(0u32.into(), b"shutdown");
    state.lifecycle.wait_until_torn_down().await;
    drained
}

/// The URL to point a client at.
///
/// Not the bind address verbatim. A wildcard bind is a listen address, not
/// a destination — nobody can connect to `0.0.0.0` — so it renders as
/// loopback, which is a place the client can actually reach. An IPv6 zone
/// id is dropped rather than emitted, because no URL parser accepts one.
pub(crate) fn base_url(addr: SocketAddr) -> String {
    let host = match addr.ip() {
        ip if ip.is_unspecified() => match ip {
            IpAddr::V4(_) => "127.0.0.1".to_owned(),
            IpAddr::V6(_) => "[::1]".to_owned(),
        },
        IpAddr::V4(v4) => v4.to_string(),
        // Formatting the address rather than the socket address is what
        // drops the zone: `SocketAddrV6`'s own `Display` would include it.
        IpAddr::V6(v6) => format!("[{v6}]"),
    };
    format!("http://{host}:{}/v1", addr.port())
}

#[cfg(test)]
#[path = "dialer_tests.rs"]
mod dialer_tests;
