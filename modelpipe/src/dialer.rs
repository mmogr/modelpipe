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
use tokio::net::TcpListener;

use crate::ConnectError;
use crate::lifecycle::Lifecycle;
use crate::ticket::Ticket;
use crate::transport;

/// Everything a live connect side shares.
pub(crate) struct ConnectState {
    /// Kept so the endpoint outlives the connection opened on it.
    _endpoint: Endpoint,
    connection: Connection,
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
        let Ok((local, _)) = accepted else { break };

        let state = state.clone();
        // Registered before the spawn, so a drain cannot observe zero while
        // this exchange is starting.
        let guard = state.lifecycle.enter();
        tokio::spawn(async move {
            let _guard = guard;
            let _ = carry(&state, local).await;
        });
    }

    // Dropped here, explicitly, before anything is told teardown finished.
    // The listener owns the port, so "shutdown returned" can only mean "the
    // port is free" if the value that holds it is gone first — which is the
    // whole reason `mark_torn_down` is separate from publishing `Closed`.
    drop(listener);
    state.lifecycle.mark_torn_down();
}

/// Carry one local connection over one bi-stream.
async fn carry(state: &ConnectState, mut local: tokio::net::TcpStream) -> std::io::Result<()> {
    let (send, recv) = state
        .connection
        .open_bi()
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
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
mod tests {
    use super::*;

    /// A wildcard bind names no reachable host, so the URL must name one
    /// that is.
    #[test]
    fn a_wildcard_bind_renders_as_loopback() {
        assert_eq!(
            base_url("0.0.0.0:8080".parse().unwrap()),
            "http://127.0.0.1:8080/v1"
        );
        assert_eq!(
            base_url("[::]:8080".parse().unwrap()),
            "http://[::1]:8080/v1"
        );
    }

    #[test]
    fn a_concrete_bind_is_rendered_as_it_is() {
        assert_eq!(
            base_url("127.0.0.1:8080".parse().unwrap()),
            "http://127.0.0.1:8080/v1"
        );
        assert_eq!(
            base_url("192.168.1.5:9000".parse().unwrap()),
            "http://192.168.1.5:9000/v1"
        );
    }

    /// IPv6 needs brackets in a URL, and no URL parser accepts a zone id.
    #[test]
    fn an_ipv6_address_is_bracketed_and_loses_its_zone() {
        assert_eq!(
            base_url("[::1]:8080".parse().unwrap()),
            "http://[::1]:8080/v1"
        );
        let zoned = SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            8080,
            0,
            7,
        ));
        assert_eq!(
            base_url(zoned),
            "http://[fe80::1]:8080/v1",
            "the zone id must not reach a URL"
        );
    }

    /// The URL is meant to be pasted into a client, so it must carry the
    /// `/v1` an OpenAI-compatible one expects — for every shape of address,
    /// not just the common one.
    #[test]
    fn every_rendering_names_the_openai_compatible_base_path() {
        for addr in ["127.0.0.1:8080", "0.0.0.0:80", "[::1]:1", "[::]:65535"] {
            let url = base_url(addr.parse().expect("addr"));
            assert!(url.ends_with("/v1"), "{addr} rendered as {url}");
            assert!(url.starts_with("http://"), "{addr} rendered as {url}");
        }
    }
}
