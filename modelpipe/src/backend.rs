//! Reaching the local server, and refusing to reach anything else.
//!
//! This is where [`crate::locality`]'s verdict becomes a connection or a
//! refusal. The module exists as its own file for one reason: **resolving a
//! name and connecting to it must be a single operation.**
//!
//! `ServeError::BackendNotLocal` promises the check runs "against the
//! *resolved* address of every outbound connection, not the URL text, so a
//! DNS name cannot smuggle an address past it". Splitting resolve from
//! connect is exactly what breaks that — screen `backend.internal`, then
//! hand the *name* to something that resolves it again, and the second
//! answer is the one that gets dialled. Every connection here resolves,
//! screens what it got, and connects to that `SocketAddr`. The name is
//! never handed onward.

use std::net::SocketAddr;

use tokio::net::TcpStream;

use crate::ServeError;
use crate::exchange::Backend;
use crate::locality::{admits, classify};

/// A backend reached over TCP on this machine.
///
/// Derives `Debug`: nothing here is a credential — a host, a port, and a
/// flag the operator set — and a listener that cannot be printed is one
/// nobody can debug.
#[derive(Debug)]
pub(crate) struct TcpBackend {
    /// The host as written, re-resolved per connection.
    host: String,
    port: u16,
    /// `host:port`, for the outbound `Host` header.
    authority: String,
    allow_private: bool,
}

impl TcpBackend {
    /// Parse and screen a backend URL.
    ///
    /// Resolves once here so a misconfigured backend fails at `serve` time
    /// with a message naming the URL, rather than as a stream of failed
    /// requests later. That first answer is not cached: it is a check, and
    /// every connection screens again.
    pub(crate) async fn new(url: &str, allow_private: bool) -> Result<Self, ServeError> {
        let not_local = || ServeError::BackendNotLocal {
            url: url.to_owned(),
        };
        let parsed = url::Url::parse(url).map_err(|_| not_local())?;
        if parsed.scheme() != "http" {
            // Only `http`. The hop that matters is already encrypted by
            // QUIC, and accepting `https` would mean either verifying a
            // certificate for a loopback name or not verifying one at all.
            return Err(not_local());
        }
        let host = parsed.host_str().ok_or_else(not_local)?.to_owned();
        let port = parsed.port().unwrap_or(80);

        let this = Self {
            authority: format!("{host}:{port}"),
            host,
            port,
            allow_private,
        };
        // The startup check. A URL that resolves to nothing admissible now
        // is one the operator should hear about now.
        this.resolve().await.map_err(|_| not_local())?;
        Ok(this)
    }

    /// Resolve, and return the first address this listener may dial.
    ///
    /// Returns the `SocketAddr` itself, never the name, because that value
    /// is what the caller connects to. This signature is the mechanism: a
    /// caller physically cannot re-resolve, because it never had a name.
    async fn resolve(&self) -> std::io::Result<SocketAddr> {
        let candidates = tokio::net::lookup_host((self.host.as_str(), self.port)).await?;
        screen(candidates, self.allow_private).ok_or_else(|| {
            std::io::Error::other(format!(
                "{} did not resolve to an address this listener may reach",
                self.authority
            ))
        })
    }
}

impl Backend for TcpBackend {
    type Stream = TcpStream;

    fn authority(&self) -> &str {
        &self.authority
    }

    async fn connect(&self) -> std::io::Result<TcpStream> {
        // One expression, and deliberately so: the address screened is the
        // address dialled, with nothing in between that could resolve again.
        TcpStream::connect(self.resolve().await?).await
    }
}

/// The first address in `candidates` this listener may dial.
///
/// Pure, and separated from the resolution around it so the rule can be
/// tested exhaustively without DNS. Every candidate is screened — a name
/// resolving to a loopback address *and* a public one is not made
/// acceptable by the loopback entry, it is made dangerous by the public
/// one, so the public entry is skipped rather than the whole set accepted.
pub(crate) fn screen(
    candidates: impl IntoIterator<Item = SocketAddr>,
    allow_private: bool,
) -> Option<SocketAddr> {
    candidates
        .into_iter()
        .find(|addr| admits(classify(addr.ip()), allow_private))
}

#[cfg(test)]
#[path = "backend_tests.rs"]
mod backend_tests;
