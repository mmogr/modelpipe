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

use std::future::Future;
use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::ServeError;

/// Why a resolution produced no address to dial.
///
/// Two failures that have to stay apart, because they get opposite retry
/// verdicts: a resolver that is briefly unavailable is a machine condition
/// worth trying again, and a name that resolves only to addresses this
/// listener may not dial is the operator's to fix. Folding them into one
/// `io::Error` and telling them apart by message text is how the
/// distinction rots.
#[derive(Debug)]
enum Unreachable {
    /// Lookup itself failed.
    Lookup(std::io::Error),
    /// Lookup succeeded and nothing it returned may be dialled.
    NotLocal,
}

impl Unreachable {
    /// The public error for this failure at `serve` time.
    fn into_serve_error(self, url: &str) -> ServeError {
        let url = url.to_owned();
        match self {
            Self::Lookup(_) => ServeError::BackendUnresolvable { url },
            Self::NotLocal => ServeError::BackendNotLocal { url },
        }
    }
}

impl From<Unreachable> for std::io::Error {
    /// Per-request, where the distinction has no caller to serve: the edge
    /// answers a backend it cannot reach with a 502 either way.
    fn from(e: Unreachable) -> Self {
        match e {
            Unreachable::Lookup(e) => e,
            Unreachable::NotLocal => {
                Self::other("no resolved address may be reached by this listener")
            }
        }
    }
}
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
        // Three different objections, and they used to be one. "Not a
        // local address" is a verdict about an address; it cannot be the
        // answer for a string that is not a URL, or for a scheme, and
        // saying so sent the operator to `--allow-private-backend`.
        let invalid = || ServeError::InvalidBackendUrl {
            url: url.to_owned(),
        };
        let parsed = url::Url::parse(url).map_err(|_| invalid())?;
        if parsed.scheme() != "http" {
            // Only `http`. The hop that matters is already encrypted by
            // QUIC, and accepting `https` would mean either verifying a
            // certificate for a loopback name or not verifying one at all.
            return Err(invalid());
        }
        // `host_str` keeps an IPv6 literal's brackets, and nothing that
        // resolves a host accepts them: neither `Ipv6Addr::from_str` nor
        // `getaddrinfo` reads `[::1]`, so `http://[::1]:11434` — the
        // canonical loopback, which `locality` classifies as `Loopback` and
        // tests as such — was refused as "not a local address". The
        // brackets belong to the URL syntax, not to the host.
        // A host and a port, and nothing after them. The request path comes
        // from the client and is forwarded verbatim, so anything written
        // here is silently discarded: `serve http://127.0.0.1:11434/v1`
        // started cleanly, printed a ticket, and dropped the `/v1` — after
        // which every request went to the wrong place for a reason the
        // operator had already tried to prevent. `url` normalises an absent
        // path to `/`, so both of those spellings mean "no path".
        //
        // Refused rather than honoured, because honouring it is a bigger
        // promise than it looks: a prefix would have to be joined to every
        // target, and joined the same way this edge and the backend both
        // read it, which is the class of disagreement `framing` exists to
        // refuse. A backend that needs a prefix is one the client should
        // ask for by path.
        if !matches!(parsed.path(), "" | "/")
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(invalid());
        }
        let host = parsed.host_str().ok_or_else(invalid)?;
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host)
            .to_owned();
        let port = parsed.port().unwrap_or(80);
        // The `Host` header, on the other hand, needs them back: RFC 3986
        // brackets an IPv6 literal in an authority, and a backend reading
        // `::1:11434` cannot tell the address from the port.
        let authority = if host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };

        let this = Self {
            host,
            port,
            authority,
            allow_private,
        };
        // The startup check. A URL that resolves to nothing admissible now
        // is one the operator should hear about now — and *which* nothing
        // matters: a resolver that is briefly unavailable is a machine
        // condition a supervisor should retry, while an address this
        // listener may not dial is the operator's to fix.
        match this.resolve().await {
            Ok(_) => Ok(this),
            Err(e) => Err(e.into_serve_error(url)),
        }
    }

    /// Resolve, and return every address this listener may dial, in order.
    ///
    /// Returns `SocketAddr`s, never the name, because those values are what
    /// the caller connects to. This signature is the mechanism: a caller
    /// physically cannot re-resolve, because it never had a name.
    ///
    /// All of them rather than the first, because the first is not always
    /// the one that answers. `localhost` resolves to `::1` before
    /// `127.0.0.1` on most systems and Ollama binds `127.0.0.1` by default,
    /// so taking only the first turned `serve http://localhost:11434` into
    /// a listener that started cleanly and failed every request. Screening
    /// is unchanged: an address that is not admissible is never in this
    /// list, whatever position it held.
    async fn resolve(&self) -> Result<Vec<SocketAddr>, Unreachable> {
        let candidates = tokio::net::lookup_host((self.host.as_str(), self.port))
            .await
            .map_err(Unreachable::Lookup)?;
        let admissible = screen(candidates, self.allow_private);
        if admissible.is_empty() {
            return Err(Unreachable::NotLocal);
        }
        Ok(admissible)
    }
}

/// Where the serve side gets a connection to the backend.
///
/// A trait rather than a concrete socket so the tests can supply one that
/// counts how often it is asked — and can therefore prove that a rejected
/// request never asks at all.
pub(crate) trait Backend {
    /// The connection type. Not an iroh type and not necessarily a socket.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;

    /// What to put in the outbound `Host` header.
    fn authority(&self) -> &str;

    /// Open a connection. Called at most once per exchange, and never
    /// before the credential has been checked.
    fn connect(&self) -> impl Future<Output = std::io::Result<Self::Stream>> + Send;
}

impl Backend for TcpBackend {
    type Stream = TcpStream;

    fn authority(&self) -> &str {
        &self.authority
    }

    async fn connect(&self) -> std::io::Result<TcpStream> {
        // Every address dialled came out of `resolve`, and nothing in
        // between could resolve again — the name never leaves that method.
        let mut last = None;
        for addr in self.resolve().await? {
            match TcpStream::connect(addr).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| {
            std::io::Error::other(format!("{} resolved to no address", self.authority))
        }))
    }
}

/// The addresses in `candidates` this listener may dial, in the order given.
///
/// Pure, and separated from the resolution around it so the rule can be
/// tested exhaustively without DNS. Every candidate is screened on its own
/// merits: a name resolving to a loopback address *and* a public one is not
/// made acceptable by the loopback entry, so the public one is dropped
/// rather than the whole set being taken — and it is dropped whatever
/// position it held, which is the property that stops a hostile resolver
/// ordering its way past the rule.
///
/// Returns every admissible address rather than the first because the
/// caller has to be able to try the next one; see [`TcpBackend::connect`].
pub(crate) fn screen(
    candidates: impl IntoIterator<Item = SocketAddr>,
    allow_private: bool,
) -> Vec<SocketAddr> {
    candidates
        .into_iter()
        .filter(|addr| admits(classify(addr.ip()), allow_private))
        .collect()
}

#[cfg(test)]
#[path = "backend_tests.rs"]
mod backend_tests;
