//! Binding a local port that is the remote backend: the entry point,
//! what it is given, and how it fails.
//!
//! Orchestration. The live listener you get back lives in
//! [`crate::connect_handle`]; this module owns the call and its inputs.

use std::fmt;
use std::net::SocketAddr;

use crate::connect_handle::ConnectHandle;
use crate::dialer;
use crate::ticket::Ticket;

/// Why [`connect`] failed. Same contract as [`ServeError`](crate::ServeError): variants a
/// retry policy can match on, transport details behind `source`.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConnectError {
    /// The peer could not be reached, directly or through a relay.
    /// Retryable: the serve side may be offline, or the network in
    /// between temporarily unwilling.
    ///
    /// This is also what a ticket outlived by its listener looks like.
    /// There is no "ticket rejected" case to distinguish it from: the
    /// endpoint key is ephemeral, so a restarted serve side is a
    /// *different* endpoint, and dialing the old one reaches nobody
    /// rather than reaching someone who refuses. A caller that wants to
    /// tell "offline" from "re-paired" has to ask a human, not this
    /// enum.
    PeerUnreachable,
    /// The local address the caller asked for could not be bound.
    ///
    /// Only that one. The p2p endpoint this side also binds is
    /// [`Endpoint`](Self::Endpoint), and keeping them apart is what makes
    /// this variant's permanence true rather than merely stated.
    Bind(std::io::Error),
    /// The p2p endpoint could not be set up. The twin of
    /// [`ServeError::Bind`](crate::ServeError::Bind), and retryable for the
    /// same reason: no address here was chosen by anyone.
    Endpoint(std::io::Error),
}

impl ConnectError {
    /// Whether trying again could succeed without anyone changing
    /// anything. Same contract, and same no-`_`-arm rule, as
    /// [`ServeError::is_retryable`](crate::ServeError::is_retryable).
    ///
    /// The two enums look like they disagree about "a bind failed", and
    /// they do not: they name two different failures.
    /// [`Bind`](Self::Bind) is the address the caller passed through
    /// [`ConnectOptions::bind`], which retrying will fail on forever;
    /// [`Endpoint`](Self::Endpoint) is the p2p socket nobody chose, which
    /// is [`ServeError::Bind`](crate::ServeError::Bind) by another name and
    /// retryable exactly as that one is.
    ///
    /// Splitting them is what makes the classification honest. While one
    /// variant carried both, two of its three producers named no
    /// caller-chosen address at all — including the iroh endpoint, bound
    /// with `None` — so a supervisor following this contract abandoned
    /// `connect` permanently over a transient `EMFILE`.
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::PeerUnreachable | Self::Endpoint(_) => true,
            Self::Bind(_) => false,
        }
    }
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerUnreachable => {
                write!(f, "could not reach the serve side, directly or via a relay")
            }
            // Neither interpolates its source: `anyhow` prints the
            // top-level Display and then the chain, so a variant that does
            // both prints the OS error twice.
            Self::Bind(_) => f.write_str("could not bind the requested local address"),
            Self::Endpoint(_) => f.write_str("could not set up the p2p endpoint"),
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PeerUnreachable => None,
            Self::Bind(e) | Self::Endpoint(e) => Some(e),
        }
    }
}

/// Options for [`connect`]. Same contract as [`ServeOptions`](crate::ServeOptions).
///
/// Derives `Debug` where [`ServeOptions`](crate::ServeOptions) hand-writes one: nothing here
/// is a credential, so there is nothing to redact.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct ConnectOptions {
    /// Local address to bind. `None` picks a free port on loopback.
    pub bind: Option<SocketAddr>,
}

/// Bind a local port that transparently is the remote backend. Point any
/// OpenAI-compatible client at [`ConnectHandle::base_url`], with the
/// serve side's bearer token as the API key.
pub async fn connect(ticket: &Ticket, opts: ConnectOptions) -> Result<ConnectHandle, ConnectError> {
    let (state, listener) = dialer::dial(ticket, opts.bind).await?;
    tokio::spawn(dialer::local_loop(state.clone(), listener));
    Ok(ConnectHandle::new(state))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unreachable_peer_is_retryable() {
        assert!(ConnectError::PeerUnreachable.is_retryable());
    }

    /// The p2p endpoint is nobody's choice, so failing to bind it is a
    /// machine condition — the same verdict `ServeError::Bind` gets for the
    /// same socket.
    #[test]
    fn failing_to_bind_the_p2p_endpoint_is_retryable() {
        let e = ConnectError::Endpoint(std::io::Error::other("too many open files"));
        assert!(e.is_retryable(), "{e} should be retryable");
    }

    /// The one variant that is permanent, and the reason it is a variant of
    /// its own: the caller named this port through `ConnectOptions::bind`,
    /// so retrying the same value fails the same way forever. The p2p
    /// endpoint's own bind failure is `Endpoint`, above.
    #[test]
    fn a_connect_bind_failure_is_not_retryable_because_the_caller_chose_the_address() {
        let e = ConnectError::Bind(std::io::Error::other("address in use"));
        assert!(!e.is_retryable(), "{e} should not be retryable");
    }
}
