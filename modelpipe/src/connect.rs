//! Binding a local port that is the remote backend: the entry point,
//! what it is given, and how it fails.
//!
//! Orchestration. The live listener you get back lives in
//! [`crate::handle`]; this module owns the call and its inputs.

use std::fmt;
use std::net::SocketAddr;

use crate::handle::ConnectHandle;
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
    /// The requested local address could not be bound.
    Bind(std::io::Error),
    /// The transport failed some other way. Opaque on purpose; see
    /// [`ServeError::Transport`](crate::ServeError::Transport).
    Transport(Box<dyn std::error::Error + Send + Sync>),
}

impl ConnectError {
    /// Whether trying again could succeed without anyone changing
    /// anything. Same contract, and same no-`_`-arm rule, as
    /// [`ServeError::is_retryable`](crate::ServeError::is_retryable).
    ///
    /// The two enums disagree about [`Bind`](Self::Bind), and the
    /// disagreement is the point rather than an oversight: here the
    /// caller named the address, through [`ConnectOptions::bind`], so a
    /// bind failure is theirs to resolve by choosing another port. On the
    /// serve side no address is caller-chosen, which is why the same
    /// variant is retryable there. This is also why the two enums are
    /// kept as separate types with duplicated arms instead of being
    /// collapsed into one — they are two contracts that must stay free to
    /// diverge, and here they already have.
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::PeerUnreachable | Self::Transport(_) => true,
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
            Self::Bind(e) => write!(f, "could not bind the local address: {e}"),
            Self::Transport(e) => write!(f, "transport failure: {e}"),
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PeerUnreachable => None,
            Self::Bind(e) => Some(e),
            Self::Transport(e) => Some(&**e),
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
    let _ = (ticket, opts);
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unreachable_peer_is_retryable() {
        assert!(ConnectError::PeerUnreachable.is_retryable());
        assert!(ConnectError::Transport("stream reset".into()).is_retryable());
    }

    /// The one point where the two enums disagree, and the reason they
    /// stay two types rather than one shared enum: here the caller named
    /// the port through `ConnectOptions::bind`, so retrying the same value
    /// fails the same way forever.
    #[test]
    fn a_connect_bind_failure_is_not_retryable_because_the_caller_chose_the_address() {
        let e = ConnectError::Bind(std::io::Error::other("address in use"));
        assert!(!e.is_retryable(), "{e} should not be retryable");
    }
}
