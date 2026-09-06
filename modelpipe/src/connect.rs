//! Binding a local port that is the remote backend: the entry point,
//! what it is given, and how it fails.
//!
//! Orchestration. The live listener you get back lives in
//! [`crate::connect_handle`]; this module owns the call and its inputs.

use std::fmt;
use std::net::SocketAddr;

use crate::connect_handle::ConnectHandle;
use crate::dialer;
use crate::peer;
use crate::ticket::Ticket;
use crate::transport;

/// Why [`connect`] failed. Same contract as [`ServeError`](crate::ServeError): variants a
/// retry policy can match on, transport details behind `source`.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConnectError {
    /// The ticket names an address nobody could ever be at — an endpoint
    /// id that is not a key. Retryable in the sense the other variants
    /// are, and dialling it again will fail again.
    ///
    /// **Not what an offline serve side looks like.** [`connect`] returns
    /// once the local port is bound, so a peer that is merely absent is
    /// never reported here: it is a handle at
    /// [`PipeStatus::Idle`](crate::PipeStatus::Idle) that keeps trying. A
    /// ticket outlived by its listener is that case too, and there is no
    /// "ticket rejected" to distinguish it from — a serve side that
    /// restarted **without** an identity file is a *different* endpoint, so
    /// the old ticket reaches nobody rather than reaching someone who
    /// refuses. A caller wanting to tell "offline" from "re-paired" has to
    /// ask a human, not this enum.
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
    /// [`ConnectOptions::relay`] does not parse as a relay URL. The twin of
    /// [`ServeError::InvalidRelay`](crate::ServeError::InvalidRelay), with
    /// the same scope: syntactic, before anything is dialled, and the
    /// operator's to fix.
    InvalidRelay {
        /// The offending URL, for the error message.
        url: String,
    },
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
            Self::Bind(_) | Self::InvalidRelay { .. } => false,
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
            Self::InvalidRelay { url } => {
                write!(
                    f,
                    "{url} does not parse as a relay URL — check the value passed as the relay"
                )
            }
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PeerUnreachable | Self::InvalidRelay { .. } => None,
            Self::Bind(e) | Self::Endpoint(e) => Some(e),
        }
    }
}

/// Options for [`connect`]. Same contract as [`ServeOptions`](crate::ServeOptions).
///
/// Derives `Debug` where [`ServeOptions`](crate::ServeOptions) hand-writes one: nothing here
/// is a credential, so there is nothing to redact.
#[derive(Debug)]
#[non_exhaustive]
pub struct ConnectOptions {
    /// Local address to bind. `None` picks a free port on loopback.
    pub bind: Option<SocketAddr>,
    /// Self-hosted relay URL for *this* side's endpoint. `None` uses iroh's
    /// public relays. The serve side's relay travels in the ticket and is
    /// dialled regardless; this is the relay this endpoint registers with
    /// and falls back to, which until now was always a public one.
    pub relay: Option<String>,
    /// Same as [`ServeOptions::port_mapping`](crate::ServeOptions#structfield.port_mapping).
    pub port_mapping: bool,
    /// Same as [`ServeOptions::discovery`](crate::ServeOptions#structfield.discovery),
    /// from the side that *resolves*: with it off, this side dials only
    /// the paths the ticket carries.
    pub discovery: bool,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            bind: None,
            relay: None,
            port_mapping: true,
            discovery: true,
        }
    }
}

/// Bind a local port that transparently is the remote backend. Point any
/// OpenAI-compatible client at [`ConnectHandle::base_url`], with the
/// serve side's bearer token as the API key.
///
/// **Returns as soon as that port is bound.** Reaching the serve side runs
/// on a background task, so an absent peer costs the caller nothing: iroh
/// spends about thirty seconds giving up on one, and a caller blocked for
/// that long cannot even be told which port it was given, let alone point a
/// client at it. Requests arriving before the pairing forms are answered
/// `502` rather than refused, which is the same answer they get if the peer
/// goes away later.
///
/// The dial's outcome is the handle's to report, not this `Result`'s:
/// [`ConnectHandle::status`] reads [`PipeStatus::Idle`](crate::PipeStatus::Idle)
/// until a connection forms and [`Direct`](crate::PipeStatus::Direct) or
/// [`Relayed`](crate::PipeStatus::Relayed) once one has, and
/// [`ConnectHandle::status_changed`] delivers each transition. A dial that
/// fails is not an error and not the end — this side keeps trying, because
/// a sleeping laptop, a dead one and a serve side five seconds from
/// starting are the same picture from here. **Deciding how long to wait
/// before giving up is the caller's**, and `modelpipe-cli` is one worked
/// example of making that decision.
///
/// What this `Result` still reports is everything local and immediate: an
/// address that will not bind, a relay that will not parse, an endpoint
/// this machine will not open.
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Tickets are text: they arrive over whatever channel you already
/// // trust, and parse before anything is dialled.
/// let ticket: modelpipe::Ticket = "pipeabc…".parse()?;
///
/// let connected = modelpipe::connect(&ticket, modelpipe::ConnectOptions::default()).await?;
///
/// // Point an OpenAI-compatible client here, with the serve side's token
/// // as the API key.
/// println!("{}", connected.base_url());
/// println!("reaching the peer: {}", connected.status().as_str());
///
/// connected.shutdown().await;
/// # Ok(())
/// # }
/// ```
///
/// To bind somewhere specific, assign to [`ConnectOptions::bind`] — the
/// same `default()`-then-assign shape [`serve`](fn@crate::serve) uses, and
/// for the same reason:
///
/// ```no_run
/// # async fn example(ticket: &modelpipe::Ticket) -> Result<(), Box<dyn std::error::Error>> {
/// let mut opts = modelpipe::ConnectOptions::default();
/// opts.bind = Some("127.0.0.1:8080".parse()?);
/// let connected = modelpipe::connect(ticket, opts).await?;
/// # let _ = connected;
/// # Ok(())
/// # }
/// ```
pub async fn connect(ticket: &Ticket, opts: ConnectOptions) -> Result<ConnectHandle, ConnectError> {
    // Cheapest and the operator's to fix, so first — the order `serve`
    // keeps for the same value.
    if let Some(relay) = opts.relay.as_deref() {
        transport::validate_relay_for_connect(relay)?;
    }
    let (state, listener) = dialer::bind(ticket, &opts).await?;
    tokio::spawn(dialer::local_loop(state.clone(), listener));
    // The reconnect loop takes the two halves it needs by reference, so
    // the `Arc` that keeps them alive is held here rather than threaded
    // through `peer`, which has no business knowing how the connect side
    // stores its state.
    let watching = state.clone();
    // The dial lives in here, first attempt included. Spawning it rather
    // than awaiting it is the whole of this function's contract: the handle
    // below is handed out with a port already answering.
    tokio::spawn(async move { peer::keep_connected(&watching.peer, &watching.lifecycle).await });
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

    /// The operator typed the relay, so no amount of waiting fixes it —
    /// the same verdict the serve side gives the same value.
    #[test]
    fn an_unparseable_relay_is_permanent_and_names_the_value() {
        let e = ConnectError::InvalidRelay {
            url: "not a url".to_owned(),
        };
        assert!(!e.is_retryable());
        assert!(e.to_string().contains("not a url"));
        assert!(std::error::Error::source(&e).is_none());
    }

    /// The defaults are what every version before this one did.
    #[test]
    fn the_default_options_keep_every_network_contact_on() {
        let opts = ConnectOptions::default();
        assert!(opts.port_mapping);
        assert!(opts.discovery);
        assert!(opts.relay.is_none());
    }
}
