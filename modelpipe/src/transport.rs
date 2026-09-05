//! The iroh endpoint, and the one place a ticket meets an iroh address.
//!
//! Three modules in this crate name an iroh type — this one, which binds
//! the endpoint, [`crate::listener`], which accepts on it, and
//! [`crate::peer`], which holds one connection and re-dials it. That is
//! deliberate rather than incidental, and the line is drawn at *lifetime*:
//! anything that owns an iroh value for longer than a call is here or in
//! those two. Everything above them — the codec, the locality rule, the
//! header edge, the request exchange — is generic or pure, which is why the
//! whole authentication edge is exercised over `tokio::io::duplex()` with
//! no socket anywhere.
//!
//! (This file said "the only module" until the listener and the peer
//! watcher arrived. They did, and it stayed. The invariant those two do not
//! break is the one below.)
//!
//! **Nothing iroh owns reaches the public surface.** That is the promise
//! the crate docs make, it is what an iroh major upgrade is measured
//! against, and unlike the sentence above it is checked rather than
//! asserted: `tests/api_surface.rs` links this crate as an external
//! dependent and names every exported item. Failures leave as
//! [`ServeError`] / [`ConnectError`] variants with the transport's own
//! error reachable only as an opaque `source`.
//!
//! There is deliberately no general iroh-error-to-public-error converter.
//! Two one-line boxing helpers were written and removed: with no caller
//! they discriminated nothing, and a conversion site that does not yet know
//! which failures it has to tell apart is a boundary invented ahead of the
//! code that would justify it. The listener has since arrived and still
//! does not want one — its dial and accept failures are classified where
//! they happen, in `serve_error.rs` and `connect.rs`, against the variants
//! a caller can actually match a retry policy on.

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey, TransportAddr};

use crate::ticket::{BackendHint, Ticket};
use crate::ticket_addr::TicketAddr;
use crate::{ConnectError, ServeError};

/// The protocol name both sides must agree on before a byte is exchanged.
///
/// **Versioned, and that is the whole point.** iroh will neither accept nor
/// dial without an ALPN, so this string gets chosen by whoever writes the
/// first line of the listener — and it is a compatibility commitment as
/// binding as the ticket format, on a version space entirely separate from
/// it. A ticket that parses perfectly still gets you to a peer you cannot
/// speak to.
///
/// The ticket's version byte cannot cover for this, so the version lives
/// here too. An accept side may offer several of these at once, which is
/// what makes introducing `modelpipe/1` a rollout rather than a flag day;
/// shipping an unversioned name would have left no lever at all.
///
/// A non-Rust client cannot guess this, so it belongs in the format spec
/// alongside the ticket layout.
pub(crate) const ALPN: &[u8] = b"modelpipe/0";

/// Why binding an endpoint failed.
///
/// The discrimination site the two public error types need, and the reason
/// it exists here rather than being written twice: both sides bind, both
/// have a `Bind` variant, and only this module knows which iroh failure is
/// which. It earns its place now that it has callers — a pair of boxing
/// helpers written before that were removed for having none.
#[derive(Debug)]
pub(crate) enum BindFailure {
    /// The relay value does not parse. Permanent and user-fixable.
    InvalidRelay(String),
    /// The listener could not be set up. Describes the machine.
    Io(std::io::Error),
}

impl From<BindFailure> for ServeError {
    fn from(e: BindFailure) -> Self {
        match e {
            BindFailure::InvalidRelay(url) => Self::InvalidRelay { url },
            BindFailure::Io(e) => Self::Bind(e),
        }
    }
}

impl From<BindFailure> for ConnectError {
    fn from(e: BindFailure) -> Self {
        match e {
            // The connect side has no `InvalidRelay` of its own: it is not
            // configured with a relay, so this arm is unreachable from
            // `dial`, which calls `bind(None)`. It is still written out
            // rather than collapsed with a wildcard — a wildcard here would
            // silently absorb a variant added later, which is the mistake
            // the `is_retryable` matches avoid for the same reason.
            BindFailure::InvalidRelay(url) => Self::Endpoint(std::io::Error::other(format!(
                "relay {url} is not a relay URL"
            ))),
            // Not `Bind`. That variant means the address the *caller* named
            // through `ConnectOptions::bind`, and is classified permanent
            // on exactly that basis; this is the p2p endpoint, which nobody
            // chose, and which `serve` reports as the retryable
            // `ServeError::Bind`.
            BindFailure::Io(e) => Self::Endpoint(e),
        }
    }
}

/// Bind an endpoint for this side of the pipe.
///
/// `relay` is the operator's own relay, or `None` for the defaults. It is
/// passed as the string it arrived as — see [`validate_relay`] for why the
/// value is never handed through a parsed URL type.
///
/// `key` is the endpoint's secret key, or `None` to let iroh generate one
/// for this process. Supplying it is what makes a ticket survive a restart,
/// because the public half of this key *is* the address a ticket carries.
/// It arrives as bare bytes rather than as an iroh type so that
/// [`crate::identity`] — which decides where those bytes come from and who
/// may read them — needs to know nothing about the transport.
pub(crate) async fn bind(
    relay: Option<&str>,
    key: Option<[u8; crate::identity::KEY_BYTES]>,
) -> Result<Endpoint, BindFailure> {
    let mut builder = Endpoint::builder(presets::N0).alpns(vec![ALPN.to_vec()]);
    if let Some(bytes) = key {
        builder = builder.secret_key(SecretKey::from_bytes(&bytes));
    }
    if let Some(url) = relay {
        let parsed =
            RelayUrl::from_str(url).map_err(|_| BindFailure::InvalidRelay(url.to_owned()))?;
        builder = builder.relay_mode(RelayMode::Custom(parsed.into()));
    }
    builder
        .bind()
        .await
        .map_err(|e| BindFailure::Io(bind_io(&e)))
}

/// Wait, up to `within`, for the endpoint to reach a relay.
///
/// iroh considers an endpoint "online" once a relay handshake has
/// completed, which is what puts a relay address into the set
/// [`ticket_from`] reads — binding alone does not. That makes this the
/// difference between a ticket a remote machine can dial and one that
/// describes only the paths this machine could see from where it sits.
///
/// The cap is not optional and not tuning. iroh's own wait has no timeout
/// and pends forever where no relay is reachable, so a bare await would
/// turn "no route to the internet" into a listener that never starts. This
/// is why the caller passes a `Duration` and why running out of it is
/// silent: the endpoint is live either way, and there is nothing here the
/// operator could fix.
pub(crate) async fn wait_online(endpoint: &Endpoint, within: Duration) {
    // The result is deliberately discarded: `Err` means the deadline won,
    // which is a slower pairing and not a failure to report.
    let _ = tokio::time::timeout(within, endpoint.online()).await;
}

/// Check that a relay value is a relay URL at all.
///
/// Returns `()` and never the parsed URL, which is not fastidiousness: a
/// ticket carries relay URLs **verbatim**, and every URL library
/// normalizes — lowercasing the host, appending a trailing slash, dropping
/// a default port. Handing a parsed value onward is how "carried verbatim"
/// quietly stops being true, so the parse is used for its verdict and then
/// discarded.
///
/// Syntactic only, and the error says so. A well-formed URL naming a relay
/// that does not exist is indistinguishable from one that is merely down,
/// and surfaces later as a transport failure.
pub(crate) fn validate_relay(url: &str) -> Result<(), ServeError> {
    RelayUrl::from_str(url)
        .map(|_| ())
        .map_err(|_| ServeError::InvalidRelay {
            url: url.to_owned(),
        })
}

/// Mint a ticket describing where this endpoint can be reached.
///
/// Addresses iroh knows that v0 has no tag for are dropped rather than
/// failing the mint. That is not a loss to work around: the ticket's
/// address set exists to help a peer avoid the relay, not to connect at
/// all, so a ticket carrying fewer paths is slower in the worst case and
/// never broken. `TransportAddr` is `#[non_exhaustive]` with a `Custom`
/// variant precisely so iroh can add transports, which is the situation
/// this arm exists for.
pub(crate) fn ticket_from(addr: &EndpointAddr) -> Ticket {
    let addrs = addr
        .addrs
        .iter()
        .filter_map(|transport| match transport {
            TransportAddr::Relay(url) => Some(TicketAddr::Relay(url.to_string())),
            TransportAddr::Ip(SocketAddr::V4(v4)) => Some(TicketAddr::V4(*v4)),
            TransportAddr::Ip(SocketAddr::V6(v6)) => Some(TicketAddr::V6(*v6)),
            _ => None,
        })
        .collect();
    // `Ticket::new` canonicalizes and bounds; nothing here needs to.
    Ticket::new(*addr.id.as_bytes(), addrs, BackendHint::OpenAiCompatible)
}

/// The iroh address a ticket names.
///
/// The format spec says a parser treats the endpoint id as 32 opaque bytes
/// and leaves curve validity to the transport. iroh agrees and defers it
/// further: `EndpointId::from_bytes` accepts any 32 bytes, because
/// decompressing the point is left until a signature is verified. So in
/// practice this does not fail today, and a key nobody holds becomes a dial
/// that reaches nobody — which is the right shape anyway.
///
/// The `Result` stays regardless. The function is fallible in iroh's own
/// signature, and treating today's laziness as a guarantee would be the
/// same mistake as depending on a dependency's private feature choice: it
/// would turn a stricter future iroh into a panic here.
///
/// A relay URL the ticket carried but iroh will not parse is dropped rather
/// than fatal, on the same reasoning as the unknown-tag rule: an address we
/// cannot use costs the pairing one path, not the pairing.
pub(crate) fn addr_from(ticket: &Ticket) -> Result<EndpointAddr, ConnectError> {
    let id = EndpointId::from_bytes(ticket.endpoint_id()).map_err(|_| {
        // Not a curve point, so nobody is at this address and nobody ever
        // was. Reported as unreachable, which is what it is.
        ConnectError::PeerUnreachable
    })?;
    let addrs = ticket
        .addrs()
        .iter()
        .filter_map(|addr| match addr {
            TicketAddr::Relay(url) => RelayUrl::from_str(url).ok().map(TransportAddr::Relay),
            TicketAddr::V4(v4) => Some(TransportAddr::Ip(SocketAddr::V4(*v4))),
            TicketAddr::V6(v6) => Some(TransportAddr::Ip(SocketAddr::V6(*v6))),
        })
        .collect();
    Ok(EndpointAddr { id, addrs })
}

/// iroh's bind failure, reduced to the `io::Error` the public variant
/// carries.
fn bind_io(e: &impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod transport_tests;
