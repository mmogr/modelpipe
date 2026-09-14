//! Pairing from the connect side, in one call.
//!
//! A device holds a pairing string, `<ticket>-<code>`, and wants a key of its
//! own. [`pair`] dials the ticket, waits until the serve side is reached, and
//! presents the code to the edge's pairing route through this side's own local
//! port, which is the pipe. What comes back is the key, and the live pipe it
//! was redeemed over, so a device that pairs and then talks does not dial
//! twice.
//!
//! The exchange's bytes, the request and how its answer is read, are in
//! [`crate::pair_wire`].

use std::fmt;
use std::time::Duration;

use crate::connect::{ConnectError, ConnectOptions, connect};
use crate::connect_handle::ConnectHandle;
use crate::connect_reach::Unreached;
use crate::pair_wire::{dialable, exchange, redeem_request, redeemed};
use crate::pairing_string::PairingString;
use crate::peer_id::PeerId;

/// How long the exchange may take once the serve side is reached: the edge's
/// own deadline for a pairing request's head and body.
const REDEEM_WITHIN: Duration = Duration::from_secs(30);

/// A device that has paired: its key, the name it is held under, and the pipe
/// it paired over.
#[non_exhaustive]
pub struct Paired {
    /// The pipe the code was redeemed over, still up. Shut it down if it is not
    /// needed.
    pub handle: ConnectHandle,
    /// This device's key from now on, presented as its bearer. Store it:
    /// nothing hands it out again.
    pub api_key: String,
    /// The name the serve side holds the key under.
    pub device: String,
    /// The serve side's endpoint, which the ticket named and the answer
    /// confirmed.
    pub serving: PeerId,
}

impl fmt::Debug for Paired {
    /// The device and the serve side, never the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Paired")
            .field("device", &self.device)
            .field("serving", &self.serving)
            .finish_non_exhaustive()
    }
}

/// Why [`pair`] did not pair.
#[derive(Debug)]
#[non_exhaustive]
pub enum PairError {
    /// The pairing string is a ticket alone, with no code to redeem.
    NoCode,
    /// [`connect`](fn@crate::connect) failed before anything was dialled.
    Connect(ConnectError),
    /// The serve side was not reached in the time given, or the pipe closed
    /// first. The code was not presented.
    Unreached(Unreached),
    /// The serve side refused the code. It does not say why, on purpose: a
    /// wrong code, an expired or spent one, one not yet armed, and an endpoint
    /// locked out are one answer.
    Refused,
    /// The code could not be presented, or its answer could not be read. The
    /// code may have been spent before the answer was lost, in which case a
    /// retry is [`Refused`](Self::Refused) and a new invite is the way on.
    Exchange(std::io::Error),
    /// The serve side answered with something that is not a pairing answer.
    Unexpected(&'static str),
}

impl PairError {
    /// Whether trying again could succeed without anyone changing anything.
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Connect(e) => e.is_retryable(),
            Self::Unreached(_) | Self::Exchange(_) => true,
            Self::NoCode | Self::Refused | Self::Unexpected(_) => false,
        }
    }
}

impl fmt::Display for PairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCode => f.write_str("the pairing string has no code: ask the serve side for an invite"),
            // The cause is `source`, so it is not repeated here.
            Self::Connect(_) => f.write_str("could not set up the pipe to pair over"),
            Self::Unreached(_) => f.write_str("could not reach the serve side to pair with it"),
            Self::Refused => f.write_str(
                "the serve side did not accept the pairing code: it may be wrong, expired or already used, so ask for a new one",
            ),
            Self::Exchange(_) => f.write_str("the pairing code could not be presented, or its answer read"),
            Self::Unexpected(why) => write!(f, "the serve side's answer was not a pairing answer: {why}"),
        }
    }
}

impl std::error::Error for PairError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect(e) => Some(e),
            Self::Unreached(e) => Some(e),
            Self::Exchange(e) => Some(e),
            Self::NoCode | Self::Refused | Self::Unexpected(_) => None,
        }
    }
}

/// Pair with the serve side a pairing string names, and keep the pipe.
///
/// Dials the ticket with `opts`, waits up to `reach_within` for the serve
/// side, and presents the code at [`PAIR_PATH`](crate::PAIR_PATH) through the
/// pipe, with `label`, what this device calls itself, as the body. The edge
/// answers the request itself; `docs/pairing-v0.md` specifies the exchange.
/// The answer must name the endpoint the ticket named.
///
/// Give `opts.identity` a file when the serve side may pin the key to this
/// device's endpoint, or each restart is an endpoint the pin refuses.
///
/// # Errors
///
/// [`PairError`], whose variants say what failed and
/// [`is_retryable`](PairError::is_retryable) whether to try again.
///
/// # Examples
///
/// ```no_run
/// # async fn example(pasted: &str) -> Result<(), Box<dyn std::error::Error>> {
/// let pairing: modelpipe::PairingString = pasted.parse()?;
/// let paired = modelpipe::pair(
///     &pairing,
///     Some("Laptop"),
///     modelpipe::ConnectOptions::default(),
///     std::time::Duration::from_secs(40),
/// )
/// .await?;
/// println!("paired as {}; point a client at {}", paired.device, paired.handle.base_url());
/// # Ok(())
/// # }
/// ```
pub async fn pair(
    pairing: &PairingString,
    label: Option<&str>,
    opts: ConnectOptions,
    reach_within: Duration,
) -> Result<Paired, PairError> {
    let code = pairing.code().ok_or(PairError::NoCode)?;
    let handle = connect(pairing.ticket(), opts)
        .await
        .map_err(PairError::Connect)?;
    handle
        .wait_reachable(reach_within)
        .await
        .map_err(PairError::Unreached)?;
    let serving = PeerId::from_bytes(*pairing.ticket().endpoint_id());
    let local = dialable(handle.local_addr());
    let request = redeem_request(local, code.as_str(), label.unwrap_or(""));
    let answer = tokio::time::timeout(REDEEM_WITHIN, exchange(local, &request))
        .await
        .map_err(|_| PairError::Exchange(std::io::ErrorKind::TimedOut.into()))?
        .map_err(PairError::Exchange)?;
    let (api_key, device) = redeemed(&answer, serving)?;
    Ok(Paired {
        handle,
        api_key,
        device,
        serving,
    })
}
