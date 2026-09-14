//! What an embedder is handed when it invites a device, and what it learns
//! when the invite ends.
//!
//! The store is `invites.rs` and the edge's half is `pair_route.rs`; this
//! module is the surface. The protocol, with the odds a guesser has, is
//! `docs/pairing-v0.md`.

use std::fmt;
use std::num::NonZeroU8;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use crate::invites::Invites;
use crate::pairing_string::{PairingCode, PairingString};
use crate::peer_id::PeerId;

/// The path the edge answers a pairing request on, itself and without the
/// backend: `POST`, bearing the code. See `docs/pairing-v0.md`.
pub const PAIR_PATH: &str = "/modelpipe/pair";

/// The longest [`InviteOptions::ttl`] accepted.
pub(crate) const MAX_TTL: Duration = Duration::from_mins(15);

/// The most [`InviteOptions::wrong_codes`] accepted.
pub(crate) const MAX_WRONG_CODES: u8 = 10;

const THREE: NonZeroU8 = NonZeroU8::new(3).expect("three is not zero");

/// Options for [`ServeHandle::invite`](crate::ServeHandle::invite).
///
/// Start from `Default` and set what you need.
///
/// **The odds.** A code is six digits. One endpoint gets `wrong_codes` tries
/// at an invite, and a guesser can mint a fresh endpoint whenever one is
/// locked out; the edge tracks 64 endpoints, and a wrong code from a
/// sixty-fifth ends every live invite as [`InviteOutcome::Burned`]. With `k`
/// invites live, the chance a guesser finds one first is about
/// `k × (64 × wrong_codes + 1) / 1,000,000` per round of invites: 0.019% for
/// one invite at the defaults, and `1 − (1 − p)^n` over `n` rounds. Denying
/// pairing costs about 65 handshakes, so `Burned` is the sign that someone
/// holding this machine's ticket is guessing, and retiring the address is the
/// remedy.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct InviteOptions {
    /// How long the code stays redeemable, counted from the invite. At most
    /// fifteen minutes; two by default.
    pub ttl: Duration,
    /// Wrong codes one endpoint may present against this invite before it is
    /// locked out of it. At most ten; three by default.
    pub wrong_codes: NonZeroU8,
    /// The name the device's key is held under, as
    /// [`ServeHandle::add_token`](crate::ServeHandle::add_token) takes one.
    /// `None`, the default, mints `dev-` and eight hex digits.
    pub device: Option<String>,
}

impl Default for InviteOptions {
    fn default() -> Self {
        Self {
            ttl: Duration::from_mins(2),
            wrong_codes: THREE,
            device: None,
        }
    }
}

/// A device invited to pair, and what to show the person pairing it.
///
/// **The code is not live yet.** Store [`api_key`](Self::api_key) under
/// [`device`](Self::device) wherever you keep devices, then
/// [`arm`](Self::arm), then show [`pairing`](Self::pairing). A code redeemed
/// before its key was stored would hand a device a credential this side has
/// no record of.
pub struct Invite {
    pub(crate) pairing: PairingString,
    pub(crate) code: PairingCode,
    pub(crate) device: String,
    pub(crate) api_key: String,
    pub(crate) handle: InviteHandle,
}

impl Invite {
    /// The ticket and the code as one string, for a person to carry or a QR
    /// code to hold.
    #[must_use]
    pub const fn pairing(&self) -> &PairingString {
        &self.pairing
    }

    /// The code alone.
    #[must_use]
    pub const fn code(&self) -> &PairingCode {
        &self.code
    }

    /// The name the device's key is held under.
    #[must_use]
    pub fn device(&self) -> &str {
        &self.device
    }

    /// The device's key, already held at the edge. A device that redeems the
    /// code receives this same value.
    #[must_use]
    pub fn api_key(&self) -> &str {
        &self.api_key
    }

    /// Make the code redeemable. Until this, a presentation of it is an
    /// ordinary wrong code. A no-op once the invite has ended.
    pub fn arm(&self) {
        self.handle.invites.arm(self.handle.id);
    }

    /// A handle to learn how the invite ends, or to end it.
    #[must_use]
    pub fn handle(&self) -> InviteHandle {
        self.handle.clone()
    }
}

impl fmt::Debug for Invite {
    /// The device and the ticket's fingerprint, never the code or the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invite")
            .field("device", &self.device)
            .field("pairing", &self.pairing)
            .finish_non_exhaustive()
    }
}

/// How an invite ends, and a way to end it first.
///
/// Cloneable, and independent of the [`Invite`] it came from.
#[derive(Clone)]
pub struct InviteHandle {
    pub(crate) id: u64,
    pub(crate) outcome: watch::Receiver<Option<InviteOutcome>>,
    pub(crate) invites: Arc<Invites>,
}

impl InviteHandle {
    /// Wait until the invite ends, and say how. Resolves at once if it already
    /// has.
    pub async fn outcome(&self) -> InviteOutcome {
        let mut watching = self.outcome.clone();
        loop {
            let ended = watching.borrow_and_update().clone();
            if let Some(ended) = ended {
                return ended;
            }
            if watching.changed().await.is_err() {
                // The listener let go of the invite without saying how, so
                // nothing can redeem it now.
                let last = watching.borrow().clone();
                return last.unwrap_or(InviteOutcome::Withdrawn);
            }
        }
    }

    /// How the invite ended, or `None` while it is live.
    #[must_use]
    pub fn ended(&self) -> Option<InviteOutcome> {
        self.outcome.borrow().clone()
    }

    /// End the invite now, as [`InviteOutcome::Withdrawn`]. A no-op once it
    /// has ended. The key stays held;
    /// [`remove_token`](crate::ServeHandle::remove_token) retires it.
    pub fn withdraw(&self) {
        self.invites.withdraw(self.id);
    }
}

impl fmt::Debug for InviteHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InviteHandle")
            .field("ended", &self.ended())
            .finish_non_exhaustive()
    }
}

/// How an invite ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InviteOutcome {
    /// A device presented the code and was handed its key.
    ///
    /// Set when the invite is taken, before the response is written. A device
    /// that never received that response holds nothing, and
    /// [`remove_token`](crate::ServeHandle::remove_token) and a new invite are
    /// the recovery.
    Redeemed {
        /// The name its key is held under.
        device: String,
        /// The endpoint it redeemed from. Record it, and pin the key to it
        /// with [`add_token_pinned`](crate::ServeHandle::add_token_pinned) if
        /// a copied key should be no use on its own.
        peer: PeerId,
        /// What the device called itself, cleaned: invisible characters
        /// dropped, at most 64 characters, trimmed. Text from a stranger until
        /// it paired, so escape it wherever it is shown.
        label: Option<String>,
    },
    /// The ttl passed with the code unredeemed.
    Expired,
    /// [`InviteHandle::withdraw`], [`remove_token`](crate::ServeHandle::remove_token)
    /// for its device, or the listener closing.
    Withdrawn,
    /// A wrong code from a sixty-fifth endpoint while it was live: someone
    /// holding this machine's ticket is guessing.
    Burned,
}

/// Why [`ServeHandle::invite`](crate::ServeHandle::invite) refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InviteRefusal {
    /// The listener serves open, where no request is told apart by its key, so
    /// a device's key would admit nothing it does not already.
    OpenListener,
    /// The listener has closed.
    Closed,
    /// `ttl` is longer than fifteen minutes.
    TtlTooLong,
    /// `wrong_codes` is more than ten.
    TooManyWrongCodes,
}

impl fmt::Display for InviteRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OpenListener => {
                "the listener serves open, so a device's own key would admit nothing"
            }
            Self::Closed => "the listener has closed",
            Self::TtlTooLong => "an invite lives at most fifteen minutes",
            Self::TooManyWrongCodes => "an invite allows at most ten wrong codes per endpoint",
        })
    }
}
