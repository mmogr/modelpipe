//! Inviting a device: another `impl` block of [`ServeHandle`].
//!
//! The one call an embedder makes to pair a machine. The key is minted and
//! held first, the invite registered disarmed, and its expiry scheduled on the
//! listener's own runtime; [`Invite::arm`] is the embedder's to call once the
//! key is stored.

use std::sync::Arc;
use std::time::Instant;

use crate::invite::{Invite, InviteHandle, InviteOptions, InviteRefusal, MAX_TTL, MAX_WRONG_CODES};
use crate::minting::mint;
use crate::pairing_string::PairingString;
use crate::serve_error::{NamedTokenRefusal, ServeError};
use crate::serve_handle::ServeHandle;

/// How many minted device names are tried before a taken one is reported.
const MINT_ATTEMPTS: usize = 5;

impl ServeHandle {
    /// Invite a device: mint a key for it and hold it at the edge, and mint a
    /// one-time code it redeems for that key at [`PAIR_PATH`](crate::PAIR_PATH).
    ///
    /// The code is not redeemable until [`Invite::arm`], so store the key
    /// first. The invite ends once, as an
    /// [`InviteOutcome`](crate::InviteOutcome) that [`InviteHandle::outcome`]
    /// waits for. A key whose invite ends unredeemed stays held;
    /// [`remove_token`](Self::remove_token) retires it, and withdraws its
    /// invite first if that is still live. The options' docs give the odds a
    /// guesser has.
    ///
    /// # Errors
    ///
    /// [`ServeError::Invite`] when the options are out of bounds, or the
    /// listener serves open or has closed; [`ServeError::NamedToken`] when
    /// `device` is not a name or is taken. Nothing is held on either.
    pub fn invite(&self, opts: InviteOptions) -> Result<Invite, ServeError> {
        let refusal = if opts.ttl > MAX_TTL {
            Some(InviteRefusal::TtlTooLong)
        } else if opts.wrong_codes.get() > MAX_WRONG_CODES {
            Some(InviteRefusal::TooManyWrongCodes)
        } else if self.state.lifecycle.close_reason().is_some() {
            Some(InviteRefusal::Closed)
        } else if self.state.credential.serves_open() {
            Some(InviteRefusal::OpenListener)
        } else {
            None
        };
        if let Some(reason) = refusal {
            return Err(ServeError::Invite(reason));
        }
        let api_key = mint();
        let device = self.hold_invited(opts.device, &api_key)?;
        let invites = Arc::clone(self.state.credential.invites());
        let expires = Instant::now() + opts.ttl;
        let registered = invites.register(
            device.clone(),
            api_key.clone(),
            expires,
            opts.wrong_codes.get(),
        );
        let id = registered.id;
        let state = Arc::clone(&self.state);
        self.state.runtime.spawn(async move {
            tokio::select! {
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(expires)) => {
                    state.credential.invites().expire(id);
                }
                () = state.lifecycle.wait_until_closed() => {
                    state.credential.invites().withdraw(id);
                }
            }
        });
        Ok(Invite {
            pairing: PairingString::new(self.ticket(), Some(registered.code.clone())),
            code: registered.code,
            device,
            api_key,
            handle: InviteHandle {
                id,
                outcome: registered.outcome,
                invites,
            },
        })
    }

    /// Hold `key` under `name`, or under a minted name when there is none.
    fn hold_invited(&self, name: Option<String>, key: &str) -> Result<String, ServeError> {
        if let Some(name) = name {
            self.hold(&name, key.to_owned(), None)?;
            return Ok(name);
        }
        let mut taken = None;
        for _ in 0..MINT_ATTEMPTS {
            let name = minted_device();
            match self.hold(&name, key.to_owned(), None) {
                Ok(()) => return Ok(name),
                Err(
                    refused @ ServeError::NamedToken {
                        reason: NamedTokenRefusal::NameTaken,
                        ..
                    },
                ) => taken = Some(refused),
                Err(other) => return Err(other),
            }
        }
        Err(taken.unwrap_or(ServeError::Invite(InviteRefusal::Closed)))
    }
}

/// `dev-` and eight hex digits from the CSPRNG: a token name, and a different
/// shape from a twelve-hex fingerprint.
fn minted_device() -> String {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).expect("the OS CSPRNG must be available");
    format!("dev-{:08x}", u32::from_le_bytes(bytes))
}
