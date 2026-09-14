//! Live invites, the strikes against them, and the one place an invite ends.
//!
//! One `std` mutex over all of it, never held across an await. Every path
//! that ends an invite removes it from `live` under that lock, and publishes
//! through [`publish`], which writes an outcome only where there is none yet:
//! a redemption, an expiry, a withdrawal and a burn can race, and the first to
//! take the lock is the one that happened.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use subtle::ConstantTimeEq;
use tokio::sync::watch;

use crate::invite::InviteOutcome;
use crate::pairing_string::PairingCode;
use crate::peer_id::PeerId;

/// How many distinct endpoints may hold strikes before every live invite
/// burns.
pub(crate) const MAX_STRIKERS: usize = 64;

struct Live {
    id: u64,
    code: PairingCode,
    armed: bool,
    device: String,
    key: String,
    expires: Instant,
    wrong_codes: u8,
    outcome: watch::Sender<Option<InviteOutcome>>,
}

#[derive(Default)]
struct State {
    live: Vec<Live>,
    /// Wrong codes by endpoint, forgotten whenever no invite is live.
    strikes: HashMap<PeerId, u8>,
    next: u64,
}

/// Every invite a listener holds.
#[derive(Default)]
pub(crate) struct Invites {
    state: Mutex<State>,
}

/// What a redeemed code hands back.
#[derive(Debug)]
pub(crate) struct Redeemed {
    pub(crate) device: String,
    pub(crate) key: String,
}

/// A freshly registered invite, as [`Invites::register`] hands it back.
pub(crate) struct Registered {
    pub(crate) id: u64,
    pub(crate) code: PairingCode,
    pub(crate) outcome: watch::Receiver<Option<InviteOutcome>>,
}

impl Invites {
    /// Hold a disarmed invite for `device`'s `key` until `expires`.
    ///
    /// Its code differs from every other live code, so one presentation can
    /// never match two invites.
    pub(crate) fn register(
        &self,
        device: String,
        key: String,
        expires: Instant,
        wrong_codes: u8,
    ) -> Registered {
        self.register_drawing(device, key, expires, wrong_codes, PairingCode::mint)
    }

    /// [`register`](Self::register), drawing codes from `draw`: a code another
    /// live invite holds is drawn again. Apart so a test can script the draws.
    fn register_drawing(
        &self,
        device: String,
        key: String,
        expires: Instant,
        wrong_codes: u8,
        mut draw: impl FnMut() -> PairingCode,
    ) -> Registered {
        let mut state = self.lock();
        let code = loop {
            let code = draw();
            if state.live.iter().all(|live| live.code != code) {
                break code;
            }
        };
        let id = state.next;
        state.next = state.next.wrapping_add(1);
        let (sender, outcome) = watch::channel(None);
        state.live.push(Live {
            id,
            code: code.clone(),
            armed: false,
            device,
            key,
            expires,
            wrong_codes,
            outcome: sender,
        });
        drop(state);
        Registered { id, code, outcome }
    }

    /// Make invite `id`'s code redeemable, if it is still live.
    pub(crate) fn arm(&self, id: u64) {
        if let Some(live) = self.lock().live.iter_mut().find(|live| live.id == id) {
            live.armed = true;
        }
    }

    /// End invite `id` as withdrawn, if it is still live.
    pub(crate) fn withdraw(&self, id: u64) {
        end_where(
            &mut self.lock(),
            |live| live.id == id,
            &InviteOutcome::Withdrawn,
        );
    }

    /// End every live invite for `device` as withdrawn.
    pub(crate) fn withdraw_device(&self, device: &str) {
        end_where(
            &mut self.lock(),
            |live| live.device == device,
            &InviteOutcome::Withdrawn,
        );
    }

    /// End invite `id` as expired, if it is live.
    ///
    /// Called when the invite's timer fires, and that timer is the clock.
    /// Checking the system clock as well would leave the invite live wherever
    /// the two disagree, as they do under a paused test clock.
    pub(crate) fn expire(&self, id: u64) {
        end_where(
            &mut self.lock(),
            |live| live.id == id,
            &InviteOutcome::Expired,
        );
    }

    /// How many invites are live, for a `Debug` that reports state.
    pub(crate) fn count(&self) -> usize {
        self.lock().live.len()
    }

    /// Present `presented` from `from`, and hand back the device and key it
    /// redeemed, if it redeemed one.
    ///
    /// Anything else is a refusal the caller cannot tell apart from another:
    /// no invite live, a wrong code, a code not yet armed, or an endpoint
    /// locked out. A wrong code counts one strike against `from`, unless
    /// `from` is locked out of every live invite already, and a strike from a
    /// sixty-fifth endpoint burns every live invite.
    pub(crate) fn redeem(
        &self,
        presented: &[u8],
        from: PeerId,
        label: Option<String>,
    ) -> Option<Redeemed> {
        let now = Instant::now();
        let mut state = self.lock();
        end_where(
            &mut state,
            |live| live.expires <= now,
            &InviteOutcome::Expired,
        );
        if state.live.is_empty() {
            return None;
        }
        let strikes = state.strikes.get(&from).copied().unwrap_or(0);
        // Every live code is compared, with no early exit: which one matched
        // is not a secret, but the time a search took would say where it was.
        let mut matched = None;
        for (index, live) in state.live.iter().enumerate() {
            let code = live.code.as_str().as_bytes();
            let equal = code.len() == presented.len() && bool::from(code.ct_eq(presented));
            if equal && matched.is_none() {
                matched = Some(index);
            }
        }
        if let Some(index) = matched {
            if strikes >= state.live[index].wrong_codes {
                return None;
            }
            if state.live[index].armed {
                let live = state.live.remove(index);
                live.outcome.send_if_modified(|ended| {
                    publish(
                        ended,
                        InviteOutcome::Redeemed {
                            device: live.device.clone(),
                            peer: from,
                            label,
                        },
                    )
                });
                if state.live.is_empty() {
                    state.strikes.clear();
                }
                return Some(Redeemed {
                    device: live.device,
                    key: live.key,
                });
            }
        }
        // A miss. An endpoint locked out of every live invite has nothing left
        // to spend, and counting it again is how a counter wraps round.
        if state.live.iter().all(|live| strikes >= live.wrong_codes) {
            return None;
        }
        if !state.strikes.contains_key(&from) && state.strikes.len() >= MAX_STRIKERS {
            end_where(&mut state, |_| true, &InviteOutcome::Burned);
            return None;
        }
        let count = state.strikes.entry(from).or_insert(0);
        *count = count.saturating_add(1);
        drop(state);
        None
    }

    // A poisoned lock cannot happen here: nothing panics while holding it.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// End every live invite `ends` selects with `outcome`, and forget the strikes
/// once none is left.
fn end_where(state: &mut State, ends: impl Fn(&Live) -> bool, outcome: &InviteOutcome) {
    state.live.retain(|live| {
        if !ends(live) {
            return true;
        }
        live.outcome
            .send_if_modified(|ended| publish(ended, outcome.clone()));
        false
    });
    if state.live.is_empty() {
        state.strikes.clear();
    }
}

/// Write `outcome` where there is none yet. The first writer is the one that
/// happened.
fn publish(ended: &mut Option<InviteOutcome>, outcome: InviteOutcome) -> bool {
    if ended.is_some() {
        return false;
    }
    *ended = Some(outcome);
    true
}

#[cfg(test)]
#[path = "invites_tests.rs"]
mod invites_tests;
