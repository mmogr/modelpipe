//! What the serve side requires in `Authorization: Bearer …`.
//!
//! Owns the policy a listener is configured with, the cell that holds the
//! credential it currently enforces, and the comparison itself. It does not
//! know what an HTTP request looks like: it is handed the bytes of an
//! `Authorization` header, or nothing, and answers whether they admit —
//! and, because a listener may hold one token per paired machine, *which*
//! of its credentials did.
//!
//! The cell is always present, even when serving open. `set_token` takes
//! `&self` and turns authentication *on* at runtime, so a listener that had
//! decided at startup not to install a check could not honour that later —
//! the difference between open and closed is whether the cell holds a
//! credential, never whether the check runs.
//!
//! The primary itself — its type, and everything that writes it or the
//! upstream bearer — is in `credential_rotate.rs`, a child module, and
//! the answer to *which credential admitted* is the [`Admitted`] type in
//! `admitted.rs`; both were split off when named tokens brought this file
//! to the file-size budget.

use std::fmt;
use std::sync::{Arc, RwLock};

use subtle::ConstantTimeEq;

use crate::ServeError;
pub(crate) use crate::admitted::{Admitted, Forward};
use crate::invites::Invites;
use crate::minting::{mint, presentable};
use crate::named::{AddRefused, Named, NamedMatch};
use crate::peer_id::PeerId;
use crate::superseded::Superseded;
use crate::token_policy::TokenPolicy;

#[path = "credential_rotate.rs"]
mod rotate;
use rotate::{Enforced, Primary};

/// The scheme, with its trailing space, as it appears in the header.
const BEARER_PREFIX: &str = "Bearer ";

/// The credential in an `Authorization` value, after its `Bearer ` scheme, or
/// `None` for a value that is not a bearer credential.
///
/// `BEARER_PREFIX` carries the space, so this splits scheme from credential in
/// one step, and a value shorter than the scheme cannot index past its end.
pub(crate) fn bearer(offered: Option<&[u8]>) -> Option<&[u8]> {
    let offered = offered?;
    let scheme = BEARER_PREFIX.len();
    if offered.len() <= scheme || !offered[..scheme].eq_ignore_ascii_case(BEARER_PREFIX.as_bytes())
    {
        return None;
    }
    Some(&offered[scheme..])
}

/// The credential a listener currently enforces, and the comparison
/// against it.
pub(crate) struct Credential {
    /// The listener's own credential. Behind a lock so a rotation swaps
    /// the value rather than mutating a buffer some request may be part
    /// way through comparing against; the token inside is an `Arc` for the
    /// same reason.
    primary: RwLock<Primary>,
    /// Standing credentials added by name, one per paired machine.
    /// Consulted after the primary and before the graced key below, and it
    /// is the answer to "which device" that the backend is told.
    named: Named,
    /// The key a graced rotation replaced, until its window closes.
    /// Consulted after the primary and the named tokens.
    superseded: Superseded,
    /// Invites for devices not yet paired, and the strikes against them.
    /// Shared with every `InviteHandle`, which may outlive a borrow of this.
    invites: Arc<Invites>,
    /// What the backend is told in `Authorization`, in place of whatever
    /// the client sent — or `None` to forward the client's own. The
    /// outbound half of the concern the rest of this type is the inbound
    /// half of, kept here so one type owns everything the edge does about
    /// that header.
    upstream: RwLock<Option<Arc<str>>>,
}

impl Credential {
    /// Build the cell a policy asks for, returning the token to show the
    /// operator — `None` when there is no primary to show.
    pub(crate) fn new(policy: &TokenPolicy) -> Result<(Self, Option<String>), ServeError> {
        let (primary, token) = match policy {
            TokenPolicy::Generate => {
                let token = mint();
                (Primary::Token(Enforced::new(token.clone())), Some(token))
            }
            // Refused rather than enforced. `"Bearer "` with a trailing
            // space is a header no conforming client can present, because
            // HTTP parsers trim trailing whitespace from values — so the
            // listener would come up and refuse everything, silently, for
            // the life of the process.
            TokenPolicy::Supplied(t) if !presentable(t) => return Err(ServeError::InvalidToken),
            TokenPolicy::Supplied(t) => (Primary::Token(Enforced::new(t.clone())), Some(t.clone())),
            TokenPolicy::InsecureNoAuth => (Primary::Open, None),
            TokenPolicy::Named => (Primary::Absent, None),
            // `TokenPolicy` is `#[non_exhaustive]` within its own crate only
            // for downstream matches; here the match is total and a new
            // variant must be a compile error rather than silently serving
            // open, which is the one wrong default this type could have.
        };
        let cell = Self {
            primary: RwLock::new(primary),
            named: Named::new(),
            superseded: Superseded::new(),
            invites: Arc::default(),
            upstream: RwLock::new(None),
        };
        Ok((cell, token))
    }

    /// Which credential an `Authorization` header value admits under, or
    /// `None` when it admits under none.
    ///
    /// `None` offered is a request with no such header, which is distinct
    /// from one carrying an empty value only in that neither is ever
    /// accepted while anything is enforced.
    ///
    /// The comparison is constant-time in every **token**, via `subtle`.
    /// What deliberately is not, in every case because it is a public
    /// parameter of the system rather than a secret: the length, so an
    /// unequal-length value is rejected without comparing (the alternative
    /// is a padded buffer for no gain); the scheme, which is a fixed
    /// seven-byte string every client sends in the clear; and *which* of
    /// the credentials below admitted, which follows from the
    /// short-circuiting order and tells an attacker nothing the 200 has
    /// not already told them.
    ///
    /// The scheme is matched case-insensitively because RFC 9110 §11.1 says
    /// it is: `auth-scheme` is a token, and token comparison is
    /// case-insensitive. This edge required `Bearer` exactly, so a client
    /// sending the equally-valid `bearer` was told its key was invalid —
    /// the least actionable 401 available, since the key really was correct
    /// and nothing in the message pointed at the capitalisation.
    ///
    /// Split at the first space rather than trimmed, so the single
    /// `SP` RFC 9110 §11.1 puts between scheme and credential stays exactly
    /// one: the whitespace refusals this type has always made are still
    /// made, and a token that begins with a space is still a different
    /// token.
    ///
    /// `from` is the endpoint the request arrived from. A token pinned to one
    /// endpoint admits from that one only, and from any other is refused here,
    /// before a graced key holding the same value could admit it.
    pub(crate) fn admits(&self, offered: Option<&[u8]>, from: PeerId) -> Option<Admitted> {
        // Cloned and the lock released before comparing, so a rotation is
        // never blocked behind an in-flight request.
        let primary = self.snapshot();
        if matches!(primary, Primary::Open) {
            return Some(Admitted::Open);
        }
        let presented = bearer(offered)?;
        if let Primary::Token(enforced) = &primary {
            let expected = enforced.token.as_bytes();
            if expected.len() == presented.len() && bool::from(expected.ct_eq(presented)) {
                return Some(Admitted::Token);
            }
        }
        // Not the primary. A named token, then the key a graced rotation
        // replaced; a pinned token from the wrong endpoint stops here rather
        // than being admitted by a graced key of the same value.
        match self.named.admits(presented, from) {
            NamedMatch::Admits(name) => return Some(Admitted::Named(name)),
            NamedMatch::PinnedElsewhere => return None,
            NamedMatch::Unknown => {}
        }
        if self.superseded.admits(presented) {
            return Some(Admitted::Superseded);
        }
        None
    }

    /// Hold `token` under `name` as a standing credential, admitting only from
    /// `pinned` when it is given. See [`Named::add`] for what is refused and
    /// why.
    pub(crate) fn add_named(
        &self,
        name: &str,
        token: String,
        pinned: Option<PeerId>,
    ) -> Result<(), AddRefused> {
        self.named.add(name, token, pinned)
    }

    /// Stop admitting the token held under `name`; whether there was one.
    pub(crate) fn remove_named(&self, name: &str) -> bool {
        self.named.remove(name)
    }

    /// Every name a token is held under.
    pub(crate) fn named(&self) -> Vec<String> {
        self.named.names()
    }

    /// The invites this listener holds.
    pub(crate) const fn invites(&self) -> &Arc<Invites> {
        &self.invites
    }

    /// Whether the listener serves open, admitting everything unchecked.
    pub(crate) fn serves_open(&self) -> bool {
        matches!(self.snapshot(), Primary::Open)
    }

    /// Whether a named token is pinned to `peer`: a device this listener
    /// already knows by its endpoint.
    pub(crate) fn pinned_to(&self, peer: PeerId) -> bool {
        self.named.pins(peer)
    }

    /// What the backend is told about a request `admitted` let through.
    pub(crate) fn forward(&self, admitted: &Admitted) -> Forward {
        Forward {
            device: match admitted {
                Admitted::Named(name) => Some(Arc::clone(name)),
                Admitted::Open | Admitted::Token | Admitted::Superseded => None,
            },
            upstream: self.upstream(),
        }
    }

    /// What the listener enforces of its own, or `None` when it has no
    /// primary — serving open, or admitting by name only.
    pub(crate) fn token(&self) -> Option<String> {
        match self.snapshot() {
            Primary::Token(enforced) => Some(enforced.token.clone()),
            Primary::Open | Primary::Absent => None,
        }
    }

    fn snapshot(&self) -> Primary {
        self.read().clone()
    }

    // A poisoned lock cannot happen here: nothing panics while holding it —
    // the only operations are a clone and a store. Recovering the guard
    // rather than propagating is the honest response to an impossible case,
    // and turns a hypothetical panic in one request into no effect on the
    // rest.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, Primary> {
        self.primary
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Primary> {
        self.primary
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl fmt::Debug for Credential {
    /// Reports only what kind of credential is enforced, never which — the
    /// same rule `Debug for TokenPolicy` follows one screen up. Named
    /// tokens are counted and a grace window is reported open or
    /// shut, for the same reason: state, never secrets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match self.snapshot() {
            Primary::Open => "open",
            Primary::Absent => "named",
            Primary::Token(_) => "enforced",
        };
        // `finish_non_exhaustive` rather than `finish`: the token field is
        // deliberately absent, and the lint that asks for every field is
        // right to ask — the answer is that this one is withheld on purpose.
        f.debug_struct("Credential")
            .field("state", &state)
            .field("named", &self.named.count())
            .field("grace", &self.superseded.is_open())
            .field("invites", &self.invites.count())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[path = "credential_tests.rs"]
mod credential_tests;
