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
//! Everything that *writes* the primary is in `credential_rotate.rs`, a
//! child module, and the answer to *which credential admitted* is the
//! [`Admitted`] type in `admitted.rs`; both were split off when named
//! tokens brought this file to the file-size budget.

use std::fmt;
use std::num::NonZeroU8;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use subtle::ConstantTimeEq;

use crate::ServeError;
pub(crate) use crate::admitted::Admitted;
use crate::grant::Grants;
use crate::minting::{mint, presentable};
use crate::named::{AddRefused, Named};
use crate::superseded::Superseded;
use crate::token_policy::TokenPolicy;

#[path = "credential_rotate.rs"]
mod rotate;

/// The scheme, with its trailing space, as it appears in the header.
const BEARER_PREFIX: &str = "Bearer ";

/// The credential a listener currently enforces, and the comparison
/// against it.
pub(crate) struct Credential {
    /// The listener's own credential. Behind a lock so a rotation swaps
    /// the value rather than mutating a buffer some request may be part
    /// way through comparing against; the token inside is an `Arc` for the
    /// same reason.
    primary: RwLock<Primary>,
    /// Standing credentials added by name, one per paired machine.
    /// Consulted after the primary and before the two below: presenting
    /// one spends nothing, and it is the answer to "which device" that the
    /// backend is told.
    named: Named,
    /// Credentials that admit once. Consulted only after everything that
    /// spends nothing has failed to match, so nothing here can widen what
    /// the others admit — only add a single, expiring exception to them.
    grants: Grants,
    /// The key a graced rotation replaced, until its window closes.
    /// Consulted after the primary and the named tokens, and *before*
    /// `grants` because this check spends nothing.
    superseded: Superseded,
}

/// What the listener enforces of its own, apart from anything added by
/// name.
#[derive(Clone)]
enum Primary {
    /// Serving open: everything admits, and nothing else is consulted.
    Open,
    /// No token of its own — [`TokenPolicy::Named`]. Only named tokens, a
    /// graced key and grants admit. This is *closed*, and the difference
    /// from [`Open`](Self::Open) is the whole reason the cell is an enum
    /// rather than an `Option`: before named tokens, "no primary" and
    /// "serving open" were the same state.
    Absent,
    /// The enforced token.
    Token(Arc<Enforced>),
}

/// The token a listener enforces.
///
/// One field, since the scheme stopped being part of what is compared: the
/// `Authorization` value is split at its single space and only the
/// credential after it is matched, so the pre-built `"Bearer <token>"`
/// string this used to carry beside the token had no reader left.
struct Enforced {
    /// What [`ServeHandle::token`](crate::ServeHandle::token) reports.
    token: String,
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
            grants: Grants::new(),
            superseded: Superseded::new(),
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
    pub(crate) fn admits(&self, offered: Option<&[u8]>) -> Option<Admitted> {
        // Cloned and the lock released before comparing, so a rotation is
        // never blocked behind an in-flight request.
        let primary = self.snapshot();
        if matches!(primary, Primary::Open) {
            return Some(Admitted::Open);
        }
        let offered = offered?;
        // `BEARER_PREFIX` carries the space, so this splits scheme from
        // credential in one step and a value shorter than the scheme cannot
        // index past its end.
        let scheme = BEARER_PREFIX.len();
        if offered.len() <= scheme
            || !offered[..scheme].eq_ignore_ascii_case(BEARER_PREFIX.as_bytes())
        {
            return None;
        }
        let presented = &offered[scheme..];
        if let Primary::Token(enforced) = &primary {
            let expected = enforced.token.as_bytes();
            if expected.len() == presented.len() && bool::from(expected.ct_eq(presented)) {
                return Some(Admitted::Token);
            }
        }
        // Not the primary. Three other things it could be, and the order
        // is load-bearing: everything that spends nothing is asked before
        // the one thing that does. A named token and the key a graced
        // rotation replaced both admit repeatedly; a grant, which
        // presenting *does* spend, only after them. Reversed, a value that
        // is both would burn its one admission on a request that would
        // have been admitted for free.
        if let Some(name) = self.named.admits(presented) {
            return Some(Admitted::Named(name));
        }
        if self.superseded.admits(presented) {
            return Some(Admitted::Superseded);
        }
        if self.grants.consume(presented) {
            return Some(Admitted::Grant);
        }
        None
    }

    /// Admit one request bearing `token` before `ttl` elapses, without
    /// touching what is enforced. With `burn_after`, the grant also dies at
    /// that many wrong presentations — see [`Grants::consume`] for what
    /// counts as one.
    ///
    /// Returns whether it took: a token nothing can present is refused for
    /// the reason [`Credential::new`] refuses it. Has no effect while
    /// serving open, where everything is admitted already — the grant is
    /// stored, and is simply never the reason a request got in.
    pub(crate) fn grant(
        &self,
        token: String,
        ttl: Duration,
        burn_after: Option<NonZeroU8>,
    ) -> bool {
        if !presentable(&token) {
            return false;
        }
        self.grants.add(token, ttl, burn_after);
        true
    }

    /// Hold `token` under `name` as a standing credential. See
    /// [`Named::add`] for what is refused and why.
    pub(crate) fn add_named(&self, name: &str, token: String) -> Result<(), AddRefused> {
        self.named.add(name, token)
    }

    /// Stop admitting the token held under `name`; whether there was one.
    pub(crate) fn remove_named(&self, name: &str) -> bool {
        self.named.remove(name)
    }

    /// Every name a token is held under.
    pub(crate) fn named(&self) -> Vec<String> {
        self.named.names()
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
    /// tokens and grants are counted and a grace window is reported open or
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
            .field("grants", &self.grants.count())
            .field("grace", &self.superseded.is_open())
            .finish_non_exhaustive()
    }
}

impl Enforced {
    fn new(token: String) -> Arc<Self> {
        Arc::new(Self { token })
    }
}

#[cfg(test)]
#[path = "credential_tests.rs"]
mod credential_tests;
