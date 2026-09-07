//! What the serve side requires in `Authorization: Bearer …`.
//!
//! Owns the policy a listener is configured with, the cell that holds the
//! credential it currently enforces, and the comparison itself. It does not
//! know what an HTTP request looks like: it is handed the bytes of an
//! `Authorization` header, or nothing, and answers whether they admit.
//!
//! The cell is always present, even when serving open. `set_token` takes
//! `&self` and turns authentication *on* at runtime, so a listener that had
//! decided at startup not to install a check could not honour that later —
//! the difference between open and closed is whether the cell holds a
//! credential, never whether the check runs.

use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use subtle::ConstantTimeEq;

use crate::ServeError;
use crate::grant::Grants;
use crate::minting::{mint, presentable};
use crate::superseded::Superseded;
use crate::token_policy::TokenPolicy;

/// The scheme, with its trailing space, as it appears in the header.
const BEARER_PREFIX: &str = "Bearer ";

/// The credential a listener currently enforces, and the comparison
/// against it.
pub(crate) struct Credential {
    /// `None` means serving open. Wrapped in an `Arc` so a rotation swaps a
    /// pointer rather than mutating a buffer some request may be part way
    /// through comparing against.
    enforced: RwLock<Option<Arc<Enforced>>>,
    /// Credentials that admit once. Consulted only after the enforced
    /// token has failed to match, so nothing here can widen what the
    /// primary admits — only add a single, expiring exception to it.
    grants: Grants,
    /// The key a graced rotation replaced, until its window closes.
    /// Consulted after the enforced token for the reason `grants` is, and
    /// *before* `grants` because this check spends nothing.
    superseded: Superseded,
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
    /// operator — `None` when serving open.
    pub(crate) fn new(policy: &TokenPolicy) -> Result<(Self, Option<String>), ServeError> {
        let token = match policy {
            TokenPolicy::Generate => Some(mint()),
            // Refused rather than enforced. `"Bearer "` with a trailing
            // space is a header no conforming client can present, because
            // HTTP parsers trim trailing whitespace from values — so the
            // listener would come up and refuse everything, silently, for
            // the life of the process.
            TokenPolicy::Supplied(t) if !presentable(t) => return Err(ServeError::InvalidToken),
            TokenPolicy::Supplied(t) => Some(t.clone()),
            TokenPolicy::InsecureNoAuth => None,
            // `TokenPolicy` is `#[non_exhaustive]` within its own crate only
            // for downstream matches; here the match is total and a new
            // variant must be a compile error rather than silently serving
            // open, which is the one wrong default this type could have.
        };
        let cell = Self {
            enforced: RwLock::new(token.clone().map(Enforced::new)),
            grants: Grants::new(),
            superseded: Superseded::new(),
        };
        Ok((cell, token))
    }

    /// Whether an `Authorization` header value admits.
    ///
    /// `None` is a request with no such header, which is distinct from one
    /// carrying an empty value only in that neither is ever accepted while
    /// a credential is enforced.
    ///
    /// The comparison is constant-time in the **token**, via `subtle`. Two
    /// things deliberately are not, and both are public parameters of the
    /// system rather than secrets: the length, so an unequal-length value is
    /// rejected without comparing (the alternative is a padded buffer for no
    /// gain), and the scheme, which is a fixed seven-byte string every
    /// client sends in the clear.
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
    pub(crate) fn admits(&self, offered: Option<&[u8]>) -> bool {
        // The Arc is cloned and the lock released before comparing, so a
        // rotation is never blocked behind an in-flight request.
        let enforced = self.snapshot();
        let Some(enforced) = enforced else {
            return true; // serving open
        };
        let Some(offered) = offered else {
            return false;
        };
        // `BEARER_PREFIX` carries the space, so this splits scheme from
        // credential in one step and a value shorter than the scheme cannot
        // index past its end.
        let scheme = BEARER_PREFIX.len();
        if offered.len() <= scheme
            || !offered[..scheme].eq_ignore_ascii_case(BEARER_PREFIX.as_bytes())
        {
            return false;
        }
        let expected = enforced.token.as_bytes();
        let presented = &offered[scheme..];
        if expected.len() == presented.len() && bool::from(expected.ct_eq(presented)) {
            return true;
        }
        // Not the token. Two other things it could be, and the order is
        // load-bearing: the key a graced rotation replaced spends nothing
        // and so is asked first; a grant, which presenting *does* spend,
        // only after. Reversed, a value that is both would burn its one
        // admission on a request the open window admits for free.
        self.superseded.admits(presented) || self.grants.consume(presented)
    }

    /// Admit one request bearing `token` before `ttl` elapses, without
    /// touching what is enforced.
    ///
    /// Returns whether it took: a token nothing can present is refused for
    /// the reason [`Credential::new`] refuses it. Has no effect while
    /// serving open, where everything is admitted already — the grant is
    /// stored, and is simply never the reason a request got in.
    pub(crate) fn grant(&self, token: String, ttl: Duration) -> bool {
        if !presentable(&token) {
            return false;
        }
        self.grants.add(token, ttl);
        true
    }

    /// What the listener currently enforces, or `None` when serving open.
    pub(crate) fn token(&self) -> Option<String> {
        self.snapshot().map(|e| e.token.clone())
    }

    /// Install `token`, replacing whatever is enforced. Turns
    /// authentication on if it was off.
    ///
    /// Returns whether it did. A token nothing can present is refused here
    /// for the reason [`Credential::new`] refuses it, and refusing means
    /// keeping the credential already in force — installing it would take a
    /// working listener down to one that answers nothing.
    pub(crate) fn set(&self, token: String) -> bool {
        self.install(token, None)
    }

    /// [`set`](Self::set), keeping the key it replaced admitting until
    /// `grace` elapses. See [`Superseded::hold`] for what a second
    /// rotation inside that window does, and why.
    pub(crate) fn set_with_grace(&self, token: String, grace: Duration) -> bool {
        self.install(token, Some(grace))
    }

    /// The one place the enforced cell is written.
    ///
    /// `grace` is `Some` only for a rotation asked to leave an overlap
    /// behind. Everything else releases the window instead — a plain
    /// [`set`](Self::set), which is how "the old value stops working
    /// immediately" stays true even when one is called mid-window, and a
    /// rotation onto a listener that was serving open, which has no key to
    /// leave behind in the first place.
    ///
    /// The old key is held *before* the new one is enforced, both under
    /// the enforced write lock, so no request can fall between the two and
    /// find neither value admitting. That is the only place these two
    /// locks nest, and this is the order.
    fn install(&self, token: String, grace: Option<Duration>) -> bool {
        if !presentable(&token) {
            return false;
        }
        let mut enforced = self.write();
        match (grace, enforced.as_ref()) {
            (Some(grace), Some(old)) => self.superseded.hold(old.token.clone(), grace),
            _ => self.superseded.release(),
        }
        *enforced = Some(Enforced::new(token));
        true
    }

    /// Install a freshly minted token and return it.
    pub(crate) fn rotate(&self) -> String {
        let token = mint();
        // Always presentable: 256 bits of base32 is never empty. Asserted
        // rather than ignored, so that a change to `mint` that broke it
        // fails here instead of producing a listener nobody can reach.
        assert!(self.set(token.clone()), "a minted token is always usable");
        token
    }

    fn snapshot(&self) -> Option<Arc<Enforced>> {
        self.read().clone()
    }

    // A poisoned lock cannot happen here: nothing panics while holding it —
    // the only operations are a clone and a store. Recovering the guard
    // rather than propagating is the honest response to an impossible case,
    // and turns a hypothetical panic in one request into no effect on the
    // rest.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, Option<Arc<Enforced>>> {
        self.enforced
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Option<Arc<Enforced>>> {
        self.enforced
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl fmt::Debug for Credential {
    /// Reports only whether a credential is enforced, never which one — the
    /// same rule `Debug for TokenPolicy` follows one screen up. Grants are
    /// counted and a grace window is reported open or shut, for the same
    /// reason: state, never secrets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = if self.read().is_some() {
            "enforced"
        } else {
            "open"
        };
        // `finish_non_exhaustive` rather than `finish`: the token field is
        // deliberately absent, and the lint that asks for every field is
        // right to ask — the answer is that this one is withheld on purpose.
        f.debug_struct("Credential")
            .field("state", &state)
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
