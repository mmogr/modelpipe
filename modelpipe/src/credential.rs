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
//! Three questions are answered here. *What admits* is [`Credential`] and
//! its comparison. *What the listener holds of its own*, and what becomes
//! of it when the operator changes it, is the primary and the methods that
//! write it or the upstream bearer. *Which credential admitted* is
//! [`Admitted`], the one thing about admission the rest of the edge needs
//! to know: [`crate::exchange`] reads [`Admitted::device`] to tell the
//! backend which named token a request arrived under, and nothing else
//! about the comparison leaves this module.

use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use subtle::ConstantTimeEq;

use crate::ServeError;
use crate::invites::Invites;
use crate::minting::{mint, presentable};
use crate::named::{AddRefused, Named, NamedMatch};
use crate::peer_id::PeerId;
use crate::superseded::Superseded;
use crate::token_policy::TokenPolicy;

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

/// What the listener enforces of its own, apart from anything added by
/// name.
#[derive(Clone)]
enum Primary {
    /// Serving open: everything admits, and nothing else is consulted.
    Open,
    /// No token of its own — [`TokenPolicy::Named`]. Only named tokens and a
    /// graced key admit. This is *closed*, and the difference
    /// from [`Open`](Self::Open) is the whole reason the cell is an enum
    /// rather than an `Option`: before named tokens, "no primary" and
    /// "serving open" were the same state.
    Absent,
    /// The enforced token.
    Token(Arc<Enforced>),
}

/// The token a listener enforces.
///
/// One field, because the scheme is not part of what is compared: the
/// `Authorization` value is split at its single space and only the
/// credential after it is matched against this.
struct Enforced {
    /// What [`ServeHandle::token`](crate::ServeHandle::token) reports.
    token: String,
}

impl Enforced {
    fn new(token: String) -> Arc<Self> {
        Arc::new(Self { token })
    }
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

    /// Whether `token` is the one held under `name`.
    pub(crate) fn holds_named(&self, name: &str, token: &str) -> bool {
        self.named.holds(name, token)
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

    // The primary and the upstream bearer: everything that writes them, and
    // what becomes of the old key when the operator changes it.

    /// Install `token`, replacing whatever is enforced. Turns
    /// authentication on if it was off, and gives a listener that had no
    /// token of its own ([`TokenPolicy::Named`])
    /// one — the named tokens are untouched either way.
    ///
    /// Returns whether it did. A token nothing can present is refused here
    /// for the reason [`Credential::new`] refuses it, and refusing means
    /// keeping the credential already in force — installing it would take a
    /// working listener down to one that answers nothing.
    pub(crate) fn set(&self, token: String) -> bool {
        self.install(token, None)
    }

    /// [`set`](Self::set), keeping the key it replaced admitting until
    /// `grace` elapses. See [`Superseded::hold`](crate::superseded::Superseded::hold)
    /// for what a second rotation inside that window does, which `grace`
    /// values hold nothing at all, and why.
    pub(crate) fn set_with_grace(&self, token: String, grace: Duration) -> bool {
        self.install(token, Some(grace))
    }

    /// The one place the primary is written.
    ///
    /// `grace` is `Some` only for a rotation asked to leave an overlap
    /// behind. Everything else releases the window instead — a plain
    /// [`set`](Self::set), which is how "the old value stops working
    /// immediately" stays true even when one is called mid-window, and a
    /// rotation onto a listener that had no token to leave behind, whether
    /// it was serving open or admitting by name only.
    ///
    /// A refused token returns before either lock is taken, so an open
    /// window is left exactly as it was — neither shut nor extended. That
    /// is the right behaviour (a rotation that did not happen must not
    /// change what admits) and it is the one the callers above have to
    /// document, because "nothing changed" reads to an operator as "no old
    /// key is admitting" and mid-window those are different claims.
    ///
    /// The old key is held *before* the new one is enforced, and both
    /// happen under the primary's write lock, so the **stored state** is
    /// never a gap: at every instant a reader could observe it, one of the
    /// two values is admitting. That is the only place these two locks
    /// nest, and this is the order.
    ///
    /// It does not follow — and is not claimed — that no request can be
    /// refused during a rotation. [`admits`](Self::admits) reads the
    /// credentials under separate locks, releasing each before taking the
    /// next, precisely so a rotation is never held up behind an in-flight
    /// request. A rotation landing between those reads can refuse a value
    /// that admitted before it and admits after it. That is fail-closed, it
    /// is the snapshot race `admits` has always run, and the honest
    /// guarantee is about the state rather than about every request that
    /// races it.
    fn install(&self, token: String, grace: Option<Duration>) -> bool {
        if !presentable(&token) {
            return false;
        }
        let mut primary = self.write();
        match (grace, &*primary) {
            (Some(grace), Primary::Token(old)) => self.superseded.hold(old.token.clone(), grace),
            _ => self.superseded.release(),
        }
        *primary = Primary::Token(Enforced::new(token));
        true
    }

    /// What the backend is told in `Authorization` from now on: `Some` to
    /// present that bearer in the client's place, `None` to forward the
    /// client's own. Returns whether it took — `Some` of a value nothing
    /// could present is refused, and what was in force stays in force.
    pub(crate) fn set_upstream(&self, token: Option<String>) -> bool {
        if token.as_deref().is_some_and(|t| !presentable(t)) {
            return false;
        }
        *self
            .upstream
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = token.map(Arc::from);
        true
    }

    /// The bearer presented upstream, if one replaces the client's.
    pub(crate) fn upstream(&self) -> Option<Arc<str>> {
        self.upstream
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
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

/// Which credential admitted a request.
///
/// The edge has always known this — it follows from the short-circuiting
/// order in [`Credential::admits`](crate::credential::Credential::admits) — and telling the caller costs nothing
/// an attacker could use, since the 200 already told them a credential
/// worked. What it buys is [`device`](Self::device): the name of the token
/// that admitted, which is what the backend is told so that it can tell
/// one paired machine from another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Admitted {
    /// Serving open; nothing was checked.
    Open,
    /// The primary token.
    Token,
    /// A token added by name — this one.
    Named(Arc<str>),
    /// The key a graced rotation replaced, inside its window.
    Superseded,
}

impl Admitted {
    /// The name of the token that admitted, when one did.
    pub(crate) fn device(&self) -> Option<&str> {
        match self {
            Self::Named(name) => Some(name),
            Self::Open | Self::Token | Self::Superseded => None,
        }
    }
}

/// What the backend is told about an admitted request, beyond the bytes
/// the client sent: which named token admitted it, and what to present as
/// the bearer in the client's place.
///
/// Built by [`Credential::forward`](crate::credential::Credential::forward)
/// so the exchange hands the rewrite one value rather than reaching into
/// the credential twice, and so the decision about what the backend sees
/// is made in one place.
pub(crate) struct Forward {
    /// The name of the token that admitted, when one added by name did.
    pub(crate) device: Option<Arc<str>>,
    /// The bearer to present upstream, or `None` to forward the client's.
    pub(crate) upstream: Option<Arc<str>>,
}

#[cfg(test)]
#[path = "credential_tests.rs"]
mod credential_tests;
