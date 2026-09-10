//! Credentials that admit by name: one per paired machine, revoked one at
//! a time.
//!
//! The primary token is one value for everybody, and revoking it is
//! revoking everybody — the right shape for an operator with one client,
//! and the wrong one the moment there are three devices and one of them is
//! lost. A *named* token is the other shape: a standing credential that
//! admits exactly like the primary, except that it was added under a name
//! and can be removed under it, and the backend is told the name on every
//! request it admits. Nothing else changes when one goes.
//!
//! The name is an identifier, not a label. It travels to the backend as a
//! header value and appears in the exchange log, so it is restricted to
//! the characters both can carry without escaping. An embedder that wants
//! to show a person "Matt's iPhone" keeps that mapping on its own side,
//! keyed by the identifier it chose here.
//!
//! Kept beside, not inside, [`crate::credential`], as [`crate::grant`] is:
//! the primary's rotation contract must not be reachable from here, and
//! the file-size gate says the same from the other direction.

use std::sync::{Arc, RwLock};

use subtle::ConstantTimeEq;

use crate::minting::presentable;

/// The longest name accepted. Long enough for any identifier an embedder
/// would mint, short enough that a name is never the bulk of a header.
pub(crate) const MAX_NAME_LEN: usize = 64;

/// One standing credential, and the name it answers to.
struct NamedToken {
    name: Arc<str>,
    token: String,
}

/// Every named token a listener holds.
pub(crate) struct Named {
    entries: RwLock<Vec<NamedToken>>,
}

/// Why [`Named::add`] did not take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddRefused {
    /// The name is empty, too long, or carries a character a header value
    /// cannot — see [`valid_name`].
    InvalidName,
    /// A token is already held under this name. Replacing it silently
    /// would be a rotation nobody asked for; remove it first.
    NameTaken,
    /// This exact token is already held under another name. Two names
    /// for one value would make "which device" a question with two
    /// answers, and the backend is told exactly one.
    TokenTaken,
    /// The token is empty or nothing but whitespace — the value the
    /// primary refuses, refused for the same reason.
    UnpresentableToken,
}

/// Whether `name` can be a token's name: non-empty, at most
/// [`MAX_NAME_LEN`] bytes, and only ASCII letters, digits, `.`, `_` and
/// `-`. That is the intersection of what a header value, a log line and
/// a filename all carry unescaped, which is where a name ends up.
pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl Named {
    pub(crate) const fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
        }
    }

    /// Hold `token` under `name`.
    ///
    /// # Errors
    ///
    /// [`AddRefused`] says which rule refused it; nothing is held on any
    /// of them.
    pub(crate) fn add(&self, name: &str, token: String) -> Result<(), AddRefused> {
        if !valid_name(name) {
            return Err(AddRefused::InvalidName);
        }
        if !presentable(&token) {
            return Err(AddRefused::UnpresentableToken);
        }
        let mut entries = self.write();
        if entries.iter().any(|held| &*held.name == name) {
            return Err(AddRefused::NameTaken);
        }
        if entries
            .iter()
            .any(|held| same(&held.token, token.as_bytes()))
        {
            return Err(AddRefused::TokenTaken);
        }
        entries.push(NamedToken {
            name: Arc::from(name),
            token,
        });
        drop(entries);
        Ok(())
    }

    /// Stop admitting the token held under `name`. Returns whether there
    /// was one; a name nothing is held under is not an error, because the
    /// state the caller wanted is the state there is.
    pub(crate) fn remove(&self, name: &str) -> bool {
        let mut entries = self.write();
        let before = entries.len();
        entries.retain(|held| &*held.name != name);
        entries.len() != before
    }

    /// Every name a token is held under, in the order they were added.
    pub(crate) fn names(&self) -> Vec<String> {
        self.read()
            .iter()
            .map(|held| held.name.to_string())
            .collect()
    }

    /// The name of the token `presented` is, if it is one.
    ///
    /// Constant-time in each token, the rule the primary keeps; which
    /// *position* matched is not hidden and is not a secret. Every entry
    /// is compared rather than stopping at the first match, so the time
    /// taken says how many tokens are held — a count the operator already
    /// knows — and not where the presented one sits among them.
    pub(crate) fn admits(&self, presented: &[u8]) -> Option<Arc<str>> {
        let entries = self.read();
        let mut matched = None;
        for held in entries.iter() {
            if same(&held.token, presented) && matched.is_none() {
                matched = Some(Arc::clone(&held.name));
            }
        }
        drop(entries);
        matched
    }

    /// How many tokens are held, for a `Debug` that reports state and not
    /// secrets.
    pub(crate) fn count(&self) -> usize {
        self.read().len()
    }

    // A poisoned lock cannot happen here: nothing panics while holding it.
    // Recovering the guard is the honest response to an impossible case.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, Vec<NamedToken>> {
        self.entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Vec<NamedToken>> {
        self.entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The comparison the whole file uses: length in the open, bytes in
/// constant time.
fn same(held: &str, presented: &[u8]) -> bool {
    let expected = held.as_bytes();
    expected.len() == presented.len() && bool::from(expected.ct_eq(presented))
}

#[cfg(test)]
#[path = "named_tests.rs"]
mod named_tests;
