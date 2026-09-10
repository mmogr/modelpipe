//! Who the paired machines are, one credential each.
//!
//! A sixth `impl` block of [`ServeHandle`], split by question like the
//! others: `serve_handle.rs` answers *who may use this listener* with one
//! token for everybody, and this file answers it one machine at a time —
//! which is the only shape under which "this device, and only this
//! device, may no longer" is a sentence the listener can act on.
//!
//! A named token admits exactly like the primary. What differs is
//! bookkeeping: it was added under a name, it is removed under that name,
//! and the backend is told the name as `X-Modelpipe-Device` on every
//! request it admits. The primary, if there is one, is untouched by all of
//! it; a listener started with [`TokenPolicy::Named`](crate::TokenPolicy::Named) has none, and admits
//! nothing until the first token is added.

use crate::named::AddRefused;
use crate::serve_error::{NamedTokenRefusal, ServeError};
use crate::serve_handle::ServeHandle;

impl ServeHandle {
    /// Hold `token` under `name`, admitting requests that bear it from
    /// this call forward.
    ///
    /// `name` is an identifier, not a label — ASCII letters, digits, `.`,
    /// `_` and `-`, at most 64 bytes — because it travels to the backend
    /// as a header value and appears in the exchange log, and both carry
    /// exactly that unescaped. Keep the mapping to a person's label on
    /// your own side, keyed by this.
    ///
    /// # Errors
    ///
    /// [`ServeError::InvalidToken`] if `token` is empty or nothing but
    /// whitespace, as every other way of installing one refuses it;
    /// [`ServeError::NamedToken`] with the [`NamedTokenRefusal`] that
    /// applies otherwise — a name that is not one, a name already in use
    /// (remove it first; replacing silently would be a rotation nobody
    /// asked for), or a token already held under another name. Nothing is
    /// held on any of them.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(serving: &modelpipe::ServeHandle) -> Result<(), Box<dyn std::error::Error>> {
    /// serving.add_token("laptop-c4d1", "sk-…".to_owned())?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_token(&self, name: &str, token: String) -> Result<(), ServeError> {
        self.state
            .credential
            .add_named(name, token)
            .map_err(|refused| match refused {
                AddRefused::UnpresentableToken => ServeError::InvalidToken,
                AddRefused::InvalidName => named(name, NamedTokenRefusal::InvalidName),
                AddRefused::NameTaken => named(name, NamedTokenRefusal::NameTaken),
                AddRefused::TokenTaken => named(name, NamedTokenRefusal::TokenTaken),
            })
    }

    /// Stop admitting the token held under `name`, from this call forward.
    /// Every other credential — the primary, every other name, a graced
    /// key, a live grant — is untouched, which is the whole reason names
    /// exist.
    ///
    /// Returns whether a token was held under `name`. A name nothing is
    /// held under is `false` and not an error: the state you wanted is the
    /// state there is. Like [`set_token`](Self::set_token), this gates
    /// admission and not delivery — a request the token admitted before
    /// the call runs to completion.
    pub fn remove_token(&self, name: &str) -> bool {
        self.state.credential.remove_named(name)
    }

    /// Every name a token is currently held under, in the order they were
    /// added. Names only; the tokens are not read back, for the reason
    /// [`token`](Self::token) gives about the one that is.
    pub fn token_names(&self) -> Vec<String> {
        self.state.credential.named()
    }
}

fn named(name: &str, reason: NamedTokenRefusal) -> ServeError {
    ServeError::NamedToken {
        name: name.to_owned(),
        reason,
    }
}
