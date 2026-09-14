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
use crate::peer_id::PeerId;
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
        self.hold(name, token, None)
    }

    /// [`add_token`](Self::add_token), except the token admits only on
    /// connections from `peer`.
    ///
    /// A named token is a bearer credential: copied to another machine, it
    /// admits from there too. Pinned, it is refused from any endpoint but
    /// `peer`, as a wrong token would be, and the refusal is logged with the
    /// name, so a copied key is no use on its own. The price is that the
    /// device keeps one endpoint: its connect side needs
    /// [`ConnectOptions::identity`](crate::ConnectOptions#structfield.identity),
    /// or each restart is a new endpoint the pin refuses.
    ///
    /// `peer` is the id the device connects as, which it reads from
    /// [`ConnectHandle::peer_id`](crate::ConnectHandle::peer_id). A pinned
    /// token is removed with [`remove_token`](Self::remove_token) like any
    /// other.
    ///
    /// # Errors
    ///
    /// The refusals [`add_token`](Self::add_token) makes, for the same
    /// reasons.
    pub fn add_token_pinned(
        &self,
        name: &str,
        token: String,
        peer: PeerId,
    ) -> Result<(), ServeError> {
        self.hold(name, token, Some(peer))
    }

    /// Hold `token` under `name`, pinned to `pinned` when it is given.
    pub(crate) fn hold(
        &self,
        name: &str,
        token: String,
        pinned: Option<PeerId>,
    ) -> Result<(), ServeError> {
        self.state
            .credential
            .add_named(name, token, pinned)
            .map_err(|refused| match refused {
                AddRefused::UnpresentableToken => ServeError::InvalidToken,
                AddRefused::InvalidName => named(name, NamedTokenRefusal::InvalidName),
                AddRefused::NameTaken => named(name, NamedTokenRefusal::NameTaken),
                AddRefused::TokenTaken => named(name, NamedTokenRefusal::TokenTaken),
            })
    }

    /// Stop admitting the token held under `name`, from this call forward.
    /// Every other credential — the primary, every other name, a graced
    /// key — is untouched, which is the whole reason names
    /// exist.
    ///
    /// Returns whether a token was held under `name`. A name nothing is
    /// held under is `false` and not an error: the state you wanted is the
    /// state there is. Like [`set_token`](Self::set_token), this gates
    /// admission and not delivery — a request the token admitted before
    /// the call runs to completion.
    ///
    /// A live [`invite`](Self::invite) for `name` is withdrawn first, so its
    /// code cannot hand out a key that no longer admits.
    pub fn remove_token(&self, name: &str) -> bool {
        // Before the token goes, and not inside its lock: the invites are
        // never locked while the named tokens are.
        self.state.credential.invites().withdraw_device(name);
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
