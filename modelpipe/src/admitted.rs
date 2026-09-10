//! Which of a listener's credentials admitted a request.
//!
//! Split from [`crate::credential`] for the file-size gate, and because it
//! is the one thing about admission the rest of the edge needs to know:
//! [`crate::exchange`] reads [`Admitted::device`] to tell the backend which
//! named token a request arrived under, and nothing else about the
//! comparison leaves that module.

use std::sync::Arc;

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
    /// A one-time grant, now spent.
    Grant,
}

impl Admitted {
    /// The name of the token that admitted, when one did.
    pub(crate) fn device(&self) -> Option<&str> {
        match self {
            Self::Named(name) => Some(name),
            Self::Open | Self::Token | Self::Superseded | Self::Grant => None,
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
