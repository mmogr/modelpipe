//! Who is on either end of an exchange.
//!
//! The listener knows the endpoint that opened a stream before a byte of the
//! request is read, and the edge needs it in two forms: the whole key, which a
//! pinned token and an invite's strikes are checked against, and the
//! fingerprint every log line and the `X-Modelpipe-Peer` header carry. The
//! pairing route also needs the listener's own id, to tell a device which
//! machine it paired with. Built once per connection, and handed to every
//! exchange on it.

use std::sync::Arc;

use crate::peer_id::PeerId;

/// The endpoint an exchange arrived from, and the one it arrived at.
#[derive(Debug, Clone)]
pub(crate) struct Caller {
    /// Its whole key.
    pub(crate) id: PeerId,
    /// Its fingerprint, formatted once rather than per exchange.
    pub(crate) name: Arc<str>,
    /// This listener's own id.
    pub(crate) at: PeerId,
}

impl Caller {
    pub(crate) fn new(id: PeerId, at: PeerId) -> Self {
        Self {
            id,
            name: id.fingerprint().into(),
            at,
        }
    }
}
