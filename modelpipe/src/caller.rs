//! Who is on the far end of an exchange.
//!
//! The listener knows the endpoint that opened a stream before a byte of the
//! request is read, and the edge needs it in two forms: the whole key, which a
//! token pinned to one endpoint is checked against, and the fingerprint every
//! log line and the `X-Modelpipe-Peer` header carry. Built once per
//! connection, and handed to every exchange on it.

use std::sync::Arc;

use crate::peer_id::PeerId;

/// The endpoint an exchange arrived from.
#[derive(Debug, Clone)]
pub(crate) struct Caller {
    /// Its whole key.
    pub(crate) id: PeerId,
    /// Its fingerprint, formatted once rather than per exchange.
    pub(crate) name: Arc<str>,
}

impl Caller {
    pub(crate) fn new(id: PeerId) -> Self {
        Self {
            id,
            name: id.fingerprint().into(),
        }
    }
}
