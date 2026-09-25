//! What [`serve`](fn@crate::serve) is given.
//!
//! Split from `serve.rs` when `backend_auth` brought it to the file-size
//! budget, along the line `token_policy.rs` already drew: this is a
//! *request* an embedder constructs, and the call that consumes it lives
//! next door.

use std::fmt;
use std::num::NonZeroUsize;
use std::time::Duration;

use crate::peers::{DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_PEERS};
use crate::token_policy::TokenPolicy;

/// Options for [`serve`](fn@crate::serve).
///
/// Start from `Default` — the recommended configuration — and set what
/// you need. `#[non_exhaustive]`, so a new option is not a breaking
/// change for callers who construct it that way.
#[non_exhaustive]
// The three remaining booleans do not interact: each names a separate
// thing the endpoint does or does not do on the network, they are legal
// in all eight combinations, and the README documents them as
// independent switches. `struct_excessive_bools` used to fire here and
// was allowed for that reason; the permission moving onto `BackendUrl`
// took the fourth away, so the allowance went with it.
pub struct ServeOptions {
    /// What the listener requires in `Authorization: Bearer …`.
    pub auth: TokenPolicy,
    /// What the backend is told in `Authorization`, in place of whatever
    /// the client sent.
    ///
    /// `None` — the default — forwards the client's header verbatim, which
    /// is what every version before did and is right when the backend
    /// enforces the same credential the edge does. `Some(token)` replaces
    /// it with `Bearer <token>` on every admitted request and drops the
    /// client's, so a device's own token never reaches the backend: the
    /// edge is the only thing that ever sees it. Pair it with
    /// [`TokenPolicy::Named`] and the backend keeps exactly one credential
    /// while every device keeps a different one; rotate the backend's with
    /// [`ServeHandle::set_backend_auth`](crate::ServeHandle::set_backend_auth)
    /// and no device notices.
    ///
    /// Refused by [`serve`](fn@crate::serve) as [`ServeError::InvalidToken`](crate::ServeError::InvalidToken) when blank, for
    /// the reason `auth` is.
    pub backend_auth: Option<String>,
    /// Self-hosted relay URL. `None` uses iroh's public relays, which
    /// carry only ciphertext either way. Parsed when [`serve`](fn@crate::serve) starts, and
    /// that parse is the only check there is: a value that is not a relay
    /// URL at all is [`ServeError::InvalidRelay`](crate::ServeError::InvalidRelay) up front.
    ///
    /// A well-formed URL naming a relay that does not exist is **accepted
    /// silently**. Nothing dials it here, so the endpoint binds, `serve`
    /// returns `Ok`, and the ticket carries the URL verbatim. The cost is
    /// paid by whoever holds that ticket: they lose one path to this
    /// machine, which is invisible when hole-punching finds a direct one
    /// and is [`ConnectError::PeerUnreachable`](crate::ConnectError::PeerUnreachable)
    /// when it does not.
    pub relay: Option<String>,
    /// Where to keep this listener's endpoint key, so its ticket survives
    /// a restart.
    ///
    /// `None` — the default — generates a fresh key per process, so every
    /// ticket is disposable: restart and every ticket ever handed out names
    /// a peer nobody is. That is the rotation [`ServeHandle`](crate::ServeHandle) documents,
    /// and also why a paired device is re-paired after every reboot.
    ///
    /// Naming a path stores the key there, minting one on first use. The
    /// trade is real in both directions — a ticket that survives a restart
    /// is a *leaked* ticket that survives one too, revocation becomes
    /// deleting this file, and there is now a secret on disk where there
    /// was none — and is argued in full in ADR 0002. The file is created
    /// readable only by its owner, and a listener refuses to start on one
    /// others can read, or on a path that is not a regular file: a symlink
    /// is refused even when it points at a key.
    pub identity: Option<std::path::PathBuf>,
    /// Wait, up to this long, for the endpoint to reach a relay before
    /// [`serve`](fn@crate::serve) returns.
    ///
    /// `None` — the default — returns as soon as the socket is bound and
    /// the accept loop is running, which is the fastest a listener can
    /// start and is what an embedder holding the handle in a daemon wants.
    /// The cost is paid by [`ServeHandle::ticket`](crate::ServeHandle::ticket): a ticket read in that
    /// first instant carries only what the endpoint has found so far, and
    /// reaching a relay takes a network round trip that binding does not.
    ///
    /// Set it when a *person* is about to be handed the ticket — printed,
    /// or rendered as a QR code — because that ticket is copied once and
    /// then used from a machine that is not this one. Waiting costs
    /// seconds; a ticket that is missing the path its holder needed costs
    /// a re-pair.
    ///
    /// A duration rather than a `bool` because the underlying wait has no
    /// natural end: it is satisfied by a relay handshake completing, so on
    /// a machine with no route to one — an air-gapped LAN, a laptop in
    /// flight — it would never return. **Expiry is not an error.** The
    /// listener is up either way, and a ticket with direct addresses and
    /// no relay still pairs across a LAN, so [`serve`](fn@crate::serve) returns `Ok` and
    /// the caller is free to say nothing about it.
    pub wait_online: Option<Duration>,
    /// Ask the local gateway for a `UPnP` / NAT-PMP / PCP port mapping, so
    /// a peer behind a stricter NAT can reach this machine directly more
    /// often.
    ///
    /// `true` — the default — is what every version before this one did.
    /// `false` skips the gateway probe entirely, including the SSDP
    /// multicast that raises firewall dialogs on some desktops; the cost
    /// is a connection that falls back to the relay a little more often
    /// behind some NATs. Nothing about pairing changes either way.
    pub port_mapping: bool,
    /// Publish this endpoint's addresses to n0's discovery service, and
    /// resolve peers through it.
    ///
    /// `true` — the default — is what makes a ticket work after this
    /// machine changes network: the ticket names the endpoint, and
    /// discovery is how a holder finds where it is now. It is also a
    /// contact with n0 before any client connects, refreshed while the
    /// listener runs, and it is what
    /// [`identity`](Self::identity) depends on to make a stored key worth
    /// anything.
    ///
    /// `false` removes that contact, and the property with it: a ticket
    /// then carries every path its holder will ever have, so it works on
    /// the LAN it was minted on and through the relay it names, and fails
    /// the moment this machine's addresses change. An embedder that mints
    /// a fresh ticket per session — and so never needed a stale one to
    /// keep working — loses little; one relying on `identity` loses the
    /// thing it was for.
    pub discovery: bool,
    /// Reach every peer through a relay, never directly: this endpoint
    /// opens no IP transport at all.
    ///
    /// `false` — the default — is what every version before this one did,
    /// and is what you want in production: a direct path is faster and
    /// costs nobody's relay anything.
    ///
    /// **A measuring instrument, and it exists because relayed is the case
    /// nobody can reproduce on demand.** Whether hole punching works from a
    /// given network is decided by that network's NAT, so "it went direct"
    /// is easy to observe and "it fell back, and the fallback is good
    /// enough to use" is not — you would have to find a hostile enough NAT
    /// to sit behind. With this set the fallback is the *only* path, so
    /// what a relayed session costs can be read off
    /// [`ServeHandle::peers`](crate::ServeHandle::peers) on any network at
    /// all, and held against the same reading without it.
    ///
    /// The ticket minted while this is on carries the relay and nothing
    /// else, because there are no IP addresses for it to carry. That is
    /// honest rather than a limitation, and it means a ticket handed out
    /// under this switch keeps a holder relayed even if they are on the
    /// same LAN — which is the other half of what makes the comparison a
    /// comparison.
    pub relay_only: bool,
    /// How many distinct peers the listener carries at once. 32 by default.
    ///
    /// A peer is an endpoint identity, so a second connection from a device
    /// already carried is not a new peer. The one past the cap is sent away
    /// as soon as its identity is known, rather than queued behind a peer
    /// that may never leave.
    ///
    /// This bounds what the listener spends, not who gets in. Identities
    /// cost nothing to mint, so a ticket-holder that holds this many open
    /// fills the set, and a device not already connected is refused until
    /// one lets go. Raise it for a listener that serves more devices than
    /// that at once.
    pub max_peers: NonZeroUsize,
    /// How many connections the listener carries at once, handshakes
    /// included. 256 by default.
    ///
    /// Counted before any work is spent on a dial, and the one past the cap
    /// is refused outright. Every peer holds a connection, so when this is
    /// below [`max_peers`](Self::max_peers) it is the cap on peers too.
    pub max_connections: NonZeroUsize,
}

impl Default for ServeOptions {
    /// Written out because two of the booleans default to `true`, which
    /// `#[derive(Default)]` cannot express — and because "the default is
    /// what every version before did" is a promise worth a function.
    fn default() -> Self {
        Self {
            auth: TokenPolicy::default(),
            backend_auth: None,
            relay: None,
            identity: None,
            wait_online: None,
            port_mapping: true,
            discovery: true,
            relay_only: false,
            max_peers: NonZeroUsize::new(DEFAULT_MAX_PEERS).expect("the default is not zero"),
            max_connections: NonZeroUsize::new(DEFAULT_MAX_CONNECTIONS)
                .expect("the default is not zero"),
        }
    }
}

impl fmt::Debug for ServeOptions {
    // Delegates to `TokenPolicy`'s redacting `Debug` rather than deriving,
    // which would inline the credential. Written out field by field so
    // that adding an option to this `#[non_exhaustive]` struct without
    // adding it here is a visible omission rather than a silent one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServeOptions")
            .field("auth", &self.auth)
            .field(
                "backend_auth",
                &self.backend_auth.as_ref().map(|_| "<redacted>"),
            )
            .field("relay", &self.relay)
            .field("identity", &self.identity)
            .field("wait_online", &self.wait_online)
            .field("port_mapping", &self.port_mapping)
            .field("discovery", &self.discovery)
            .field("relay_only", &self.relay_only)
            .field("max_peers", &self.max_peers)
            .field("max_connections", &self.max_connections)
            .finish()
    }
}
