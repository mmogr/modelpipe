//! The live serve side.
//!
//! Split from its connect-side twin now that both are implemented: the two
//! were kept in one file while they were signatures, so the machinery they
//! share would be visible before it was written twice. That machinery is
//! now [`crate::lifecycle`], so the co-location has done its job and the
//! file-size gate is right that they are two things.
//!
//! They still share no public trait — see [`crate::ConnectHandle`].

use std::sync::Arc;
use std::time::Duration;

use crate::listener::{self, ServeState};
use crate::status::PipeStatus;
use crate::ticket::Ticket;
use crate::transport;

/// A live serve side.
///
/// Dropping it tears the listener down best-effort, without waiting;
/// [`shutdown`](Self::shutdown) is the graceful version that completes
/// once the listener is gone. Either way the ticket is dead from that
/// moment and a new [`serve`](fn@crate::serve) mints a fresh one — there is no way to keep
/// a ticket valid across restarts, so ticket rotation *is* the restart.
/// (Token rotation is cheaper: [`rotate_token`](Self::rotate_token).)
pub struct ServeHandle {
    state: Arc<ServeState>,
}

impl ServeHandle {
    pub(crate) const fn new(state: Arc<ServeState>) -> Self {
        Self { state }
    }

    /// The ticket to hand to connecting machines (print it, QR it).
    ///
    /// Returns an owned clone, for the same reason
    /// [`token`](Self::token) does — and for one this handle has that a
    /// credential does not. iroh discovers direct addresses *over time*:
    /// a ticket read the instant [`serve`](fn@crate::serve) returns is legitimately
    /// relay-only, and the same call later carries the direct addresses
    /// hole-punching has since found. A borrow would force the listener
    /// to mint one ticket at startup and hand out that snapshot forever,
    /// so the cheaper signature is the one that quietly makes the ticket
    /// wrong.
    pub fn ticket(&self) -> Ticket {
        // Minted fresh from the endpoint's *current* address set, which is
        // the reason this returns owned: iroh discovers direct addresses
        // over time, so a ticket read a minute after `serve` returned
        // carries paths the first one could not have.
        transport::ticket_from(&self.state.endpoint.addr())
    }

    /// The bearer token clients must present, or `None` when serving
    /// open. Print it next to the ticket; it reaches client machines
    /// out-of-band, which is what makes it a second lock rather than a
    /// decoration on the first.
    ///
    /// Under [`TokenPolicy::Supplied`](crate::TokenPolicy::Supplied) this echoes the supplied value, as
    /// later replaced through [`set_token`](Self::set_token) or
    /// [`rotate_token`](Self::rotate_token) — an embedder can always read
    /// back what the listener currently enforces. Returns an owned clone
    /// on purpose: [`set_token`](Self::set_token) takes `&self`, so a lent
    /// `&str` could outlive the credential it names, and honoring such a
    /// borrow would force the implementation to keep every rotated-out
    /// secret alive (and un-zeroizable) for the handle's whole lifetime.
    ///
    /// `String` is the settled type here, not a placeholder for a
    /// zeroizing wrapper. The token's whole job is to be read back and
    /// handed to a person — the CLI prints it to stdout, an embedder puts
    /// it in a config — so it lands in terminal scrollback and process
    /// memory the caller controls long before any wrapper could scrub the
    /// copy this returns. A `Secret<String>` here would encrypt the last
    /// three feet of a journey that is public at both ends, and swapping
    /// it in later would be a breaking change; the honest position is to
    /// say so once, here.
    pub fn token(&self) -> Option<String> {
        self.state.credential.token()
    }

    /// Install `token` as the bearer credential, replacing whatever the
    /// listener currently enforces; the old value stops working
    /// immediately and the ticket — every existing pairing — stays
    /// valid. This is how an embedder that supplied its own key
    /// ([`TokenPolicy::Supplied`](crate::TokenPolicy::Supplied)) propagates a rotation of that key
    /// into a running listener. When serving open, this turns auth *on*
    /// from this call forward.
    ///
    /// Single-token by design: there is no dual-accept window where old
    /// and new both pass, so rolling a replacement out to several clients
    /// necessarily races their reconfiguration — plan rotations
    /// accordingly. The credential gates request *admission*, not
    /// delivery: a request that passed auth before the call runs to
    /// completion (a streaming response is not cut mid-body).
    pub fn set_token(&self, token: String) {
        self.state.credential.set(token);
    }

    /// [`set_token`](Self::set_token) with a freshly minted random
    /// token, returned so the caller can redistribute it. The recovery
    /// move for a leaked generated token.
    ///
    /// For [`TokenPolicy::Supplied`](crate::TokenPolicy::Supplied) embedders this is the wrong tool: it
    /// desynchronizes the shared credential — the tunnel edge then wants
    /// a token the embedder's own backend has never heard of. Supplied
    /// embedders rotate by pushing their replacement through
    /// [`set_token`](Self::set_token).
    pub fn rotate_token(&self) -> String {
        self.state.credential.rotate()
    }

    /// Current transport status, for `status` output.
    pub fn status(&self) -> PipeStatus {
        self.state.lifecycle.status()
    }

    /// Wait until the status changes, then return the new value.
    ///
    /// This is how a caller surfaces "direct ↔ relayed" changes as they
    /// happen, rather than polling [`status`](Self::status). Snapshot
    /// semantics: each call compares against the status at the moment
    /// the call was made, so states that came and went while nobody was
    /// waiting are coalesced away, never replayed. Any number of callers
    /// may wait concurrently — a daemon and a UI stream can both watch
    /// one handle — each resolving against its own snapshot. On
    /// teardown, graceful or not, the status becomes
    /// [`PipeStatus::Closed`] and every waiting call resolves with it;
    /// once closed, calls resolve immediately, so a watcher can never
    /// block on a pipe that is already gone.
    pub async fn status_changed(&self) -> PipeStatus {
        // The snapshot is taken here, at the moment of the call, which is
        // what makes states that came and went while nobody was waiting
        // coalesce rather than replay.
        let snapshot = self.state.lifecycle.status();
        self.state.lifecycle.changed_since(snapshot).await
    }

    /// Stop admitting new requests, let the in-flight ones finish, and
    /// wait until the listener is gone.
    ///
    /// **This drains rather than cuts, and it does not time out.** For a
    /// pipe whose payload is a ten-minute token stream that is the whole
    /// question, so it is answered here rather than left to the
    /// implementation: the same promise [`set_token`](Self::set_token)
    /// already makes — that a streaming response is not cut mid-body —
    /// holds for teardown. A request admitted before this call runs to
    /// completion; one arriving after it does not get in.
    ///
    /// Dropping the handle is the other half of the pair and cuts
    /// immediately, without waiting. Both are needed: a daemon shutting
    /// down cleanly wants the drain, and a process that has already
    /// decided to die should not be held open by a backend that has
    /// stopped producing tokens. [`shutdown_timeout`](Self::shutdown_timeout)
    /// is the middle ground.
    ///
    /// Takes `&self` so a handle parked in shared state (an `Arc` in a
    /// daemon) can still be shut down gracefully — by-value `self` would
    /// leave such embedders only the best-effort drop path. Idempotent:
    /// every call after teardown has begun (however it began) awaits the
    /// same completion.
    pub async fn shutdown(&self) {
        listener::shutdown(&self.state).await;
    }

    /// [`shutdown`](Self::shutdown) with a deadline on the drain.
    ///
    /// Returns `true` if every in-flight request finished within `grace`,
    /// and `false` if the deadline arrived first and the remainder were
    /// cut. Either way the listener is gone when this returns, so a
    /// caller that does not care which happened can ignore the value.
    ///
    /// This ships alongside `shutdown` rather than after it because the
    /// unbounded wait has a real failure mode — a backend that has wedged
    /// mid-generation never completes, and an embedder with only the
    /// unbounded call would have to reach for the drop path and lose the
    /// drain entirely.
    pub async fn shutdown_timeout(&self, grace: Duration) -> bool {
        listener::shutdown_timeout(&self.state, grace).await
    }
}

// Dropping a handle tears its side down best-effort and without waiting,
// which is the other half of "`shutdown` drains, `Drop` cuts". The close is
// published synchronously so a watcher sees `Closed` immediately; anything
// that needs an await is handed to the runtime, and a handle dropped
// outside one does the synchronous half only — the process is going away
// regardless.

impl Drop for ServeHandle {
    fn drop(&mut self) {
        self.state.lifecycle.close();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let state = self.state.clone();
            runtime.spawn(async move {
                state.endpoint.close().await;
                state.lifecycle.mark_torn_down();
            });
        }
    }
}
