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
use crate::serve_error::ServeError;
use crate::ticket::Ticket;
use crate::transport;

/// A live serve side.
///
/// Dropping it tears the listener down best-effort, without waiting;
/// [`shutdown`](Self::shutdown) is the graceful version that completes
/// once the listener is gone. Either way this listener stops answering, and
/// by default the ticket dies with it: the endpoint key is minted per
/// process unless [`ServeOptions::identity`](crate::ServeOptions#structfield.identity)
/// names a file to keep it in, so a restart mints a fresh ticket and ticket
/// rotation *is* the restart. With an identity file the ticket outlives the
/// process and revocation becomes deleting that file and restarting —
/// the same act, one extra step.
/// (Token rotation is cheaper: [`rotate_token`](Self::rotate_token).)
pub struct ServeHandle {
    /// Shared with `serve_status.rs`, the second `impl` block.
    pub(crate) state: Arc<ServeState>,
}

impl ServeHandle {
    pub(crate) const fn new(state: Arc<ServeState>) -> Self {
        Self { state }
    }

    /// The ticket to hand to connecting machines (print it, QR it).
    ///
    /// Returns an owned clone, for the same reason
    /// [`token`](Self::token) does — and for one this handle has that a
    /// credential does not. **The address set behind a ticket fills in
    /// over time**, so a ticket read the instant
    /// [`serve`](fn@crate::serve) returns is not the ticket the same call
    /// makes a moment later. A borrow would force the listener to mint one
    /// at startup and hand out that snapshot forever, so the cheaper
    /// signature is the one that quietly makes the ticket wrong.
    ///
    /// The half that is usually missing first is the **relay**. Local
    /// interface addresses are there almost immediately — binding a socket
    /// is enough to enumerate them — while reaching a relay takes a
    /// handshake over the network, and it is the relay that lets a peer
    /// which cannot hole-punch to this machine reach it at all. Measured on
    /// a host with no route to one: the ticket carried a direct address and
    /// nothing else.
    ///
    /// [`ServeOptions::wait_online`](crate::ServeOptions#structfield.wait_online)
    /// is the answer where the ticket is about to be handed to a person,
    /// because that copy is taken once. Where it is not set, prefer calling
    /// this again over caching what it returned.
    pub fn ticket(&self) -> Ticket {
        // Minted fresh from the endpoint's *current* address set, which is
        // the reason this returns owned: a ticket read a minute after
        // `serve` returned carries paths the first one could not have.
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
    ///
    /// # Errors
    ///
    /// [`ServeError::InvalidToken`] if `token` is empty or nothing but
    /// whitespace, in which case **nothing changes** — whatever was in
    /// force stays in force.
    ///
    /// Returning that rather than swallowing it is the whole point of the
    /// signature. A rotation reads its replacement from somewhere: a
    /// config file, a secrets fetch, an environment variable. When that
    /// somewhere comes back blank, an embedder who is told nothing
    /// believes the old key is dead and retires it everywhere else, while
    /// this listener is still quietly enforcing it — a credential the
    /// operator thinks is revoked and is not. [`serve`](fn@crate::serve)
    /// has always refused the same value loudly; there is no reason for
    /// the runtime path to be the forgiving one, on this of all
    /// decisions.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(serving: &modelpipe::ServeHandle) -> Result<(), Box<dyn std::error::Error>> {
    /// // Rotating in place: no re-pairing, because the ticket is a
    /// // separate credential and is untouched by this.
    /// serving.set_token(std::env::var("MODELPIPE_TOKEN")?)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// A blank replacement is refused rather than enforced, which is the
    /// reason this returns a `Result` at all:
    ///
    /// ```no_run
    /// # fn example(serving: &modelpipe::ServeHandle) {
    /// assert!(serving.set_token(String::new()).is_err());
    /// # }
    /// ```
    pub fn set_token(&self, token: String) -> Result<(), ServeError> {
        if self.state.credential.set(token) {
            Ok(())
        } else {
            Err(ServeError::InvalidToken)
        }
    }

    /// Admit **one** request bearing `secret` before `ttl` elapses, on top
    /// of whatever [`set_token`](Self::set_token) enforces.
    ///
    /// A pairing primitive, not a second key. An embedder that wants a new
    /// device to *fetch* the real credential over the encrypted hop mints a
    /// short code, grants it here, shows it once, and serves a handshake
    /// route behind the tunnel: the device presents the code as its bearer,
    /// the edge lets exactly that request through, and the route answers
    /// with the key. The code is spent when presented and dead anyway when
    /// `ttl` passes, so a photograph of the screen is worth nothing later.
    ///
    /// **While live, a grant is equivalent to the token for the whole
    /// tunnel** — the edge cannot scope the one request it admits. Keep
    /// `ttl` short, make the secret unguessable for that window, and count
    /// attempts on the handshake route. The enforced token is untouched:
    /// [`token`](Self::token) still reports it, it still admits, and a
    /// rotation through [`set_token`](Self::set_token) neither spends nor
    /// extends a grant.
    ///
    /// # Errors
    ///
    /// [`ServeError::InvalidToken`] if `secret` is empty or nothing but
    /// whitespace, in which case nothing is granted — the value
    /// [`set_token`](Self::set_token) refuses, refused for the same reason.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(serving: &modelpipe::ServeHandle) -> Result<(), Box<dyn std::error::Error>> {
    /// serving.grant_once("483920".to_owned(), std::time::Duration::from_mins(2))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn grant_once(&self, secret: String, ttl: Duration) -> Result<(), ServeError> {
        if self.state.credential.grant(secret, ttl) {
            Ok(())
        } else {
            Err(ServeError::InvalidToken)
        }
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
