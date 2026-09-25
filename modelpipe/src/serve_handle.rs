//! The live serve side: [`ServeHandle`] and every method this crate gives
//! it. The inherent methods are one `impl` block, with a section for each
//! question they answer.
//!
//! The connect side is its twin, [`crate::connect_handle`], and the two
//! share no public trait — see [`crate::ConnectHandle`].

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::invite::{Invite, InviteHandle, InviteOptions, InviteRefusal, MAX_TTL, MAX_WRONG_CODES};
use crate::listener::{self, ServeState};
use crate::minting::mint;
use crate::named::AddRefused;
use crate::network::{NetworkMetrics, metrics_of, notify};
use crate::pairing_string::PairingString;
use crate::peer_id::PeerId;
use crate::serve_error::{NamedTokenRefusal, ServeError};
use crate::status::{CloseReason, PeerView, PipeStatus};
use crate::ticket::Ticket;
use crate::transport;

/// How many minted device names are tried before a taken one is reported.
const MINT_ATTEMPTS: usize = 5;

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
    /// `pub(crate)` so the listener's tests can reach the state behind a
    /// live handle.
    pub(crate) state: Arc<ServeState>,
}

impl ServeHandle {
    pub(crate) const fn new(state: Arc<ServeState>) -> Self {
        Self { state }
    }

    // Who may use this listener — the ticket and the primary token — and
    // what the backend is told.

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
    /// Single-token: this call leaves no dual-accept window where old and
    /// new both pass, so rolling a replacement out to several clients
    /// necessarily races their reconfiguration.
    /// [`set_token_with_grace`](Self::set_token_with_grace) is the form
    /// that buys time for that rollout, and calling *this* one during such
    /// a window shuts it — a rotation that says nothing about grace is a
    /// rotation that wants none. The credential gates request *admission*,
    /// not delivery: a request that passed auth before the call runs to
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

    /// What the backend is told in `Authorization` from this call forward:
    /// `Some(token)` presents that bearer in place of whatever the client
    /// sent, `None` forwards the client's own — the two states
    /// [`ServeOptions::backend_auth`](crate::ServeOptions::backend_auth)
    /// describes, changed on a running listener.
    ///
    /// This is how the backend's own key rotates when devices hold their
    /// own: the edge's admission is untouched, so no device notices, and
    /// a request admitted before the call runs to completion with what it
    /// was going to be given — the same rule [`set_token`](Self::set_token)
    /// keeps about admission and delivery.
    ///
    /// # Errors
    ///
    /// [`ServeError::InvalidToken`] if `token` is `Some` of an empty or
    /// whitespace-only value, in which case **nothing changes** — for the
    /// reason [`set_token`](Self::set_token) gives for refusing loudly.
    pub fn set_backend_auth(&self, token: Option<String>) -> Result<(), ServeError> {
        if self.state.credential.set_upstream(token) {
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

    // Rotating the credential without un-pairing everything at once.

    /// [`set_token`](Self::set_token), except the key it replaces goes on
    /// admitting until `grace` elapses.
    ///
    /// The rollout problem this exists for has no solution with one
    /// credential. Several machines are paired and holding the current
    /// key; the key has to change. Push the replacement in first and every
    /// one of them is refused — `invalid or missing bearer token` at the
    /// edge — until it is reconfigured. Reconfigure them first and they
    /// present a value this listener does not yet enforce. There is no
    /// third ordering, and the outage lasts as long as the slowest machine
    /// takes to notice. `grace` is a window in which both values admit, so
    /// the rollout has somewhere to happen.
    ///
    /// **This widens what the tunnel edge admits, and nothing beyond it.**
    /// A request bearing the old key gets through this listener and then
    /// meets whatever the backend behind it checks. If that backend reads
    /// the same rotated key from the same store, it now expects the *new*
    /// value and refuses the request a layer later — the window bought
    /// nothing, and the failure just moved. A dual-accept rollout needs
    /// both ends to hold two values at once; this is the end that belongs
    /// to the tunnel.
    ///
    /// While the window is open **two values are the credential** for the
    /// whole tunnel. Size `grace` by how long the rollout actually takes and
    /// not by what is convenient — a window measured in hours is a second
    /// standing key with a comment attached.
    ///
    /// Windows do not chain. A second call inside an open window retires
    /// the key the first one was protecting, so this never accumulates:
    /// what is enforced, plus the one thing it directly replaced. (Named
    /// tokens are credentials with lifetimes of their own, untouched by any
    /// of this.)
    /// [`set_token`](Self::set_token) closes an open window outright, and
    /// is the way to end an overlap early — a rotation that says nothing
    /// about grace is a rotation that wants none.
    ///
    /// Two `grace` values hold nothing, and both fail closed.
    /// [`Duration::ZERO`] is [`set_token`](Self::set_token): the replaced
    /// key is dropped rather than parked already-expired, so the boundary
    /// falls on the safe side rather than admitting one last request. So
    /// is any `grace` too large for the clock to represent a deadline from
    /// — [`Duration::MAX`] is the obvious way to write "never expire", and
    /// **it holds no key at all** rather than holding one forever. If that
    /// is not what you meant, name a window you can defend. On a listener
    /// that was serving open there is no key to hold either, and this
    /// turns authentication on exactly as `set_token` does.
    ///
    /// Not a replacement for [`rotate_token`](Self::rotate_token) on a
    /// *leaked* key. There the whole point is that the old value dies now,
    /// and any window is time an attacker still has.
    ///
    /// # Errors
    ///
    /// [`ServeError::InvalidToken`] if `token` is empty or nothing but
    /// whitespace — the value [`set_token`](Self::set_token) refuses,
    /// refused for the same reason. **Nothing changes**: what was in force
    /// stays in force, no window opens, and an already-open window is
    /// neither shut nor extended.
    ///
    /// Read that last clause carefully if you are rotating on a schedule.
    /// A refusal means this call did nothing — it does **not** mean no old
    /// key is admitting. An operator who opened an hour-long window and
    /// then pushed a rotation whose config value came back blank still has
    /// the first replaced key admitting for the rest of that hour.
    /// [`set_token`](Self::set_token) with a value you have checked is how
    /// to end it.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(serving: &modelpipe::ServeHandle) -> Result<(), Box<dyn std::error::Error>> {
    /// // Paired laptops keep working on the old key while they pick the
    /// // new one up; after five minutes, only the new one admits.
    /// serving.set_token_with_grace(
    ///     std::env::var("MODELPIPE_TOKEN")?,
    ///     std::time::Duration::from_mins(5),
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Cutting a window short, because the rollout finished early:
    ///
    /// ```no_run
    /// # fn example(serving: &modelpipe::ServeHandle, current: String) -> Result<(), modelpipe::ServeError> {
    /// serving.set_token(current)?; // the previous key stops admitting here
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_token_with_grace(&self, token: String, grace: Duration) -> Result<(), ServeError> {
        if self.state.credential.set_with_grace(token, grace) {
            Ok(())
        } else {
            Err(ServeError::InvalidToken)
        }
    }

    // Who may use this listener, one machine at a time: the only shape under
    // which "this device, and only this device, may no longer" is a sentence
    // the listener can act on.
    //
    // A named token is added under a name and removed under that name, and
    // the backend is told the name as `X-Modelpipe-Device` on every request
    // it admits. One pinned to a peer admits only on connections from that
    // peer; any other admits from any endpoint, as the primary does. The
    // primary, if there is one, is untouched by all of it; a listener
    // started with `TokenPolicy::Named` has none, and admits nothing until
    // a token is added or set.

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

    // Inviting a device: how an embedder pairs a machine. The key is minted
    // and held first, the invite registered disarmed, and its expiry
    // scheduled on the listener's own runtime; `Invite::arm` is the
    // embedder's to call once the key is stored.

    /// Invite a device: mint a key for it and hold it at the edge, and mint a
    /// one-time code it redeems for that key at [`PAIR_PATH`](crate::PAIR_PATH).
    ///
    /// The code is not redeemable until [`Invite::arm`], so store the key
    /// first. The invite ends once, as an
    /// [`InviteOutcome`](crate::InviteOutcome) that [`InviteHandle::outcome`]
    /// waits for. A key whose invite ends unredeemed stays held;
    /// [`remove_token`](Self::remove_token) retires it, and withdraws its
    /// invite first if that is still live. The options' docs give the odds a
    /// guesser has.
    ///
    /// # Errors
    ///
    /// [`ServeError::Invite`] when the options are out of bounds, or the
    /// listener serves open or has closed; [`ServeError::NamedToken`] when
    /// `device` is not a name or is taken. Nothing is held on either.
    pub fn invite(&self, opts: InviteOptions) -> Result<Invite, ServeError> {
        let refusal = if opts.ttl > MAX_TTL {
            Some(InviteRefusal::TtlTooLong)
        } else if opts.wrong_codes.get() > MAX_WRONG_CODES {
            Some(InviteRefusal::TooManyWrongCodes)
        } else if self.state.lifecycle.close_reason().is_some() {
            Some(InviteRefusal::Closed)
        } else if self.state.credential.serves_open() {
            Some(InviteRefusal::OpenListener)
        } else {
            None
        };
        if let Some(reason) = refusal {
            return Err(ServeError::Invite(reason));
        }
        let api_key = mint();
        let device = self.hold_invited(opts.device, &api_key)?;
        let invites = Arc::clone(self.state.credential.invites());
        let expires = Instant::now() + opts.ttl;
        let registered = invites.register(
            device.clone(),
            api_key.clone(),
            expires,
            opts.wrong_codes.get(),
        );
        let id = registered.id;
        let state = Arc::clone(&self.state);
        self.state.runtime.spawn(async move {
            tokio::select! {
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(expires)) => {
                    state.credential.invites().expire(id);
                }
                () = state.lifecycle.wait_until_closed() => {
                    state.credential.invites().withdraw(id);
                }
            }
        });
        Ok(Invite {
            pairing: PairingString::new(self.ticket(), Some(registered.code.clone())),
            code: registered.code,
            device,
            api_key,
            handle: InviteHandle {
                id,
                outcome: registered.outcome,
                invites,
            },
        })
    }

    /// Hold `key` under `name`, or under a minted name when there is none.
    fn hold_invited(&self, name: Option<String>, key: &str) -> Result<String, ServeError> {
        if let Some(name) = name {
            self.hold(&name, key.to_owned(), None)?;
            return Ok(name);
        }
        let mut taken = None;
        for _ in 0..MINT_ATTEMPTS {
            let name = minted_device();
            match self.hold(&name, key.to_owned(), None) {
                Ok(()) => return Ok(name),
                Err(
                    refused @ ServeError::NamedToken {
                        reason: NamedTokenRefusal::NameTaken,
                        ..
                    },
                ) => taken = Some(refused),
                Err(other) => return Err(other),
            }
        }
        Err(taken.unwrap_or(ServeError::Invite(InviteRefusal::Closed)))
    }

    // Who is using this listener right now, how they are reaching it, and
    // why it closed.

    /// How this side is currently reaching its peers.
    ///
    /// An aggregate over every connected peer, reporting the worst active
    /// path — see [`PipeStatus`] for why. [`peers`](Self::peers) is the
    /// per-peer answer.
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
    ///
    /// [`status_changed_since`](Self::status_changed_since) is the form for
    /// a caller that holds the value it last rendered; the two coexist
    /// because they answer different questions, and this one is the right
    /// answer for a watcher that is already parked.
    pub async fn status_changed(&self) -> PipeStatus {
        // The snapshot is taken here, at the moment of the call, which is
        // what makes states that came and went while nobody was waiting
        // coalesce rather than replay.
        let snapshot = self.state.lifecycle.status();
        // `None` can only mean the snapshot taken a line above was already
        // `Closed`, and this form owes such a caller the terminal status
        // rather than a wait — the clause the doc above states.
        self.state
            .lifecycle
            .changed_since(snapshot)
            .await
            .unwrap_or(PipeStatus::Closed)
    }

    /// Wait until the status differs from `snapshot`, then return it, and
    /// `None` once the pipe is closed and `snapshot` already says so.
    ///
    /// The gap-free half of [`status_changed`](Self::status_changed), for a
    /// caller holding the last value it rendered. That method takes its
    /// snapshot *inside itself*, at the moment it is polled, so a
    /// transition landing between a caller's [`status`](Self::status) and
    /// its next `status_changed` is coalesced away and never reported. For
    /// a watcher already parked on the handle that is exactly right — the
    /// states nobody was waiting for are not worth replaying. For anything
    /// that renders a value and *then* goes back to waiting it is a dropped
    /// transition, and no ordering of the two calls closes the window,
    /// because the race is inside the second one. Passing what was rendered
    /// closes it.
    ///
    /// **`None` ends the sequence, and that is the point.**
    /// [`PipeStatus::Closed`] is terminal, so a caller that has seen it has
    /// nothing further to wait for; a method that answered `Closed` again,
    /// immediately and forever, would make the loop below a busy loop on
    /// one core with no await in it anywhere. Every snapshot that is not
    /// already `Closed` is still delivered `Closed` exactly once, so
    /// nothing is lost by watching this way.
    ///
    /// Concurrent callers are as welcome as they are on
    /// [`status_changed`](Self::status_changed), each against the snapshot
    /// it passed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(serving: &modelpipe::ServeHandle) {
    /// let mut held = serving.status();
    /// println!("status: {}", held.as_str());
    /// // Ends on its own when the pipe does.
    /// while let Some(next) = serving.status_changed_since(held).await {
    ///     println!("status: {}", next.as_str());
    ///     held = next;
    /// }
    /// # }
    /// ```
    pub async fn status_changed_since(&self, snapshot: PipeStatus) -> Option<PipeStatus> {
        self.state.lifecycle.changed_since(snapshot).await
    }

    /// Every peer connected right now, in the order they arrived.
    ///
    /// The per-peer answer to the question [`status`](Self::status)
    /// aggregates: with a phone and a laptop on one ticket, this is what
    /// says *which* of them is relayed. Each entry names the peer by the
    /// same fingerprint the `peer` log field and the `X-Modelpipe-Peer`
    /// header carry, so a device is one name everywhere.
    ///
    /// A snapshot, honest about the moment it was taken — a peer may have
    /// left by the time the list is read. Empty when idle or closed.
    pub fn peers(&self) -> Vec<PeerView> {
        self.state.peers.views()
    }

    /// Why the listener closed, or `None` while it is still live.
    ///
    /// The serve side's half of
    /// [`ConnectHandle::close_reason`](crate::ConnectHandle::close_reason),
    /// with the same contract: set once and never changed, and read beside
    /// [`status`](Self::status) rather than instead of it.
    /// [`CloseReason::Shutdown`] means this side ended it, by `shutdown`,
    /// `shutdown_timeout` or dropping the handle.
    /// [`CloseReason::ListenerFailed`] means the endpoint stopped yielding
    /// connections with nobody asking, which is worth showing as the failure
    /// it is.
    pub fn close_reason(&self) -> Option<CloseReason> {
        self.state.lifecycle.close_reason()
    }

    // The endpoint underneath: telling it the network moved, and reading its
    // counters. Neither hands the endpoint out; `crate::network` says why.

    /// Tell this side's endpoint that the network underneath it may have
    /// changed, and wait for the notice to be taken.
    ///
    /// A *notifier*, not an observer, which is why it takes nothing and
    /// returns nothing: it pushes a fact in rather than reading one out.
    /// The endpoint responds by rebinding its sockets and re-checking its
    /// relay connection, which is what repairs a pipe whose addresses are
    /// all now wrong.
    ///
    /// Harmless when nothing changed, and harmless when the endpoint had
    /// already noticed by itself — so the honest rule is to call it
    /// whenever the host knows something this library cannot, and not to
    /// try to be clever about when.
    ///
    /// **The reason it is on the public surface is the hosts that cannot be
    /// detected from inside.** iroh watches the platform for link changes
    /// where the platform will say; on Android that information is only
    /// available to Java code, and on iOS the sleep/wake detection is
    /// deliberately disabled in favour of a poll measured in the hour. An
    /// app resuming on a new cellular bearer therefore has a pipe with
    /// nothing left to repair it until that poll comes round — unless the
    /// app itself says so, here, from the resume it already handles.
    ///
    /// Safe on a pipe that is already closed: the endpoint ignores the
    /// notice and this returns.
    pub async fn notify_network_change(&self) {
        notify(&self.state.endpoint).await;
    }

    /// What the transport underneath this listener has been doing.
    ///
    /// See [`NetworkMetrics`]: monotonic totals for this endpoint's whole
    /// life, so the useful reading is a difference or a ratio rather than
    /// one number.
    pub fn network_metrics(&self) -> NetworkMetrics {
        metrics_of(&self.state.endpoint)
    }

    // How the listener stops.

    /// Stop admitting new requests, let the in-flight ones finish, and
    /// wait until the listener is gone.
    ///
    /// **This drains rather than cuts, and it does not time out.** For a
    /// pipe whose payload is a ten-minute token stream that is the whole
    /// question, so it is answered here rather than left to the
    /// implementation: the same promise [`set_token`](Self::set_token)
    /// already makes — that a streaming response is not cut mid-body —
    /// holds for teardown. A request admitted before this call runs to
    /// completion; one arriving after it does not get in. A peer that
    /// stops reading its response can hold the drain just as a backend that
    /// stops producing one does; [`shutdown_timeout`](Self::shutdown_timeout)
    /// bounds both.
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
    /// mid-generation, or a peer that has stopped reading what it asked
    /// for, can keep that wait from completing, and an embedder with only
    /// the unbounded call would have to reach for the drop path and lose
    /// the drain entirely.
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
        // `Shutdown`, and not a reason of its own: dropping is a teardown
        // this side asked for exactly as `shutdown` is, differing in what
        // becomes of the requests in flight rather than in why the pipe
        // ended. A separate reason would also be one nobody could read —
        // the accessor needs a handle, and this is the handle going away.
        self.state.lifecycle.close(CloseReason::Shutdown);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let state = self.state.clone();
            runtime.spawn(async move {
                state.endpoint.close().await;
                state.lifecycle.mark_torn_down();
            });
        }
    }
}

/// `dev-` and eight hex digits from the CSPRNG: a token name, and a different
/// shape from a twelve-hex fingerprint.
fn minted_device() -> String {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).expect("the OS CSPRNG must be available");
    format!("dev-{:08x}", u32::from_le_bytes(bytes))
}

fn named(name: &str, reason: NamedTokenRefusal) -> ServeError {
    ServeError::NamedToken {
        name: name.to_owned(),
        reason,
    }
}
