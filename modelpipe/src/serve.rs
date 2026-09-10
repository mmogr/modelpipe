//! Exposing a local backend: the entry point, and how it fails.
//!
//! Orchestration. The live listener you get back lives in
//! [`crate::serve_handle`], and what the call is given in
//! [`crate::serve_options`] — split off when `backend_auth` brought this
//! file to the file-size budget; this module owns the call.

use std::sync::Arc;

use crate::backend::TcpBackend;
use crate::credential::Credential;
use crate::identity;
use crate::listener::{ServeState, accept_loop};
use crate::serve_error::ServeError;
use crate::serve_handle::ServeHandle;
use crate::serve_options::ServeOptions;
use crate::transport;

/// Expose the OpenAI-compatible server at `backend_url` (e.g.
/// `http://127.0.0.1:11434`) to holders of the returned handle's ticket.
///
/// Enforces a bearer token per [`ServeOptions::auth`] — generated at
/// listen time, or supplied by the caller — and rejects any incoming
/// request whose `Authorization` header doesn't carry it (compared in
/// constant time), before a byte reaches the backend. Read the token off
/// the handle ([`ServeHandle::token`]) and give it to clients alongside
/// the ticket; it is deliberately not *inside* the ticket, so the two
/// credentials travel — and leak — independently. Serving open
/// ([`TokenPolicy::InsecureNoAuth`](crate::TokenPolicy::InsecureNoAuth)) is the one exception: nothing is
/// enforced, and [`ServeHandle::token`] returns `None`.
///
/// The backend must be local: this crate extends trust outward from your
/// machine, it does not re-export someone else's server. Which addresses
/// count, and what widens that, is on [`ServeError::BackendNotLocal`].
///
/// After a successful return, per-request trouble — the backend down or
/// refusing, a re-resolved backend address failing the locality check —
/// surfaces to the *remote client* as failed requests; the pipe itself
/// stays up and its status stays [`Direct`](crate::PipeStatus::Direct)/
/// [`Relayed`](crate::PipeStatus::Relayed). Only the death of the pipe is a
/// status: [`PipeStatus::Closed`](crate::PipeStatus::Closed). Finer-grained states can be added
/// compatibly later (`PipeStatus` is `#[non_exhaustive]`).
///
/// # Examples
///
/// [`ServeOptions`] is `#[non_exhaustive]`, so a struct literal will not
/// compile outside this crate: start from `default()` and assign. That is
/// the whole reason the type is shaped this way — a new option must not
/// break you — and it is what every embedder ends up writing.
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut opts = modelpipe::ServeOptions::default();
/// opts.auth = modelpipe::TokenPolicy::Supplied("sk-your-existing-key".to_owned());
///
/// let serving = modelpipe::serve("http://127.0.0.1:11434", opts).await?;
///
/// // Two credentials, printed separately because they travel separately.
/// println!("ticket: {}", serving.ticket());
/// println!("token:  {}", serving.token().expect("a token is enforced"));
///
/// serving.shutdown().await;
/// # Ok(())
/// # }
/// ```
///
/// `no_run` throughout this crate: these compile, which is what proves the
/// paths and the signatures, but running one would bind a real endpoint and
/// contact a discovery service.
pub async fn serve(backend_url: &str, opts: ServeOptions) -> Result<ServeHandle, ServeError> {
    // Order matters, and it is the order of what the operator can fix. The
    // relay value and the backend URL are theirs; binding an endpoint is the
    // machine's. Checking the cheap, user-fixable things first means a typo
    // is reported as a typo rather than after a socket has been opened.
    if let Some(relay) = opts.relay.as_deref() {
        transport::validate_relay(relay)?;
    }
    // Before the backend and before the socket, because it is the cheapest
    // of the three and the same rule applies: a credential no client could
    // present is the operator's typo, and reporting it after a listener is
    // up would mean reporting it as a stream of refused requests instead.
    let (credential, _) = Credential::new(&opts.auth)?;
    // The same refusal one hop further on: a blank value the backend could
    // not read is the operator's typo, and every request would arrive
    // there unauthenticated.
    if let Some(upstream) = opts.backend_auth
        && !credential.set_upstream(Some(upstream))
    {
        return Err(ServeError::InvalidToken);
    }
    // Before the socket and before the backend for the reason the two above
    // it come first: a path the operator cannot use is theirs to fix, and
    // finding out after a listener is up would mean finding out as a ticket
    // that is not the one they expected.
    let key = opts
        .identity
        .as_deref()
        .map(identity::load_or_mint)
        .transpose()?;
    let backend = TcpBackend::new(backend_url, opts.allow_private_backend).await?;
    let net = transport::NetOptions {
        port_mapping: opts.port_mapping,
        discovery: opts.discovery,
        relay_only: opts.relay_only,
    };
    let endpoint = transport::bind(opts.relay.as_deref(), key, net).await?;
    // After the endpoint exists and before the handle wraps it, which is
    // the only window where waiting is free of consequence: nothing has
    // been spawned yet, so a caller who gives up here has nothing to tear
    // down. Deliberately not an error on expiry — see the field's docs.
    if let Some(within) = opts.wait_online {
        transport::wait_online(&endpoint, within).await;
    }

    let state = Arc::new(ServeState::new(endpoint, credential, backend));
    tokio::spawn(accept_loop(state.clone()));
    Ok(ServeHandle::new(state))
}

#[cfg(test)]
#[path = "serve_tests.rs"]
mod serve_tests;
