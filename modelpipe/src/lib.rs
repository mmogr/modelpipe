//! Reach an OpenAI-compatible model server from anywhere over p2p.
//!
//! This is the API sketch under review — the contract, not the
//! implementation. Signatures are settled intent; bodies are `todo!()`.
//! The iroh types stay out of the public surface deliberately: callers
//! hold [`Ticket`]s and handles, so an iroh major upgrade is this crate's
//! problem, not its dependents'. The same rule shapes the error types:
//! failures arrive as [`ServeError`] / [`ConnectError`] variants a caller
//! can match a retry policy against, with the transport's own error
//! reachable only as an opaque [`source`](std::error::Error::source).

use std::time::Duration;

// Modules are declared in dependency order, which for this crate is also
// order of testability: a module names only ones above it, and everything
// above the orchestration line can be exercised without a socket. The
// modules that will carry the implementation — the request edge, the
// address checks, the iroh transport — slot into the same order as they
// arrive.
//
// Every one of them is `mod`, never `pub mod`. The re-export block below
// is the entire public surface, so a module can be renamed, split or
// merged without that being a semver event, and `unreachable_pub` turns
// "added a type, forgot to export it" into a compile error.

// Pure: no I/O, no async.
mod base32;
mod crc32c;
mod credential;
mod status;
mod ticket;
mod ticket_addr;
mod ticket_string;

// Orchestration: the two entry points, and the live pipes they return.
mod connect;
mod handle;
mod serve;

// This block is the public API. Everything above is a private module,
// free to be rearranged at will; every name below is versioned. Adding to
// this block is the one edit in the crate that cannot be walked back.
pub use connect::{ConnectError, ConnectOptions, connect};
pub use credential::TokenPolicy;
pub use handle::{ConnectHandle, ServeHandle};
pub use serve::{ServeError, ServeOptions, serve};
pub use status::PipeStatus;
pub use ticket::{Ticket, TicketParseError};

// Auto-trait promises, pinned. The handles and the ticket live inside
// consumers' `select!` arms, spawned tasks and daemon state, and the error
// types ride through `anyhow` — those embeddings need these bounds, and a
// sketch whose types are only *accidentally* `Send + Sync` would let the
// implementation break every consumer after the fact. A regression here is
// a compile error in this crate instead.
#[expect(dead_code, reason = "compile-time pin; never called")]
const fn auto_trait_promises() {
    const fn assert<T: Send + Sync + 'static>() {}
    // Declared with `assert` above rather than beside their call sites:
    // an item after a statement is a clippy error, and these are items.
    const fn assert_clone<T: Clone>() {}
    const fn assert_copy_eq<T: Copy + Eq>() {}

    assert::<Ticket>();
    assert::<ServeHandle>();
    assert::<ConnectHandle>();
    assert::<PipeStatus>();
    assert::<ServeError>();
    assert::<ConnectError>();
    assert::<TicketParseError>();
    // The options structs and the policy they carry. Until now these were
    // only *accidentally* `Send`, by way of `future_promises` pinning the
    // futures that consume them; nothing said so, and an implementation
    // could have made one of them `!Send` without failing a single check.
    // Pinning `TokenPolicy` also forbids a future variant holding
    // something like an `Rc<dyn Fn…>` — that is the intent, not a side
    // effect: a credential source that cannot cross a thread boundary
    // would break every embedder holding the listener in a spawned task.
    assert::<ServeOptions>();
    assert::<ConnectOptions>();
    assert::<TokenPolicy>();

    // Two promises the docs make that no check enforced. `Ticket: Clone`
    // is what `ServeHandle::ticket` returning owned depends on, and
    // `PipeStatus: Copy + Eq` is stated at its derive and relied on by
    // `status_changed`'s snapshot comparison.
    assert_clone::<Ticket>();
    assert_copy_eq::<PipeStatus>();
}

// The async surface gets the same treatment: a spawned task awaiting one
// of these futures needs them `Send`, and an implementation that held a
// non-Send guard across an await point would compile on its own while
// breaking exactly that embedding. Pinning the futures has to name them,
// which means calling the functions — dead code, type-checked, never run.
#[expect(dead_code, reason = "compile-time pin; never called")]
fn future_promises(serve_side: &ServeHandle, connect_side: &ConnectHandle, ticket: &Ticket) {
    fn assert_send(_: impl Send) {}
    assert_send(serve("", ServeOptions::default()));
    assert_send(connect(ticket, ConnectOptions::default()));
    assert_send(serve_side.status_changed());
    assert_send(serve_side.shutdown());
    assert_send(serve_side.shutdown_timeout(Duration::from_secs(0)));
    assert_send(connect_side.status_changed());
    assert_send(connect_side.shutdown());
    assert_send(connect_side.shutdown_timeout(Duration::from_secs(0)));
}
