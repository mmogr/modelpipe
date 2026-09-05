//! Tests for [`super`] — what `serve` is given, and how it refuses.
//!
//! Split out via `#[path]` so `serve.rs` stays inside the file-size
//! budget, the same way every other module in the crate does it.

use super::*;

/// Distinct from the sentinel `credential.rs` uses, so a leak names
/// the type it escaped through.
const SUPPLIED: &str = "sk-zzq-serve-options-sentinel";

/// `ServeOptions` is the type an embedder is most likely to hold in a
/// struct of their own and derive `Debug` on, which is how a supplied
/// credential reaches a log without anyone deciding it should.
#[test]
fn debug_for_serve_options_never_renders_the_supplied_token() {
    // A struct literal rather than the `Default`-then-mutate dance an
    // out-of-crate embedder is forced into by `#[non_exhaustive]`:
    // inside the crate the literal is legal, and clippy rejects the
    // dance. What is under test is the `Debug` impl, which cannot tell
    // how the value was built.
    let opts = ServeOptions {
        auth: TokenPolicy::Supplied(SUPPLIED.to_owned()),
        relay: Some("https://relay.example.com/".to_owned()),
        ..Default::default()
    };
    let rendered = format!("{opts:?}");
    assert!(
        !rendered.contains(SUPPLIED),
        "the token leaked through ServeOptions: {rendered}"
    );
    assert!(
        rendered.contains("relay.example.com"),
        "the non-secret fields should still be visible: {rendered}"
    );
}

/// Running out of `wait_online` is a slower pairing, not a failure.
///
/// The wait exists because iroh's own has no end: it is satisfied by a
/// relay handshake, so on a machine with no route to one it would never
/// return. That makes the expiry path the one that has to be right —
/// a listener that refused to start where the internet is unreachable
/// would be a worse bug than the stale ticket this option exists to fix.
/// One millisecond is a deadline nothing can beat, so this exercises that
/// path without needing a network to be absent.
#[tokio::test]
async fn a_wait_that_times_out_still_yields_a_listener() {
    let backend = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let url = format!("http://{}", backend.local_addr().expect("bound"));

    let opts = ServeOptions {
        wait_online: Some(Duration::from_millis(1)),
        ..Default::default()
    };
    let serving = serve(&url, opts)
        .await
        .expect("the deadline is not an error");

    // And the listener it returns is a real one: it has a ticket to hand
    // out, whatever the address set behind that ticket had time to become.
    let _ = serving.ticket();
    serving.shutdown().await;
}
