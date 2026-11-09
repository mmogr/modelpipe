//! The relay path, against a relay in this process.
//!
//! A phone on a carrier network reaches its desktop through a relay, so the
//! relayed path is the one that most needs to work. These tests run a
//! relay on loopback (`iroh::test_utils`), which `transport::bind` trusts
//! in tests despite its self-signed certificate, so none of them needs the
//! internet.

/// A relay on loopback, and the URL to hand `--relay`.
///
/// The relay runs for as long as the first half is held.
pub(crate) async fn local() -> (impl Sized, String) {
    let (_map, url, server) = iroh::test_utils::run_relay_server()
        .await
        .expect("a relay starts on loopback");
    (server, url.to_string())
}
