//! Tests for [`super`] — screening what the backend URL resolves to.
//!
//! Split out via `#[path]` so `backend.rs` stays inside the file-size
//! budget.
//!
//! The screening rule is tested against address lists directly rather than
//! through DNS. That is not avoidance: a test that depended on what
//! `evil.example` resolves to today would be testing the internet, and the
//! property worth pinning is what this code does with an answer, not what
//! answer it gets.

use super::*;
use crate::ServeError;

fn addrs(list: &[&str]) -> Vec<SocketAddr> {
    list.iter().map(|s| s.parse().expect("addr")).collect()
}

// ── Screening ────────────────────────────────────────────────────────────

#[test]
fn loopback_is_dialable_without_any_flag() {
    for a in ["127.0.0.1:11434", "127.0.0.2:80", "[::1]:11434"] {
        assert_eq!(screen(addrs(&[a]), false), addrs(&[a]), "{a} needs no flag");
    }
}

#[test]
fn a_private_address_needs_the_flag() {
    let a = addrs(&["192.168.1.5:11434"]);
    assert_eq!(screen(a.clone(), false), addrs(&[]), "refused bare");
    assert_eq!(screen(a.clone(), true), a, "admitted with the flag");
}

#[test]
fn a_public_address_is_never_dialable() {
    for a in ["8.8.8.8:80", "[2606:4700::1111]:443"] {
        assert_eq!(screen(addrs(&[a]), false), addrs(&[]), "{a}");
        assert_eq!(
            screen(addrs(&[a]), true),
            addrs(&[]),
            "{a} even with the flag"
        );
    }
}

#[test]
fn the_metadata_endpoint_is_never_dialable_however_it_is_spelled() {
    for a in [
        "169.254.169.254:80",
        "[::ffff:169.254.169.254]:80",
        "[fe80::1]:80",
    ] {
        assert_eq!(screen(addrs(&[a]), false), addrs(&[]), "{a}");
        assert_eq!(
            screen(addrs(&[a]), true),
            addrs(&[]),
            "{a} even with the flag"
        );
    }
}

/// The heart of the rule. A name that resolves to several addresses is not
/// made acceptable by the loopback entry among them — the public one is
/// skipped, and only an address that passes on its own is ever returned.
#[test]
fn every_candidate_is_screened_and_not_merely_the_first() {
    // Public first: it must be skipped rather than taken or fatal.
    let mixed = addrs(&["8.8.8.8:11434", "127.0.0.1:11434"]);
    assert_eq!(
        screen(mixed, false),
        addrs(&["127.0.0.1:11434"]),
        "the public candidate is skipped, the loopback one taken"
    );

    // Loopback first: the public one must never be reached for.
    let mixed = addrs(&["127.0.0.1:11434", "8.8.8.8:11434"]);
    assert_eq!(screen(mixed, false), addrs(&["127.0.0.1:11434"]));

    // Nothing admissible at all, however many candidates there are.
    let all_bad = addrs(&["8.8.8.8:80", "169.254.169.254:80", "0.0.0.0:80"]);
    assert_eq!(screen(all_bad, true), addrs(&[]));
}

#[test]
fn a_name_that_resolves_to_nothing_is_not_dialable() {
    assert_eq!(screen(addrs(&[]), true), addrs(&[]));
}

// ── URL handling ─────────────────────────────────────────────────────────

#[tokio::test]
async fn a_loopback_backend_is_accepted_and_names_its_own_authority() {
    let backend = TcpBackend::new("http://127.0.0.1:11434", false)
        .await
        .expect("loopback must be accepted");
    assert_eq!(
        backend.authority(),
        "127.0.0.1:11434",
        "the Host header names the backend, port included"
    );
}

/// `localhost` is the spelling most people type, and it resolves without
/// leaving the machine.
#[tokio::test]
async fn a_named_loopback_backend_is_accepted() {
    let backend = TcpBackend::new("http://localhost:11434", false)
        .await
        .expect("localhost must be accepted");
    assert_eq!(backend.authority(), "localhost:11434");
}

#[tokio::test]
async fn the_default_port_is_supplied_when_the_url_omits_it() {
    let backend = TcpBackend::new("http://127.0.0.1", false)
        .await
        .expect("ok");
    assert_eq!(backend.authority(), "127.0.0.1:80");
}

/// A misconfigured backend fails at `serve` time with a message naming the
/// URL, rather than as a stream of failed requests later.
#[tokio::test]
async fn a_public_backend_is_refused_before_the_listener_starts() {
    let err = TcpBackend::new("http://8.8.8.8:80", true)
        .await
        .expect_err("a public backend must be refused");
    match &err {
        ServeError::BackendNotLocal { url } => assert_eq!(url, "http://8.8.8.8:80"),
        other => panic!("expected BackendNotLocal, got {other:?}"),
    }
    assert!(!err.is_retryable(), "and it is the operator's to fix");
}

/// Only `http`. The hop that matters is already encrypted by QUIC, and
/// accepting `https` would mean either verifying a certificate for a
/// loopback name or not verifying one at all.
#[tokio::test]
async fn a_non_http_backend_is_refused() {
    for url in [
        "https://127.0.0.1:11434",
        "file:///etc/passwd",
        "ftp://127.0.0.1",
        "not a url",
        "",
    ] {
        assert!(
            TcpBackend::new(url, true).await.is_err(),
            "{url:?} must be refused"
        );
    }
}

// ── Connecting ───────────────────────────────────────────────────────────

/// The one test that opens a socket. What it checks is that the screened
/// address is the address dialled — the connection lands on a listener
/// bound to exactly the address `resolve` returned.
#[tokio::test]
async fn a_screened_address_is_the_address_actually_dialled() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let bound = listener.local_addr().expect("addr");

    let backend = TcpBackend::new(&format!("http://127.0.0.1:{}", bound.port()), false)
        .await
        .expect("loopback");

    let accepted = tokio::spawn(async move { listener.accept().await.map(|(_, peer)| peer) });
    let stream = backend.connect().await.expect("connect");
    assert_eq!(stream.peer_addr().expect("peer"), bound);

    let peer = accepted.await.expect("task").expect("accept");
    assert!(peer.ip().is_loopback(), "and the caller came from loopback");
}

/// Every admissible address, not just the first, because the first is not
/// always the one that answers.
///
/// `localhost` resolves to `::1` before `127.0.0.1` on most systems and
/// Ollama binds `127.0.0.1` by default, so a screen that returned one
/// address turned `serve http://localhost:11434` into a listener that
/// started cleanly and failed every request afterwards.
#[test]
fn every_admissible_address_is_offered_in_order() {
    let mixed = addrs(&["[::1]:11434", "8.8.8.8:11434", "127.0.0.1:11434"]);
    assert_eq!(
        screen(mixed, false),
        addrs(&["[::1]:11434", "127.0.0.1:11434"]),
        "both loopback candidates, in the order the resolver gave them, \
         and the public one dropped from between them"
    );
}

// ── URL shapes ───────────────────────────────────────────────────────────

/// `::1` is the canonical IPv6 loopback and `locality` classifies it as
/// such. It was still refused, because `Url::host_str` keeps an IPv6
/// literal's brackets and nothing that resolves a host accepts them — so
/// the message an operator got for the most local address there is was
/// "not a local address".
#[tokio::test]
async fn an_ipv6_literal_backend_is_accepted_and_keeps_its_brackets() {
    let backend = TcpBackend::new("http://[::1]:11434", false)
        .await
        .expect("::1 is loopback");
    assert_eq!(
        backend.authority(),
        "[::1]:11434",
        "the Host header needs the brackets back — `::1:11434` cannot be \
         read as an address and a port"
    );
}

/// The brackets are stripped for resolution and restored for the header,
/// which is two different jobs; an IPv4 literal exercises neither and must
/// be untouched by both.
#[tokio::test]
async fn an_ipv4_literal_backend_gains_no_brackets() {
    let backend = TcpBackend::new("http://127.0.0.1:11434", false)
        .await
        .expect("loopback");
    assert_eq!(backend.authority(), "127.0.0.1:11434");
}

/// "Not a local address" is a verdict about an address, and it was the
/// answer for three things that are not addresses.
///
/// Reporting a scheme objection that way told the operator their loopback
/// URL was not loopback, and pointed them at `--allow-private-backend`,
/// which fixes none of these.
#[tokio::test]
async fn a_url_this_crate_cannot_use_is_not_reported_as_a_locality_verdict() {
    for url in [
        "not a url at all",
        "https://127.0.0.1:11434",
        "http://",
        "ftp://127.0.0.1:11434",
        // A path after the authority is silently discarded if it is
        // accepted, so it is refused instead. Measured before this:
        // `serve http://127.0.0.1:11434/v1/` started, printed a ticket, and
        // dropped the `/v1/`.
        "http://127.0.0.1:11434/v1",
        "http://127.0.0.1:11434/v1/",
        "http://127.0.0.1:11434?x=1",
        "http://127.0.0.1:11434#frag",
    ] {
        match TcpBackend::new(url, false).await {
            Err(ServeError::InvalidBackendUrl { url: named }) => {
                assert_eq!(named, url, "the error must name what was refused");
            }
            other => panic!("{url} should be InvalidBackendUrl, got {other:?}"),
        }
    }
}

/// A locality refusal keeps its own variant, so the split cannot pass by
/// everything having become `InvalidBackendUrl`.
#[tokio::test]
async fn an_address_this_listener_may_not_dial_is_still_a_locality_verdict() {
    match TcpBackend::new("http://8.8.8.8:11434", false).await {
        Err(e @ ServeError::BackendNotLocal { .. }) => {
            assert!(!e.is_retryable(), "the operator's to fix: {e}");
        }
        other => panic!("expected BackendNotLocal, got {other:?}"),
    }
}

/// A resolver outage is a machine condition, and inheriting
/// `BackendNotLocal`'s permanence told a supervisor to give up on a backend
/// that was about to come back.
#[tokio::test]
async fn a_host_that_resolves_to_nothing_is_retryable() {
    // `.invalid` is reserved by RFC 2606 precisely so it never resolves.
    match TcpBackend::new("http://nothing.invalid:11434", false).await {
        Err(e @ ServeError::BackendUnresolvable { .. }) => {
            assert!(e.is_retryable(), "a resolver outage clears: {e}");
        }
        other => panic!("expected BackendUnresolvable, got {other:?}"),
    }
}

/// The negative control for the path refusal: the two spellings that mean
/// "no path" are still accepted.
///
/// `url` normalises an absent path to `/`, so a rule written as "the path
/// must be empty" would refuse the ordinary `http://127.0.0.1:11434` and
/// every URL a browser would produce from it.
#[tokio::test]
async fn a_backend_url_with_no_path_is_accepted_either_way_it_is_written() {
    for url in ["http://127.0.0.1:11434", "http://127.0.0.1:11434/"] {
        let backend = TcpBackend::new(url, false)
            .await
            .unwrap_or_else(|e| panic!("{url} must be usable: {e}"));
        assert_eq!(backend.authority(), "127.0.0.1:11434");
    }
}

/// The refusal must happen before the host is resolved.
///
/// `serve` states the ordering as a rule — everything the operator typed is
/// checked before anything is opened — so a URL that is wrong in a way this
/// crate can see must be reported as that, not after a DNS timeout naming
/// something else. The host below has a reserved TLD and cannot resolve, so
/// only a check that runs first can produce `InvalidBackendUrl`.
#[tokio::test]
async fn a_path_is_refused_before_the_host_is_resolved() {
    let url = "http://nothing.invalid:11434/v1";
    match TcpBackend::new(url, false).await {
        Err(ServeError::InvalidBackendUrl { url: named }) => assert_eq!(named, url),
        other => panic!("the path must be refused before resolving, got {other:?}"),
    }
}

/// Userinfo in a backend URL is a credential the operator typed that this
/// crate has no route to send anywhere.
///
/// The same silent-discard failure the path rule prevents: it parses, it
/// looks like it does something, and every byte of it is dropped. There is
/// exactly one credential here — the bearer token — and a URL is not where
/// it goes.
#[tokio::test]
async fn a_backend_url_carrying_userinfo_is_refused() {
    for url in [
        "http://user:pass@127.0.0.1:11434",
        "http://user@127.0.0.1:11434",
        "http://:pass@127.0.0.1:11434",
    ] {
        match TcpBackend::new(url, false).await {
            Err(ServeError::InvalidBackendUrl { url: named }) => assert_eq!(named, url),
            other => panic!("{url} should be InvalidBackendUrl, got {other:?}"),
        }
    }
}
