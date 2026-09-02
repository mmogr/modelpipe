//! Tests for [`super`] — the connect side's URL rendering.
//!
//! Split out via `#[path]` so `dialer.rs` stays inside the file-size
//! budget, the same way every other module in the crate does it.
use super::*;

/// A wildcard bind names no reachable host, so the URL must name one
/// that is.
#[test]
fn a_wildcard_bind_renders_as_loopback() {
    assert_eq!(
        base_url("0.0.0.0:8080".parse().unwrap()),
        "http://127.0.0.1:8080/v1"
    );
    assert_eq!(
        base_url("[::]:8080".parse().unwrap()),
        "http://[::1]:8080/v1"
    );
}

#[test]
fn a_concrete_bind_is_rendered_as_it_is() {
    assert_eq!(
        base_url("127.0.0.1:8080".parse().unwrap()),
        "http://127.0.0.1:8080/v1"
    );
    assert_eq!(
        base_url("192.168.1.5:9000".parse().unwrap()),
        "http://192.168.1.5:9000/v1"
    );
}

/// IPv6 needs brackets in a URL, and no URL parser accepts a zone id.
#[test]
fn an_ipv6_address_is_bracketed_and_loses_its_zone() {
    assert_eq!(
        base_url("[::1]:8080".parse().unwrap()),
        "http://[::1]:8080/v1"
    );
    let zoned = SocketAddr::V6(std::net::SocketAddrV6::new(
        "fe80::1".parse().unwrap(),
        8080,
        0,
        7,
    ));
    assert_eq!(
        base_url(zoned),
        "http://[fe80::1]:8080/v1",
        "the zone id must not reach a URL"
    );
}

/// The URL is meant to be pasted into a client, so it must carry the
/// `/v1` an OpenAI-compatible one expects — for every shape of address,
/// not just the common one.
#[test]
fn every_rendering_names_the_openai_compatible_base_path() {
    for addr in ["127.0.0.1:8080", "0.0.0.0:80", "[::1]:1", "[::]:65535"] {
        let url = base_url(addr.parse().expect("addr"));
        assert!(url.ends_with("/v1"), "{addr} rendered as {url}");
        assert!(url.starts_with("http://"), "{addr} rendered as {url}");
    }
}
