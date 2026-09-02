//! What the edge says when it will not forward.
//!
//! Pure: each of these is a complete HTTP/1.1 response as bytes, built here
//! and never obtained from anywhere else. That is the property worth having
//! a module for — a refusal produced locally cannot be confused with
//! something the backend said, because at the point these are written the
//! backend has not been contacted.
//!
//! Every one closes the connection. A stream carries exactly one exchange
//! and a refused exchange is over.

// Scoped to the non-test build: the edge writes these, and lands next.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the request edge writes these; tests assert them meanwhile"
    )
)]

/// The 401 the edge writes itself.
///
/// Synthesized locally and never forwarded: the backend has not been
/// contacted at the point this is produced, so there is no upstream
/// response for it to be confused with. `Connection: close` because this
/// stream carries one exchange and it is over.
pub(crate) fn unauthorized() -> Vec<u8> {
    let body =
        br#"{"error":{"message":"invalid or missing bearer token","code":"invalid_api_key"}}"#;
    let mut out = Vec::new();
    out.extend_from_slice(b"HTTP/1.1 401 Unauthorized\r\n");
    out.extend_from_slice(b"WWW-Authenticate: Bearer\r\n");
    out.extend_from_slice(b"Content-Type: application/json\r\n");
    out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(body);
    out
}

/// The 400 for a head this edge refuses to interpret.
pub(crate) fn bad_request() -> Vec<u8> {
    let body = br#"{"error":{"message":"malformed or ambiguous request","code":"bad_request"}}"#;
    let mut out = Vec::new();
    out.extend_from_slice(b"HTTP/1.1 400 Bad Request\r\n");
    out.extend_from_slice(b"Content-Type: application/json\r\n");
    out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(body);
    out
}

/// The 502 for a backend whose response this edge cannot read.
///
/// Distinct from [`bad_request`] on purpose: the client did nothing wrong,
/// and reporting a gateway failure as a client error would send whoever is
/// debugging it to the wrong side of the tunnel.
pub(crate) fn bad_gateway() -> Vec<u8> {
    let body = br#"{"error":{"message":"the backend sent a response this tunnel could not read","code":"bad_gateway"}}"#;
    let mut out = Vec::new();
    out.extend_from_slice(b"HTTP/1.1 502 Bad Gateway\r\n");
    out.extend_from_slice(b"Content-Type: application/json\r\n");
    out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_head::{Framing, framing, parse_response};

    /// Each refusal must be a well-formed response whose declared length
    /// matches the body actually written — a wrong length here would hang
    /// the client waiting for bytes that never come.
    #[test]
    fn every_refusal_is_well_formed_and_declares_its_own_length() {
        for (name, bytes, status) in [
            ("unauthorized", unauthorized(), 401),
            ("bad request", bad_request(), 400),
            ("bad gateway", bad_gateway(), 502),
        ] {
            let (head, consumed) = parse_response(&bytes)
                .unwrap_or_else(|e| panic!("{name} must parse: {e:?}"))
                .unwrap_or_else(|| panic!("{name} must be complete"));
            assert_eq!(head.status, status, "{name}");
            assert_eq!(
                framing(&head.headers, true),
                Ok(Framing::Length((bytes.len() - consumed) as u64)),
                "{name} declares the body it wrote"
            );
        }
    }

    /// A 401 that does not say how to authenticate is a 401 a client cannot
    /// act on.
    #[test]
    fn the_unauthorized_response_advertises_the_scheme() {
        let bytes = unauthorized();
        let (head, _) = parse_response(&bytes).unwrap().unwrap();
        assert!(
            head.headers
                .iter()
                .any(|(n, v)| n.eq_ignore_ascii_case("www-authenticate") && v.contains("Bearer"))
        );
    }

    /// A backend failure reported as a client error sends whoever is
    /// debugging it to the wrong side of the tunnel.
    #[test]
    fn a_backend_failure_is_not_reported_as_a_client_error() {
        let (head, _) = parse_response(&bad_gateway()).unwrap().unwrap();
        assert!((500..600).contains(&head.status), "5xx, not 4xx");
    }
}
