//! Which headers cross the tunnel, and which stop at its edge.
//!
//! Pure: transforms over an owned header list, no I/O and no knowledge of
//! how those headers were parsed or will be written back. Header names are
//! compared ASCII-case-insensitively throughout, because that is what they
//! are.
//!
//! The list is a `Vec` of pairs rather than a map on purpose. Headers may
//! legitimately repeat — `Set-Cookie` most obviously — and order is
//! observable, so collapsing them into a map would silently rewrite traffic
//! this crate has no business rewriting.

/// Headers that describe *this* connection rather than the message, and so
/// must not be forwarded onto a different one. RFC 9110 §7.6.1.
///
/// `Transfer-Encoding` is on the list, and stripping it is only correct
/// because the edge re-frames the body it forwards. A component that
/// stripped it and then copied the body through unchanged would be
/// forwarding chunked bytes with nothing left to say so — the framing
/// confusion that request smuggling is built out of. The check for a
/// message that arrives with conflicting framing to begin with belongs to
/// the edge, not here: it is a question about the whole message, and this
/// module only sees the headers.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Headers describing a proxy chain in front of the client.
///
/// Stripped inbound and never added outbound. modelpipe is a private tunnel
/// between two machines someone owns, not a reverse proxy in front of a
/// fleet: there is no chain to describe, and forwarding a client-supplied
/// one into a local backend hands an attacker a free way to claim any
/// origin address they like to whatever reads the backend's logs.
const FORWARDING: &[&str] = &[
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
];

/// Fields a `Connection` header may not nominate, whatever it says.
///
/// RFC 9110 §7.6.1 forbids a sender from naming a field that is meaningful
/// to every recipient, and this is the recipient half of that rule: these
/// describe the *message*, not the hop, so deleting one on a peer's say-so
/// changes what the message means rather than what the connection does.
///
/// `content-length` is the one that matters. Framing is decided from the
/// headers as they arrived; the strip happens afterwards; and the
/// serializer re-declares framing only for chunked. So honouring
/// `Connection: content-length` deletes the length from the head while the
/// body is still forwarded under it — the edge emitting a body beneath a
/// head that declares none, which is the framing confusion the module
/// comment above says stripping must not create.
const NEVER_NOMINABLE: &[&str] = &["connection", "content-length", "host", "transfer-encoding"];

/// Remove the hop-by-hop headers, including the ones this message nominates.
///
/// `Connection` may name further headers as hop-by-hop for this connection
/// only, and honouring that is not optional: a header a peer marked
/// connection-scoped is one it did not intend to reach anybody else. A
/// nomination of a message-level field is the exception and is ignored —
/// see [`NEVER_NOMINABLE`].
pub(crate) fn strip_hop_by_hop(headers: &mut Vec<(String, String)>) {
    // Collected before anything is removed, because `Connection` is itself
    // hop-by-hop and is about to be deleted along with the list it carries.
    let nominated: Vec<String> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        // A peer may not redefine what its own message means.
        .filter(|token| !NEVER_NOMINABLE.contains(&token.as_str()))
        .collect();

    headers.retain(|(name, _)| {
        let lower = name.to_ascii_lowercase();
        !HOP_BY_HOP.contains(&lower.as_str()) && !nominated.contains(&lower)
    });
}

/// Whether a field name is one the edge removes from a head.
///
/// Exported so the chunked trailer section can be filtered against the same
/// two lists rather than a second copy of them. A trailer is a header field
/// that happens to arrive after the body, and the rules above are about what
/// a field *means*, not where it sits — so a trailer that restates a name
/// the head strip removed is that strip undone.
///
/// Deliberately ignores `Connection` nominations. Those describe the head
/// they arrived with; a trailer arrives after it, and re-reading a
/// nomination here would hand a peer the same message-rewriting lever
/// [`NEVER_NOMINABLE`] exists to take away.
pub(crate) fn is_stripped(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    HOP_BY_HOP.contains(&lower.as_str()) || FORWARDING.contains(&lower.as_str())
}

/// Whether a field name is one a *trailer* may not carry.
///
/// Everything [`is_stripped`] covers, plus [`NEVER_NOMINABLE`] — which is
/// where `content-length` and `host` live, and which `is_stripped` does not
/// consult. `body.rs` filtered trailers through `is_stripped` alone while
/// the comment above that filter said a backend could not use one to put
/// back "`Connection` or a second `Content-Length`". Half of that was true:
/// `Connection` is hop-by-hop and was caught, `Content-Length` is neither
/// hop-by-hop nor a forwarding header and sailed through.
///
/// The rule is RFC 9110 §6.5.1: a trailer may not carry a field that
/// affects message framing, routing, authentication, or processing. These
/// two lists are this crate's spelling of the first two, and a trailer
/// restating either is the head strip undone a few hundred bytes later —
/// on the one part of the message nothing else filters.
///
/// Still deliberately ignores `Connection` nominations, for the reason
/// [`is_stripped`] gives: those describe the head they arrived with, and
/// re-reading one here would hand a peer the message-rewriting lever
/// [`NEVER_NOMINABLE`] exists to take away.
pub(crate) fn is_forbidden_in_trailer(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    is_stripped(name) || NEVER_NOMINABLE.contains(&lower.as_str())
}

/// Remove any inbound description of a proxy chain, and add none.
pub(crate) fn strip_inbound_forwarded(headers: &mut Vec<(String, String)>) {
    headers.retain(|(name, _)| {
        let lower = name.to_ascii_lowercase();
        !FORWARDING.contains(&lower.as_str())
    });
}

/// Replace `Host` with the backend's authority.
///
/// The client's `Host` names the local listener it connected to, which the
/// backend has never heard of. Rewriting rather than passing through is also
/// what keeps a name-based backend from being addressed as something it is
/// not: whatever the client asked for, what arrives is the authority the
/// operator configured.
///
/// Every existing `Host` is removed first — a request carrying two is
/// ambiguous, and resolving it by appending a third would be worse.
pub(crate) fn set_host(headers: &mut Vec<(String, String)>, authority: &str) {
    headers.retain(|(name, _)| !name.eq_ignore_ascii_case("host"));
    headers.insert(0, ("Host".to_owned(), authority.to_owned()));
}

#[cfg(test)]
#[path = "headers_tests.rs"]
mod headers_tests;
