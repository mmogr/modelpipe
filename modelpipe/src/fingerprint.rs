//! Naming an endpoint identity short enough to read.
//!
//! One rule, in one place, because it is applied to two things that must
//! come out comparable: the endpoint id inside a [`Ticket`](crate::Ticket),
//! which is how the serve side names *itself*, and the endpoint id on an
//! accepted connection, which is how it names whoever turned up. An
//! operator holding a ticket and reading a log line has to be able to tell
//! at a glance whether they are looking at the same peer, and two rules
//! that agree today are two rules that will disagree eventually.
//!
//! Never the whole key. Thirty-two bytes is ninety-six characters of hex
//! that nobody reads and every log line would carry; the leading bytes are
//! enough to tell two peers apart by eye and are all a diagnostic needs.
//! Nothing here is a secret — an endpoint id is a public key, and the full
//! one is printed in every ticket — so the truncation is about legibility
//! rather than disclosure.

use std::fmt::Write as _;

/// How many bytes of the endpoint id a fingerprint shows.
///
/// Six, which is what tickets have always shown, and it is not changed by
/// being moved here: a fingerprint is something people compare against one
/// they wrote down earlier, so its length is part of the format rather than
/// a tuning knob. Twelve hex characters — enough that two peers colliding
/// by accident is not a thing that happens, short enough to sit at the
/// front of a log line without being what the eye lands on.
const FINGERPRINT_BYTES: usize = 6;

/// The fingerprint rule itself, over raw endpoint id bytes.
///
/// Free rather than a method because the serve side needs it for a peer it
/// never had a ticket for: what arrives on a connection is the *other* end's
/// endpoint id, and naming it by any other rule would mean an operator could
/// not match a line in their log against the ticket they handed out. One
/// rule, so the two are comparable by eye — which is the entire purpose of a
/// fingerprint.
///
/// Takes a slice rather than the array so the caller need not know the
/// length; anything shorter than [`FINGERPRINT_BYTES`] is rendered whole
/// rather than panicking, because a diagnostic that panics is worse than a
/// short one.
pub(crate) fn of(endpoint_id: &[u8]) -> String {
    let shown = endpoint_id.len().min(FINGERPRINT_BYTES);
    let mut out = String::with_capacity(shown * 2);
    for byte in &endpoint_id[..shown] {
        // Infallible: writing to a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
#[path = "fingerprint_tests.rs"]
mod fingerprint_tests;
