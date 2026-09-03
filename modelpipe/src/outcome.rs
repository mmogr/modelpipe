//! What one exchange did, as a value.
//!
//! Split from [`crate::exchange`] when diagnostics gave this type a second
//! job. It was a return value the listener discarded; it is now also the
//! word a log line uses for what happened, and [`Outcome::as_str`] is the
//! whole of that second job — the same shape, and for the same reason, as
//! [`PipeStatus::as_str`](crate::PipeStatus::as_str).
//!
//! Nothing here is a secret and nothing here can become one. That is worth
//! stating in a crate where the redaction discipline is otherwise
//! hand-written `Debug` impls: an `Outcome` names a *class* of result and
//! never carries the request that produced it, so putting one in a log
//! field is safe by construction rather than by review.

/// What happened to one exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Admitted, and carried to the backend and back.
    Forwarded,
    /// Refused on the credential. The backend was not contacted.
    Unauthorized,
    /// Refused on the head — unparseable, oversized, or framed
    /// ambiguously. The backend was not contacted.
    BadRequest,
    /// The peer opened a stream and never finished asking. Nothing was
    /// written back, and the backend was not contacted.
    TimedOut,
    /// The backend was contacted and the exchange failed there — it would
    /// not take the connection, or answered with something this edge
    /// cannot read. The client was told so; distinct from
    /// [`Forwarded`](Self::Forwarded) because nothing came back.
    BadGateway,
    /// The request body stopped before its declared end — truncated, or
    /// framed so this edge could not go on reading it — and the backend,
    /// told by a half-close where it stopped, answered nothing this edge
    /// could relay.
    ///
    /// Not [`BadRequest`](Self::BadRequest), which promises the backend was
    /// never contacted: by the time a body can fail, its head is already
    /// upstream. Not [`BadGateway`](Self::BadGateway) either — the backend
    /// did nothing wrong, and reporting it there sends whoever is debugging
    /// to the far side of a tunnel that was working.
    Unfinished,
}

impl Outcome {
    /// The name to log this under.
    ///
    /// A borrowed `&'static str` rather than the derived `Debug`, which is
    /// what a `tracing` field would otherwise reach for. Two reasons, and
    /// the second is the one that matters. It is a value an operator greps
    /// for, so it is spelled once here rather than being whatever
    /// `#[derive(Debug)]` happens to render — and a `Debug` field on a
    /// *different* type is exactly how this crate leaks a credential, so
    /// the habit worth having at every log site is naming the string
    /// deliberately.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Forwarded => "forwarded",
            Self::Unauthorized => "unauthorized",
            Self::BadRequest => "bad_request",
            Self::TimedOut => "timed_out",
            Self::BadGateway => "bad_gateway",
            Self::Unfinished => "unfinished",
        }
    }
}

#[cfg(test)]
#[path = "outcome_tests.rs"]
mod outcome_tests;
