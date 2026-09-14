//! What one exchange did, as a value.
//!
//! Split from [`crate::exchange`] when diagnostics gave this type a second
//! job. It was a return value the listener discarded; it is now also the
//! word a log line uses for what happened, and [`Outcome::as_str`] is the
//! whole of that second job, with [`Outcome::of_error`] deciding which word an
//! error is logged under — the same shape, and for the same reason, as
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
    /// A pairing request the edge answered itself, handing a device its key.
    /// The backend was not contacted.
    Paired,
    /// The client went away before the exchange ended: it stopped reading,
    /// reset its stream, or its connection closed, reset or timed out.
    ///
    /// Never returned by an exchange. It is the word an exchange's error is
    /// logged under, at `debug`, when [`of_error`](Self::of_error) finds the
    /// client gone: a client hanging up is not a fault at this end.
    ClientGone,
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
            Self::Paired => "paired",
            Self::ClientGone => "client_gone",
        }
    }

    /// [`ClientGone`](Self::ClientGone) when `error` says the client went
    /// away, or `None` for a failure worth a warning.
    ///
    /// Read from the QUIC error inside, never from the kind alone. A backend
    /// that resets its TCP connection gives the same `ConnectionReset` a
    /// stopped stream does, and that is a fault. The client's stream is the
    /// only QUIC stream an exchange has, so a QUIC error inside is about the
    /// client. A connection this side closed is not the client's doing.
    pub(crate) fn of_error(error: &std::io::Error) -> Option<Self> {
        use iroh::endpoint::{ConnectionError, ReadError, WriteError};
        let inner = error.get_ref()?;
        let lost = |e: &ConnectionError| {
            matches!(
                e,
                ConnectionError::ApplicationClosed(_)
                    | ConnectionError::Reset
                    | ConnectionError::TimedOut
            )
        };
        let gone = match (
            inner.downcast_ref::<WriteError>(),
            inner.downcast_ref::<ReadError>(),
        ) {
            (Some(WriteError::Stopped(_)), _) | (_, Some(ReadError::Reset(_))) => true,
            (Some(WriteError::ConnectionLost(e)), _) | (_, Some(ReadError::ConnectionLost(e))) => {
                lost(e)
            }
            _ => false,
        };
        gone.then_some(Self::ClientGone)
    }
}

#[cfg(test)]
#[path = "outcome_tests.rs"]
mod outcome_tests;
