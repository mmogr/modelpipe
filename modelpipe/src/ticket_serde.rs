//! `serde` for a ticket, behind the `serde` feature.
//!
//! A ticket serializes as its canonical string — the same text
//! [`Display`](std::fmt::Display) prints and [`FromStr`](std::str::FromStr)
//! reads — and nothing else. Not as a struct: the byte layout is private,
//! `docs/ticket-format-v0.md` is the public contract, and a struct
//! serialization would be a second wire format for the same bytes, one
//! that every other language's client would then have to match as well.
//!
//! Deserialization is the parse, with the parse's own error. That keeps the
//! redaction discipline: a failed deserialization names
//! [`TicketParseError`](crate::TicketParseError)'s one-line advice and never
//! echoes the offending input, which may be most of a real ticket.
//!
//! Its own module rather than an `impl` block in `ticket.rs`, because the
//! file-size gate says that file is full — and because everything here is
//! conditional on a feature, which is easier to see at a module boundary
//! than scattered through `#[cfg]` attributes on a type's impls.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::ticket::Ticket;

impl Serialize for Ticket {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Ticket {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[path = "ticket_serde_tests.rs"]
mod ticket_serde_tests;
