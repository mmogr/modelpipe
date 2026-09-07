//! What a ticket says about where it points.
//!
//! The second `impl` block of [`Ticket`], split from `ticket.rs` the way
//! `serve_status.rs` was split from `serve_handle.rs`, and for both of that
//! split's reasons: the file is at its budget, and the question is a
//! different one. `ticket.rs` owns what a ticket *is* — the fields, their
//! widths, how they are written down and read back. This owns what a holder
//! may ask of one.
//!
//! Two narrow accessors rather than a public address type, and the
//! narrowness is the point. [`crate::ticket_addr::TicketAddr`] is
//! `pub(crate)`: its shape has never been public, so exporting it now would
//! be inventing a versioned type to answer a question that two `Vec`s of
//! `std` values answer completely. A transport tag added in a later format
//! version gets its own accessor, and the two here keep meaning exactly
//! what they mean today.

use std::net::SocketAddr;

use crate::ticket::Ticket;
use crate::ticket_addr::TicketAddr;

impl Ticket {
    /// Every relay URL this ticket carries, in the ticket's own order.
    ///
    /// **Empty is the answer worth checking for**, and it is why this
    /// exists. A ticket's relay is what lets a machine that cannot be
    /// hole-punched to be reached at all, and it is routinely the half that
    /// is missing: local interface addresses are enumerable the moment a
    /// socket is bound, while reaching a relay takes a handshake over the
    /// network, so a ticket read immediately after
    /// [`serve`](fn@crate::serve) returns can carry direct addresses and
    /// nothing else — as can one minted on a host with no route to a relay
    /// at all. [`ServeHandle::ticket`](crate::ServeHandle::ticket) says so
    /// in prose and
    /// [`ServeOptions::wait_online`](crate::ServeOptions#structfield.wait_online)
    /// is the switch that waits; until now there was no way for an embedder
    /// that skipped the wait to *find out*, and a ticket printed for a
    /// person is printed once.
    ///
    /// **Verbatim.** No case folding, no percent-decoding, no trailing-dot
    /// removal, no default-port elision — a `String` and not a parsed URL
    /// type, because the format spec makes carrying the relay body
    /// unchanged normative and every URL library normalizes. A caller that
    /// wants a parsed URL is welcome to parse it; what it must not receive
    /// is one this crate parsed and re-printed on its behalf.
    ///
    /// Ordering is the ticket's canonical one — sorted by encoded bytes,
    /// which puts relays before direct addresses — so it is stable across a
    /// parse and re-encode rather than being whatever order arrived.
    pub fn relay_urls(&self) -> Vec<String> {
        self.addrs()
            .iter()
            .filter_map(|addr| match addr {
                TicketAddr::Relay(url) => Some(url.clone()),
                TicketAddr::V4(_) | TicketAddr::V6(_) => None,
            })
            .collect()
    }

    /// Every direct socket address this ticket carries, in the ticket's own
    /// order.
    ///
    /// The optimization half of a ticket: a holder on the same network as
    /// the listener reaches it at one of these without a relay in the path,
    /// and a holder anywhere else usually cannot. They are a snapshot of
    /// the serving machine's interfaces and reflexive addresses at the
    /// moment the ticket was minted, so a listener that has since changed
    /// network is found through its endpoint id and address lookup rather
    /// than through any of these.
    ///
    /// Worth knowing before printing one: these include the machine's
    /// **private LAN addresses** and, once the endpoint has reached a relay,
    /// the **public address that relay saw the connection come from** —
    /// which is the larger disclosure of the two, and anyone holding the
    /// ticket reads both. That is a disclosure to weigh rather than a defect
    /// to fix: filtering either out would break the direct paths they exist
    /// for and leave the holder on a relay. `SECURITY.md` and the README say
    /// so too, for the reader who never looks this accessor up.
    ///
    /// `SocketAddr` rather than the crate's own type because there is
    /// nothing to add to `std`'s: an IPv6 address here carries no zone id
    /// or flow info, which are local facts about one machine's interfaces
    /// and meaningless to whoever reads the ticket.
    pub fn direct_addrs(&self) -> Vec<SocketAddr> {
        self.addrs()
            .iter()
            .filter_map(|addr| match addr {
                TicketAddr::V4(v4) => Some(SocketAddr::V4(*v4)),
                TicketAddr::V6(v6) => Some(SocketAddr::V6(*v6)),
                TicketAddr::Relay(_) => None,
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "ticket_view_tests.rs"]
mod ticket_view_tests;
