//! Where a listener dials its backend, and whether it may.
//!
//! `serve` needs two things about a backend: a URL, and whether the
//! operator has agreed to reach a private address. Those used to travel
//! separately — a `&str` argument and a `ServeOptions` flag — and keeping
//! them apart made the flag mean "trust me" in general when it only ever
//! means "trust *this* address". Here they are one value, so the
//! permission is attached to the thing it is about and cannot be set for
//! one backend and left on for the next.
//!
//! **Two constructors, and the difference between them is the whole
//! design.**
//!
//! [`BackendUrl::dial`] takes a URL as written and never permits a private
//! address; saying yes to one is a separate, visible call to
//! [`allow_private`](BackendUrl::allow_private). That is the rule
//! [`locality`] states — the operator's explicit decision,
//! and only theirs — and nothing here weakens it.
//!
//! [`BackendUrl::at`] takes a **bind address**, and derives the permission
//! instead of asking for it. The reasoning is narrow and worth stating
//! plainly, because a derived permission looks like the thing the rule
//! forbids. A caller holding a bind address is holding the address of a
//! socket on this machine that it already owns: it chose that interface,
//! or read it back from a listener it started. There is no third party
//! whose server could be re-exported by accident, which is the case the
//! rule exists for — and the URL is built from that address, so the
//! permission cannot travel to any other host. A caller that merely *has*
//! a private URL, from a config file or an argument, still has to say so
//! out loud, because for that caller the rule's reasoning applies in full.
//!
//! `at` also rewrites a wildcard bind. `0.0.0.0` and `::` name no host, so
//! they are not destinations; on Linux, dialling the first reaches
//! loopback, which would make an accident look like a decision. A listener
//! on the wildcard is listening on loopback too, so the loopback literal
//! of the same family is what the caller meant, and the port is kept.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::locality::{self, Locality};

/// A backend to dial, carrying its own permission to be dialled.
///
/// Built with [`at`](Self::at) from a bind address this process owns, or
/// with [`dial`](Self::dial) from a URL. `&str` and `String` convert as
/// [`dial`](Self::dial) does, so `serve("http://127.0.0.1:11434", opts)`
/// still reads the way it always has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendUrl {
    url: String,
    allow_private: bool,
}

impl BackendUrl {
    /// The backend a server bound to `bind` is reached at.
    ///
    /// A wildcard bind becomes the loopback literal of the same family,
    /// keeping the port. Everything else is dialled as written. A private
    /// address is permitted, because a caller that owns the bind has
    /// already made that choice — see the module documentation for why
    /// this is not the general "trust me" the rule forbids.
    ///
    /// Link-local and public addresses are **not** permitted by this, and
    /// no constructor permits them: `serve` refuses them whatever it is
    /// handed.
    #[must_use]
    pub fn at(bind: SocketAddr) -> Self {
        let ip = dialable_ip(bind.ip());
        Self {
            // From an `IpAddr` rather than the `SocketAddr` as given, which
            // is what drops an IPv6 zone id: `SocketAddrV6`'s own `Display`
            // emits one and no URL parser accepts it. `SocketAddr`'s
            // `Display` brackets the literal, which a URL authority needs.
            url: format!("http://{}", SocketAddr::new(ip, bind.port())),
            allow_private: locality::classify(ip) == Locality::Private,
        }
    }

    /// The backend at `url`, exactly as written.
    ///
    /// Never permits a private address. A caller that means to reach one
    /// says so with [`allow_private`](Self::allow_private), which is the
    /// visible decision the rule asks for.
    #[must_use]
    pub fn dial(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            allow_private: false,
        }
    }

    /// Permit this backend to be a private address — RFC 1918 or
    /// `fc00::/7`.
    ///
    /// Moves exactly one class and nothing else: link-local and public
    /// addresses stay refused. The full rule is on
    /// [`ServeError::BackendNotLocal`](crate::ServeError::BackendNotLocal).
    #[must_use]
    pub const fn allow_private(mut self) -> Self {
        self.allow_private = true;
        self
    }

    /// The URL this dials.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Whether a private address is permitted for this backend.
    pub(crate) const fn permits_private(&self) -> bool {
        self.allow_private
    }
}

impl From<&str> for BackendUrl {
    fn from(url: &str) -> Self {
        Self::dial(url)
    }
}

impl From<String> for BackendUrl {
    fn from(url: String) -> Self {
        Self::dial(url)
    }
}

impl From<&String> for BackendUrl {
    fn from(url: &String) -> Self {
        Self::dial(url.as_str())
    }
}

/// A wildcard address as the loopback literal of its own family.
///
/// The one rewrite three call sites need: this one, the pairing exchange
/// dialling this side's own port, and the base URL a connect side prints.
/// Written once so the three cannot drift — and because "a bind address is
/// not a dial address" is the kind of rule that gets re-derived slightly
/// differently each time.
pub(crate) const fn dialable_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        other => other,
    }
}

/// [`dialable_ip`] for a whole socket address.
pub(crate) const fn dialable(mut addr: SocketAddr) -> SocketAddr {
    addr.set_ip(dialable_ip(addr.ip()));
    addr
}

#[cfg(test)]
#[path = "backend_url_tests.rs"]
mod backend_url_tests;
