//! What the unit tests bind with, so that none of them reaches past this
//! machine except where a test is about exactly that.
//!
//! The defaults publish to n0's discovery service and ask the router for a
//! port mapping. Neither changes what a test on one machine observes, and
//! both make the suite's behaviour depend on a network it does not control.

use iroh::Endpoint;
use iroh::endpoint::{PortmapperConfig, presets};

use crate::connect::ConnectOptions;
use crate::serve_options::ServeOptions;
use crate::transport::NetOptions;

/// No discovery and no port mapping.
pub(crate) const QUIET: NetOptions = NetOptions {
    port_mapping: false,
    discovery: false,
    relay_only: false,
};

/// [`ServeOptions`] with [`QUIET`]'s two contacts off.
pub(crate) fn serve_options() -> ServeOptions {
    ServeOptions {
        port_mapping: false,
        discovery: false,
        ..ServeOptions::default()
    }
}

/// [`ConnectOptions`] with [`QUIET`]'s two contacts off.
pub(crate) fn connect_options() -> ConnectOptions {
    ConnectOptions {
        port_mapping: false,
        discovery: false,
        ..ConnectOptions::default()
    }
}

/// A bare iroh endpoint that contacts nothing: no relay, no discovery, no
/// port mapping. It reaches another endpoint on this machine directly.
pub(crate) fn endpoint() -> iroh::endpoint::Builder {
    Endpoint::builder(presets::Minimal).portmapper_config(PortmapperConfig::Disabled)
}

/// A relay on loopback, and the URL to hand `--relay`. It runs for as long
/// as the first half is held; `transport::bind` trusts its self-signed
/// certificate in tests.
pub(crate) async fn relay() -> (impl Sized, String) {
    let (_map, url, server) = iroh::test_utils::run_relay_server()
        .await
        .expect("a relay starts on loopback");
    (server, url.to_string())
}
