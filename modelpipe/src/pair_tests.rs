//! Tests for [`super`]: a serve side that takes the pipe and never answers the
//! pairing request.
//!
//! The pipe is real, as in `peer_redial_tests.rs`: the deadline under test
//! starts once the serve side is reached, and only an endpoint that accepts
//! the connection gets `pair` that far. Discovery and port mapping are off on
//! both sides, so `pair` reaches the serve side only at the paths its ticket
//! carries. The relays are left on, and each endpoint still contacts iroh's
//! default ones.

use std::time::Duration;

use iroh::Endpoint;

use super::*;
use crate::pairing_string::PairingCode;
use crate::transport::{self, NetOptions};

/// What the test waits for `pair` to give up by. Shorter than
/// [`REDEEM_WITHIN`], so a `pair` that waited out the real deadline instead
/// of the one it was given fails here rather than passing slowly.
const PATIENCE: Duration = Duration::from_secs(20);

/// The exchange's deadline in the test. What is under test is that `pair`
/// gives up at the deadline it is given, not the number.
const BRIEFLY: Duration = Duration::from_millis(500);

/// No port mapping and no discovery: the endpoint publishes nothing about
/// itself, so it is found only at the paths its ticket carries. The relays
/// stay on.
const NO_LOOKUP: NetOptions = NetOptions {
    port_mapping: false,
    discovery: false,
    relay_only: false,
};

/// An endpoint that answers this crate's ALPN, takes every connection and every
/// stream opened on it, and never writes a byte back: a serve side that
/// accepts the pipe and then never answers.
///
/// The streams are held rather than dropped, so the pairing request is left
/// unanswered rather than reset.
async fn silent() -> Endpoint {
    let endpoint = transport::bind(None, None, NO_LOOKUP)
        .await
        .expect("an endpoint binds");
    let accepting = endpoint.clone();
    tokio::spawn(async move {
        while let Some(incoming) = accepting.accept().await {
            let Ok(connection) = incoming.await else {
                continue;
            };
            tokio::spawn(async move {
                while let Ok(stream) = connection.accept_bi().await {
                    tokio::spawn(async move {
                        let _held = stream;
                        std::future::pending::<()>().await;
                    });
                }
            });
        }
    });
    endpoint
}

#[tokio::test]
async fn a_serve_side_that_never_answers_is_given_up_on_at_the_redeem_deadline() {
    let serving = silent().await;
    let code: PairingCode = "483920".parse().expect("a code");
    let pairing = PairingString::new(transport::ticket_from(&serving.addr()), Some(code));
    let opts = ConnectOptions {
        port_mapping: false,
        discovery: false,
        ..ConnectOptions::default()
    };

    let result = tokio::time::timeout(
        PATIENCE,
        pair_within(&pairing, None, opts, PATIENCE, BRIEFLY),
    )
    .await
    .expect("pair gave up by itself, at the deadline it was given");
    let Err(PairError::Exchange(e)) = &result else {
        panic!("an exchange that timed out, not {result:?}");
    };
    assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "{e}");
}
