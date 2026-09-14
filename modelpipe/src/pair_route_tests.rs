//! Tests for [`super`]: the edge's answer to a pairing request, step by step.
//!
//! Driven through [`answer`] with a head parsed the way the exchange parses
//! one, so each refusal can be compared byte for byte with the one refusal.
//! `exchange_tests.rs` covers that the route is reached, only by its exact
//! path, and never touches the backend.

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt as _, duplex};
use tokio::sync::watch;

use super::*;
use crate::framing;
use crate::invite::InviteOutcome;
use crate::token_policy::TokenPolicy;

const DEVICE: PeerId = PeerId::from_bytes([1; 32]);
const STRANGER: PeerId = PeerId::from_bytes([2; 32]);
const SERVING: PeerId = PeerId::from_bytes([0xd7; 32]);
const KEY: &str = "sk-zzq-device-key";
const NAME: &str = "dev-0a1b2c3d";

/// A named-only listener holding one device's key, with an armed invite for
/// it: the credential, the code, and the invite's outcome.
fn inviting(wrong_codes: u8) -> (Credential, String, watch::Receiver<Option<InviteOutcome>>) {
    let (credential, _) = Credential::new(&TokenPolicy::Named).expect("a usable policy");
    credential
        .add_named(NAME, KEY.to_owned(), None)
        .expect("held");
    let registered = credential.invites().register(
        NAME.to_owned(),
        KEY.to_owned(),
        Instant::now() + Duration::from_mins(2),
        wrong_codes,
    );
    credential.invites().arm(registered.id);
    (
        credential,
        registered.code.as_str().to_owned(),
        registered.outcome,
    )
}

/// A `POST` to the route carrying `body`, bearing `bearer` when there is one.
fn post(bearer: Option<&str>, body: &[u8]) -> Vec<u8> {
    let mut head = format!(
        "POST /modelpipe/pair HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(value) = bearer {
        let _ = write!(head, "Authorization: Bearer {value}\r\n");
    }
    head.push_str("\r\n");
    let mut request = head.into_bytes();
    request.extend_from_slice(body);
    request
}

/// Answer `request` from `from` as the route: the outcome, and every byte the
/// client read.
async fn answered(credential: &Credential, from: PeerId, request: &[u8]) -> (Outcome, Vec<u8>) {
    let (head, consumed) = http_head::parse_request(request)
        .expect("a head")
        .expect("a whole head");
    let request_framing = framing::framing(&head.headers, false).expect("framed");
    let (mut client, mut edge) = duplex(64 * 1024);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let outcome = answer(
        &mut edge,
        &head,
        request[consumed..].to_vec(),
        request_framing,
        credential,
        &Caller::new(from, SERVING),
        deadline,
    )
    .await
    .expect("no transport failure");
    drop(edge);
    let mut seen = Vec::new();
    client.read_to_end(&mut seen).await.expect("read");
    (outcome, seen)
}

#[tokio::test]
async fn a_device_redeems_its_code_and_is_handed_its_key() {
    let (credential, code, outcome) = inviting(3);
    let (result, seen) = answered(&credential, DEVICE, &post(Some(&code), b"Matt's iPhone")).await;
    let seen = String::from_utf8(seen).expect("utf-8");

    assert_eq!(result, Outcome::Paired);
    assert!(seen.starts_with("HTTP/1.1 200 OK\r\n"), "{seen}");
    assert!(seen.contains("\r\nCache-Control: no-store\r\n"), "{seen}");
    let body = format!(r#"{{"api_key":"{KEY}","device_id":"{NAME}","peer":"{SERVING}"}}"#);
    assert!(seen.ends_with(&body), "{seen}");
    assert!(
        seen.contains(&format!("\r\nContent-Length: {}\r\n", body.len())),
        "{seen}"
    );
    assert_eq!(
        outcome.borrow().clone(),
        Some(InviteOutcome::Redeemed {
            device: NAME.to_owned(),
            peer: DEVICE,
            label: Some("Matt's iPhone".to_owned()),
        })
    );
}

#[tokio::test]
async fn every_refusal_is_the_same_401_and_leaves_the_invite_live() {
    let (credential, code, outcome) = inviting(3);
    let pinned = PeerId::from_bytes([3; 32]);
    credential
        .add_named("pinned", "sk-zzq-pinned-key".to_owned(), Some(pinned))
        .expect("held");
    let wrong = if code == "000000" { "000001" } else { "000000" };
    let get =
        format!("GET /modelpipe/pair HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {code}\r\n\r\n");
    let chunked = format!(
        "POST /modelpipe/pair HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\
         Authorization: Bearer {code}\r\n\r\n0\r\n\r\n"
    );
    let cases: [(&str, PeerId, Vec<u8>); 8] = [
        ("a GET", DEVICE, get.into_bytes()),
        ("a chunked body", DEVICE, chunked.into_bytes()),
        (
            "a body over 4 KiB",
            DEVICE,
            post(Some(&code), &[b'a'; 4097]),
        ),
        ("a key the listener holds", DEVICE, post(Some(KEY), b"")),
        (
            "an endpoint a pinned token names",
            pinned,
            post(Some(&code), b""),
        ),
        (
            "a body that is not UTF-8",
            DEVICE,
            post(Some(&code), &[0xff, 0xfe]),
        ),
        ("no bearer", DEVICE, post(None, b"")),
        ("a wrong code", STRANGER, post(Some(wrong), b"")),
    ];
    for (what, from, request) in cases {
        let (result, seen) = answered(&credential, from, &request).await;
        assert_eq!(result, Outcome::Unauthorized, "{what}");
        assert_eq!(seen, refusal::pairing_refused(), "{what}");
    }
    assert_eq!(
        outcome.borrow().clone(),
        None,
        "and the invite is still live"
    );
    let (result, _) = answered(&credential, DEVICE, &post(Some(&code), b"")).await;
    assert_eq!(result, Outcome::Paired, "for the device it was meant for");
}

/// A key the listener holds is refused before any `100 Continue`, so a device
/// that has paired is never asked for a body.
#[tokio::test]
async fn a_held_key_asking_to_continue_is_refused_without_one() {
    let (credential, _code, _outcome) = inviting(3);
    let request = format!(
        "POST /modelpipe/pair HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\
         Expect: 100-continue\r\nAuthorization: Bearer {KEY}\r\n\r\n"
    );
    let (result, seen) = answered(&credential, DEVICE, request.as_bytes()).await;

    assert_eq!(result, Outcome::Unauthorized);
    assert_eq!(
        seen,
        refusal::pairing_refused(),
        "the refusal, and no 100 Continue before it"
    );
}

/// A pairing request whose body never arrives is refused when the deadline its
/// head was read under passes, rather than held open.
#[tokio::test(start_paused = true)]
async fn a_body_that_never_arrives_is_refused_at_the_deadline() {
    let (credential, code, _outcome) = inviting(3);
    let request = format!(
        "POST /modelpipe/pair HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\
         Authorization: Bearer {code}\r\n\r\n"
    );
    let (head, consumed) = http_head::parse_request(request.as_bytes())
        .expect("a head")
        .expect("a whole head");
    let request_framing = framing::framing(&head.headers, false).expect("framed");
    let (mut client, mut edge) = duplex(64 * 1024);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

    let outcome = tokio::time::timeout(
        Duration::from_secs(31),
        answer(
            &mut edge,
            &head,
            request.as_bytes()[consumed..].to_vec(),
            request_framing,
            &credential,
            &Caller::new(DEVICE, SERVING),
            deadline,
        ),
    )
    .await
    .expect("answered by the deadline")
    .expect("no transport failure");
    drop(edge);
    let mut seen = Vec::new();
    client.read_to_end(&mut seen).await.expect("read");

    assert_eq!(outcome, Outcome::Unauthorized);
    assert_eq!(seen, refusal::pairing_refused());
}

#[tokio::test]
async fn a_key_the_listener_holds_counts_no_strike() {
    let (credential, code, _outcome) = inviting(1);
    for _ in 0..5 {
        let (result, _) = answered(&credential, DEVICE, &post(Some(KEY), b"")).await;
        assert_eq!(result, Outcome::Unauthorized);
    }
    let (result, _) = answered(&credential, DEVICE, &post(Some(&code), b"")).await;
    assert_eq!(
        result,
        Outcome::Paired,
        "one wrong code was allowed, and none was spent"
    );
}

#[tokio::test]
async fn a_label_is_cleaned_before_anyone_reads_it() {
    let (credential, code, outcome) = inviting(3);
    let label = format!("  Evil\u{202e}Phone\n{}  ", "x".repeat(100));
    let (result, _) = answered(&credential, DEVICE, &post(Some(&code), label.as_bytes())).await;
    assert_eq!(result, Outcome::Paired);
    let Some(InviteOutcome::Redeemed {
        label: Some(kept), ..
    }) = outcome.borrow().clone()
    else {
        panic!("redeemed with a label");
    };
    assert!(kept.starts_with("EvilPhone"), "{kept:?}");
    assert!(
        !kept.chars().any(|c| c == '\u{202e}' || c == '\n'),
        "{kept:?}"
    );
    assert!(kept.chars().count() <= 64, "{kept:?}");
}

#[tokio::test]
async fn a_label_with_nothing_visible_is_no_label() {
    let (credential, code, outcome) = inviting(3);
    let (result, _) = answered(
        &credential,
        DEVICE,
        &post(Some(&code), " \t \u{200b} ".as_bytes()),
    )
    .await;
    assert_eq!(result, Outcome::Paired);
    assert!(matches!(
        outcome.borrow().clone(),
        Some(InviteOutcome::Redeemed { label: None, .. })
    ));
}
