//! Tests for [`super`]: the request a device sends, how it reads the answer,
//! and the messages [`PairError`] prints. `tests/integration_pair.rs` pairs over a real pipe.

use super::*;

const SERVING_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

fn serving() -> PeerId {
    SERVING_HEX.parse().expect("hex")
}

fn answer(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[test]
fn a_pairing_answer_hands_back_the_key_and_the_device() {
    let body =
        format!(r#"{{"api_key":"KEYBASE32","device_id":"dev-0a1b2c3d","peer":"{SERVING_HEX}"}}"#);
    let (key, device) = redeemed(&answer("200 OK", &body), serving()).expect("a pairing answer");
    assert_eq!(key, "KEYBASE32");
    assert_eq!(device, "dev-0a1b2c3d");
}

#[test]
fn a_refusal_is_refused_and_a_dropped_pipe_is_a_lost_exchange() {
    assert!(matches!(
        redeemed(&answer("401 Unauthorized", "{}"), serving()),
        Err(PairError::Refused)
    ));
    let dropped = redeemed(&answer("502 Bad Gateway", "{}"), serving()).unwrap_err();
    assert!(matches!(dropped, PairError::Exchange(_)), "{dropped:?}");
    assert!(dropped.is_retryable());
    assert!(!PairError::Refused.is_retryable());
}

#[test]
fn an_answer_that_is_not_a_pairing_answer_is_unexpected() {
    let elsewhere = "0".repeat(64);
    let cases = [
        answer("200 OK", r#"{"api_key":"K","device_id":"d"}"#),
        answer(
            "200 OK",
            &format!(r#"{{"api_key":"K","device_id":"d","peer":"{elsewhere}"}}"#),
        ),
        answer(
            "200 OK",
            &format!(r#"{{"api_key":"K\"x","device_id":"d","peer":"{SERVING_HEX}"}}"#),
        ),
        answer(
            "200 OK",
            &format!(r#"{{"api_key":"","device_id":"d","peer":"{SERVING_HEX}"}}"#),
        ),
        answer(
            "200 OK",
            &format!(
                "{{\"api_key\":\"K\u{1b}[2J\",\"device_id\":\"d\",\"peer\":\"{SERVING_HEX}\"}}"
            ),
        ),
        answer(
            "200 OK",
            &format!("{{\"api_key\":\"K\",\"device_id\":\"d\u{7}\",\"peer\":\"{SERVING_HEX}\"}}"),
        ),
        b"not http at all\r\n\r\n".to_vec(),
    ];
    for case in cases {
        let got = redeemed(&case, serving());
        assert!(
            matches!(got, Err(PairError::Unexpected(_))),
            "{:?} gave {got:?}",
            String::from_utf8_lossy(&case)
        );
    }
}

/// A status this exchange does not define is carried as a number.
///
/// `404` is the one that matters: it is what a serve side too old to know
/// [`PAIR_PATH`](crate::PAIR_PATH) answers, and the remedy is to update
/// that machine rather than to check the code. It used to arrive as
/// `Unexpected("a status other than 200 or 401")`, and both embedders
/// matched that sentence to tell the two apart.
#[test]
fn a_status_this_exchange_does_not_define_is_carried_as_a_number() {
    for (status, expected) in [
        ("404 Not Found", 404),
        ("500 Internal", 500),
        ("204 No", 204),
    ] {
        let got = redeemed(&answer(status, "{}"), serving());
        assert!(
            matches!(got, Err(PairError::UnexpectedStatus { status: s }) if s == expected),
            "{status} gave {got:?}"
        );
    }
}

/// The three statuses this exchange *does* define keep their own answers,
/// so the variant above cannot quietly swallow a refusal or a lost pipe.
#[test]
fn the_defined_statuses_are_not_reported_as_an_unexpected_status() {
    assert!(matches!(
        redeemed(&answer("401 Unauthorized", "{}"), serving()),
        Err(PairError::Refused)
    ));
    assert!(matches!(
        redeemed(&answer("502 Bad Gateway", "{}"), serving()),
        Err(PairError::Exchange(_))
    ));
    // 200 reaches the body checks rather than any status refusal.
    assert!(matches!(
        redeemed(&answer("200 OK", "{}"), serving()),
        Err(PairError::Unexpected(_))
    ));
}

/// The status rides in the sentence a person reads, and — for 404 alone —
/// so does the remedy. Nothing else in this crate will say it for them:
/// `Display` here is the whole message, since the variant carries no
/// source.
///
/// **The remedy is not offered for the other statuses**, which is the
/// half worth pinning. This arm catches a 503 from a proxy in front of a
/// perfectly current serve side just as readily as a 404 from an old one,
/// and telling that operator to update the other machine sends them at
/// something that is not wrong.
#[test]
fn only_a_404_is_told_to_update_the_other_machine() {
    let old = redeemed(&answer("404 Not Found", "{}"), serving()).expect_err("refused");
    let said = old.to_string();
    assert!(said.contains("404"), "names the status: {said}");
    assert!(said.contains("update"), "names the remedy: {said}");
    assert!(
        !old.is_retryable(),
        "an old serve side is not a wait-and-retry"
    );
    assert!(std::error::Error::source(&old).is_none());

    for status in ["500 Internal", "503 Unavailable", "504 Timeout"] {
        let other = redeemed(&answer(status, "{}"), serving()).expect_err("refused");
        let said = other.to_string();
        assert!(
            said.contains(&status[..3]),
            "still names the status: {said}"
        );
        assert!(
            !said.contains("update"),
            "{status} must not be blamed on an old serve side: {said}"
        );
    }
}

/// An answer the pipe cut short, before its head ended or inside its body, is
/// a lost exchange, which may have spent the code, and not an answer the edge
/// gave.
#[test]
fn an_answer_cut_short_is_a_lost_exchange() {
    let body =
        format!(r#"{{"api_key":"KEYBASE32","device_id":"dev-0a1b2c3d","peer":"{SERVING_HEX}"}}"#);
    let whole = answer("200 OK", &body);
    let head_end = whole
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a head")
        + 4;
    for cut in [0, head_end - 3, head_end + 5] {
        let got = redeemed(&whole[..cut], serving());
        assert!(
            matches!(got, Err(PairError::Exchange(_))),
            "cut at {cut}: {got:?}"
        );
    }
    assert!(
        redeemed(&whole, serving()).is_ok(),
        "and the whole answer pairs"
    );
}

#[test]
fn the_request_carries_the_code_and_cuts_a_long_label_at_a_character_boundary() {
    // Three bytes a character, so the cut at 4096 bytes falls inside one.
    let long = "\u{20ac}".repeat(2000);
    let request = String::from_utf8(redeem_request(
        "127.0.0.1:8080".parse().expect("an address"),
        "483920",
        &long,
    ))
    .expect("utf-8");
    assert!(
        request.starts_with("POST /modelpipe/pair HTTP/1.1\r\n"),
        "{request}"
    );
    assert!(request.contains("\r\nAuthorization: Bearer 483920\r\n"));
    let body = request.split("\r\n\r\n").nth(1).expect("a body");
    assert!(
        body.len() <= MAX_LABEL_BYTES && body.len() + 3 > MAX_LABEL_BYTES,
        "{}",
        body.len()
    );
    assert!(request.contains(&format!("\r\nContent-Length: {}\r\n", body.len())));
}

#[test]
fn a_wildcard_bind_is_dialled_on_loopback() {
    assert_eq!(
        dialable("0.0.0.0:8080".parse().expect("v4")),
        "127.0.0.1:8080".parse().expect("v4")
    );
    assert_eq!(
        dialable("[::]:8080".parse().expect("v6")),
        "[::1]:8080".parse().expect("v6")
    );
    assert_eq!(
        dialable("192.168.1.5:8080".parse().expect("v4")),
        "192.168.1.5:8080".parse().expect("v4")
    );
}

#[test]
fn the_messages_say_what_to_do() {
    assert!(PairError::NoCode.to_string().contains("invite"));
    assert!(PairError::Refused.to_string().contains("new one"));
}
