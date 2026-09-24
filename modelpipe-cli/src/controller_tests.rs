//! Tests for the controller over a real listener: one code at a time, the
//! list's states, and what forgetting does to the listener and the record.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use modelpipe::{ConnectOptions, InviteOutcome, ServeOptions, TokenPolicy};

use super::{Controller, ago, clock};
use crate::store;

fn named() -> ServeOptions {
    let mut opts = ServeOptions::default();
    opts.auth = TokenPolicy::Named;
    opts.port_mapping = false;
    opts.discovery = false;
    opts
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "modelpipe-cli-controller-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir.join("devices.json")
}

#[tokio::test]
async fn one_code_is_on_offer_at_a_time_and_forgetting_it_withdraws_it() {
    let record = scratch("offer");
    let serving = Arc::new(
        modelpipe::serve("http://127.0.0.1:9", named())
            .await
            .expect("serve"),
    );
    let mut controller = Controller::new(Arc::clone(&serving), Some(record.clone()), None);
    assert_eq!(
        controller.list().expect("empty"),
        ["no devices yet: press i to invite one"]
    );

    let first = controller.invite().expect("a code");
    assert!(!first.again);
    assert!(first.left > Duration::from_secs(100), "{:?}", first.left);
    let again = controller.invite().expect("the same code");
    assert!(again.again);
    assert_eq!(again.pairing, first.pairing);
    assert_eq!(again.device, first.device);
    assert_eq!(controller.offered(), Some(first.device.as_str()));
    assert_eq!(serving.token_names(), vec![first.device.clone()]);
    let listed = controller.list().expect("one row");
    assert_eq!(listed.len(), 1);
    assert!(listed[0].starts_with("  1. "), "{}", listed[0]);
    assert!(listed[0].contains("code on offer"), "{}", listed[0]);

    let done = controller.forget("1").expect("forgotten by number");
    assert!(done.contains("withdrawn"), "{done}");
    assert!(serving.token_names().is_empty());
    assert!(store::load(&record).expect("the record").devices.is_empty());
    assert!(controller.left().is_none());

    for who in ["", "7", "dev-nobody"] {
        assert!(controller.forget(who).is_err(), "{who:?}");
    }
    serving.shutdown().await;
}

#[tokio::test]
async fn a_code_that_ends_is_settled_and_the_list_says_how() {
    let record = scratch("settle");
    let serving = Arc::new(
        modelpipe::serve("http://127.0.0.1:9", named())
            .await
            .expect("serve"),
    );
    let mut controller = Controller::new(Arc::clone(&serving), Some(record.clone()), None);

    // Withdrawn from outside the controller, as `remove_token` does.
    let unused = controller.invite().expect("a code");
    serving.remove_token(&unused.device);
    let outcome = tokio::time::timeout(Duration::from_secs(5), controller.ended())
        .await
        .expect("the code ends");
    assert_eq!(outcome, InviteOutcome::Withdrawn);
    let said = controller.settle(&outcome);
    assert!(said.contains("withdrawn"), "{said}");
    assert!(controller.left().is_none());
    let listed = controller.list().expect("one row");
    assert!(listed[0].contains("never joined"), "{}", listed[0]);

    // Redeemed by a device that calls itself something.
    let used = controller.invite().expect("another code");
    let mut opts = ConnectOptions::default();
    opts.port_mapping = false;
    opts.discovery = false;
    let paired = modelpipe::pair(
        &used.pairing.parse().expect("a pairing string"),
        Some("Laptop"),
        opts,
        Duration::from_secs(20),
    )
    .await
    .expect("paired");
    let outcome = tokio::time::timeout(Duration::from_secs(5), controller.ended())
        .await
        .expect("the code ends");
    assert!(
        matches!(outcome, InviteOutcome::Redeemed { .. }),
        "{outcome:?}"
    );
    let said = controller.settle(&outcome);
    assert!(said.contains("paired") && said.contains("Laptop"), "{said}");
    let listed = controller.list().expect("two rows");
    assert_eq!(listed.len(), 2);
    assert!(
        listed[1].contains("paired just now") && listed[1].contains("\"Laptop\""),
        "{}",
        listed[1]
    );
    assert!(!listed[1].contains("not admitted"), "{}", listed[1]);

    let done = controller.forget(&used.device).expect("forgotten by name");
    assert!(done.contains("no longer admitted"), "{done}");
    assert!(serving.token_names().is_empty());
    assert_eq!(store::load(&record).expect("the record").devices.len(), 1);

    paired.handle.shutdown().await;
    serving.shutdown().await;
}

#[test]
fn a_clock_and_an_age_read_as_a_person_expects() {
    assert_eq!(clock(Duration::from_secs(119)), "1:59");
    assert_eq!(clock(Duration::from_secs(5)), "0:05");
    assert_eq!(ago(100, 130), "just now");
    assert_eq!(ago(100, 100 + 5 * 60), "5 min ago");
    assert_eq!(ago(100, 100 + 3 * 3600), "3 h ago");
    assert_eq!(ago(100, 100 + 2 * 86_400), "2 d ago");
    assert_eq!(ago(200, 100), "just now");
}
