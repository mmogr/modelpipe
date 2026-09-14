//! Tests for [`super`]: the lines a person reads, and the devices file kept in
//! step with an invite over a real listener.

use std::time::Duration;

use modelpipe::{ConnectOptions, InviteOutcome, PairingCode, ServeOptions, TokenPolicy};

use super::{ended, hold, invite_one, parse, watch};
use crate::devices;

/// Vector 1 from `docs/ticket-format-v0.md`.
const TICKET: &str = "pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaaauhlp2na";

#[test]
fn how_an_invite_ended_is_said_and_a_label_is_escaped() {
    let peer = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        .parse()
        .expect("an endpoint id");
    let paired = ended(&InviteOutcome::Redeemed {
        device: "dev-0a1b2c3d".to_owned(),
        peer,
        label: Some("Laptop\u{1b}[2J".to_owned()),
    });
    assert!(paired.contains("dev-0a1b2c3d"), "{paired}");
    assert!(paired.contains("d75a980182b1"), "{paired}");
    assert!(
        !paired.contains('\u{1b}'),
        "the label reached the terminal raw: {paired}"
    );
    assert!(ended(&InviteOutcome::Expired).contains("--invite"));
    assert!(ended(&InviteOutcome::Burned).contains("guessing"));
}

#[test]
fn connect_takes_a_ticket_alone_or_a_pairing_string() {
    assert!(parse(TICKET).expect("a ticket").code().is_none());
    let given = parse(&format!("{TICKET}-483920")).expect("a pairing string");
    assert_eq!(given.code().map(PairingCode::as_str), Some("483920"));
    assert!(parse("pipenotaticket").is_err());
    assert!(parse(&format!("{TICKET}-4839")).is_err());
}

fn named() -> ServeOptions {
    let mut opts = ServeOptions::default();
    opts.auth = TokenPolicy::Named;
    opts.port_mapping = false;
    opts.discovery = false;
    opts
}

/// A device that pairs stays in the file, an invite withdrawn unused is taken
/// back out, and a listener started later holds the device from the file.
#[tokio::test]
async fn the_devices_file_keeps_a_paired_device_and_drops_an_unused_invite() {
    const BACKEND: &str = "http://127.0.0.1:9";
    let dir = std::env::temp_dir().join(format!("modelpipe-cli-pairing-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let file = dir.join("devices");
    let serving = modelpipe::serve(BACKEND, named()).await.expect("serve");

    let used = invite_one(&serving, Some(&file)).expect("an invite");
    let watching = tokio::spawn(watch(
        used.handle(),
        used.device().to_owned(),
        Some(file.clone()),
    ));
    let mut opts = ConnectOptions::default();
    opts.port_mapping = false;
    opts.discovery = false;
    let paired = modelpipe::pair(
        used.pairing(),
        Some("Laptop"),
        opts,
        Duration::from_secs(20),
    )
    .await
    .expect("paired");
    tokio::time::timeout(Duration::from_secs(20), watching)
        .await
        .expect("the invite ends")
        .expect("the watch task");

    let unused = invite_one(&serving, Some(&file)).expect("a second invite");
    let watching = tokio::spawn(watch(
        unused.handle(),
        unused.device().to_owned(),
        Some(file.clone()),
    ));
    unused.handle().withdraw();
    tokio::time::timeout(Duration::from_secs(20), watching)
        .await
        .expect("the invite ends")
        .expect("the watch task");

    let kept = devices::load(&file);
    paired.handle.shutdown().await;
    serving.shutdown().await;
    let restarted = modelpipe::serve(BACKEND, named())
        .await
        .expect("serve again");
    let held = hold(&restarted, &file);
    let names = restarted.token_names();
    restarted.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        kept.expect("the devices file"),
        vec![(used.device().to_owned(), paired.api_key.clone())]
    );
    assert_eq!(held.expect("held from the file"), 1);
    assert_eq!(names, vec![used.device().to_owned()]);
}
