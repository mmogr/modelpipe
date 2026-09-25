//! Tests for [`super`]: the lines a person reads, and the devices file kept in
//! step with an invite over a real listener.

use std::sync::Arc;
use std::time::Duration;

use modelpipe::{ConnectOptions, InviteOutcome, PairingCode, ServeOptions, TokenPolicy};

use super::{ended, hold, invite_one, parse, watch};
use crate::store;

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
    assert!(ended(&InviteOutcome::Expired).contains("expired"));
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

/// A device that pairs is recorded as such, an invite withdrawn unused keeps
/// its row but loses its key at the listener, and a listener started later
/// holds the device that paired and not the one that did not.
#[tokio::test]
async fn the_devices_file_keeps_a_paired_device_and_drops_an_unused_invite() {
    const BACKEND: &str = "http://127.0.0.1:9";
    let dir = std::env::temp_dir().join(format!("modelpipe-cli-pairing-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let file = dir.join("devices.json");
    let serving = Arc::new(modelpipe::serve(BACKEND, named()).await.expect("serve"));

    let used = invite_one(&serving, Some(&file)).expect("an invite");
    let watching = tokio::spawn(watch(
        Arc::clone(&serving),
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
        Arc::clone(&serving),
        unused.handle(),
        unused.device().to_owned(),
        Some(file.clone()),
    ));
    unused.handle().withdraw();
    tokio::time::timeout(Duration::from_secs(20), watching)
        .await
        .expect("the invite ends")
        .expect("the watch task");

    let kept = store::load(&file);
    // The withdrawn invite's key is gone from the live listener, not only
    // from the file: the device that paired is the one name still held.
    let still_held = serving.token_names();
    paired.handle.shutdown().await;
    serving.shutdown().await;
    let restarted = modelpipe::serve(BACKEND, named())
        .await
        .expect("serve again");
    let held = hold(&restarted, &file);
    let names = restarted.token_names();
    restarted.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);

    let kept = kept.expect("the devices record").devices;
    assert_eq!(kept.len(), 2, "{kept:?}");
    assert_eq!(kept[0].name, used.device());
    assert_eq!(kept[0].key, paired.api_key);
    assert!(kept[0].paired(), "{:?}", kept[0]);
    assert_eq!(kept[0].label.as_deref(), Some("Laptop"));
    let peer = kept[0]
        .peer
        .as_deref()
        .expect("the endpoint that redeemed it");
    assert!(
        peer.len() == 64 && peer.bytes().all(|b| b.is_ascii_hexdigit()),
        "{peer}"
    );
    assert_eq!(kept[1].name, unused.device());
    assert!(!kept[1].paired(), "{:?}", kept[1]);
    assert_eq!(still_held, vec![used.device().to_owned()]);
    assert_eq!(held.expect("held from the file"), 1);
    assert_eq!(names, vec![used.device().to_owned()]);
}

/// A devices record that cannot be written refuses the invite, and the key
/// the library held for it goes with it, so the listener holds no name at
/// all.
#[tokio::test]
async fn an_invite_whose_devices_record_cannot_be_written_leaves_no_key_held() {
    let dir = std::env::temp_dir().join(format!("modelpipe-cli-unwritable-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    // A regular file where the record's directory would be.
    let blocker = dir.join("blocker");
    std::fs::write(&blocker, "not a directory").expect("the blocking file");
    let serving = modelpipe::serve("http://127.0.0.1:9", named())
        .await
        .expect("serve");

    let invited = invite_one(&serving, Some(&blocker.join("devices.json")));
    let held = serving.token_names();
    serving.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);

    invited.expect_err("an invite with no row is refused");
    assert_eq!(held, Vec::<String>::new());
}
