//! Tests for the devices record: what a row keeps, what the older file
//! becomes, and that a key never reaches an error or a log line.

use std::fs;
use std::path::{Path, PathBuf};

use super::{Device, load, now, save, update, upsert};

/// A fresh path for a record, in a directory of its own.
fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("modelpipe-cli-store-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("a scratch directory");
    dir.join("devices.json")
}

/// Write `text` as the file, readable only by its owner.
fn write_private(path: &Path, text: &str) {
    fs::write(path, text).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod");
    }
}

fn invited(name: &str, key: &str) -> Device {
    Device {
        name: name.to_owned(),
        key: key.to_owned(),
        label: None,
        invited_at: 1_700_000_000,
        redeemed_at: None,
        peer: None,
    }
}

#[test]
fn rows_round_trip_in_order_and_a_missing_file_names_none() {
    let path = scratch("roundtrip");
    let loaded = load(&path).expect("a missing file");
    assert!(loaded.devices.is_empty() && !loaded.legacy);

    upsert(&path, invited("dev-0a1b2c3d", "KEYONE")).expect("the first");
    upsert(&path, invited("dev-9f8e7d6c", "KEYTWO")).expect("the second");
    assert!(
        update(&path, "dev-0a1b2c3d", |row| {
            row.redeemed_at = Some(1_700_000_060);
            row.peer = Some("d75a980182b1".to_owned());
            row.label = Some("Laptop".to_owned());
        })
        .expect("update")
    );
    assert!(!update(&path, "nobody", |_| {}).expect("a name the record lacks"));

    let loaded = load(&path).expect("the record");
    assert!(!loaded.legacy);
    let names: Vec<&str> = loaded.devices.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(names, ["dev-0a1b2c3d", "dev-9f8e7d6c"]);
    assert!(loaded.devices[0].paired());
    assert_eq!(loaded.devices[0].label.as_deref(), Some("Laptop"));
    assert_eq!(loaded.devices[0].peer.as_deref(), Some("d75a980182b1"));
    assert!(!loaded.devices[1].paired());

    // Replacing a row by name keeps its place.
    upsert(&path, invited("dev-0a1b2c3d", "KEYTHREE")).expect("replace");
    let loaded = load(&path).expect("the record");
    assert_eq!(loaded.devices[0].key, "KEYTHREE");
    assert!(!loaded.devices[0].paired());
    assert_eq!(loaded.devices.len(), 2);
}

/// The file an earlier serve kept — a name, a space, a key — reads as rows
/// that paired when the file was written, since that form kept no row for
/// an invite nobody redeemed. Saving writes JSON.
#[test]
fn the_older_line_form_is_read_as_paired_rows_and_written_back_as_json() {
    let path = scratch("legacy");
    write_private(
        &path,
        "# kept by hand\n\ndev-0a1b2c3d KEYONE\nlaptop KEYTWO\n",
    );
    let loaded = load(&path).expect("the older form");
    assert!(loaded.legacy);
    assert_eq!(loaded.devices.len(), 2);
    assert!(loaded.devices.iter().all(Device::paired));
    assert_eq!(loaded.devices[1].name, "laptop");
    assert_eq!(loaded.devices[1].key, "KEYTWO");

    save(&path, &loaded.devices).expect("save");
    let text = fs::read_to_string(&path).expect("the file");
    assert!(text.starts_with('{'), "{text}");
    assert!(text.contains("\"version\": 1"), "{text}");
    let again = load(&path).expect("as JSON");
    assert!(!again.legacy);
    assert_eq!(again.devices, loaded.devices);
}

/// A malformed line in the older form is named by its number, and a file
/// from a later format is refused; neither error repeats a key.
#[test]
fn a_file_this_cannot_read_is_refused_without_its_keys() {
    let path = scratch("malformed");
    write_private(&path, "laptop KEYONE\nphone SECRETKEY extra\n");
    let refused = format!("{:#}", load(&path).expect_err("three fields"));
    assert!(refused.contains(":2:"), "{refused}");
    assert!(!refused.contains("SECRETKEY"), "{refused}");

    write_private(
        &path,
        "{\"version\": 2, \"devices\": [{\"name\": \"a\", \"key\": \"SECRETKEY\", \"invited_at\": 1}]}",
    );
    let refused = format!("{:#}", load(&path).expect_err("a newer format"));
    assert!(refused.contains("newer"), "{refused}");
    assert!(!refused.contains("SECRETKEY"), "{refused}");

    write_private(
        &path,
        "{\"version\": 1, \"devices\": [{\"key\": \"SECRETKEY\"}]}",
    );
    let refused = format!("{:#}", load(&path).expect_err("a row with no name"));
    assert!(!refused.contains("SECRETKEY"), "{refused}");
}

#[test]
fn debug_output_never_holds_the_key() {
    let shown = format!("{:?}", invited("dev-0a1b2c3d", "SECRETKEY"));
    assert!(shown.contains("dev-0a1b2c3d"), "{shown}");
    assert!(!shown.contains("SECRETKEY"), "{shown}");
}

#[cfg(unix)]
#[test]
fn the_file_is_written_private_and_one_others_can_read_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    let path = scratch("modes");
    upsert(&path, invited("laptop", "KEYONE")).expect("upsert");
    let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{mode:o}");

    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
    let refused = format!("{:#}", load(&path).expect_err("readable by others"));
    assert!(refused.contains("chmod 600"), "{refused}");
    assert!(upsert(&path, invited("phone", "KEYTWO")).is_err());
}

#[test]
fn now_is_after_the_day_this_was_written() {
    assert!(now() > 1_700_000_000);
}
