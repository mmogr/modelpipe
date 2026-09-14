//! Tests for the devices file.

use std::fs;
use std::path::{Path, PathBuf};

use super::{append, forget, load};

/// A fresh path for a devices file, in a directory of its own.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "modelpipe-cli-devices-{}-{name}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("a scratch directory");
    dir.join("devices")
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

fn pair(name: &str, key: &str) -> (String, String) {
    (name.to_owned(), key.to_owned())
}

#[test]
fn devices_come_back_in_the_order_they_were_added() {
    let path = scratch("order");
    assert!(
        load(&path).expect("a missing file").is_empty(),
        "a missing file names no devices"
    );
    append(&path, "dev-0a1b2c3d", "KEYONE").expect("the first");
    append(&path, "laptop", "KEYTWO").expect("the second");
    assert_eq!(
        load(&path).expect("the file"),
        vec![pair("dev-0a1b2c3d", "KEYONE"), pair("laptop", "KEYTWO")]
    );
}

/// A line the file cannot read is named by its number, and its key is not
/// repeated in the error.
#[test]
fn comments_are_skipped_and_a_malformed_line_is_named_without_its_key() {
    let path = scratch("malformed");
    write_private(&path, "# kept by hand\n\nlaptop KEYONE\n");
    assert_eq!(
        load(&path).expect("the file"),
        vec![pair("laptop", "KEYONE")]
    );

    write_private(&path, "laptop KEYONE\nphone SECRETKEY extra\n");
    let refused = format!("{:#}", load(&path).expect_err("three fields"));
    assert!(refused.contains(":2:"), "{refused}");
    assert!(
        !refused.contains("SECRETKEY"),
        "the key is in the error: {refused}"
    );
}

#[test]
fn forgetting_a_device_leaves_every_other_line() {
    let path = scratch("forget");
    write_private(&path, "# kept by hand\na KA\nb KB\nc KC\n");
    forget(&path, "b").expect("forget");
    assert_eq!(
        fs::read_to_string(&path).expect("the file"),
        "# kept by hand\na KA\nc KC\n"
    );
    forget(&path, "nobody").expect("forgetting a name the file lacks");
    assert_eq!(load(&path).expect("the file").len(), 2);
}

#[cfg(unix)]
#[test]
fn the_file_is_created_private_and_one_others_can_read_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;

    let path = scratch("modes");
    append(&path, "laptop", "KEYONE").expect("append");
    let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{mode:o}");

    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
    let refused = format!("{:#}", load(&path).expect_err("readable by others"));
    assert!(refused.contains("chmod 600"), "{refused}");
    assert!(
        append(&path, "phone", "KEYTWO").is_err(),
        "appending to it is refused too"
    );
}

/// A rewrite file an earlier run left behind, readable by others, does not
/// make the devices file readable when a device is forgotten.
#[cfg(unix)]
#[test]
fn a_stale_rewrite_file_does_not_make_the_file_readable() {
    use std::os::unix::fs::PermissionsExt as _;

    let path = scratch("stale");
    append(&path, "a", "KA").expect("append");
    append(&path, "b", "KB").expect("append");
    let mut beside = path.as_os_str().to_owned();
    beside.push(".new");
    fs::write(&beside, "stale").expect("a leftover");
    fs::set_permissions(&beside, fs::Permissions::from_mode(0o644)).expect("chmod");

    forget(&path, "a").expect("forget");
    let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{mode:o}");
    assert_eq!(load(&path).expect("the file"), vec![pair("b", "KB")]);
}
