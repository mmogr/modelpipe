//! Tests for the devices file's handling on disk: the older line form, and
//! a replacement that lands whole and private.

use std::fs;
use std::path::{Path, PathBuf};

use super::{parse_lines, read, replace};

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

fn pair(name: &str, key: &str) -> (String, String) {
    (name.to_owned(), key.to_owned())
}

/// Comments and blank lines are skipped, order is kept, and a line the file
/// cannot read is named by its number without its key.
#[test]
fn lines_are_read_in_order_and_a_malformed_line_is_named_without_its_key() {
    let path = Path::new("devices");
    assert_eq!(
        parse_lines(
            path,
            "# kept by hand\n\ndev-0a1b2c3d KEYONE\nlaptop KEYTWO\n"
        )
        .expect("lines"),
        vec![pair("dev-0a1b2c3d", "KEYONE"), pair("laptop", "KEYTWO")]
    );
    let refused = format!(
        "{:#}",
        parse_lines(path, "laptop KEYONE\nphone SECRETKEY extra\n").expect_err("three fields")
    );
    assert!(refused.contains("devices:2:"), "{refused}");
    assert!(!refused.contains("SECRETKEY"), "{refused}");
}

#[test]
fn a_missing_file_reads_as_none_and_a_replacement_reads_back() {
    let path = scratch("replace");
    assert!(read(&path).expect("a missing file").is_none());
    replace(&path, "one\n").expect("the first");
    replace(&path, "two\n").expect("the second");
    assert_eq!(read(&path).expect("the file").as_deref(), Some("two\n"));
}

#[cfg(unix)]
#[test]
fn the_file_is_created_private_and_one_others_can_read_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;

    let path = scratch("modes");
    replace(&path, "laptop KEYONE\n").expect("replace");
    let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{mode:o}");

    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
    let refused = format!("{:#}", read(&path).expect_err("readable by others"));
    assert!(refused.contains("chmod 600"), "{refused}");
}

/// A rewrite file an earlier run left behind, readable by others, does not
/// make the devices file readable when it is replaced.
#[cfg(unix)]
#[test]
fn a_stale_rewrite_file_does_not_make_the_file_readable() {
    use std::os::unix::fs::PermissionsExt as _;

    let path = scratch("stale");
    replace(&path, "a KA\n").expect("replace");
    let mut beside = path.as_os_str().to_owned();
    beside.push(".new");
    fs::write(&beside, "stale").expect("a leftover");
    fs::set_permissions(&beside, fs::Permissions::from_mode(0o644)).expect("chmod");

    replace(&path, "b KB\n").expect("replace again");
    let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{mode:o}");
    assert_eq!(read(&path).expect("the file").as_deref(), Some("b KB\n"));
}
