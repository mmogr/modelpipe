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

/// Run `f` on a thread and wait at most `bound` for it, so a call that
/// blocks on the path fails the test instead of hanging the suite.
#[cfg(unix)]
fn within<T: Send + 'static>(
    bound: std::time::Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (sent, received) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sent.send(f());
    });
    received
        .recv_timeout(bound)
        .expect("it returned rather than blocking on the path")
}

/// A FIFO at the devices path is refused before anything opens it, so the
/// read returns instead of waiting for a writer, and the FIFO is left as
/// found.
#[cfg(unix)]
#[test]
fn a_fifo_at_the_devices_path_is_refused_without_blocking() {
    let path = scratch("fifo");
    let made = std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "mkfifo made {}", path.display());

    let probe = path.clone();
    let refused = within(std::time::Duration::from_secs(10), move || read(&probe))
        .expect_err("a FIFO is not a devices file");

    let said = format!("{refused:#}");
    assert!(said.contains("not a regular file"), "{said}");
    assert!(
        std::os::unix::fs::FileTypeExt::is_fifo(
            &fs::symlink_metadata(&path)
                .expect("still there")
                .file_type()
        ),
        "the FIFO was replaced"
    );
}

/// A symlink at the devices path is refused even when it points at a
/// devices file this module wrote and reads: the type checked is the
/// link's own.
#[cfg(unix)]
#[test]
fn a_symlink_to_a_devices_file_is_refused() {
    let real = scratch("linked");
    replace(&real, "laptop KEYONE\n").expect("replace");
    let link = real.with_file_name("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");

    let said = format!("{:#}", read(&link).expect_err("a symlink is refused"));

    assert!(said.contains("it is a symlink"), "{said}");
    assert!(!said.contains("KEYONE"), "{said}");
    assert_eq!(
        read(&real).expect("the target reads").as_deref(),
        Some("laptop KEYONE\n")
    );
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
