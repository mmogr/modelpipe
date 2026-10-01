//! Tests for [`super`] — the owner and mode check on a path holding keys.
//! Unix only, as the check is.

use super::*;

/// Another user's path is refused whatever its mode, the owner's private
/// one passes, and a mode others can read is still refused. The decision
/// is checked apart from the read, because no test can `chown` a file to
/// another user without root.
#[test]
fn another_users_path_is_refused_and_the_owners_private_one_is_not() {
    for mode in [0o100_600, 0o100_400, 0o040_700] {
        assert_eq!(exposure(mode, 0, 501), Some(Exposure::Owner), "{mode:o}");
        assert_eq!(exposure(mode, 501, 0), Some(Exposure::Owner), "{mode:o}");
        assert_eq!(exposure(mode, 501, 501), None, "{mode:o} is the owner's");
    }
    for mode in [0o100_644, 0o100_640, 0o040_750, 0o040_701] {
        assert_eq!(exposure(mode, 501, 501), Some(Exposure::Mode), "{mode:o}");
    }
}

/// The read compares the owner with the uid this process runs as. The
/// filesystem root, which another user owns wherever these tests do not run
/// as root, is refused for its owner, and the message names both uids.
#[test]
fn the_read_compares_the_owner_with_the_uid_this_process_runs_as() {
    use std::os::unix::fs::MetadataExt as _;

    let euid = rustix::process::geteuid().as_raw();
    let root = Path::new("/");
    let owner = std::fs::metadata(root).expect("the root").uid();
    if owner == euid {
        return; // run as the root's owner, so there is no other user to see
    }
    let refused = format!(
        "{:#}",
        refuse_unless_private(root, "keys", "700").expect_err("another user's path")
    );
    assert!(refused.contains(&format!("uid {owner}")), "{refused}");
    assert!(refused.contains(&format!("uid {euid}")), "{refused}");
    assert!(refused.contains("chown"), "{refused}");
}
