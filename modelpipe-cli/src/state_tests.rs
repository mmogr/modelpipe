//! Tests for the state folder: where it goes, what a backend's folder is
//! called, and that one serve at a time holds it.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

use super::{StateDir, backend_key, data_dir_from};

/// A fresh root for state folders, in a directory of its own.
fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("modelpipe-cli-state-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
    let map: HashMap<String, OsString> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), OsString::from(v)))
        .collect();
    move |name| map.get(name).cloned()
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn the_data_dir_follows_xdg_and_ignores_a_relative_value() {
    assert_eq!(
        data_dir_from(env(&[("HOME", "/home/matt")])).expect("a default"),
        PathBuf::from("/home/matt/.local/share/modelpipe")
    );
    assert_eq!(
        data_dir_from(env(&[("HOME", "/home/matt"), ("XDG_DATA_HOME", "/data")]))
            .expect("an absolute XDG_DATA_HOME"),
        PathBuf::from("/data/modelpipe")
    );
    assert_eq!(
        data_dir_from(env(&[("HOME", "/home/matt"), ("XDG_DATA_HOME", "data")]))
            .expect("a relative one is ignored"),
        PathBuf::from("/home/matt/.local/share/modelpipe")
    );
}

#[cfg(target_os = "macos")]
#[test]
fn the_data_dir_is_under_application_support() {
    assert_eq!(
        data_dir_from(env(&[("HOME", "/Users/matt")])).expect("a default"),
        PathBuf::from("/Users/matt/Library/Application Support/modelpipe")
    );
}

/// Relative to the working directory is the one place an identity file
/// must never land, so no `HOME` is an error and not a fallback.
#[test]
fn no_home_is_refused_with_the_flags_that_avoid_it() {
    for pairs in [&[][..], &[("HOME", "")][..]] {
        let refused = format!("{:#}", data_dir_from(env(pairs)).expect_err("no HOME"));
        assert!(refused.contains("--state-dir"), "{refused}");
        assert!(refused.contains("--no-state"), "{refused}");
    }
}

#[test]
fn a_backend_is_named_by_its_host_and_port_and_nothing_else() {
    assert_eq!(backend_key("http://127.0.0.1:11434"), "127.0.0.1_11434");
    assert_eq!(backend_key("HTTP://LocalHost:8080/v1/"), "localhost_8080");
    assert_eq!(backend_key("http://localhost"), "localhost_80");
    assert_eq!(backend_key("https://localhost"), "localhost_443");
    assert_eq!(
        backend_key("http://user:pass@127.0.0.1:11434?x=1#y"),
        "127.0.0.1_11434"
    );
    assert_eq!(backend_key("http://[::1]:11434"), "___1__11434");
    assert_eq!(backend_key("http://[::1]"), "___1__80");
    assert_eq!(backend_key("127.0.0.1:9"), "127.0.0.1_9");
}

/// The folder is made for its owner alone, the paths in it are where the
/// two files go, and a second serve on the same backend is told who has it.
#[test]
fn one_serve_at_a_time_holds_a_backend_folder() {
    let root = scratch("lock");
    let held = StateDir::open(&root, "127.0.0.1_11434").expect("the first");
    assert_eq!(held.path(), root.join("127.0.0.1_11434"));
    assert_eq!(held.identity(), held.path().join("identity"));
    assert_eq!(held.devices(), held.path().join("devices.json"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for dir in [&root, held.path()] {
            let mode = fs::metadata(dir).expect("made").permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", dir.display());
        }
        for file in ["lock", "pid"] {
            let mode = fs::metadata(held.path().join(file))
                .expect(file)
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{file}");
        }
    }

    let refused = format!(
        "{:#}",
        StateDir::open(&root, "127.0.0.1_11434").expect_err("a second on the same backend")
    );
    assert!(refused.contains("another modelpipe serve"), "{refused}");
    assert!(
        refused.contains(&format!("pid {}", std::process::id())),
        "{refused}"
    );
    assert!(refused.contains("--state-dir"), "{refused}");

    // A different backend is a different folder, and free.
    let other = StateDir::open(&root, "127.0.0.1_8080").expect("another backend");
    drop(other);
    drop(held);
    StateDir::open(&root, "127.0.0.1_11434").expect("released with the first");
    let _ = fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn a_folder_other_users_can_read_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = scratch("shared");
    let dir = root.join("127.0.0.1_11434");
    fs::create_dir_all(&dir).expect("a folder");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).expect("chmod");
    let refused = format!(
        "{:#}",
        StateDir::open(&root, "127.0.0.1_11434").expect_err("group can read")
    );
    assert!(refused.contains("chmod 700"), "{refused}");
    let _ = fs::remove_dir_all(&root);
}
