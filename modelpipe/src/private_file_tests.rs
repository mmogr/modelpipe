//! Tests for [`super`] — a private file that appears whole or not at all.
//!
//! Split out via `#[path]` so `private_file.rs` stays inside the file-size
//! budget.
//!
//! Nothing here binds anything or touches a key: this module is about a
//! filesystem, and every property it owes its one caller is checkable with
//! a scratch directory.

use std::fs;

use super::*;

/// A path in a fresh temporary directory, removed when the guard drops.
///
/// The twin of `identity_tests`'s, and hand-rolled for the same reason the
/// crate takes almost no dependencies: a dozen lines over `std`, whose
/// behaviour is written down rather than configured.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        // The process id keeps two test binaries out of each other's way,
        // and the name keeps two tests in this one apart. Both matter:
        // `cargo test` runs these concurrently.
        let dir = std::env::temp_dir().join(format!("modelpipe-pf-{}-{name}", std::process::id()));
        fs::create_dir_all(&dir).expect("a scratch directory");
        Self(dir)
    }

    fn join(&self, file: &str) -> PathBuf {
        self.0.join(file)
    }

    /// Everything in the directory, sorted — the check that a temporary did
    /// not outlive the write that made it.
    fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.0)
            .expect("readable")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// ── What it writes ───────────────────────────────────────────────────────

/// The ordinary case: the bytes handed in are the bytes on disk.
#[test]
fn a_new_file_holds_exactly_what_was_written() {
    let scratch = Scratch::new("writes");
    let path = scratch.join("secret");

    write_new(&path, "hello\n").expect("writes");

    assert_eq!(fs::read_to_string(&path).expect("readable"), "hello\n");
}

/// The temporary is an implementation detail and must not survive as one.
/// A leftover would be the next run's `create_new` failure, which is how an
/// atomic write turns into a file that can never be written again.
#[test]
fn the_temporary_does_not_outlive_the_write() {
    let scratch = Scratch::new("no-litter");
    let path = scratch.join("secret");

    write_new(&path, "hello\n").expect("writes");

    assert_eq!(
        scratch.entries(),
        vec!["secret".to_owned()],
        "only the file itself is left behind"
    );
}

/// **The race, run as a race.** Every other test here is sequential, and
/// the whole argument for linking rather than renaming is about two
/// writers arriving at once — so one test has to actually do that.
///
/// Exactly one writer wins, the loser is told the path is taken, the file
/// holds one writer's bytes whole, and no temporary is left behind. A
/// rename-based placement passes none of it: both would report success,
/// and the two callers would believe different things about what is on
/// disk.
#[test]
fn only_one_of_two_concurrent_writers_takes_the_path() {
    let scratch = Scratch::new("race");
    let path = scratch.join("secret");

    let outcomes: Vec<Result<(), std::io::Error>> = std::thread::scope(|s| {
        // The collect is the test. Chaining `.map(spawn).map(join)` lazily
        // would join the first thread before the second is spawned, which
        // is the sequential case two other tests already cover — clippy's
        // `needless_collect` cannot see that the point is the overlap.
        #[expect(clippy::needless_collect, reason = "both must be running at once")]
        let racers: Vec<_> = ["aaa\n", "bbb\n"]
            .into_iter()
            .map(|body| {
                let path = path.clone();
                s.spawn(move || write_new(&path, body))
            })
            .collect();
        racers
            .into_iter()
            .map(|r| r.join().expect("no panic"))
            .collect()
    });

    let won = outcomes.iter().filter(|r| r.is_ok()).count();
    assert_eq!(won, 1, "exactly one writer takes the path: {outcomes:?}");
    let refused = outcomes
        .iter()
        .find_map(|r| r.as_ref().err())
        .expect("one loser");
    assert_eq!(
        refused.kind(),
        std::io::ErrorKind::AlreadyExists,
        "and the loser is told the path is taken, not something else"
    );

    let landed = fs::read_to_string(&path).expect("readable");
    assert!(
        landed == "aaa\n" || landed == "bbb\n",
        "one writer's bytes, whole: {landed:?}"
    );
    assert_eq!(
        scratch.entries(),
        vec!["secret".to_owned()],
        "and neither racer left a temporary behind"
    );
}

/// A temporary name that is already taken is retried, not reported.
///
/// The distinction matters to the caller: [`write_new`] documents
/// `AlreadyExists` as meaning *`path`* is taken, so a collision on a
/// temporary — the remains of a dead process that held this pid — must
/// not surface as that kind and send the caller down the wrong branch.
///
/// `temp_beside` is a pure function of the path and the attempt, so the
/// name attempt 0 will reach for can be occupied here exactly. Delete the
/// retry and this test fails rather than passing on a name that never
/// collided.
#[test]
fn a_taken_temporary_name_is_stepped_over() {
    let scratch = Scratch::new("stale-temp");
    let path = scratch.join("secret");
    let first = temp_beside(&path, 0);
    fs::write(&first, "remains of a dead run").expect("write");

    write_new(&path, "hello\n").expect("a taken temporary is stepped over");

    assert_eq!(fs::read_to_string(&path).expect("readable"), "hello\n");
    assert_eq!(
        fs::read_to_string(&first).expect("untouched"),
        "remains of a dead run",
        "and the file in the way is neither read nor written"
    );
    assert!(
        !temp_beside(&path, 1).exists(),
        "the attempt that did succeed cleaned up after itself"
    );
}

/// Every name the retry can reach is taken, so it gives up — and not with
/// `AlreadyExists`, which this module reserves for `path` itself.
#[test]
fn exhausting_the_temporary_names_is_not_reported_as_a_taken_path() {
    let scratch = Scratch::new("exhausted");
    let path = scratch.join("secret");
    for attempt in 0..ATTEMPTS {
        fs::write(temp_beside(&path, attempt), "in the way").expect("write");
    }

    let gave_up = write_new(&path, "hello\n").expect_err("no name left");

    assert_ne!(
        gave_up.kind(),
        std::io::ErrorKind::AlreadyExists,
        "that kind would say `path` was taken, and it is not: {gave_up}"
    );
    assert!(!path.exists(), "and nothing was written");
}

// ── What it refuses ──────────────────────────────────────────────────────

/// **The property a rename would have cost.** Two listeners starting at
/// once must not both succeed: the loser has to be told the path is taken,
/// because the alternative is it serving a ticket that names a peer nobody
/// is. This is the whole reason the placement links instead of renaming.
#[test]
fn an_existing_file_is_never_replaced() {
    let scratch = Scratch::new("exclusive");
    let path = scratch.join("secret");
    write_new(&path, "first\n").expect("writes");

    let refused = write_new(&path, "second\n").expect_err("must not replace");

    assert_eq!(refused.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(
        fs::read_to_string(&path).expect("readable"),
        "first\n",
        "the first writer's content stands"
    );
}

/// A refusal must not litter either — the temporary is cleaned up on the
/// failing path too, or one lost race poisons every later write.
#[test]
fn a_refused_write_leaves_no_temporary() {
    let scratch = Scratch::new("clean-refusal");
    let path = scratch.join("secret");
    write_new(&path, "first\n").expect("writes");

    write_new(&path, "second\n").expect_err("refused");

    assert_eq!(scratch.entries(), vec!["secret".to_owned()]);
}

/// A directory that does not exist is the caller's error, reported rather
/// than created: this module is handed a path by an operator, and inventing
/// directories under it would put a secret somewhere nobody named.
#[test]
fn a_missing_directory_is_an_error_not_a_creation() {
    let scratch = Scratch::new("no-dir");
    let path = scratch.join("nested").join("secret");

    write_new(&path, "hello\n").expect_err("must not create the directory");

    assert!(!path.parent().expect("a parent").exists());
}

// ── What a failed placement says ─────────────────────────────────────────

/// A destination that is taken comes back untouched, message and all.
///
/// That kind is this module's documented signal, and a caller matching on
/// it must not also have to recognise a sentence wrapped around it.
#[test]
fn a_taken_destination_is_reported_exactly_as_the_filesystem_gave_it() {
    let original = std::io::Error::new(std::io::ErrorKind::AlreadyExists, "File exists");

    let passed = unlinkable(Path::new("/tmp/secret"), original);

    assert_eq!(passed.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(
        passed.to_string(),
        "File exists",
        "not wrapped, not renamed"
    );
}

/// The two kinds a filesystem without hard links produces get the
/// explanation, because `link(2)` returning EPERM on its own says nothing
/// about why writing a key suddenly stopped working.
#[test]
fn a_filesystem_that_cannot_link_says_so() {
    for kind in [
        std::io::ErrorKind::PermissionDenied,
        std::io::ErrorKind::Unsupported,
    ] {
        let explained = unlinkable(
            Path::new("/mnt/usb/secret"),
            std::io::Error::new(kind, "Operation not permitted"),
        );

        assert_eq!(explained.kind(), kind, "the kind a caller matches survives");
        let said = explained.to_string();
        assert!(said.contains("hard links"), "names the cause: {said}");
        assert!(said.contains("/mnt/usb/secret"), "names the file: {said}");
        assert!(
            said.contains("Operation not permitted"),
            "and keeps what the filesystem actually said: {said}"
        );
    }
}

/// Everything else is left alone. A full disk or an unwritable directory
/// explains itself, and blaming the filesystem's feature set would send
/// the reader at something there is nothing wrong with.
#[test]
fn an_ordinary_failure_is_not_blamed_on_the_filesystem() {
    for kind in [
        std::io::ErrorKind::StorageFull,
        std::io::ErrorKind::NotFound,
        std::io::ErrorKind::Interrupted,
    ] {
        let passed = unlinkable(Path::new("/tmp/secret"), std::io::Error::new(kind, "nope"));

        assert_eq!(passed.to_string(), "nope", "{kind:?} was rewritten");
    }
}

// ── Permissions ──────────────────────────────────────────────────────────

/// The file is owner-only the instant it exists. Created through a link
/// from the temporary, so this is also the assertion that the mode set at
/// creation travels with the link rather than being reset by it.
#[cfg(unix)]
#[test]
fn the_file_is_owner_only_from_the_start() {
    use std::os::unix::fs::PermissionsExt as _;

    let scratch = Scratch::new("mode");
    let path = scratch.join("secret");

    write_new(&path, "hello\n").expect("writes");

    let mode = fs::metadata(&path).expect("metadata").permissions().mode();
    assert_eq!(mode & 0o077, 0, "created owner-only: {mode:04o}");
    check_private(&path).expect("and its own check agrees");
}

/// The control for the test above: the check refuses what it should, and
/// says what to do. A guard that passed everything would make the test
/// above vacuous.
#[cfg(unix)]
#[test]
fn a_file_others_can_read_is_refused_with_a_remedy() {
    use std::os::unix::fs::PermissionsExt as _;

    let scratch = Scratch::new("exposed");
    let path = scratch.join("secret");
    write_new(&path, "hello\n").expect("writes");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");

    let refused = check_private(&path).expect_err("must be refused");

    assert!(
        refused.to_string().contains("chmod"),
        "it must say what to do: {refused}"
    );
}
