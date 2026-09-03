//! Tests for [`super`] — the stored endpoint key, and who may read it.
//!
//! Split out via `#[path]` so `identity.rs` stays inside the file-size
//! budget.
//!
//! No endpoint is bound anywhere here, which is the point of the module
//! handing back bare bytes: the whole of the format, the permissions and
//! the refusals is checkable without a socket, and only
//! `transport::bind` has to know these thirty-two bytes are a key.

use std::fs;

use super::*;

/// A path in a fresh temporary directory, removed when the guard drops.
///
/// Hand-rolled rather than reaching for `tempfile`, for the reason the
/// crate takes almost no dependencies: this is a dozen lines over `std`,
/// and a fixture whose behaviour is written down is easier to reason about
/// than one whose behaviour is configured.
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        // The process id keeps two test binaries out of each other's way,
        // and the name keeps two tests in this one apart. Both matter:
        // `cargo test` runs these concurrently.
        let dir = std::env::temp_dir().join(format!("modelpipe-{}-{name}", std::process::id()));
        fs::create_dir_all(&dir).expect("a scratch directory");
        Self(dir)
    }

    fn join(&self, file: &str) -> std::path::PathBuf {
        self.0.join(file)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// ── Minting and reading back ─────────────────────────────────────────────

/// The whole point, in one assertion: the second run gets the first run's
/// key. Everything about a durable ticket rests on this and nothing else —
/// the public half of these bytes *is* the address a ticket carries.
#[test]
fn a_stored_identity_is_the_same_identity_next_time() {
    let scratch = Scratch::new("same");
    let path = scratch.join("key");

    let first = load_or_mint(&path).expect("a first run mints one");
    let second = load_or_mint(&path).expect("a second run reads it back");

    assert_eq!(first, second, "a restart must not change the identity");
}

/// The control for the test above, and the reason it is not vacuous: two
/// *different* files are two different identities. Without this, a
/// `load_or_mint` that returned a constant would pass.
#[test]
fn two_identity_files_are_two_identities() {
    let scratch = Scratch::new("distinct");

    let one = load_or_mint(&scratch.join("one")).expect("mints");
    let two = load_or_mint(&scratch.join("two")).expect("mints");

    assert_ne!(one, two, "each file gets its own key");
}

/// The file is written in the form the module documents, and that form
/// round-trips. A key that could be written and not read back would be a
/// listener that works once.
#[test]
fn the_stored_form_is_lowercase_base32_on_one_line() {
    let scratch = Scratch::new("form");
    let path = scratch.join("key");
    let minted = load_or_mint(&path).expect("mints");

    let written = fs::read_to_string(&path).expect("readable");
    assert!(written.ends_with('\n'), "one line: {written:?}");
    let body = written.trim();
    assert_eq!(body, body.to_ascii_lowercase(), "lowercase: {body:?}");
    assert_eq!(
        base32::decode(&body.to_ascii_uppercase()).as_deref(),
        Some(&minted[..]),
        "and it decodes to the key that was handed back"
    );
}

// ── What it refuses ──────────────────────────────────────────────────────

/// A file that is not base32 at all is refused rather than hashed,
/// truncated or otherwise coerced into a key. Silently deriving one would
/// mean a typo in a config-management template becomes a working listener
/// with an identity nobody intended and no ticket matches.
#[test]
fn a_file_that_is_not_base32_is_refused() {
    let scratch = Scratch::new("garbage");
    let path = scratch.join("key");
    fs::write(&path, "not a key!!!\n").expect("write");

    let refused = load_or_mint(&path).expect_err("must not be accepted");
    assert!(
        matches!(refused, ServeError::Identity { .. }),
        "got: {refused:?}"
    );
    assert!(!refused.is_retryable(), "the operator named this path");
}

/// Valid base32 of the wrong length is the more dangerous shape — it
/// decodes, so only the length check stands between it and a key padded or
/// truncated into something that is not what the file says.
#[test]
fn a_file_of_the_wrong_length_is_refused() {
    let scratch = Scratch::new("short");
    let path = scratch.join("key");
    fs::write(
        &path,
        format!("{}\n", base32::encode(b"too short")).to_lowercase(),
    )
    .expect("write");

    assert!(
        matches!(load_or_mint(&path), Err(ServeError::Identity { .. })),
        "a key is exactly {KEY_BYTES} bytes"
    );
}

/// A key others can read is not a secret, and a listener that starts on one
/// is minting tickets anybody on the machine can mint too. The same refusal
/// `ssh` makes, and the message says what to do about it.
#[cfg(unix)]
#[test]
fn an_identity_others_can_read_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;

    let scratch = Scratch::new("exposed");
    let path = scratch.join("key");
    load_or_mint(&path).expect("mints");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");

    let refused = load_or_mint(&path).expect_err("a readable key must be refused");
    let explained = format!("{}", std::error::Error::source(&refused).expect("a cause"));
    assert!(
        explained.contains("chmod"),
        "and it must say what to do: {explained}"
    );
}

/// The control for the test above: the file this module *writes* passes its
/// own check. A guard that refused everything would pass the refusal test
/// and make the flag unusable.
#[cfg(unix)]
#[test]
fn the_identity_this_module_writes_is_one_it_will_read() {
    use std::os::unix::fs::PermissionsExt as _;

    let scratch = Scratch::new("owner-only");
    let path = scratch.join("key");
    load_or_mint(&path).expect("mints");

    let mode = fs::metadata(&path).expect("metadata").permissions().mode();
    assert_eq!(mode & 0o077, 0, "created owner-only: {mode:04o}");
    load_or_mint(&path).expect("and read back without complaint");
}
