//! Files this crate writes that nobody else may read, and that a crash
//! cannot leave half-written.
//!
//! One secret lives on disk: the endpoint key in [`crate::identity`]. Two
//! properties make that safe to keep, and they pull in opposite directions,
//! which is why they are written down here rather than inline at the one
//! call site.
//!
//! **Only the owner may read it.** The mode is set at creation rather than
//! afterwards, because a file created world-readable and tightened a
//! moment later was readable for that moment, and a key that was briefly
//! readable is a key that leaked. On a platform with no mode to set the
//! file lands with whatever the directory grants, which `SECURITY.md` says
//! plainly rather than papering over.
//!
//! **A crash must not leave a file that is refused for ever.** Writing in
//! place — open, write, flush — has a window between the open and the bytes
//! reaching the disk in which a power loss leaves a file holding less than
//! was written: empty, a prefix of the bytes, or on some filesystems a run
//! of NULs. Only the empty case is recognisable afterwards — a prefix and
//! a run of NULs are indistinguishable from a corrupted key, and are
//! refused as one — and [`crate::identity`] will not replace a file that
//! exists, so recovery meant finding and deleting it by hand.
//!
//! So the bytes go to a temporary name, are flushed to the disk, and only
//! then take the real name. That makes the half-written state
//! *unreachable* rather than recoverable, which is the only fix that
//! works for all three shapes: recovering after the fact would mean
//! unlinking a path this process does not own, and that races every other
//! writer — including one that has just put a valid key there.
//!
//! **The placement links rather than renames**, and that is the whole of
//! why this is not three lines. A rename replaces whatever is there, and
//! the thing it would replace is an endpoint key: two listeners starting at
//! once would both mint, both rename, and the loser would serve a ticket
//! naming a peer nobody is. `create_new` gave that race an error instead,
//! and the atomicity must not cost it. [`fs::hard_link`] is the one POSIX
//! operation that is both atomic and refuses an existing destination, so it
//! is what puts the file in place.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// How many temporary names to try before giving up.
///
/// The names are `<file>.<pid>.<attempt>.new`, so the attempt number is
/// the only thing separating two temporaries beside one path — which is
/// what makes the retry load-bearing rather than defensive. It covers the
/// two writers that can collide: a second one in this process working on
/// the same path, and the remains of a dead process that held this pid.
const ATTEMPTS: u8 = 4;

/// Write `contents` to a new private file at `path`.
///
/// Atomic and exclusive: after this returns, `path` either holds all of
/// `contents` or does not exist, and an existing `path` is never replaced.
///
/// # Errors
///
/// [`io::ErrorKind::AlreadyExists`] means **`path` is taken**, and nothing
/// else does: a collision on the temporary is retried internally rather
/// than reported, so a caller can read that one kind as "somebody else got
/// there first" without having to wonder which file it is about. It is not
/// a condition to retry.
///
/// Anything else is the underlying filesystem error, with the temporary
/// cleaned up before it is returned.
pub(crate) fn write_new(path: &Path, contents: &str) -> Result<(), io::Error> {
    use std::io::Write as _;

    let (temp, mut file) = new_temp(path)?;
    let written = file
        .write_all(contents.as_bytes())
        // The flush to the disk the module doc describes. Without it the
        // bytes may still be in the page cache when the link below makes the
        // file reachable under its real name, and the half-written state the
        // temporary name exists to hide would be reachable after all.
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(why) = written {
        clean_up(&temp);
        return Err(why);
    }

    // Atomic, and refuses a destination that exists — see the module doc for
    // why a rename will not do. The mode travels with it: a link is another
    // name for the same inode, so the 0600 set at creation is what `path`
    // has the instant it appears.
    let placed = fs::hard_link(&temp, path).map_err(|why| unlinkable(path, why));
    // The temporary has served its purpose either way, and leaving it would
    // make the next run's `create_new` the thing that fails.
    clean_up(&temp);
    placed
}

/// A fresh temporary beside `path`, already open and already private.
///
/// Retries on a name that is taken instead of reporting it. A temporary is
/// this function's own business — the caller asked about `path` — and
/// letting its collision surface as [`io::ErrorKind::AlreadyExists`] would
/// tell a caller that `path` was claimed when it was not.
///
/// The retry is also what separates two writers in one process working on
/// the same path, since the names differ only by the attempt number, and
/// what steps over a dead process's remains under this pid. [`ATTEMPTS`]
/// names is plenty for both.
fn new_temp(path: &Path) -> Result<(PathBuf, fs::File), io::Error> {
    let mut taken = None;
    for attempt in 0..ATTEMPTS {
        let candidate = temp_beside(path, attempt);
        match create_private(&candidate) {
            Ok(file) => return Ok((candidate, file)),
            Err(why) if why.kind() == io::ErrorKind::AlreadyExists => taken = Some(why),
            Err(why) => return Err(why),
        }
    }
    // Deliberately not `AlreadyExists`: that kind is this module's way of
    // saying `path` is taken, and every name here is a temporary.
    Err(io::Error::other(format!(
        "could not make a temporary file beside {}: {ATTEMPTS} names were already taken ({})",
        path.display(),
        taken.expect("ATTEMPTS is not zero, so the loop ran at least once"),
    )))
}

/// Say what a failed link means, for the filesystems that have none.
///
/// FAT, exFAT and some network and FUSE mounts do not support hard links,
/// and there the placement fails with a bare "Operation not permitted"
/// that says nothing about why writing a key suddenly stopped working.
///
/// Only those two kinds get the explanation. A destination that is taken
/// is returned untouched, because that kind is the caller's documented
/// signal; and a disk that is full or a directory that cannot be written
/// says so for itself, so blaming the filesystem's feature set would send
/// the reader somewhere there is nothing to find.
///
/// `PermissionDenied` is broader than the case this names — Linux's
/// `protected_hardlinks`, an immutable inode and an LSM denial all land
/// here too — so the filesystem's own words are kept inside the sentence
/// rather than replaced by it, and the hint is offered as *a* cause rather
/// than asserted as *the* cause.
fn unlinkable(path: &Path, why: io::Error) -> io::Error {
    if !matches!(
        why.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
    ) {
        return why;
    }
    io::Error::new(
        why.kind(),
        format!(
            "could not put the file in place at {} ({why}) — one cause is a filesystem with no \
             hard links, such as FAT or some network mounts",
            path.display()
        ),
    )
}

/// Refuse a path that is not a regular file, before anything opens it.
///
/// Takes the path's own metadata, not its target's, so a symlink is
/// refused even when it points at a regular file, and so is anything else
/// that is not a regular file, a FIFO included. A caller runs this before
/// its read, so a FIFO at the path is refused rather than opened. An absent
/// path is the same [`io::ErrorKind::NotFound`] a read would return, so a
/// caller keeps one arm for it.
pub(crate) fn check_regular(path: &Path) -> Result<(), io::Error> {
    let kind = fs::symlink_metadata(path)?.file_type();
    if kind.is_file() {
        return Ok(());
    }
    let what = if kind.is_symlink() {
        "a symlink, and only a regular file is read: use the file it points to"
    } else {
        "not a regular file"
    };
    Err(io::Error::other(format!("{} is {what}", path.display())))
}

/// Refuse a file anyone else on this machine can read.
///
/// The check `ssh` makes on a private key, for the reason it makes it: a
/// key is only a secret while it is one, and a file that has become
/// group-readable — restored from a backup, copied with the wrong umask,
/// left in a shared directory — is a secret somebody else holds, silently,
/// for as long as the file lives.
///
/// Refusing is the safe direction and the message says what to do. Unix
/// only, because there is no mode to inspect elsewhere.
#[cfg(unix)]
pub(crate) fn check_private(path: &Path) -> Result<(), io::Error> {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = fs::metadata(path)?.permissions().mode();
    // Clippy prefers `trailing_zeros() >= 6` here, and it is the same
    // predicate. It is also unreadable: `0o077` is the group and other bits
    // written the way every chmod manual and every reader of this function
    // writes them, and a bit count is a fact about the number rather than
    // about the permission. The lint is right that the mask is verbose and
    // wrong that verbosity is the cost worth cutting.
    #[expect(clippy::verbose_bit_mask, reason = "0o077 names what it checks")]
    let private = mode & 0o077 == 0;
    if private {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "{} is readable by others (mode {:04o}) — chmod 600 it",
        path.display(),
        mode & 0o7777
    )))
}

/// The same, where there is no mode to inspect.
///
/// The signature is its unix twin's rather than its own: the caller chains
/// this into a `Result`, and a stub that returned `()` here would make the
/// call site itself `#[cfg]`-dependent — which is how the two platforms
/// stop being the same code with one function swapped.
#[expect(
    clippy::unnecessary_wraps,
    clippy::missing_const_for_fn,
    reason = "the signature belongs to the unix twin, not to this body"
)]
#[cfg(not(unix))]
pub(crate) fn check_private(_path: &Path) -> Result<(), io::Error> {
    Ok(())
}

/// The `attempt`-th temporary name beside `path`, on the same filesystem.
///
/// Beside it rather than in the system temporary directory, because
/// [`fs::hard_link`] cannot cross a filesystem boundary and a data
/// directory is routinely a different mount from `/tmp`.
///
/// A pure function of its two arguments, so the name a given attempt will
/// reach for is predictable — which is what lets a test occupy it and see
/// the retry actually happen.
fn temp_beside(path: &Path, attempt: u8) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.{attempt}.new", std::process::id()));
    path.with_file_name(name)
}

/// Remove a temporary, ignoring the failure.
///
/// Nothing depends on a temporary existing or not existing, so a failure
/// here has nobody to report to: the operation it belongs to has already
/// succeeded or already has an error worth more than this one.
fn clean_up(temp: &Path) {
    let _ = fs::remove_file(temp);
}

/// Create the file with its contents already unreadable to anyone else.
#[cfg(unix)]
fn create_private(path: &Path) -> Result<fs::File, io::Error> {
    use std::os::unix::fs::OpenOptionsExt as _;

    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// The same, on a platform with no mode to set.
///
/// The file lands with whatever the directory grants, and this crate has no
/// way to narrow it. Said plainly in `SECURITY.md` rather than papered over:
/// on Windows, choose a directory only you can read.
#[cfg(not(unix))]
fn create_private(path: &Path) -> Result<fs::File, io::Error> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

#[cfg(test)]
#[path = "private_file_tests.rs"]
mod private_file_tests;
