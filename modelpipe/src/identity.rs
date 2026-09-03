//! The key that decides whether a ticket outlives the process.
//!
//! An endpoint's secret key is its name on the network: its public half is
//! what a ticket carries, and what a connecting peer dials. Generated fresh
//! per process — the default, and what every version before this one did —
//! it makes every ticket disposable. Restart the listener and every ticket
//! ever handed out names a peer nobody is, which is the ticket rotation the
//! README sells, and also the reason a laptop has to be re-paired every time
//! a desktop reboots.
//!
//! Storing the key swaps one of those for the other, and it is worth being
//! exact about which. It does **not** weaken revocation: a leaked ticket is
//! killed by deleting this file and restarting, which costs precisely what
//! restarting cost before — a re-pairing of every device. What it removes is
//! revocation *by accident*, which is what a reboot used to be. What it adds
//! is a secret on disk, and that is the real cost: there was nothing to
//! steal before and now there is.
//!
//! Pure of iroh, deliberately. This hands back thirty-two bytes and
//! [`crate::transport`] is where they become a key, so the whole of the
//! file handling — the format, the permissions, the refusals — is
//! exercisable without binding an endpoint.

use std::fs;
use std::io;
use std::path::Path;

use crate::ServeError;
use crate::base32;

/// Bytes in an endpoint's secret key. Fixed by the curve, not by us.
pub(crate) const KEY_BYTES: usize = 32;

/// Read the key stored at `path`, minting and storing one if there is none.
///
/// The mint-on-absence is what makes the flag usable as a single step: a
/// first run creates the file, and every run after it reads the same key
/// back and mints the same ticket. Requiring the operator to generate one
/// first would be a second command whose only job is to make this one work.
///
/// # Errors
///
/// [`ServeError::Identity`] for a file that exists and is not a key this
/// can use, or one it cannot read or write. All of them are permanent: the
/// path came from the operator, and retrying it fails the same way.
pub(crate) fn load_or_mint(path: &Path) -> Result<[u8; KEY_BYTES], ServeError> {
    match fs::read_to_string(path) {
        Ok(stored) => check_private(path)
            .and_then(|()| parse(&stored))
            .map_err(|why| unusable(path, why)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let minted = mint();
            store(path, minted).map_err(|why| unusable(path, why))?;
            Ok(minted)
        }
        Err(e) => Err(unusable(path, e)),
    }
}

/// The stored form: base32 of the key's bytes, one line.
///
/// Text rather than raw bytes so the file survives a copy-paste, an editor
/// and a config-management tool that assumes UTF-8 — and base32 rather than
/// hex or base64 for the reason the token uses it: no character a person can
/// confuse reading it off a screen, and nothing a shell wants to quote.
///
/// Read case-insensitively and written lower-case, matching the ticket. The
/// trailing newline is written because every editor adds one anyway, and
/// trimmed on read for the same reason `--token-file` trims it.
fn parse(stored: &str) -> Result<[u8; KEY_BYTES], io::Error> {
    let trimmed = stored.trim();
    let decoded = base32::decode(&trimmed.to_ascii_uppercase())
        .ok_or_else(|| io::Error::other("the identity file is not base32"))?;
    decoded.try_into().map_err(|_| {
        io::Error::other(format!(
            "an identity is {KEY_BYTES} bytes and this file decodes to a different length"
        ))
    })
}

/// Write `key` where only this user can read it.
fn store(path: &Path, key: [u8; KEY_BYTES]) -> Result<(), io::Error> {
    use std::io::Write as _;

    let mut file = create_private(path)?;
    writeln!(file, "{}", base32::encode(&key).to_ascii_lowercase())?;
    file.flush()
}

/// Create the file with the key already unreadable to anyone else.
///
/// `create_new`, so a race between two listeners starting at once is an
/// error rather than one of them silently overwriting the other's key —
/// which would leave the loser serving a ticket nobody holds.
///
/// The mode is set **at creation** rather than afterwards. Creating a
/// world-readable file and then tightening it leaves a window in which the
/// key is on disk and readable, and a key that was briefly readable is a key
/// that leaked.
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

/// Refuse a key anyone else on this machine can read.
///
/// The check `ssh` makes on a private key, for the reason it makes it: a
/// key is only a secret while it is one, and a file that has become
/// group-readable — restored from a backup, copied with the wrong umask,
/// left in a shared directory — is a ticket somebody else can mint at any
/// time, silently, for as long as the file lives.
///
/// Refusing is the safe direction and the message says what to do. Unix
/// only, because there is no mode to inspect elsewhere; see
/// [`create_private`].
#[cfg(unix)]
fn check_private(path: &Path) -> Result<(), io::Error> {
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
        "the identity file is readable by others (mode {:04o}) — chmod 600 it",
        mode & 0o7777
    )))
}

/// The same, where there is no mode to inspect.
#[cfg(not(unix))]
fn check_private(_path: &Path) -> Result<(), io::Error> {
    Ok(())
}

/// Thirty-two bytes from the operating system's CSPRNG.
///
/// The same source and the same reasoning as the bearer token: a CSPRNG
/// that cannot produce bytes is not a condition to paper over with a weaker
/// one, because an endpoint key anybody can guess is worse than no listener.
fn mint() -> [u8; KEY_BYTES] {
    let mut bytes = [0u8; KEY_BYTES];
    getrandom::fill(&mut bytes).expect("the OS CSPRNG must be available");
    bytes
}

/// Every failure here is the same verdict with a different cause, so the
/// cause rides in `source` and the variant names the file.
fn unusable(path: &Path, why: io::Error) -> ServeError {
    ServeError::Identity {
        path: path.display().to_string(),
        source: why,
    }
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod identity_tests;
