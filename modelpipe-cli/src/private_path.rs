//! The check that a file or folder holding keys is this user's alone.
//!
//! The devices file and the state folder are refused when other users can
//! read them, and when another user owns them: a process running as root
//! reads another user's `0600` file as easily as its own, and the mode bits
//! do not say whose they are. The library checks its identity file the
//! same way.

use std::path::Path;

/// Why a path is not private to the user this process runs as.
#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Exposure {
    /// Another user owns it.
    Owner,
    /// Users other than its owner can read it.
    Mode,
}

/// Why a path with `mode`, owned by `owner`, is not private to a process
/// running as `euid`, or `None` when it is.
///
/// Apart from the read of the path, so a test can name an owner it has no
/// way to `chown` a file to.
#[cfg(unix)]
pub(crate) const fn exposure(mode: u32, owner: u32, euid: u32) -> Option<Exposure> {
    if owner != euid {
        return Some(Exposure::Owner);
    }
    #[expect(clippy::verbose_bit_mask, reason = "0o077 names what it checks")]
    let private = mode & 0o077 == 0;
    if private { None } else { Some(Exposure::Mode) }
}

/// Refuse `path` when another user owns it or others can read it.
///
/// `holds` is what it holds, for the message, and `chmod` is the mode that
/// makes it private.
#[cfg(unix)]
pub(crate) fn refuse_unless_private(path: &Path, holds: &str, chmod: &str) -> anyhow::Result<()> {
    use anyhow::{Context as _, bail};
    use std::os::unix::fs::MetadataExt as _;

    let found =
        std::fs::metadata(path).with_context(|| format!("could not read {}", path.display()))?;
    let euid = rustix::process::geteuid().as_raw();
    match exposure(found.mode(), found.uid(), euid) {
        None => Ok(()),
        Some(Exposure::Owner) => bail!(
            "{} holds {holds} and belongs to uid {}, not uid {euid} that this runs as: chown it, \
             or run as its owner",
            path.display(),
            found.uid()
        ),
        Some(Exposure::Mode) => bail!(
            "{} holds {holds} and other users can read it: chmod {chmod} it",
            path.display()
        ),
    }
}

/// Nothing to check where there are no Unix modes or owners.
#[cfg(not(unix))]
#[expect(clippy::unnecessary_wraps, reason = "the Unix twin can fail")]
pub(crate) const fn refuse_unless_private(_: &Path, _: &str, _: &str) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "private_path_tests.rs"]
mod private_path_tests;
