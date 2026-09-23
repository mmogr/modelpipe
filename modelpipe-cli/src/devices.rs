//! The devices file on disk: reading it, replacing it, and the form it had
//! before it was JSON.
//!
//! What the file *says* is `store.rs`'s business. This module owns how it is
//! read and written: the keys are credentials, so the file is created
//! readable only by its owner, one others can read is refused rather than
//! used, a replacement lands whole or not at all, and no error from here
//! repeats a key.
//!
//! Before 0.8 the file was one device per line — its name, a space, and its
//! key — with blank lines and `#` lines skipped. [`parse_lines`] still reads
//! that form, so a file an earlier serve kept is a file this one holds.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};

/// The file's text, or `None` when there is no file.
pub(crate) fn read(path: &Path) -> anyhow::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(text) => {
            refuse_if_shared(path)?;
            Ok(Some(text))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("could not read {}", path.display())),
    }
}

/// Every device a line-per-device file names, in order.
pub(crate) fn parse_lines(path: &Path, text: &str) -> anyhow::Result<Vec<(String, String)>> {
    let mut devices = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(name), Some(key), None) = (fields.next(), fields.next(), fields.next()) else {
            bail!(
                "{}:{}: a line is a device's name and its key, and nothing else",
                path.display(),
                index + 1
            );
        };
        devices.push((name.to_owned(), key.to_owned()));
    }
    Ok(devices)
}

/// Replace the file with `text`, whole: written beside it, synced, and
/// renamed over it, so a crash leaves either the old file or the new.
pub(crate) fn replace(path: &Path, text: &str) -> anyhow::Result<()> {
    if let Some(dir) = path.parent()
        && !dir.as_os_str().is_empty()
    {
        fs::create_dir_all(dir).with_context(|| format!("could not create {}", dir.display()))?;
    }
    let mut beside = path.as_os_str().to_owned();
    beside.push(".new");
    let beside = PathBuf::from(beside);
    // A file an earlier run left there would keep its own mode through a
    // truncating open, and the rename would hand that mode to the devices
    // file. So it goes first, and this one is created afresh.
    match fs::remove_file(&beside) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("could not remove {}", beside.display())),
    }
    let written = private_options()
        .write(true)
        .create_new(true)
        .open(&beside)
        .and_then(|mut file| {
            file.write_all(text.as_bytes())?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&beside, path));
    written.with_context(|| format!("could not rewrite {}", path.display()))
}

/// Open options that create a file readable only by its owner.
fn private_options() -> fs::OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut options = fs::OpenOptions::new();
        options.mode(0o600);
        options
    }
    #[cfg(not(unix))]
    {
        fs::OpenOptions::new()
    }
}

/// Refuse a file that other users can read: it holds every paired device's key.
#[cfg(unix)]
fn refuse_if_shared(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = fs::metadata(path)
        .with_context(|| format!("could not read {}", path.display()))?
        .permissions()
        .mode();
    #[expect(clippy::verbose_bit_mask, reason = "0o077 names what it checks")]
    let private = mode & 0o077 == 0;
    if !private {
        bail!(
            "{} holds device keys and other users can read it: chmod 600 it",
            path.display()
        );
    }
    Ok(())
}

/// Nothing to check where there are no Unix modes.
#[cfg(not(unix))]
#[expect(clippy::unnecessary_wraps, reason = "the Unix twin can fail")]
const fn refuse_if_shared(_: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
#[path = "devices_tests.rs"]
mod devices_tests;
