//! The devices file: the keys `serve --named --devices` holds, kept across
//! restarts.
//!
//! One device per line: its name, a space, and its key. Names are the
//! library's identifiers and keys carry no spaces, so nothing is quoted. Blank
//! lines and lines starting with `#` are skipped, and kept when a device is
//! forgotten. The keys are credentials, so the file is created readable only
//! by its owner, one others can read is refused rather than used, and no error
//! from here repeats a key.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};

/// Every device the file names, in order. A file that does not exist names
/// none.
pub(crate) fn load(path: &Path) -> anyhow::Result<Vec<(String, String)>> {
    let Some(text) = read(path)? else {
        return Ok(Vec::new());
    };
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

/// Add a device at the end of the file, creating the file if there is none.
pub(crate) fn append(path: &Path, name: &str, key: &str) -> anyhow::Result<()> {
    let mut file = private_options()
        .append(true)
        .create(true)
        .open(path)
        .with_context(|| format!("could not open {}", path.display()))?;
    refuse_if_shared(path)?;
    writeln!(file, "{name} {key}")
        .and_then(|()| file.sync_all())
        .with_context(|| format!("could not write to {}", path.display()))
}

/// Take a device out of the file, leaving every other line as it was.
pub(crate) fn forget(path: &Path, name: &str) -> anyhow::Result<()> {
    let Some(text) = read(path)? else {
        return Ok(());
    };
    let mut kept = String::with_capacity(text.len());
    for line in text.lines() {
        if line.trim_start().starts_with('#') || line.split_whitespace().next() != Some(name) {
            kept.push_str(line);
            kept.push('\n');
        }
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
            file.write_all(kept.as_bytes())?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&beside, path));
    written.with_context(|| format!("could not rewrite {}", path.display()))
}

/// The file's text, or `None` when there is no file.
fn read(path: &Path) -> anyhow::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(text) => {
            refuse_if_shared(path)?;
            Ok(Some(text))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("could not read {}", path.display())),
    }
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
