//! Where `serve` keeps what should survive a restart.
//!
//! The library persists one thing, the endpoint key, and only at a path it
//! is handed. The CLI persists two — that key, and the devices file — and
//! until now each needed its own flag, so a serve that remembered anything
//! was a serve started with two paths typed by hand. This module is one
//! folder for both, chosen once: `--state-dir` names it, and a later change
//! picks a default for it.
//!
//! One folder per **backend**, under the root: two serves on one machine
//! fronting two servers share nothing, and neither is refused for the
//! other's sake. Within a backend's folder a lock file makes the serve that
//! holds it the only one, because two listeners loading one identity would
//! serve one ticket from two places, which the library's own file rules go
//! to some length to prevent.

use std::fs::{self, File, TryLockError};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};

/// The folder name for `url`'s backend: its host and port, and nothing
/// else, in characters every filesystem takes.
///
/// The scheme, any credentials and the path are dropped, the host is
/// lowercased, a port left off is the scheme's, and every character
/// outside `[a-z0-9.-]` becomes `_`. Two URLs that reach the same server
/// therefore share a folder however they were spelled, which is what makes
/// a restart find its own state.
pub(crate) fn backend_key(url: &str) -> String {
    let (scheme, rest) = url
        .split_once("://")
        .map_or(("http", url), |(scheme, rest)| (scheme, rest));
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let (host, port) = split_port(&authority).unwrap_or_else(|| {
        let default = if scheme.eq_ignore_ascii_case("https") {
            "443"
        } else {
            "80"
        };
        (authority.as_str(), default)
    });
    let safe = |text: &str| -> String {
        text.chars()
            .map(|c| {
                if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    };
    format!("{}_{}", safe(host), safe(port))
}

/// `host:port` split at the port, allowing for an IPv6 host in brackets,
/// whose colons are not the one that matters.
fn split_port(authority: &str) -> Option<(&str, &str)> {
    let at = authority.rfind(':')?;
    let (host, port) = (&authority[..at], &authority[at + 1..]);
    if host.starts_with('[') && !host.ends_with(']') {
        return None;
    }
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((host, port))
}

/// One backend's folder, held for as long as this serve runs.
///
/// Dropping it releases the lock; the folder and its files stay.
#[derive(Debug)]
pub(crate) struct StateDir {
    dir: PathBuf,
    _lock: File,
}

impl StateDir {
    /// Open `root/<key>`, creating it readable only by its owner, and take
    /// its lock.
    ///
    /// # Errors
    ///
    /// The folder exists and other users can read it; another serve holds
    /// the lock; or the folder could not be made or the lock file opened.
    pub(crate) fn open(root: &Path, key: &str) -> anyhow::Result<Self> {
        let dir = root.join(key);
        make_private(&dir)?;
        refuse_if_shared(&dir)?;
        let lock_path = dir.join("lock");
        let mut options = File::options();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut lock = options
            .open(&lock_path)
            .with_context(|| format!("could not open {}", lock_path.display()))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                let holder = fs::read_to_string(&lock_path).unwrap_or_default();
                let holder = holder.trim();
                let by = if holder.is_empty() {
                    String::new()
                } else {
                    format!(" (pid {holder})")
                };
                bail!(
                    "another modelpipe serve is using {}{by}: stop it, or pass --state-dir",
                    dir.display()
                );
            }
            Err(TryLockError::Error(e)) => {
                return Err(e).with_context(|| format!("could not lock {}", lock_path.display()));
            }
        }
        // Who holds it, for the refusal above. Written after the lock is
        // ours, so a loser never overwrites the winner's pid.
        lock.set_len(0)
            .and_then(|()| writeln!(lock, "{}", std::process::id()))
            .with_context(|| format!("could not write {}", lock_path.display()))?;
        Ok(Self { dir, _lock: lock })
    }

    /// The folder itself.
    pub(crate) fn path(&self) -> &Path {
        &self.dir
    }

    /// Where the endpoint key is kept, in the library's own format.
    pub(crate) fn identity(&self) -> PathBuf {
        self.dir.join("identity")
    }

    /// Where paired devices' keys are kept.
    pub(crate) fn devices(&self) -> PathBuf {
        self.dir.join("devices")
    }
}

/// Create `dir` and the folder above it, both readable only by their
/// owner, and whatever is above *those* with the platform's defaults.
///
/// Both folders are this program's, so both get the strict mode; the ones
/// above them — `~/.local/share`, say — are not, and a parent created
/// `0700` because we happened to be the first to need it would lock every
/// other program's data away from that user's own group.
fn make_private(dir: &Path) -> anyhow::Result<()> {
    let ours = dir.parent().unwrap_or(dir);
    if let Some(above) = ours.parent() {
        fs::create_dir_all(above)
            .with_context(|| format!("could not create {}", above.display()))?;
    }
    for folder in [ours, dir] {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        match builder.create(folder) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(e).with_context(|| format!("could not create {}", folder.display()));
            }
        }
    }
    Ok(())
}

/// Refuse a folder other users can read into: it holds the endpoint key and
/// every paired device's.
#[cfg(unix)]
fn refuse_if_shared(dir: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = fs::metadata(dir)
        .with_context(|| format!("could not read {}", dir.display()))?
        .permissions()
        .mode();
    #[expect(clippy::verbose_bit_mask, reason = "0o077 names what it checks")]
    let private = mode & 0o077 == 0;
    if !private {
        bail!(
            "{} holds keys and other users can read it: chmod 700 it",
            dir.display()
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
#[path = "state_tests.rs"]
mod state_tests;
