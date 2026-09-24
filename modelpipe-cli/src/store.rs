//! What `serve --named` remembers about each device: the record behind the
//! devices file.
//!
//! One row per device that was ever invited. A row is written the moment
//! the invite is offered, so a device that redeems the code is on record
//! before its first request; when the device pairs, the row gains when, from
//! which endpoint, and what the device called itself. A row whose invite was
//! never redeemed stays, marked as such, rather than being swept: what this
//! machine offered is always visible, and the person who offered it is the
//! one to clear it. Only a row that *was* redeemed is admitted when serve
//! restarts, so a key nobody ever received admits nobody.
//!
//! JSON, versioned, in the file `devices.rs` guards. A file in the older
//! line-per-device form is read as rows that paired when the file was last
//! written, since that form kept no row for an invite that was not redeemed.

use std::fmt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};

use crate::devices;

/// The one format this writes. A file with a higher number was written by a
/// later serve and is refused rather than rewritten with what this one
/// understands of it.
const VERSION: u32 = 1;

/// One device, invited or paired.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Device {
    /// The library's identifier for it, `dev-` and eight hex characters.
    pub(crate) name: String,
    /// Its key, held at the edge while it is admitted.
    pub(crate) key: String,
    /// What it called itself when it paired: text from a stranger, escaped
    /// wherever it is shown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) label: Option<String>,
    /// When the invite was offered, in seconds since the Unix epoch.
    pub(crate) invited_at: u64,
    /// When the code was redeemed, or `None` for an invite nobody spent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) redeemed_at: Option<u64>,
    /// The endpoint that redeemed it, as the library prints one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) peer: Option<String>,
}

impl Device {
    /// Whether the device ever paired, and so is admitted on a restart.
    pub(crate) const fn paired(&self) -> bool {
        self.redeemed_at.is_some()
    }
}

/// Everything but the key, which a log line has no business holding.
impl fmt::Debug for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Device")
            .field("name", &self.name)
            .field("label", &self.label)
            .field("invited_at", &self.invited_at)
            .field("redeemed_at", &self.redeemed_at)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

/// The file's shape.
#[derive(Serialize, Deserialize)]
struct Record {
    version: u32,
    devices: Vec<Device>,
}

/// What a read found: the rows, and whether they came from the older form
/// and so are worth rewriting.
#[derive(Debug)]
pub(crate) struct Loaded {
    pub(crate) devices: Vec<Device>,
    pub(crate) legacy: bool,
}

/// Seconds since the Unix epoch, now.
pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Every device the file names, in order. A file that does not exist names
/// none.
pub(crate) fn load(path: &Path) -> anyhow::Result<Loaded> {
    let Some(text) = devices::read(path)? else {
        return Ok(Loaded {
            devices: Vec::new(),
            legacy: false,
        });
    };
    if !text.trim_start().starts_with('{') {
        let written = std::fs::metadata(path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |since| since.as_secs());
        let devices = devices::parse_lines(path, &text)?
            .into_iter()
            .map(|(name, key)| Device {
                name,
                key,
                label: None,
                invited_at: written,
                redeemed_at: Some(written),
                peer: None,
            })
            .collect();
        return Ok(Loaded {
            devices,
            legacy: true,
        });
    }
    // serde_json's errors carry a line and column and not the text, so a
    // malformed file is named without its keys.
    let record: Record = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a devices file this can read", path.display()))?;
    if record.version > VERSION {
        bail!(
            "{} was written by a newer modelpipe (format {}) — this one reads up to {VERSION}",
            path.display(),
            record.version
        );
    }
    Ok(Loaded {
        devices: record.devices,
        legacy: false,
    })
}

/// Write every row, replacing the file whole.
pub(crate) fn save(path: &Path, devices: &[Device]) -> anyhow::Result<()> {
    let record = Record {
        version: VERSION,
        devices: devices.to_vec(),
    };
    let mut text = serde_json::to_string_pretty(&record).context("could not encode the devices")?;
    text.push('\n');
    devices::replace(path, &text)
}

/// Add a row, or replace the one with the same name.
pub(crate) fn upsert(path: &Path, device: Device) -> anyhow::Result<()> {
    let mut devices = load(path)?.devices;
    match devices.iter_mut().find(|d| d.name == device.name) {
        Some(row) => *row = device,
        None => devices.push(device),
    }
    save(path, &devices)
}

/// Change the row named `name` in place. Whether there was one.
pub(crate) fn update(
    path: &Path,
    name: &str,
    change: impl FnOnce(&mut Device),
) -> anyhow::Result<bool> {
    let mut devices = load(path)?.devices;
    let Some(row) = devices.iter_mut().find(|d| d.name == name) else {
        return Ok(false);
    };
    change(row);
    save(path, &devices)?;
    Ok(true)
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod store_tests;
