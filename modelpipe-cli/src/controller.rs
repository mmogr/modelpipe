//! What the keys do: invite, list and forget, over the listener and the
//! record together.
//!
//! One code on offer at a time. A second `i` while one is live shows the
//! same code again with the time it has left, rather than minting another
//! that the first would then race; a new one is minted only once the last
//! has ended. Forgetting a device retires its key at the listener, ends its
//! invite if that is what it has, and takes its row out of the record, in
//! that order, so nothing is on record that the listener still admits.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::bail;
use modelpipe::{Invite, InviteHandle, InviteOptions, InviteOutcome, ServeHandle};

use crate::pairing::{invite_one, settle};
use crate::store;

/// The code on offer.
struct Open {
    device: String,
    pairing: String,
    handle: InviteHandle,
    until: Instant,
}

/// A code to show: the pairing string, whose it is, and how long it has.
pub(crate) struct Offer {
    pub(crate) pairing: String,
    pub(crate) device: String,
    pub(crate) left: Duration,
    /// Whether this is the code already on offer, shown again.
    pub(crate) again: bool,
}

/// The listener, the record, and the invite in flight.
pub(crate) struct Controller {
    handle: Arc<ServeHandle>,
    record: Option<PathBuf>,
    open: Option<Open>,
}

impl Controller {
    /// Over `handle` and the record at `record`, adopting the invite
    /// `serve --invite` minted at startup as the one on offer.
    pub(crate) fn new(
        handle: Arc<ServeHandle>,
        record: Option<PathBuf>,
        adopted: Option<Invite>,
    ) -> Self {
        let open = adopted.map(|invite| Open {
            device: invite.device().to_owned(),
            pairing: invite.pairing().to_string(),
            handle: invite.handle(),
            until: Instant::now() + InviteOptions::default().ttl,
        });
        Self {
            handle,
            record,
            open,
        }
    }

    /// The code on offer: the one already live, or a fresh one.
    pub(crate) fn invite(&mut self) -> anyhow::Result<Offer> {
        if let Some(open) = &self.open
            && open.handle.ended().is_none()
        {
            return Ok(Offer {
                pairing: open.pairing.clone(),
                device: open.device.clone(),
                left: open.until.saturating_duration_since(Instant::now()),
                again: true,
            });
        }
        let ttl = InviteOptions::default().ttl;
        let invite = invite_one(&self.handle, self.record.as_deref())?;
        let offer = Offer {
            pairing: invite.pairing().to_string(),
            device: invite.device().to_owned(),
            left: ttl,
            again: false,
        };
        self.open = Some(Open {
            device: offer.device.clone(),
            pairing: offer.pairing.clone(),
            handle: invite.handle(),
            until: Instant::now() + ttl,
        });
        Ok(offer)
    }

    /// How long the code on offer has left, or `None` when there is none.
    pub(crate) fn left(&self) -> Option<Duration> {
        self.open
            .as_ref()
            .map(|open| open.until.saturating_duration_since(Instant::now()))
    }

    /// The device whose code is on offer, if one is.
    pub(crate) fn offered(&self) -> Option<&str> {
        self.open.as_ref().map(|open| open.device.as_str())
    }

    /// Wait until the code on offer ends. Pends for ever when there is
    /// none, which is what a `select!` arm for it wants.
    pub(crate) async fn ended(&self) -> InviteOutcome {
        match &self.open {
            Some(open) => open.handle.outcome().await,
            None => std::future::pending().await,
        }
    }

    /// The code on offer has ended: keep the listener and the record in
    /// step, and say how it ended.
    pub(crate) fn settle(&mut self, outcome: &InviteOutcome) -> String {
        let Some(open) = self.open.take() else {
            return String::new();
        };
        settle(&self.handle, &open.device, outcome, self.record.as_deref())
    }

    /// Every device on record, one line each, numbered for `forget`.
    pub(crate) fn list(&self) -> anyhow::Result<Vec<String>> {
        let devices = match &self.record {
            Some(path) => store::load(path)?.devices,
            None => Vec::new(),
        };
        let held = self.handle.token_names();
        let now = store::now();
        let mut lines: Vec<String> = devices
            .iter()
            .enumerate()
            .map(|(index, device)| {
                let label = device
                    .label
                    .as_deref()
                    .map(|label| format!("  {label:?}"))
                    .unwrap_or_default();
                let state = if self.offered() == Some(device.name.as_str()) {
                    let left = self.left().unwrap_or_default();
                    format!("code on offer, {} left", clock(left))
                } else if let Some(at) = device.redeemed_at {
                    let admitted = if held.contains(&device.name) {
                        ""
                    } else {
                        ", not admitted until serve restarts"
                    };
                    format!("paired {}{admitted}", ago(at, now))
                } else {
                    format!("invited {}, never joined", ago(device.invited_at, now))
                };
                format!("{:>3}. {}{label}  {state}", index + 1, device.name)
            })
            .collect();
        if lines.is_empty() {
            lines.push("no devices yet: press i to invite one".to_owned());
        }
        Ok(lines)
    }

    /// Forget the device `who` names — its number in the list or its name.
    /// What was done, for the window.
    pub(crate) fn forget(&mut self, who: &str) -> anyhow::Result<String> {
        let who = who.trim();
        let devices = match &self.record {
            Some(path) => store::load(path)?.devices,
            None => Vec::new(),
        };
        let name = match who.parse::<usize>() {
            Ok(index) if index >= 1 => devices
                .get(index - 1)
                .map(|device| device.name.clone())
                .ok_or_else(|| anyhow::anyhow!("there is no device {index} in the list"))?,
            _ if devices.iter().any(|d| d.name == who) => who.to_owned(),
            _ if self.offered() == Some(who) => who.to_owned(),
            _ if who.is_empty() => bail!("nothing forgotten"),
            _ => bail!("no device is called {who:?}"),
        };
        let was_offered = self.offered() == Some(name.as_str());
        // The listener first, so nothing on record is still admitted; the
        // invite is withdrawn by `remove_token` itself, and `ended` will
        // report it, so the offer is dropped here without settling it.
        self.handle.remove_token(&name);
        if was_offered {
            self.open = None;
        }
        if let Some(path) = &self.record {
            store::remove(path, &name)?;
        }
        Ok(if was_offered {
            format!("forgot {name}: its code is withdrawn")
        } else {
            format!("forgot {name}: it is no longer admitted")
        })
    }
}

/// A duration as `m:ss`.
pub(crate) fn clock(left: Duration) -> String {
    let secs = left.as_secs();
    format!("{}:{:02}", secs / 60, secs % 60)
}

/// How long ago `then` was, for a person: minutes, hours or days.
fn ago(then: u64, now: u64) -> String {
    let secs = now.saturating_sub(then);
    match secs {
        0..60 => "just now".to_owned(),
        60..3600 => format!("{} min ago", secs / 60),
        3600..86_400 => format!("{} h ago", secs / 3600),
        _ => format!("{} d ago", secs / 86_400),
    }
}

#[cfg(test)]
#[path = "controller_tests.rs"]
mod controller_tests;
