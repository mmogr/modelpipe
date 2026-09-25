//! Pairing from the command line: an invite when `serve --named --invite`
//! starts, and `connect`'s two ways in, a ticket alone or a pairing string
//! whose code it redeems.
//!
//! The library does the pairing. What lives here is what a terminal adds: the
//! devices record kept in step with each invite, and the lines a person reads.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use modelpipe::{
    ConnectHandle, ConnectOptions, Invite, InviteHandle, InviteOptions, InviteOutcome, Paired,
    PairingString, ServeHandle, Ticket,
};

use crate::park::{FIRST_CONTACT, first_contact};
use crate::store::{self, Device};

/// Hold the record's keys, and invite one device more when asked — or when
/// `if_none` and nothing is held, which is a first run. The invite, when
/// there is one, for the caller to show and to watch; `how` says how a
/// device is invited later, for the warning when none can use the listener
/// yet.
pub(crate) fn start(
    handle: &ServeHandle,
    invite: bool,
    if_none: bool,
    file: Option<&Path>,
    how: &str,
) -> anyhow::Result<Option<Invite>> {
    let held = if let Some(path) = file {
        hold(handle, path)?
    } else {
        eprintln!(
            "note: devices paired now are forgotten when serve stops — \
             pass --state-dir <dir> to keep them"
        );
        0
    };
    let first_run = if_none && held == 0;
    if !invite && !first_run {
        if held == 0 {
            eprintln!("WARNING: no device can use this listener yet — {how}");
        }
        return Ok(None);
    }
    invite_one(handle, file).map(Some)
}

/// Hold every device the record says paired, and say how many. A row whose
/// invite was never redeemed is a key nobody received, and it is not held.
pub(crate) fn hold(handle: &ServeHandle, path: &Path) -> anyhow::Result<usize> {
    let loaded = store::load(path)?;
    if loaded.legacy {
        // Rewritten now rather than at the next change, so that a file the
        // person reads after this run is in the one form serve writes.
        store::save(path, &loaded.devices)?;
        eprintln!("note: {} was rewritten as JSON", path.display());
    }
    let mut held = 0;
    for device in loaded.devices.iter().filter(|d| d.paired()) {
        handle
            .add_token(&device.name, device.key.clone())
            .map_err(|e| {
                anyhow::anyhow!(
                    "{}: the device {} could not be held: {e}",
                    path.display(),
                    device.name
                )
            })?;
        held += 1;
    }
    Ok(held)
}

/// Invite a device: its row written to the record first, when there is one,
/// and only then the code armed, so a device that redeems it is always on
/// record.
///
/// The library holds the key as it mints the invite, so a row that cannot
/// be written takes the key back out before the error returns, rather than
/// leave one held that no row names.
pub(crate) fn invite_one(handle: &ServeHandle, file: Option<&Path>) -> anyhow::Result<Invite> {
    let invite = handle.invite(InviteOptions::default())?;
    if let Some(path) = file {
        let row = Device {
            name: invite.device().to_owned(),
            key: invite.api_key().to_owned(),
            label: None,
            invited_at: store::now(),
            redeemed_at: None,
            peer: None,
        };
        if let Err(e) = store::upsert(path, row) {
            handle.remove_token(invite.device());
            return Err(e);
        }
    }
    invite.arm();
    Ok(invite)
}

/// Say on stderr how the invite ended, once it has.
pub(crate) async fn watch(
    handle: Arc<ServeHandle>,
    invite: InviteHandle,
    device: String,
    file: Option<PathBuf>,
) {
    let outcome = invite.outcome().await;
    eprintln!("{}", settle(&handle, &device, &outcome, file.as_deref()));
}

/// Keep the listener and the record in step with how an invite ended, and
/// say how: a device that paired is marked so, with when and from where,
/// and the key of one that never did is taken back out of the listener.
///
/// The listener first. Withdrawing an invite leaves its key held — the
/// library says so, and `remove_token` is the call that retires it — so a
/// watcher that only tidied the file left every expired code's key admitting
/// until serve restarted, which is a key on record nowhere and a device
/// nobody can `forget`.
///
/// The row stays, marked as never joined, rather than being swept: what this
/// machine offered is always visible, and its key is not held again on a
/// restart, so the row costs nothing but a line in a list.
pub(crate) fn settle(
    handle: &ServeHandle,
    device: &str,
    outcome: &InviteOutcome,
    file: Option<&Path>,
) -> String {
    let mut said = ended(outcome);
    let InviteOutcome::Redeemed { peer, label, .. } = outcome else {
        handle.remove_token(device);
        return said;
    };
    let Some(path) = file else {
        return said;
    };
    let (peer, label) = (peer.to_string(), label.clone());
    let recorded = store::update(path, device, |row| {
        row.redeemed_at = Some(store::now());
        row.peer = Some(peer);
        row.label = label;
    });
    if let Err(e) = recorded {
        use std::fmt::Write as _;
        let _ = write!(said, "\ncould not record that {device} paired: {e:#}");
    }
    said
}

/// The line for how an invite ended. A device's label is text from a stranger
/// until it paired, so it is printed escaped.
pub(crate) fn ended(outcome: &InviteOutcome) -> String {
    match outcome {
        InviteOutcome::Redeemed {
            device,
            peer,
            label: Some(label),
        } => format!("paired: {device}, from {peer}, which calls itself {label:?}"),
        InviteOutcome::Redeemed { device, peer, .. } => format!("paired: {device}, from {peer}"),
        InviteOutcome::Expired => "the pairing code expired unused".to_owned(),
        InviteOutcome::Burned => "the pairing code was burned: someone holding this ticket is \
                                  guessing codes, and only a new ticket shuts them out"
            .to_owned(),
        _ => "the pairing code was withdrawn".to_owned(),
    }
}

/// What `connect` was given: a pairing string, or a ticket alone. Text with no
/// `-` that is not a ticket keeps the ticket's own error.
pub(crate) fn parse(text: &str) -> anyhow::Result<PairingString> {
    match text.parse::<PairingString>() {
        Ok(given) => Ok(given),
        Err(_) if !text.contains('-') => Ok(PairingString::new(text.parse::<Ticket>()?, None)),
        Err(e) => Err(e.into()),
    }
}

/// Connect as `connect` was asked to: redeem the code when the pairing string
/// has one, and otherwise dial the ticket and wait for the serve side.
pub(crate) async fn connect(
    given: &PairingString,
    name: Option<&str>,
    opts: ConnectOptions,
) -> anyhow::Result<ConnectHandle> {
    if given.code().is_some() {
        // `pair` waits for the serve side before it spends the code, so there
        // is no first contact to wait out here as well.
        eprintln!("pairing with the serve side…");
        return redeem(given, name, opts).await;
    }
    if name.is_some() {
        eprintln!("note: --name is sent when pairing, and this ticket has no code");
    }
    let mut handle = modelpipe::connect(given.ticket(), opts).await?;
    // The local port is bound; reaching the peer is not. `connect` used to do
    // both before returning, and the terminal is owed the same sentence for an
    // absent serve side — so the wait that used to happen inside the library
    // happens here, where picking a deadline is this command's to do. To stderr
    // and before it, so a terminal about to sit still says why.
    eprintln!("reaching the serve side…");
    first_contact(&mut handle, FIRST_CONTACT).await?;
    println!("{}", handle.base_url());
    Ok(handle)
}

/// Redeem a pairing string's code for this device's key. Prints the base URL,
/// as a plain `connect` does, and then the key, once.
pub(crate) async fn redeem(
    given: &PairingString,
    name: Option<&str>,
    opts: ConnectOptions,
) -> anyhow::Result<ConnectHandle> {
    let Paired {
        handle,
        api_key,
        device,
        serving,
        ..
    } = modelpipe::pair(given, name, opts, FIRST_CONTACT).await?;
    println!("{}", handle.base_url());
    println!("key: {api_key}");
    eprintln!(
        "paired as {device} with {serving}. The key is printed once, so keep it, and connect \
         with the ticket alone from now on"
    );
    Ok(handle)
}

#[cfg(test)]
#[path = "pairing_tests.rs"]
mod pairing_tests;
