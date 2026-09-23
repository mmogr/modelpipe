//! Pairing from the command line: an invite when `serve --named --invite`
//! starts, and `connect`'s two ways in, a ticket alone or a pairing string
//! whose code it redeems.
//!
//! The library does the pairing. What lives here is what a terminal adds: the
//! devices file kept in step with each invite, and the lines a person reads.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use modelpipe::{
    ConnectHandle, ConnectOptions, Invite, InviteHandle, InviteOptions, InviteOutcome, Paired,
    PairingString, ServeHandle, Ticket,
};

use crate::devices;
use crate::park::{FIRST_CONTACT, first_contact};

/// Hold the devices file's keys, and invite one device more when asked. The
/// pairing string to show, when there is an invite.
pub(crate) fn start(
    handle: &Arc<ServeHandle>,
    invite: bool,
    file: Option<&Path>,
) -> anyhow::Result<Option<String>> {
    let held = if let Some(path) = file {
        hold(handle, path)?
    } else {
        eprintln!(
            "note: devices paired now are forgotten when serve stops — \
             pass --state-dir <dir> to keep them"
        );
        0
    };
    if !invite {
        if held == 0 {
            eprintln!("WARNING: no device can use this listener yet — pass --invite to pair one");
        }
        return Ok(None);
    }
    let invited = invite_one(handle, file)?;
    let pairing = invited.pairing().to_string();
    println!("pairing: {pairing}");
    eprintln!(
        "the code in it works once, for two minutes: run modelpipe connect with the whole \
         pairing string on the device"
    );
    tokio::spawn(watch(
        Arc::clone(handle),
        invited.handle(),
        invited.device().to_owned(),
        file.map(Path::to_path_buf),
    ));
    Ok(Some(pairing))
}

/// Hold every device the file names, and say how many.
pub(crate) fn hold(handle: &ServeHandle, path: &Path) -> anyhow::Result<usize> {
    let held = devices::load(path)?;
    for (name, key) in &held {
        handle.add_token(name, key.clone()).map_err(|e| {
            anyhow::anyhow!(
                "{}: the device {name} could not be held: {e}",
                path.display()
            )
        })?;
    }
    Ok(held.len())
}

/// Invite a device: its key written to the file first, when there is one, and
/// only then the code armed, so a device that redeems it is always on record.
pub(crate) fn invite_one(handle: &ServeHandle, file: Option<&Path>) -> anyhow::Result<Invite> {
    let invite = handle.invite(InviteOptions::default())?;
    if let Some(path) = file {
        devices::append(path, invite.device(), invite.api_key())?;
    }
    invite.arm();
    Ok(invite)
}

/// Say on stderr how the invite ended, and take the key of a device that never
/// redeemed it back out of the listener and out of the file.
///
/// The listener first. Withdrawing an invite leaves its key held — the
/// library says so, and `remove_token` is the call that retires it — so a
/// watcher that only tidied the file left every expired code's key admitting
/// until serve restarted, which is a key on record nowhere and a device
/// nobody can `forget`.
pub(crate) async fn watch(
    handle: Arc<ServeHandle>,
    invite: InviteHandle,
    device: String,
    file: Option<PathBuf>,
) {
    let outcome = invite.outcome().await;
    eprintln!("{}", ended(&outcome));
    if matches!(outcome, InviteOutcome::Redeemed { .. }) {
        return;
    }
    handle.remove_token(&device);
    if let Some(path) = file
        && let Err(e) = devices::forget(&path, &device)
    {
        eprintln!(
            "could not take {device} back out of {}: {e:#}",
            path.display()
        );
    }
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
        InviteOutcome::Expired => {
            "the pairing code expired unused: restart serve with --invite for a new one".to_owned()
        }
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
