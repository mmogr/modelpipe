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
//! **A durable ticket is not the same as a reachable one**, and the gap is
//! worth naming here because this module is where people will look. The key
//! fixes the *name* in a ticket; the addresses beside it are a snapshot,
//! and a restarted process holds a different UDP port. Closing that gap is
//! discovery's job — by default n0's, which the README's disclosure section
//! covers — so a peer whose address has changed is found by resolving the
//! endpoint id, not by the ticket alone.
//!
//! Measured, on a host with n0's DNS blocked: a listener restarted with the
//! same identity minted the same ticket, a *fresh* ticket from it paired
//! and served, and the *old* ticket could not reach it at all. Nothing was
//! wrong with the key. Somewhere with discovery reachable the old ticket
//! resolves the same id to the new address, which is the whole design; this
//! is only a note that the two halves are separate, and that switching off
//! the one this crate does not control takes the other with it.
//!
//! The connect side keeps a key too, for another reason. Nothing dials it,
//! so its key is in no ticket, but a serve side sees it on every connection,
//! and a key that lasts is a device the serve side can recognise.
//!
//! Pure of iroh, deliberately. This hands back thirty-two bytes and
//! [`crate::transport`] is where they become a key, so the whole of the
//! file handling — the format, the permissions, the refusals — is
//! exercisable without binding an endpoint.

use std::fs;
use std::io;
use std::path::Path;

use crate::base32;
use crate::private_file::{self, check_private};
use crate::{ConnectError, ServeError};

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
/// [`Unusable`] for a file that exists and is not a key this can use, or
/// one it cannot read or write, which each side reports as its own error's
/// `Identity` variant. All of them are permanent: the path came from the
/// operator, and retrying it fails the same way.
pub(crate) fn load_or_mint(path: &Path) -> Result<[u8; KEY_BYTES], Unusable> {
    match fs::read_to_string(path) {
        // A file with nothing in it holds no key, and now says so instead
        // of failing as "not base32". This crate can no longer produce
        // one — writes go through [`private_file::write_new`] — but a
        // version before 0.7.0 wrote in place, and a crash between the
        // open and the bytes left exactly this (#103).
        //
        // **Refused rather than replaced, deliberately.** Minting over it
        // means unlinking a path this process does not own, and two
        // listeners recovering at once would then race: the second
        // `remove_file` would delete the *valid* key the first had just
        // written, and the two would serve different identities from one
        // file. That is precisely the failure [`private_file`] refuses a
        // rename to avoid, and saving the operator one `rm` is not worth
        // reintroducing it. So the refusal names the file and the remedy,
        // which is the other half of what #103 asked for.
        Ok(stored) if stored.trim().is_empty() => Err(unusable(
            path,
            io::Error::other(format!(
                "the identity file is empty, so it holds no key — delete {} and start again",
                path.display()
            )),
        )),
        Ok(stored) => check_private(path)
            .and_then(|()| parse(&stored))
            .map_err(|why| unusable(path, why)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let minted = mint();
            // Atomic, and refuses a file that exists — so two listeners
            // starting at once resolve the way they always did: one wins,
            // and the other is told the path is taken rather than quietly
            // serving a ticket that names a peer nobody is.
            store(path, minted).map_err(|why| unusable(path, why))?;
            Ok(minted)
        }
        Err(e) => Err(unusable(path, e)),
    }
}

/// [`load_or_mint`] for a path that may not have been given. `None` keeps
/// no key, and the endpoint mints one for the life of the process.
pub(crate) fn stored(path: Option<&Path>) -> Result<Option<[u8; KEY_BYTES]>, Unusable> {
    path.map(load_or_mint).transpose()
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

/// Write `key` where only this user can read it, atomically.
///
/// The permissions, the atomicity and the refusal to replace an existing
/// file all belong to [`private_file::write_new`], which documents why the
/// last of those rules out a rename.
fn store(path: &Path, key: [u8; KEY_BYTES]) -> Result<(), io::Error> {
    private_file::write_new(
        path,
        &format!("{}\n", base32::encode(&key).to_ascii_lowercase()),
    )
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
/// cause rides in `source` and the verdict names the file.
fn unusable(path: &Path, why: io::Error) -> Unusable {
    Unusable {
        path: path.display().to_string(),
        source: why,
    }
}

/// A key file this cannot use, and why.
///
/// Neither side's error, because both sides keep a key: `serve` reports it
/// as [`ServeError::Identity`] and `connect` as [`ConnectError::Identity`],
/// with the same path and the same cause.
#[derive(Debug)]
pub(crate) struct Unusable {
    pub(crate) path: String,
    pub(crate) source: io::Error,
}

impl From<Unusable> for ServeError {
    fn from(unusable: Unusable) -> Self {
        Self::Identity {
            path: unusable.path,
            source: unusable.source,
        }
    }
}

impl From<Unusable> for ConnectError {
    fn from(unusable: Unusable) -> Self {
        Self::Identity {
            path: unusable.path,
            source: unusable.source,
        }
    }
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod identity_tests;
