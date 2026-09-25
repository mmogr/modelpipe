//! The `serve` command, from the flags to the parked pipe.
//!
//! Split from `main.rs` so that the file which parses what the operator
//! typed is not also the file that acts on it. Everything `serve` does after
//! clap is done lives here, in the order it happens, and `main` calls it
//! once.

use std::path::PathBuf;
use std::sync::Arc;

use modelpipe::{Invite, ServeHandle, ServeOptions, TokenPolicy};

use crate::cli::ServeArgs;
use crate::controller::Controller;
use crate::interrupt::Interrupt;
use crate::keys::Keys;
use crate::pairing;
use crate::park::{park, shut_down};
use crate::serve_out::{WAIT_ONLINE, print_token, qr, qr_of, token_policy, undialable};
use crate::session::{self, HINT};
use crate::state::{self, StateDir, backend_key};
use crate::stdout;

/// Serve as asked, and stay parked on the pipe until told to stop.
pub(crate) async fn run(args: ServeArgs, interrupt: &mut Interrupt) -> anyhow::Result<()> {
    let ServeArgs {
        backend_url,
        insecure_no_auth,
        token,
        token_file,
        allow_private_backend,
        relay,
        identity,
        no_qr,
        no_portmap,
        no_discovery,
        relay_only,
        named,
        invite,
        invite_if_none,
        devices,
        state_dir,
        no_state,
    } = args;
    // Held to the end of this function, which is the life of the lock: a
    // second serve on the same backend is refused while this one runs.
    let key = backend_key(&backend_url);
    let state = match state_dir {
        _ if no_state => None,
        Some(root) => Some(StateDir::open(&root, &key)?),
        // Serving open, a ticket is the only lock there is, and one that
        // survives a restart is a credential with no expiry and nothing
        // behind it; keeping it is asked for with --state-dir, not
        // defaulted. Off Unix nothing here can keep the folder private, so
        // the same applies.
        None if insecure_no_auth || !cfg!(unix) => None,
        None => Some(StateDir::open(&state::data_dir()?, &key)?),
    };
    // A flag names a file; the folder names the rest. Each file's flag
    // wins over its place in the folder, so an operator with a key
    // somewhere already can keep it there.
    let identity = identity.or_else(|| state.as_ref().map(StateDir::identity));
    let devices = devices.or_else(|| state.as_ref().map(StateDir::devices));
    if let Some(state) = &state {
        // Where a restart will look, said once so that a `forget` by hand,
        // or a revocation by `rm`, knows the folder.
        eprintln!("state: {}", state.path().display());
    }
    // Mutation rather than a struct literal: the options structs
    // are #[non_exhaustive], so a literal cannot cross the crate
    // boundary — which is the point, new options must not break
    // existing callers (this one included).
    let mut opts = ServeOptions::default();
    opts.auth = if named {
        TokenPolicy::Named
    } else {
        token_policy(token, token_file, insecure_no_auth)?
    };
    // Read before `opts` is moved into `serve`, and the only thing
    // that survives it: all three supplying flags collapse into
    // `Supplied`, so this is the last point at which the CLI can
    // tell an operator's own credential from one minted here.
    let supplied = matches!(opts.auth, TokenPolicy::Supplied(_));
    opts.relay = relay;
    let ephemeral = identity.is_none();
    opts.identity = identity;
    opts.port_mapping = !no_portmap;
    opts.discovery = !no_discovery;
    opts.relay_only = relay_only;
    opts.wait_online = Some(WAIT_ONLINE);

    // To stderr, and before the wait rather than after it, so a
    // terminal that is about to sit still for a moment says why.
    eprintln!("finding a relay…");
    // Shared rather than owned from here on: an invite's watcher
    // outlives this function's straight line — it ends when the
    // code does, minutes later, on a task of its own — and it needs
    // the listener to take the key back. Every call it makes takes
    // `&self`, so nothing but the sharing changes.
    let handle =
        Arc::new(modelpipe::serve(backend(&backend_url, allow_private_backend), opts).await?);
    let ticket = handle.ticket();
    // Between minting the ticket and printing it, which is the only
    // place the check is worth anything: a person who reads the
    // refusal here is a person who has not yet carried an empty
    // ticket to another machine.
    if let Some(refusal) = undialable(&ticket, relay_only) {
        handle.shutdown().await;
        anyhow::bail!("{refusal}");
    }
    stdout::say(&format!("ticket: {ticket}"));
    // The keyboard, when a person is at one and there is something a key
    // can do: a listener with a key per device. A token for everybody has
    // nothing to invite into.
    let keys = if named { Keys::open() } else { None };
    let how = if keys.is_some() {
        "press i to pair one"
    } else {
        "pass --invite to pair one"
    };
    let invited = if named {
        // A key per device, so no token for everybody to print.
        match pairing::start(&handle, invite, invite_if_none, devices.as_deref(), how) {
            Ok(invited) => invited,
            Err(e) => {
                handle.shutdown().await;
                return Err(e);
            }
        }
    } else {
        print_token(supplied, handle.token());
        None
    };
    if let Some(invite) = &invited {
        stdout::say(&format!("pairing: {}", invite.pairing()));
        eprintln!(
            "the code in it works once, for two minutes: run modelpipe connect with the whole \
             pairing string on the device"
        );
    }
    if ephemeral && !no_state {
        // Printed every time rather than once, and to stderr so it
        // never lands in whatever the ticket was piped into. The
        // flag is the only thing standing between a paired laptop
        // and being re-paired after every reboot, and a flag nobody
        // hears about is a flag nobody uses.
        eprintln!(
            "note: this ticket dies when serve restarts — \
             pass --state-dir <dir> to keep it across restarts, or --no-state to say so"
        );
    }
    // The pairing string's code when there is an invite: a device
    // pairing from this screen needs the code as well as the ticket.
    let shown = invited.as_ref().map(|invite| invite.pairing().to_string());
    if !no_qr && let Some(code) = shown.as_deref().map_or_else(|| qr(&ticket), qr_of) {
        stdout::say(&format!("\n{code}"));
    }
    attend(&handle, keys, devices, invited, interrupt).await?;
    shut_down(handle.shutdown(), interrupt).await;
    Ok(())
}

/// Stay on the pipe until told to stop: at the keyboard when there is one,
/// and parked as ever when there is not.
async fn attend(
    handle: &Arc<ServeHandle>,
    keys: Option<Keys>,
    devices: Option<PathBuf>,
    invited: Option<Invite>,
    interrupt: &mut Interrupt,
) -> anyhow::Result<()> {
    let Some(keys) = keys else {
        if let Some(invite) = invited {
            tokio::spawn(pairing::watch(
                Arc::clone(handle),
                invite.handle(),
                invite.device().to_owned(),
                devices,
            ));
        }
        return park(&**handle, interrupt).await;
    };
    eprintln!("{HINT}");
    let controller = Controller::new(Arc::clone(handle), devices, invited);
    session::run(
        &**handle,
        controller,
        keys,
        interrupt.next(),
        std::io::stderr(),
    )
    .await
}

/// The backend to serve, and whether the operator said it may be private.
///
/// The permission rides on the backend rather than on the options: a URL
/// an operator typed is never self-permitting, so `--allow-private-backend`
/// is this explicit call and nothing else grants it.
fn backend(url: &str, allow_private: bool) -> modelpipe::BackendUrl {
    let backend = modelpipe::BackendUrl::dial(url);
    if allow_private {
        backend.allow_private()
    } else {
        backend
    }
}
