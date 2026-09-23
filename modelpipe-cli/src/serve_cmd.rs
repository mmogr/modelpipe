//! The `serve` command, from the flags to the parked pipe.
//!
//! Split from `main.rs` so that the file which parses what the operator
//! typed is not also the file that acts on it. Everything `serve` does after
//! clap is done lives here, in the order it happens, and `main` calls it
//! once.

use std::sync::Arc;

use modelpipe::{ServeOptions, TokenPolicy};

use crate::cli::ServeArgs;
use crate::interrupt::Interrupt;
use crate::pairing;
use crate::park::{park, shut_down};
use crate::serve_out::{WAIT_ONLINE, print_token, qr, qr_of, token_policy, undialable};

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
        devices,
    } = args;
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
    println!("ticket: {ticket}");
    let invited = if named {
        // A key per device, so no token for everybody to print.
        match pairing::start(&handle, invite, devices.as_deref()) {
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
    if ephemeral {
        // Printed every time rather than once, and to stderr so it
        // never lands in whatever the ticket was piped into. The
        // flag is the only thing standing between a paired laptop
        // and being re-paired after every reboot, and a flag nobody
        // hears about is a flag nobody uses.
        eprintln!(
            "note: this ticket dies when serve restarts — \
             pass --identity <file> to keep it across restarts"
        );
    }
    // The pairing string's code when there is an invite: a device
    // pairing from this screen needs the code as well as the ticket.
    if !no_qr && let Some(code) = invited.as_deref().map_or_else(|| qr(&ticket), qr_of) {
        println!("\n{code}");
    }
    park(&*handle, interrupt).await?;
    shut_down(handle.shutdown(), interrupt).await;
    Ok(())
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
