//! `modelpipe` CLI: thin face over the library crate. All behavior lives
//! in `modelpipe`; this file parses arguments and prints.

use std::sync::Arc;

use clap::Parser as _;
use modelpipe::{ConnectOptions, ServeOptions, TokenPolicy};

mod cli;
mod devices;
mod diagnostics;
mod interrupt;
mod pairing;
mod park;
mod serve_out;

use cli::{Cli, Command};
use interrupt::Interrupt;
use park::{park, shut_down};
use serve_out::{WAIT_ONLINE, print_token, qr, qr_of, token_policy, undialable};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // Before anything that might emit. The library's events go nowhere
    // until a subscriber exists, so a line installed after the first call
    // into `modelpipe` is a line that silently loses whatever happened
    // during it.
    diagnostics::install(cli.verbose);
    // Created before either subcommand runs and held across both phases, so
    // the signal that asks for shutdown and the one that gives up waiting
    // are heard by the same listener. On Unix that listener hears SIGINT
    // and SIGTERM alike, so `kill` and a service manager get the same drain
    // Ctrl-C gets.
    let mut interrupt = Interrupt::new()?;
    match cli.command {
        Command::Serve {
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
        } => {
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
            let handle = Arc::new(
                modelpipe::serve(backend(&backend_url, allow_private_backend), opts).await?,
            );
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
            park(&*handle, &mut interrupt).await?;
            shut_down(handle.shutdown(), &mut interrupt).await;
        }
        Command::Connect {
            ticket,
            name,
            identity,
            bind,
            relay,
            no_portmap,
            no_discovery,
            relay_only,
        } => {
            let given = pairing::parse(&ticket)?;
            if let Some(addr) = bind
                && !addr.ip().is_loopback()
            {
                // The local port is the one hop in the design with no
                // encryption in front of it; leaving loopback is a choice
                // worth a warning, not a guard.
                eprintln!(
                    "WARNING: binding {addr} exposes the pipe beyond this machine — anyone who can reach that port can reach the backend (with the token)"
                );
            }
            let mut opts = ConnectOptions::default();
            opts.bind = bind;
            opts.relay = relay;
            opts.port_mapping = !no_portmap;
            opts.discovery = !no_discovery;
            opts.relay_only = relay_only;
            opts.identity = identity;
            let mut handle = pairing::connect(&given, name.as_deref(), opts).await?;
            park(&mut handle, &mut interrupt).await?;
            shut_down(handle.shutdown(), &mut interrupt).await;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod main_tests;

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
