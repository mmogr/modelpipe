//! `modelpipe` CLI: thin face over the library crate. All behavior lives
//! in `modelpipe`; this file parses arguments and prints.

use clap::Parser as _;
use modelpipe::ConnectOptions;

mod cli;
mod controller;
mod devices;
mod diagnostics;
mod interrupt;
mod keys;
mod pairing;
mod park;
mod screen;
mod serve_cmd;
mod serve_out;
mod session;
mod state;
mod store;

use cli::{Cli, Command};
use interrupt::Interrupt;
use park::{park, shut_down};

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
        Command::Serve(args) => serve_cmd::run(args, &mut interrupt).await?,
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
