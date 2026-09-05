//! `modelpipe` CLI: thin face over the library crate. All behavior lives
//! in `modelpipe`; this file parses arguments and prints.

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser as _;
use modelpipe::{ConnectOptions, ServeOptions, Ticket, TokenPolicy};

mod cli;
mod diagnostics;
mod interrupt;
mod park;

use cli::{Cli, Command};
use interrupt::Interrupt;
use park::{park, shut_down};

/// Which credential policy a set of flags asks for.
///
/// Extracted rather than left inline so it can be tested: `conflicts_with`
/// is what makes the contradictory combinations unrepresentable, and a
/// function is the only way to check that this code relies on it correctly
/// without spawning a process.
fn token_policy(
    token: Option<String>,
    token_file: Option<PathBuf>,
    insecure: bool,
) -> anyhow::Result<TokenPolicy> {
    Ok(match (token, token_file, insecure) {
        // An empty value is a misconfiguration, not an empty credential —
        // the same verdict `--token-file` has always given an empty file.
        // `MODELPIPE_TOKEN=` set but empty is the common way in: clap reads
        // an exported-but-empty variable as present, so the listener came
        // up enforcing `"Bearer "`, printed a blank `token:` line, and 401'd
        // every request afterwards with nothing to say why.
        (Some(t), _, _) if t.trim().is_empty() => {
            anyhow::bail!("the bearer token is empty — unset MODELPIPE_TOKEN or pass a value")
        }
        (Some(t), _, _) => TokenPolicy::Supplied(t),
        (None, Some(path), _) => {
            let raw = std::fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("could not read {}: {e}", path.display()))?;
            // Trailing newline trimmed, because every editor adds one and a
            // credential that differs from the file's visible contents by an
            // invisible byte is a bad afternoon.
            let trimmed = raw.trim_end_matches(['\n', '\r']).to_owned();
            if trimmed.is_empty() {
                anyhow::bail!("{} is empty", path.display());
            }
            TokenPolicy::Supplied(trimmed)
        }
        (None, None, true) => TokenPolicy::InsecureNoAuth,
        (None, None, false) => TokenPolicy::Generate,
    })
}

/// The `token:` line to print, or `None` when nothing is enforced.
///
/// A token the operator supplied is acknowledged rather than echoed. They
/// already hold it — that is what "supplied" means — so printing it back
/// buys nothing and costs the one thing `--token-file` exists to protect:
/// it puts the credential on stdout, which is the stream the README tells
/// people to pipe. `hide_env_values` on `--token` already refuses to render
/// a supplied credential in `--help`; this is the same rule applied to the
/// other place the value would otherwise surface.
///
/// A *generated* token is printed in full, because this is the only place
/// it exists. Withholding it would leave the listener enforcing a
/// credential nobody can present.
fn token_line(supplied: bool, token: Option<String>) -> Option<String> {
    // Two spaces after the colon, aligning the value with the ticket's on
    // the line above. Both are meant to be read off a screen together.
    let token = token?;
    Some(if supplied {
        "token:  (supplied)".to_owned()
    } else {
        format!("token:  {token}")
    })
}

/// The ticket as a QR code, or `None` if it will not fit one.
///
/// Uppercased first, which is not cosmetic: QR alphanumeric mode encodes
/// only uppercase, and using it rather than byte mode makes the code
/// materially smaller and easier for a phone to read. That a scan of the
/// result still parses is the reason the ticket format requires parsers to
/// be case-insensitive over the whole string, prefix included.
fn qr(ticket: &Ticket) -> Option<String> {
    use qrcode::QrCode;
    use qrcode::render::unicode;

    let code = QrCode::new(ticket.to_string().to_uppercase()).ok()?;
    Some(code.render::<unicode::Dense1x2>().quiet_zone(true).build())
}

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
        } => {
            // Mutation rather than a struct literal: the options structs
            // are #[non_exhaustive], so a literal cannot cross the crate
            // boundary — which is the point, new options must not break
            // existing callers (this one included).
            let mut opts = ServeOptions::default();
            opts.auth = token_policy(token, token_file, insecure_no_auth)?;
            // Read before `opts` is moved into `serve`, and the only thing
            // that survives it: all three supplying flags collapse into
            // `Supplied`, so this is the last point at which the CLI can
            // tell an operator's own credential from one minted here.
            let supplied = matches!(opts.auth, TokenPolicy::Supplied(_));
            opts.allow_private_backend = allow_private_backend;
            opts.relay = relay;
            let ephemeral = identity.is_none();
            opts.identity = identity;
            opts.port_mapping = !no_portmap;
            opts.discovery = !no_discovery;
            // The ticket below is printed once and carried to another
            // machine by hand, so it is worth a few seconds to let the
            // endpoint find its relay first. Ten of them is what iroh
            // recommends waiting on a network report; running out is not an
            // error, and `serve` says nothing when it does.
            opts.wait_online = Some(Duration::from_secs(10));

            // To stderr, and before the wait rather than after it, so a
            // terminal that is about to sit still for a moment says why.
            eprintln!("finding a relay…");
            let mut handle = modelpipe::serve(&backend_url, opts).await?;
            let ticket = handle.ticket();
            println!("ticket: {ticket}");
            match token_line(supplied, handle.token()) {
                // Two lines, two credentials: the ticket and the token
                // travel to client machines separately on purpose.
                Some(line) => println!("{line}"),
                None => eprintln!(
                    "WARNING: serving open — anyone holding the ticket can use your backend"
                ),
            }
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
            if !no_qr && let Some(code) = qr(&ticket) {
                println!("\n{code}");
            }
            park(&mut handle, &mut interrupt).await?;
            shut_down(handle.shutdown(), &mut interrupt).await;
        }
        Command::Connect {
            ticket,
            bind,
            relay,
            no_portmap,
            no_discovery,
        } => {
            let ticket: Ticket = ticket.parse()?;
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
            let mut handle = modelpipe::connect(&ticket, opts).await?;
            println!("{}", handle.base_url());
            park(&mut handle, &mut interrupt).await?;
            shut_down(handle.shutdown(), &mut interrupt).await;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod main_tests;
