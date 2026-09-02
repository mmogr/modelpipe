//! `modelpipe` CLI: thin face over the library crate. All behavior lives
//! in `modelpipe`; this file parses arguments and prints.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use modelpipe::{ConnectOptions, PipeStatus, ServeOptions, Ticket, TokenPolicy};

mod interrupt;

use interrupt::Interrupt;

#[derive(Parser)]
#[command(
    name = "modelpipe",
    version,
    about = "Your model server, from anywhere"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Expose a local OpenAI-compatible server; prints a pairing ticket + token
    Serve {
        /// Backend base URL, e.g. http://127.0.0.1:11434. Must resolve to
        /// loopback (or a private address, with --allow-private-backend)
        // Bare URL on purpose: clap prints this doc comment verbatim as
        // `--help` text, where rustdoc's `<…>` link syntax would show up as
        // literal angle brackets in `modelpipe serve --help`.
        #[expect(clippy::doc_markdown, reason = "clap help text, not rustdoc")]
        backend_url: String,
        /// Serve without a bearer token. The name is the warning.
        #[arg(long)]
        insecure_no_auth: bool,
        /// Require this existing bearer token instead of generating one
        ///
        /// Also read from MODELPIPE_TOKEN. Prefer that or --token-file: a
        /// value passed here is visible in ps and lands in shell history.
        // Backtick-free for the same reason as backend_url above: clap
        // prints this verbatim, and backticks would appear as backticks.
        #[expect(clippy::doc_markdown, reason = "clap help text, not rustdoc")]
        // `hide_env_values` because clap otherwise renders the variable's
        // *value* into `--help`: an operator running `modelpipe serve
        // --help` with MODELPIPE_TOKEN set printed the credential to their
        // terminal, and into whatever they pasted the help text into.
        #[arg(
            long,
            env = "MODELPIPE_TOKEN",
            hide_env_values = true,
            conflicts_with = "insecure_no_auth"
        )]
        token: Option<String>,
        /// Read the bearer token from this file, trimming trailing newline
        #[arg(long, conflicts_with_all = ["insecure_no_auth", "token"])]
        token_file: Option<PathBuf>,
        /// Accept a backend on a private (RFC 1918) address, not just loopback
        #[arg(long)]
        allow_private_backend: bool,
        /// Self-hosted relay URL (default: iroh public relays)
        #[arg(long)]
        relay: Option<String>,
        /// Do not print a QR code for the ticket
        #[arg(long)]
        no_qr: bool,
    },
    /// Bind a local port that is the remote server
    Connect {
        /// Pairing ticket printed by `serve`
        ticket: String,
        /// Local bind address (default: a free loopback port)
        #[arg(long)]
        bind: Option<std::net::SocketAddr>,
    },
}

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

/// Park until Ctrl-C, reporting transport changes as they happen.
///
/// `Relayed` is worth surfacing: it explains latency, and a user who does
/// not know their traffic is going through a relay has no way to guess why
/// the pipe feels slow.
async fn park(mut status: impl AsyncStatus, interrupt: &mut Interrupt) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            r = interrupt.next() => {
                r?;
                return Ok(());
            }
            next = status.changed() => {
                eprintln!("status: {}", next.as_str());
                if next == PipeStatus::Closed {
                    return Ok(());
                }
            }
        }
    }
}

/// Shut down gracefully, unless the operator asks again.
///
/// The graceful path can legitimately take a while — it is waiting for
/// admitted requests to finish, which is the whole promise — so the second
/// Ctrl-C has to be able to stop waiting. Dropping the handle is the cut,
/// and returning from here does exactly that.
async fn shut_down(handle: impl Future<Output = ()>, interrupt: &mut Interrupt) {
    tokio::select! {
        () = handle => {}
        _ = interrupt.next() => {
            eprintln!("interrupted again — cutting rather than waiting");
        }
    }
}

/// The one thing `park` needs from either handle.
///
/// A trait here rather than in the library: the two handles deliberately
/// share none, and inventing a public one to save a few lines in a CLI
/// would put it on a surface that has to live with it.
trait AsyncStatus {
    fn changed(&mut self) -> impl Future<Output = PipeStatus>;
}

impl AsyncStatus for modelpipe::ServeHandle {
    async fn changed(&mut self) -> PipeStatus {
        self.status_changed().await
    }
}

impl AsyncStatus for modelpipe::ConnectHandle {
    async fn changed(&mut self) -> PipeStatus {
        self.status_changed().await
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // Created before either subcommand runs and held across both phases, so
    // the interrupt that asks for shutdown and the one that gives up
    // waiting are heard by the same listener.
    let mut interrupt = Interrupt::new()?;
    match cli.command {
        Command::Serve {
            backend_url,
            insecure_no_auth,
            token,
            token_file,
            allow_private_backend,
            relay,
            no_qr,
        } => {
            // Mutation rather than a struct literal: the options structs
            // are #[non_exhaustive], so a literal cannot cross the crate
            // boundary — which is the point, new options must not break
            // existing callers (this one included).
            let mut opts = ServeOptions::default();
            opts.auth = token_policy(token, token_file, insecure_no_auth)?;
            opts.allow_private_backend = allow_private_backend;
            opts.relay = relay;

            let mut handle = modelpipe::serve(&backend_url, opts).await?;
            let ticket = handle.ticket();
            println!("ticket: {ticket}");
            match handle.token() {
                // Two lines, two credentials: the ticket and the token
                // travel to client machines separately on purpose.
                Some(token) => println!("token:  {token}"),
                None => eprintln!(
                    "WARNING: serving open — anyone holding the ticket can use your backend"
                ),
            }
            if !no_qr && let Some(code) = qr(&ticket) {
                println!("\n{code}");
            }
            park(&mut handle, &mut interrupt).await?;
            shut_down(handle.shutdown(), &mut interrupt).await;
        }
        Command::Connect { ticket, bind } => {
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
            let mut handle = modelpipe::connect(&ticket, opts).await?;
            println!("{}", handle.base_url());
            park(&mut handle, &mut interrupt).await?;
            shut_down(handle.shutdown(), &mut interrupt).await;
        }
    }
    Ok(())
}

impl<T: AsyncStatus> AsyncStatus for &mut T {
    async fn changed(&mut self) -> PipeStatus {
        (**self).changed().await
    }
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod main_tests;
