//! `modelpipe` CLI: thin face over the library crate. All behavior lives
//! in `modelpipe`; this file parses arguments and prints.

use clap::{Parser, Subcommand};
use modelpipe::{ConnectOptions, ServeOptions, Ticket, TokenPolicy};

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
        #[arg(long, conflicts_with = "insecure_no_auth")]
        token: Option<String>,
        /// Accept a backend on a private (RFC 1918) address, not just loopback
        #[arg(long)]
        allow_private_backend: bool,
        /// Self-hosted relay URL (default: iroh public relays)
        #[arg(long)]
        relay: Option<String>,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve {
            backend_url,
            insecure_no_auth,
            token,
            allow_private_backend,
            relay,
        } => {
            // Mutation rather than a struct literal: the options structs
            // are #[non_exhaustive], so a literal cannot cross the crate
            // boundary — which is the point, new options must not break
            // existing callers (this one included).
            let mut opts = ServeOptions::default();
            // clap's conflicts_with makes (Some, true) unrepresentable.
            opts.auth = match (token, insecure_no_auth) {
                (Some(t), _) => TokenPolicy::Supplied(t),
                (None, true) => TokenPolicy::InsecureNoAuth,
                (None, false) => TokenPolicy::Generate,
            };
            opts.allow_private_backend = allow_private_backend;
            opts.relay = relay;
            let handle = modelpipe::serve(&backend_url, opts).await?;
            println!("ticket: {}", handle.ticket());
            match handle.token() {
                // Two lines, two credentials: the ticket and the token
                // travel to client machines separately on purpose.
                Some(token) => println!("token:  {token}"),
                None => eprintln!(
                    "WARNING: serving open — anyone holding the ticket can use your backend"
                ),
            }
            // TODO: QR render, then park until ctrl-c; print status changes
            // (direct vs relayed) as status_changed() yields them.
            tokio::signal::ctrl_c().await?;
            handle.shutdown().await;
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
            let handle = modelpipe::connect(&ticket, opts).await?;
            println!("{}", handle.base_url());
            tokio::signal::ctrl_c().await?;
            handle.shutdown().await;
        }
    }
    Ok(())
}
