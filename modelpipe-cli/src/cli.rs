//! The flag surface: what `modelpipe` accepts on its command line.
//!
//! Split from `main.rs` when the network flags arrived and pushed it past
//! the file-size budget, which is the gate doing its job: the argument
//! model and the code that acts on it are two things, and this is the
//! first. Everything here is declarative — clap derives, help text, the
//! conflicts that make contradictory combinations unrepresentable — and
//! `main_tests.rs` checks it stays internally consistent.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "modelpipe",
    version,
    about = "Your model server, from anywhere"
)]
pub(crate) struct Cli {
    /// Print more about what the pipe is doing; repeat for more still
    ///
    /// Once is a line per request. Twice adds the transport, which is where
    /// the answer lives when two machines will not pair. Set RUST_LOG to
    /// choose targets and levels yourself instead.
    // Backtick-free like the flags below: clap prints this verbatim.
    #[expect(clippy::doc_markdown, reason = "clap help text, not rustdoc")]
    // `global`, so it is accepted before or after the subcommand. An
    // operator who has already typed the whole `serve` line and wants more
    // detail appends `-v` to it, and a flag that only works in front of the
    // subcommand fails them for a reason they cannot see.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub(crate) verbose: u8,

    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Expose a local OpenAI-compatible server; prints a pairing ticket + token
    Serve {
        /// Backend base URL, e.g. http://127.0.0.1:11434. Host and port
        /// only — the request path comes from the client. Must resolve to
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
        /// Keep the endpoint key here so the ticket survives a restart
        ///
        /// Created on first use, readable only by you. Without it a fresh
        /// key is generated per run, so every restart mints a new ticket
        /// and every paired device has to be paired again. To revoke a
        /// leaked ticket, delete this file and restart.
        #[arg(long, value_name = "FILE")]
        identity: Option<PathBuf>,
        /// Do not print a QR code for the ticket
        #[arg(long)]
        no_qr: bool,
        /// Do not ask the router for a UPnP/NAT-PMP port mapping
        ///
        /// Skips the gateway probe (and the multicast that raises firewall
        /// dialogs on some desktops). Behind some NATs a connection falls
        /// back to the relay a little more often; pairing is unaffected.
        #[arg(long)]
        no_portmap: bool,
        /// Do not publish this endpoint to, or resolve peers through, n0's
        /// discovery service
        ///
        /// Removes that contact entirely. The ticket then carries every
        /// path its holder will ever have: it works on this LAN and via
        /// the relay it names, and stops working when this machine's
        /// addresses change. --identity buys nothing with this set.
        #[arg(long)]
        no_discovery: bool,
    },
    /// Bind a local port that is the remote server
    Connect {
        /// Pairing ticket printed by `serve`
        ticket: String,
        /// Local bind address (default: a free loopback port)
        #[arg(long)]
        bind: Option<std::net::SocketAddr>,
        /// Self-hosted relay URL for this side (default: iroh public relays)
        ///
        /// The serve side's relay is in the ticket and is dialled
        /// regardless; this is the one this endpoint registers with.
        #[arg(long)]
        relay: Option<String>,
        /// Do not ask the router for a UPnP/NAT-PMP port mapping
        #[arg(long)]
        no_portmap: bool,
        /// Do not resolve the peer through n0's discovery service; dial
        /// only the paths the ticket carries
        #[arg(long)]
        no_discovery: bool,
    },
}
