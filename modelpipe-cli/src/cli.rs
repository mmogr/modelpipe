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
    Serve(ServeArgs),
    /// Put the Ollama on this machine on your other devices: one word, no flags
    ///
    /// serve with a key per device and everything kept across restarts. The
    /// first run shows a code for your first device; after that, i in the
    /// window offers a code for one more, l lists them and f forgets one.
    Ollama(OllamaArgs),
    /// Bind a local port that is the remote server
    Connect {
        /// Pairing ticket printed by `serve`, or a pairing string to pair with
        ticket: String,
        /// What this device calls itself when it pairs; the serve side shows it
        #[arg(long, value_name = "LABEL")]
        name: Option<String>,
        /// Keep this side's endpoint key here, so the serve side sees the same device
        ///
        /// Created on first use, readable only by you, and refused if it is a
        /// symlink or anything else but a regular file. Without it a fresh key
        /// is generated per run, and a serve side that pins a device's key to
        /// its endpoint refuses the next one.
        #[arg(long, value_name = "FILE")]
        identity: Option<PathBuf>,
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
        /// Reach the peer through the relay only, never directly
        ///
        /// As for serve, and it takes only one side: with no IP transport
        /// here the ticket's direct addresses are unreachable, so the relay
        /// is what is left. Needs no re-pairing — the ticket is untouched.
        #[arg(long)]
        relay_only: bool,
    },
}

/// What `serve` takes: its own struct rather than fields on the variant, so
/// that the command that runs it can be handed the lot, and so that a
/// subcommand which is `serve` with the answers filled in can build one.
// Flags are what a command line is made of, and every one of these is a
// switch the operator either typed or did not; a struct of them is the
// honest shape.
#[expect(clippy::struct_excessive_bools, reason = "a flag surface")]
#[derive(clap::Args)]
pub(crate) struct ServeArgs {
    /// Backend base URL, e.g. http://127.0.0.1:11434. Host and port
    /// only — the request path comes from the client. Must resolve to
    /// loopback (or a private address, with --allow-private-backend)
    // Bare URL on purpose: clap prints this doc comment verbatim as
    // `--help` text, where rustdoc's `<…>` link syntax would show up as
    // literal angle brackets in `modelpipe serve --help`.
    #[expect(clippy::doc_markdown, reason = "clap help text, not rustdoc")]
    pub(crate) backend_url: String,
    /// Serve without a bearer token. The name is the warning.
    #[arg(long)]
    pub(crate) insecure_no_auth: bool,
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
    pub(crate) token: Option<String>,
    /// Read the bearer token from this file, trimming trailing newline
    #[arg(long, conflicts_with_all = ["insecure_no_auth", "token"])]
    pub(crate) token_file: Option<PathBuf>,
    /// Hold a key per device instead of one token for everybody
    ///
    /// No token is generated or printed. Pair a device with --invite, and
    /// keep paired devices across restarts with --devices.
    #[arg(long, conflicts_with_all = ["insecure_no_auth", "token", "token_file"])]
    pub(crate) named: bool,
    /// Print a pairing string that a device redeems once for its own key
    ///
    /// The ticket, a dash and a six-digit code. The code works once, for
    /// two minutes, and serve says on stderr how it ended. Needs --named.
    /// In a terminal, pressing i while serve runs does the same at any
    /// time; l lists the devices and f forgets one.
    #[arg(long, requires = "named")]
    pub(crate) invite: bool,
    /// Offer a code at startup when no device has ever paired: what
    /// `ollama` means by a first run. Not a flag; `serve` has --invite.
    #[arg(skip)]
    pub(crate) invite_if_none: bool,
    /// Keep the devices record in this file, so a restart admits them
    ///
    /// JSON, one row per device ever invited: its key, when it was invited,
    /// when it paired and from where. Created on first use, readable only
    /// by you, and refused if others can read it or if it is a symlink or
    /// anything else but a regular file. Needs --named.
    #[arg(long, value_name = "FILE", requires = "named")]
    pub(crate) devices: Option<PathBuf>,
    /// Accept a backend on a private (RFC 1918) address, not just loopback
    #[arg(long)]
    pub(crate) allow_private_backend: bool,
    /// Self-hosted relay URL (default: iroh public relays)
    #[arg(long)]
    pub(crate) relay: Option<String>,
    /// Keep the endpoint key in this file instead of the state folder
    ///
    /// Created on first use, readable only by you, and refused if it is a
    /// symlink or anything else but a regular file. To revoke a leaked
    /// ticket, delete the file and restart: every device then pairs again.
    #[arg(long, value_name = "FILE")]
    pub(crate) identity: Option<PathBuf>,
    /// Keep everything that survives a restart in this folder
    ///
    /// The endpoint key, and with --named the devices record, in a folder
    /// of their own per backend under DIR, created readable only by you.
    /// One serve at a time holds a backend's folder. Unless this says
    /// otherwise the folder is $XDG_DATA_HOME/modelpipe, or
    /// ~/.local/share/modelpipe (macOS: ~/Library/Application
    /// Support/modelpipe). --identity and --devices each override their
    /// file's place in it.
    // Backtick-free like the rest: clap prints this verbatim.
    #[expect(clippy::doc_markdown, reason = "clap help text, not rustdoc")]
    #[arg(long, value_name = "DIR", env = "MODELPIPE_STATE_DIR")]
    pub(crate) state_dir: Option<PathBuf>,
    /// Keep nothing across restarts: a fresh ticket, and no devices record
    ///
    /// Restarting is then revocation, as it was before 0.8: every ticket
    /// handed out names a peer nobody is, and every device pairs again.
    #[arg(long, conflicts_with = "state_dir")]
    pub(crate) no_state: bool,
    /// Do not print a QR code for the ticket
    #[arg(long)]
    pub(crate) no_qr: bool,
    /// Do not ask the router for a UPnP/NAT-PMP port mapping
    ///
    /// Skips the gateway probe (and the multicast that raises firewall
    /// dialogs on some desktops). Behind some NATs a connection falls
    /// back to the relay a little more often; pairing is unaffected.
    #[arg(long)]
    pub(crate) no_portmap: bool,
    /// Do not publish this endpoint to, or resolve peers through, n0's
    /// discovery service
    ///
    /// Removes that contact entirely. The ticket then carries every
    /// path its holder will ever have: it works on this LAN and via
    /// the relay it names, and stops working when this machine's
    /// addresses change. --identity buys nothing with this set.
    #[arg(long)]
    pub(crate) no_discovery: bool,
    /// Serve through the relay only, never directly
    ///
    /// A measuring switch, not a production one. Whether hole punching
    /// works is the far NAT's decision, so relayed is the case you
    /// cannot reproduce on demand; this makes it the only path, so what
    /// it costs can be read off a status line on any network. The
    /// ticket then carries the relay and no direct addresses — and if
    /// no relay is reached, no addresses at all, which serve refuses to
    /// print rather than hand you a ticket nobody could dial.
    #[arg(long)]
    pub(crate) relay_only: bool,
}

/// What `ollama` takes: the few things worth choosing when the backend is
/// Ollama at its usual address and the rest is decided.
#[expect(clippy::struct_excessive_bools, reason = "a flag surface")]
#[derive(clap::Args)]
pub(crate) struct OllamaArgs {
    /// Where Ollama listens, if not its default
    #[arg(long, value_name = "URL", default_value = "http://127.0.0.1:11434")]
    pub(crate) backend: String,
    /// Accept a backend on a private (RFC 1918) address, not just loopback
    #[arg(long)]
    pub(crate) allow_private_backend: bool,
    /// Keep the endpoint key and the devices record under this folder
    ///
    /// Otherwise the data directory: see modelpipe serve --help.
    #[arg(long, value_name = "DIR", env = "MODELPIPE_STATE_DIR")]
    pub(crate) state_dir: Option<PathBuf>,
    /// Do not print a QR code for the pairing string
    #[arg(long)]
    pub(crate) no_qr: bool,
    /// Self-hosted relay URL (default: iroh public relays)
    #[arg(long)]
    pub(crate) relay: Option<String>,
    /// Do not ask the router for a UPnP/NAT-PMP port mapping
    #[arg(long)]
    pub(crate) no_portmap: bool,
    /// Do not publish this endpoint to, or resolve peers through, n0's
    /// discovery service
    #[arg(long)]
    pub(crate) no_discovery: bool,
}

impl OllamaArgs {
    /// The `serve` this stands for: a key per device, the state kept, and a
    /// code offered at startup when no device has ever paired.
    pub(crate) fn into_serve(self) -> ServeArgs {
        ServeArgs {
            backend_url: self.backend,
            insecure_no_auth: false,
            token: None,
            token_file: None,
            named: true,
            invite: false,
            invite_if_none: true,
            devices: None,
            allow_private_backend: self.allow_private_backend,
            relay: self.relay,
            identity: None,
            state_dir: self.state_dir,
            no_state: false,
            no_qr: self.no_qr,
            no_portmap: self.no_portmap,
            no_discovery: self.no_discovery,
            relay_only: false,
        }
    }
}
