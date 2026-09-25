//! What `serve` works out and prints around its ticket: the credential policy
//! the flags ask for, the token line, the refusal for a ticket nobody could
//! dial, the QR code, and the hint on a backend refused as not local.
//!
//! Split from `main.rs` when the pairing flags pushed it past the file-size
//! budget. Moved as they were, apart from `qr_of`, which a pairing string needs
//! as much as a ticket does.

use std::path::PathBuf;
use std::time::Duration;

use modelpipe::{ServeError, Ticket, TokenPolicy};

use crate::stdout;

/// How long `serve` lets the endpoint look for a relay before minting the
/// ticket.
///
/// The ticket is printed once and carried to another machine by hand, so it
/// is worth a few seconds to find the relay first. Ten of them is what iroh
/// recommends waiting on a network report; running out is not an error, and
/// the library says nothing when it does. Named rather than written inline
/// because [`undialable`] quotes it, and a refusal that says how long this
/// waited must not be able to disagree with how long it waited.
pub(crate) const WAIT_ONLINE: Duration = Duration::from_secs(10);

/// Which credential policy a set of flags asks for.
///
/// Extracted rather than left inline so it can be tested: `conflicts_with`
/// is what makes the contradictory combinations unrepresentable, and a
/// function is the only way to check that this code relies on it correctly
/// without spawning a process.
pub(crate) fn token_policy(
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
pub(crate) fn token_line(supplied: bool, token: Option<String>) -> Option<String> {
    // Two spaces after the colon, aligning the value with the ticket's on
    // the line above. Both are meant to be read off a screen together.
    let token = token?;
    Some(if supplied {
        "token:  (supplied)".to_owned()
    } else {
        format!("token:  {token}")
    })
}

/// Why this ticket must not be printed, or `None` when it names somewhere a
/// holder could dial.
///
/// **Refused rather than printed with a warning beside it.** A ticket
/// carrying no addresses is not a weak ticket, it is an empty one: `connect`
/// has nothing to dial, so its holder gets `PeerUnreachable`, whose stock
/// explanation — off, offline, or its ticket replaced — names none of the
/// real causes. Print it and that failure surfaces on the *other* machine,
/// after the string has been scanned or pasted, with every piece of evidence
/// left behind on this one.
///
/// Being wrong costs differently in each direction, which is what settles
/// it. Refusing a listener whose relay was merely slower than
/// [`WAIT_ONLINE`] costs a re-run, and the re-run mints a better ticket;
/// printing one costs somebody else an afternoon on the wrong machine.
/// Keeping this string buys nothing either way — it never becomes dialable,
/// because a ticket minted once the relay is up carries the relay.
///
/// **The ticket's own address list is the test**, not the flag that usually
/// empties it. `--relay-only` clears every IP transport, so it is the one
/// switch under which an unreachable relay leaves nothing at all — but a
/// machine with no usable interface reaches the same ticket without it, and
/// a listener nobody can dial is the same refusal either way. The network
/// counters cannot stand in: iroh probes a relay before dialling it, so an
/// unreachable one starts no relay actor and moves nothing, which is why
/// `network_tests` reads zeros from an endpoint pointed at one.
pub(crate) fn undialable(ticket: &Ticket, relay_only: bool) -> Option<String> {
    if !ticket.relay_urls().is_empty() || !ticket.direct_addrs().is_empty() {
        return None;
    }
    let secs = WAIT_ONLINE.as_secs();
    Some(if relay_only {
        format!(
            "the ticket names nowhere, so nothing could dial it: --relay-only removed \
             every direct address and this endpoint reached no relay in {secs}s. Check \
             this machine's route to a relay (--relay <URL> names your own), or drop \
             --relay-only and pair over the LAN."
        )
    } else {
        format!(
            "the ticket names nowhere, so nothing could dial it: this endpoint reached \
             no relay in {secs}s and found no address of its own either. Check this \
             machine's network."
        )
    })
}

/// `serve`'s error as the operator reads it.
///
/// A backend refused as not local, with `--allow-private-backend` not
/// passed, gets a hint naming the flag: a private address is the one class
/// of refused backend that flag admits. Every other error, and this one
/// with the flag passed, is the library's own.
pub(crate) fn not_served(e: ServeError, allowed_private: bool) -> anyhow::Error {
    if !allowed_private && matches!(e, ServeError::BackendNotLocal { .. }) {
        return anyhow::anyhow!(
            "{e}. If the backend is on a private (RFC 1918 or ULA) address on your own \
             network, pass --allow-private-backend; a link-local or public address is refused \
             either way"
        );
    }
    e.into()
}

/// The ticket as a QR code, or `None` if it will not fit one.
///
/// Uppercased first, which is not cosmetic: QR alphanumeric mode encodes
/// only uppercase, and using it rather than byte mode makes the code
/// materially smaller and easier for a phone to read. That a scan of the
/// result still parses is the reason the ticket format requires parsers to
/// be case-insensitive over the whole string, prefix included.
pub(crate) fn qr(ticket: &Ticket) -> Option<String> {
    qr_of(&ticket.to_string())
}

/// `text` as a QR code, uppercased for the reason [`qr`] gives, or `None` if
/// it will not fit one. A pairing string is a ticket with a dash and six digits
/// after it, so it scans back the same way.
pub(crate) fn qr_of(text: &str) -> Option<String> {
    use qrcode::QrCode;
    use qrcode::render::unicode;

    let code = QrCode::new(text.to_uppercase()).ok()?;
    Some(code.render::<unicode::Dense1x2>().quiet_zone(true).build())
}

/// Print the token line, or warn on stderr that nothing is enforced.
///
/// A generated token whose write to stdout fails reaches nobody, and the
/// listener goes on enforcing it; stderr is told so, and never the token.
pub(crate) fn print_token(supplied: bool, token: Option<String>) {
    match token_line(supplied, token) {
        // Two lines, two credentials: the ticket and the token travel to
        // client machines separately on purpose.
        Some(line) => {
            if !stdout::say(&line) && !supplied {
                eprintln!(
                    "WARNING: the token was not printed: nothing is reading stdout, so no \
                     client holds it — restart serve to mint another"
                );
            }
        }
        None => eprintln!("WARNING: serving open — anyone holding the ticket can use your backend"),
    }
}
