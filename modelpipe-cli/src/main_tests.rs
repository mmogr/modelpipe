//! Tests for the CLI's flag surface and its two helpers.
//!
//! Split out via `#[path]` so `main.rs` stays inside the file-size budget.
//! What is checked here is the argument model and the pure functions behind
//! it — driving the binary itself is a job for the end-to-end suite in the
//! library crate, which already pairs two live sides.

use clap::Parser as _;

use super::{Cli, Ticket, TokenPolicy, qr, token_line, token_policy};

/// clap's own consistency checks are debug-only, so they are compiled
/// out of the `cargo install` binary whose `--help` this defines. This
/// is where they actually run.
#[test]
fn the_flag_surface_is_internally_consistent() {
    use clap::CommandFactory;
    Cli::command().debug_assert();
}

/// `conflicts_with` makes the contradictory combinations unrepresentable
/// at the parser; this checks the code below relies on that correctly
/// rather than re-deriving it.
#[test]
fn a_supplied_token_wins_and_absence_generates_one() {
    assert!(matches!(
        token_policy(Some("k".to_owned()), None, false).unwrap(),
        TokenPolicy::Supplied(t) if t == "k"
    ));
    assert!(matches!(
        token_policy(None, None, false).unwrap(),
        TokenPolicy::Generate
    ));
    assert!(matches!(
        token_policy(None, None, true).unwrap(),
        TokenPolicy::InsecureNoAuth
    ));
}

/// Every editor adds a trailing newline, and a credential differing from
/// the file's visible contents by an invisible byte is a bad afternoon.
#[test]
fn a_token_file_is_read_and_its_trailing_newline_trimmed() {
    let dir = std::env::temp_dir().join(format!("modelpipe-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    for (contents, expected) in [
        ("secret", "secret"),
        ("secret\n", "secret"),
        ("secret\r\n", "secret"),
        ("secret\n\n", "secret"),
    ] {
        let path = dir.join("token");
        std::fs::write(&path, contents).unwrap();
        assert!(
            matches!(
                token_policy(None, Some(path.clone()), false).unwrap(),
                TokenPolicy::Supplied(t) if t == expected
            ),
            "{contents:?} should yield {expected:?}"
        );
    }

    // An empty file is a misconfiguration, not an empty credential.
    let path = dir.join("token");
    std::fs::write(&path, "\n").unwrap();
    assert!(token_policy(None, Some(path), false).is_err());

    let missing = dir.join("does-not-exist");
    assert!(token_policy(None, Some(missing), false).is_err());
    std::fs::remove_dir_all(&dir).ok();
}

/// The QR carries the uppercased ticket so it can use alphanumeric
/// mode, and the format's case-insensitivity is what makes the scan
/// parse back to the same ticket.
#[test]
fn the_qr_encodes_an_uppercased_ticket_that_still_parses() {
    // A ticket string from the format spec's own vectors.
    let text = "pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaaauhlp2na";
    let ticket: Ticket = text.parse().expect("a normative vector");

    let upper = ticket.to_string().to_uppercase();
    assert_eq!(
        upper.parse::<Ticket>().expect("the scan must parse"),
        ticket,
        "an upcased ticket is the same ticket"
    );
    assert!(qr(&ticket).is_some(), "and it must fit a QR code");
}

/// An empty value is a misconfiguration, not an empty credential.
///
/// `--token-file` has always said so about an empty file; `--token` and
/// `MODELPIPE_TOKEN` did not, and clap reads an exported-but-empty variable
/// as present. So `export MODELPIPE_TOKEN=` — one stray keystroke in a
/// shell profile — brought up a listener enforcing exactly `"Bearer "`,
/// which httparse's trailing-whitespace trim makes unpresentable, printed a
/// blank `token:` line, and refused every request afterwards with nothing
/// to say why.
#[test]
fn an_empty_supplied_token_is_refused_rather_than_enforced() {
    for empty in ["", " ", "\t", "\n"] {
        assert!(
            token_policy(Some(empty.to_owned()), None, false).is_err(),
            "{empty:?} must not become a credential"
        );
    }
    // And the guard is narrow: a token that merely *contains* whitespace is
    // the operator's business, not ours.
    assert!(matches!(
        token_policy(Some(" sk-real ".to_owned()), None, false).unwrap(),
        TokenPolicy::Supplied(t) if t == " sk-real "
    ));
}

/// `--help` must not print the credential. clap renders `[env: NAME=value]`
/// by default, so an operator asking how the flag works got the token
/// echoed into their terminal — and into wherever they pasted the output.
#[test]
fn the_help_text_never_renders_the_environment_token() {
    use clap::CommandFactory;

    let serve = Cli::command();
    let serve = serve
        .get_subcommands()
        .find(|c| c.get_name() == "serve")
        .expect("serve");
    let token = serve
        .get_arguments()
        .find(|a| a.get_id() == "token")
        .expect("--token");
    assert!(
        token.is_hide_env_values_set(),
        "`--help` would print the value of MODELPIPE_TOKEN"
    );
}

/// `-v` has to work where an operator actually types it.
///
/// The realistic sequence is that the whole `serve` line already exists and
/// more detail is wanted, so `-v` is appended to the end of it. A flag that
/// is only accepted in front of the subcommand fails exactly that person,
/// with a usage error that does not explain itself. `global = true` is what
/// makes both work, and it is one attribute away from not being there.
#[test]
fn verbosity_is_accepted_on_either_side_of_the_subcommand() {
    let leading = Cli::try_parse_from(["modelpipe", "-vv", "serve", "http://127.0.0.1:11434"])
        .expect("-vv before the subcommand");
    let trailing = Cli::try_parse_from(["modelpipe", "serve", "http://127.0.0.1:11434", "-vv"])
        .expect("-vv after the subcommand");
    assert_eq!(leading.verbose, 2);
    assert_eq!(trailing.verbose, 2);
}

/// The negative control for the test above: a count that ignored its input
/// and returned 2 would pass it.
#[test]
fn verbosity_counts_what_was_typed() {
    let none = Cli::try_parse_from(["modelpipe", "serve", "http://127.0.0.1:11434"]).expect("none");
    let one =
        Cli::try_parse_from(["modelpipe", "serve", "http://127.0.0.1:11434", "-v"]).expect("one");
    let spelled = Cli::try_parse_from([
        "modelpipe",
        "serve",
        "http://127.0.0.1:11434",
        "--verbose",
        "--verbose",
        "--verbose",
    ])
    .expect("the long form, thrice");
    assert_eq!((none.verbose, one.verbose, spelled.verbose), (0, 1, 3));
}

/// A credential the operator supplied is acknowledged, never echoed.
///
/// `--token-file` and `MODELPIPE_TOKEN` exist so the value stays out of
/// `argv`, where `ps` and shell history can read it. Printing it to stdout
/// afterwards hands it straight back to the place the flags were chosen to
/// avoid — and the README tells people to pipe that stream.
#[test]
fn a_supplied_token_is_named_rather_than_printed() {
    let line = token_line(true, Some("sk-secret".to_owned())).expect("auth is on");
    assert_eq!(line, "token:  (supplied)");
    assert!(
        !line.contains("sk-secret"),
        "the supplied credential must not reach stdout: {line}"
    );
}

/// The other half, and the reason this is not simply "never print a token":
/// a generated one exists nowhere else, so withholding it would leave the
/// listener enforcing a credential nobody can present.
#[test]
fn a_generated_token_is_printed_in_full() {
    assert_eq!(
        token_line(false, Some("sk-minted".to_owned())).expect("auth is on"),
        "token:  sk-minted"
    );
}

/// Serving open has no token to name, and the caller turns that into the
/// warning on stderr rather than a line on stdout.
#[test]
fn serving_open_produces_no_token_line() {
    assert!(token_line(false, None).is_none());
    assert!(token_line(true, None).is_none());
}

/// Both lines are read off a screen together, so the value column has to
/// line up. `ticket: ` is eight characters; `token:  ` matches it with two
/// spaces, and a single-space "fix" would silently un-align them.
#[test]
fn the_token_line_aligns_with_the_ticket_line() {
    let token = token_line(false, Some("x".to_owned())).expect("auth is on");
    let ticket = "ticket: pipeabc";
    assert_eq!(
        token.find('x'),
        ticket.find('p'),
        "the value columns must agree: {token:?} vs {ticket:?}"
    );
}
