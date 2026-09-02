//! Tests for the CLI's flag surface and its two helpers.
//!
//! Split out via `#[path]` so `main.rs` stays inside the file-size budget.
//! What is checked here is the argument model and the pure functions behind
//! it — driving the binary itself is a job for the end-to-end suite in the
//! library crate, which already pairs two live sides.

use super::{Cli, Ticket, TokenPolicy, qr, token_policy};

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
