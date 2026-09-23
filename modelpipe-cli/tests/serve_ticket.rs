//! Driving the binary, because a decision is only worth something if `main`
//! reaches it.
//!
//! `main_tests.rs` pins what `undialable` decides and cannot pin that it is
//! consulted: deleting the call in `main` leaves every unit test in this
//! crate green. That is the failure mode this workspace has hit before —
//! `integration_pipe.rs` exists for the library's half of it — so the two
//! tests here run the real binary and read the two streams a person reads.
//!
//! **Hermetic apart from one address.** The relay named below is a loopback
//! port nothing listens on, so the relay handshake fails without a route to
//! the internet; discovery and port-mapping are switched off, so nothing
//! else is contacted; and the backend URL is only resolved, never dialled,
//! because `serve` checks the address is local at startup and connects when
//! a request arrives. The one environmental thing
//! `a_ticket_that_names_somewhere_is_printed` needs is a non-loopback
//! address on this machine, which is what it asserts it found when it fails.
//!
//! Each test costs the ten seconds `main` spends letting the endpoint look
//! for the relay it will not find.
//!
//! **Nothing here touches the real data directory.** Every run either says
//! `--no-state` or is given a `HOME` of its own under the temp directory, so
//! a test never reads a developer's identity, never leaves one behind, and
//! never finds the lock another test holds.

use std::io::{BufRead as _, BufReader, Read as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The binary cargo built for this test — not one found on `PATH`, which
/// would be whatever was last `cargo install`ed.
const BIN: &str = env!("CARGO_BIN_EXE_modelpipe");

/// A backend that resolves to loopback. Nothing listens on it and nothing
/// needs to: the startup check resolves the address and screens it, and the
/// first connection is made by the first request, which never arrives here.
const BACKEND: &str = "http://127.0.0.1:9";

/// A relay URL that parses and answers nothing, so `wait_online` runs out.
/// The same value `network_tests` uses, for the same reason.
const DEAD_RELAY: &str = "https://127.0.0.1:1/";

/// How long a test waits for the child to print a ticket or give up.
///
/// Four times the ten seconds it should take, because the number that
/// matters is not this one: a machine under load may be slow, and what this
/// guards is *what* the child said rather than how quickly it said it. What
/// it buys is a failure instead of a suite that hangs when neither thing
/// happens.
const PATIENCE: Duration = Duration::from_secs(40);

/// What one run of `modelpipe serve` said before it printed a ticket or
/// ended.
struct Run {
    /// Everything it wrote to stdout — the stream the README tells people to
    /// pipe, and the one a ticket must not reach when it names nowhere.
    stdout: Vec<String>,
    /// Everything it wrote to stderr, including anyhow's `Error:` line.
    stderr: String,
    /// `Some(success)` if the child ended on its own, `None` if it was still
    /// running when a ticket appeared and had to be killed.
    exit: Option<bool>,
}

/// Run `serve` open and stateless with `extra` until it prints a ticket or
/// exits, whichever comes first, then take the process away.
///
/// Stopping at the first ticket line is what lets one helper serve both
/// tests: a listener that printed one goes on to park forever, and a
/// listener that refused one has already exited. Both endings are answers,
/// and running out of [`PATIENCE`] is neither.
fn serve(extra: &[&str]) -> Run {
    let (run, _) = serve_with(
        BACKEND,
        &["--insecure-no-auth", "--no-state"],
        extra,
        &[],
        false,
    );
    run
}

/// [`serve`] with everything a test may want to choose: the backend, how it
/// authenticates, the environment, and whether the child is left running
/// for the caller to end — which the lock tests need, since the lock is
/// held only while the process lives.
fn serve_with(
    backend: &str,
    auth: &[&str],
    extra: &[&str],
    env: &[(&str, &Path)],
    keep: bool,
) -> (Run, Option<Child>) {
    let mut child = Command::new(BIN)
        .args(["serve", backend])
        .args(auth)
        .args(["--no-qr", "--no-discovery", "--no-portmap"])
        .args(["--relay", DEAD_RELAY])
        .args(extra)
        // Neither may leak in from the developer's shell: the first would
        // move the default folder out from under `HOME`, the second would
        // name a folder outright.
        .env_remove("XDG_DATA_HOME")
        .env_remove("MODELPIPE_STATE_DIR")
        .envs(env.iter().map(|(k, v)| (*k, *v)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary cargo just built has to run");

    // A thread, because the line has to be seen *while* the child runs: the
    // interesting case is the one where it never ends on its own, so reading
    // stdout to EOF would be reading it until the deadline.
    let out = child.stdout.take().expect("piped above");
    let (lines, incoming) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if lines.send(line).is_err() {
                break;
            }
        }
    });

    let deadline = Instant::now() + PATIENCE;
    let mut stdout = Vec::new();
    let mut exit = None;
    loop {
        match incoming.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => {
                let ticket = line.starts_with("ticket:");
                stdout.push(line);
                if ticket {
                    break;
                }
            }
            // The child closed stdout without exiting yet. Nothing more will
            // arrive on this channel, so the wait moves to `try_wait` — and
            // sleeps, because a disconnected `recv_timeout` returns at once.
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if let Some(status) = child.try_wait().expect("the child is ours to wait on") {
            exit = Some(status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "`serve {extra:?}` neither printed a ticket nor exited within {PATIENCE:?}"
        );
    }

    if exit.is_none() && keep {
        // Left running, with what it has said so far. The reader thread ends
        // with the child, whenever the caller ends it.
        drop(incoming);
        return (
            Run {
                stdout,
                stderr: String::new(),
                exit,
            },
            Some(child),
        );
    }
    if exit.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    // After the kill, so the reader has seen the end of the stream; before
    // the join, because the join is what proves it has.
    while let Ok(line) = incoming.try_recv() {
        stdout.push(line);
    }
    drop(incoming);
    let _ = reader.join();

    let mut stderr = String::new();
    // The child is dead by now either way, so this reads to a real EOF.
    child
        .stderr
        .take()
        .expect("piped above")
        .read_to_string(&mut stderr)
        .expect("stderr is not binary");
    (
        Run {
            stdout,
            stderr,
            exit,
        },
        None,
    )
}

#[cfg(unix)]
/// A home of this test's own under the temp directory, so the default state
/// folder lands there and nowhere near a person's.
fn home(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("modelpipe-cli-home-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch home");
    dir
}

#[cfg(unix)]
/// Where the default state folder for [`BACKEND`] is, under `home`.
fn default_state(home: &Path) -> PathBuf {
    let data = if cfg!(target_os = "macos") {
        home.join("Library").join("Application Support")
    } else {
        home.join(".local").join("share")
    };
    data.join("modelpipe").join("127.0.0.1_9")
}

#[cfg(unix)]
/// The environment that puts the default state folder under `home`: `HOME`
/// is what both macOS and the XDG fallback read, and [`serve_with`] clears
/// `XDG_DATA_HOME` so a developer's own does not win over it.
fn at(home: &Path) -> Vec<(&'static str, &Path)> {
    vec![("HOME", home)]
}

/// `--relay-only` on a host that reached no relay mints a ticket with no
/// addresses in it, and the CLI refuses it instead of printing it.
///
/// The whole of the point is that the refusal reaches stdout as *nothing*.
/// A ticket that names nowhere is undialable, and printing it moves the
/// failure to the machine it is carried to, where `connect` reports
/// `PeerUnreachable` — "off, offline, or its ticket replaced" — and names
/// none of what actually happened.
#[test]
fn a_ticket_that_names_nowhere_is_refused_rather_than_printed() {
    let run = serve(&["--relay-only"]);

    assert_eq!(
        run.exit,
        Some(false),
        "serve must fail rather than park on a listener nobody can dial; \
         stdout was {:?} and stderr {:?}",
        run.stdout,
        run.stderr
    );
    assert!(
        run.stdout.is_empty(),
        "nothing may reach the stream people pipe: {:?}",
        run.stdout
    );
    assert!(
        run.stderr.contains("names nowhere") && run.stderr.contains("--relay-only"),
        "the refusal has to name the real cause: {:?}",
        run.stderr
    );
}

/// The same dead relay without `--relay-only`: the endpoint keeps its own
/// addresses, so the ticket names somewhere and is printed.
///
/// The negative control for the test above, and the one that catches an
/// inverted call site — a check reading `is_none()` refuses every good
/// ticket and passes every assertion in the other test. It is also the only
/// thing that says a missing relay is by itself not a refusal, which is the
/// state of every ticket for the first second of its life.
///
/// This is the one test in the file that asks something of the machine it
/// runs on: an endpoint whose only interface is loopback advertises no
/// address, and there is no such thing as a dialable ticket from there.
#[test]
fn a_ticket_that_names_somewhere_is_printed() {
    let run = serve(&[]);

    assert_eq!(
        run.exit, None,
        "serve had to still be running, having printed {:?} and said {:?}",
        run.stdout, run.stderr
    );
    let ticket = run
        .stdout
        .iter()
        .find(|line| line.starts_with("ticket:"))
        .unwrap_or_else(|| {
            panic!(
                "no ticket was printed — does this machine have a non-loopback \
                 address? stdout {:?}, stderr {:?}",
                run.stdout, run.stderr
            )
        });
    assert!(
        ticket.contains("pipe"),
        "and it has to be a ticket: {ticket:?}"
    );
}

/// With `--named` and no flags about state, a serve keeps its endpoint key
/// under the platform's data directory, in a folder readable only by its
/// owner, and says where.
#[cfg(unix)]
#[test]
fn state_is_kept_under_the_data_directory_by_default() {
    use std::os::unix::fs::PermissionsExt as _;
    let home = home("default");
    let (run, _) = serve_with(BACKEND, &["--named"], &[], &at(&home), false);
    assert_eq!(run.exit, None, "{:?} {:?}", run.stdout, run.stderr);
    let state = default_state(&home);
    assert!(
        run.stderr.contains(&format!("state: {}", state.display())),
        "{:?}",
        run.stderr
    );
    assert!(state.join("identity").is_file(), "{}", state.display());
    assert!(state.join("lock").is_file(), "{}", state.display());
    let mode = std::fs::metadata(&state)
        .expect("the folder")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);
    assert!(
        !run.stderr.contains("dies when serve restarts"),
        "{:?}",
        run.stderr
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// A second serve on the same backend is refused while the first runs, and
/// one on another backend comes up beside it.
#[cfg(unix)]
#[test]
fn one_serve_per_backend_holds_the_default_folder() {
    let home = home("lock");
    let (first, child) = serve_with(BACKEND, &["--named"], &[], &at(&home), true);
    let mut child = child.expect("the first is left running");
    assert_eq!(first.exit, None, "{:?}", first.stdout);

    let (second, _) = serve_with(BACKEND, &["--named"], &[], &at(&home), false);
    assert_eq!(
        second.exit,
        Some(false),
        "{:?} {:?}",
        second.stdout,
        second.stderr
    );
    assert!(
        second.stderr.contains("another modelpipe serve is using")
            && second.stderr.contains(&format!("pid {}", child.id())),
        "{:?}",
        second.stderr
    );
    assert!(second.stdout.is_empty(), "{:?}", second.stdout);

    let (other, _) = serve_with("http://127.0.0.1:10", &["--named"], &[], &at(&home), false);
    assert_eq!(other.exit, None, "{:?} {:?}", other.stdout, other.stderr);

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&home);
}

/// `--no-state` keeps nothing, and serving open keeps nothing unless asked:
/// a ticket that is the only lock there is has no business surviving a
/// restart by default.
#[cfg(unix)]
#[test]
fn no_state_and_serving_open_leave_the_data_directory_alone() {
    let home = home("none");
    let (named, _) = serve_with(BACKEND, &["--named", "--no-state"], &[], &at(&home), false);
    assert_eq!(named.exit, None, "{:?} {:?}", named.stdout, named.stderr);
    let (open, _) = serve_with(BACKEND, &["--insecure-no-auth"], &[], &at(&home), false);
    assert_eq!(open.exit, None, "{:?} {:?}", open.stdout, open.stderr);
    assert!(
        open.stderr.contains("dies when serve restarts"),
        "{:?}",
        open.stderr
    );
    assert!(
        !default_state(&home).exists(),
        "{} was created",
        default_state(&home).display()
    );
    let _ = std::fs::remove_dir_all(&home);
}
