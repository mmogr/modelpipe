//! Tests for [`super::Superseded`] — the key a rotation left behind.
//!
//! Split out via `#[path]` so `superseded.rs` stays inside the file-size
//! budget, the arrangement `credential.rs` already uses.
//!
//! Deadlines are asserted with `Duration::ZERO` and a minute wherever one
//! answer will do, which is what `credential_tests.rs` does with grants and
//! is the reason none of this can flake. One test sleeps, deliberately:
//! zero and a minute are both consistent with an implementation that
//! special-cases zero and never looks at the clock again, and the whole
//! claim being made here is that a real deadline arrives.

use std::time::Duration;

use super::Superseded;

const OLD: &str = "sk-zzq-the-key-that-was-replaced";
const LONG: Duration = Duration::from_mins(1);

fn holding(token: &str) -> Superseded {
    let window = Superseded::new();
    window.hold(token.to_owned(), LONG);
    window
}

/// Nothing is held until a rotation puts something there, so a fresh
/// listener has one credential and not two.
#[test]
fn a_fresh_window_is_closed_and_admits_nothing() {
    let window = Superseded::new();
    assert!(!window.is_open());
    assert!(!window.admits(OLD.as_bytes()));
    assert!(!window.admits(b""));
}

/// The one property that distinguishes this from a grant: presenting the
/// key does not spend it, so the second machine to reconnect is not
/// refused for being second.
#[test]
fn a_held_key_admits_every_time_it_is_presented() {
    let window = holding(OLD);
    for attempt in 1..=5 {
        assert!(
            window.admits(OLD.as_bytes()),
            "presentation {attempt} was refused; this is not a one-shot credential"
        );
    }
    assert!(window.is_open(), "and the window is still open afterwards");
}

/// A window is an exception for one exact value, not a hole in the check.
#[test]
fn every_near_miss_is_still_refused() {
    let window = holding(OLD);
    for wrong in [
        "",
        " ",
        "sk-zzq-the-key-that-was-replace",   // a byte short
        "sk-zzq-the-key-that-was-replaced ", // a byte long
        "sk-zzq-the-key-that-was-replacec",  // the last byte wrong
        "SK-ZZQ-THE-KEY-THAT-WAS-REPLACED",  // case is not folded
        "sk-zzq-the-replacement",
    ] {
        assert!(
            !window.admits(wrong.as_bytes()),
            "{wrong:?} must not admit through the window"
        );
    }
}

// ── The deadline ─────────────────────────────────────────────────────────

/// A window of no width is a window that was never open — and the key is
/// not parked already-expired either, because nothing would sweep it on a
/// listener that is never asked again.
#[test]
fn a_key_held_for_no_time_at_all_is_not_held_at_all() {
    let window = Superseded::new();
    window.hold(OLD.to_owned(), Duration::ZERO);
    assert!(!window.admits(OLD.as_bytes()));
    assert!(!window.is_open());
    assert!(
        window.lock().is_none(),
        "a zero window must drop the key rather than park a dead secret"
    );
}

/// `Instant + Duration` panics on overflow, and `grace` arrives from a
/// public method's caller. `Duration::MAX` is how somebody writes "never
/// expire" — it must fail closed, not take the process down, and above all
/// not panic inside the enforced write lock and poison it.
#[test]
fn a_grace_the_clock_cannot_represent_holds_nothing_rather_than_panicking() {
    for absurd in [Duration::MAX, Duration::from_secs(u64::MAX / 2)] {
        let window = Superseded::new();
        window.hold(OLD.to_owned(), absurd);
        assert!(
            !window.admits(OLD.as_bytes()),
            "{absurd:?} must not become a permanent second credential"
        );
        assert!(window.lock().is_none());
    }
}

/// The deadline is a real `Instant` comparison and not a special case for
/// zero — see the sleeping note in this file's header.
#[test]
fn a_key_outlives_its_window_by_the_clock() {
    let window = Superseded::new();
    window.hold(OLD.to_owned(), Duration::from_millis(1));
    std::thread::sleep(Duration::from_millis(20));
    assert!(
        !window.admits(OLD.as_bytes()),
        "the window closed a clock tick ago and is still admitting"
    );
}

/// Expired means *gone*, not merely refused. Asserted against the slot
/// itself, because refusing is exactly what an implementation that kept
/// the retired secret in memory forever would also do. A real deadline
/// rather than `ZERO`, which is never stored in the first place.
#[test]
fn an_expired_key_is_dropped_rather_than_ignored() {
    let window = Superseded::new();
    window.hold(OLD.to_owned(), Duration::from_millis(1));
    assert!(
        window.lock().is_some(),
        "the key occupies the slot while its window is open"
    );
    std::thread::sleep(Duration::from_millis(20));

    assert!(!window.admits(OLD.as_bytes()));
    assert!(
        window.lock().is_none(),
        "an expired key must be dropped by the check that refused it"
    );
}

/// The same sweep on the `Debug` path, so a closed window never reads as
/// open and a listener nobody talks to still lets the secret go.
#[test]
fn asking_whether_a_window_is_open_also_drops_an_expired_key() {
    let window = Superseded::new();
    window.hold(OLD.to_owned(), Duration::from_millis(1));
    std::thread::sleep(Duration::from_millis(20));
    assert!(!window.is_open());
    assert!(window.lock().is_none());
}

// ── One slot ─────────────────────────────────────────────────────────────

/// Windows do not chain: the newest rotation retires the key the previous
/// one was protecting, so at most two values ever admit.
#[test]
fn a_second_hold_retires_the_first_key_rather_than_chaining() {
    let window = holding(OLD);
    window.hold("sk-zzq-the-first-replacement".to_owned(), LONG);

    assert!(
        !window.admits(OLD.as_bytes()),
        "the older key must not survive a second rotation"
    );
    assert!(window.admits(b"sk-zzq-the-first-replacement"));
}

/// Releasing is the immediate close, and it is what a plain rotation uses
/// to keep its own "the old value stops working immediately" promise.
#[test]
fn releasing_closes_an_open_window_at_once() {
    let window = holding(OLD);
    assert!(window.is_open());

    window.release();
    assert!(!window.admits(OLD.as_bytes()));
    assert!(!window.is_open());
    assert!(window.lock().is_none(), "and the key is gone, not parked");
}

/// Releasing a closed window is not an error, because a plain rotation
/// calls it unconditionally and most rotations have no window to close.
#[test]
fn releasing_nothing_is_allowed() {
    let window = Superseded::new();
    window.release();
    window.release();
    assert!(!window.is_open());
}
