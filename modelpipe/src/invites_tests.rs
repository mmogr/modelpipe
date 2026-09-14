//! Tests for [`super::Invites`]: redeeming, strikes, lockout, burning, and an
//! outcome published once.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use super::*;

const DEVICE: PeerId = PeerId::from_bytes([1; 32]);
const STRANGER: PeerId = PeerId::from_bytes([2; 32]);

fn later() -> Instant {
    Instant::now() + Duration::from_mins(2)
}

/// An armed invite for `device`, whose key is `sk-zzq-` and the device.
fn armed(invites: &Invites, device: &str, wrong_codes: u8) -> Registered {
    let registered = invites.register(
        device.to_owned(),
        format!("sk-zzq-{device}"),
        later(),
        wrong_codes,
    );
    invites.arm(registered.id);
    registered
}

/// A six-digit code equal to none of `live`.
fn miss(live: &[&Registered]) -> String {
    (0..1_000_000)
        .map(|n| format!("{n:06}"))
        .find(|code| live.iter().all(|r| r.code.as_str() != code))
        .expect("a million codes are not all live")
}

fn ended(registered: &Registered) -> Option<InviteOutcome> {
    registered.outcome.borrow().clone()
}

#[test]
fn an_armed_code_redeems_once_and_then_is_a_miss() {
    let invites = Invites::default();
    let invite = armed(&invites, "dev-a", 3);
    let code = invite.code.as_str().as_bytes();

    let redeemed = invites
        .redeem(code, DEVICE, Some("Laptop".to_owned()))
        .expect("redeems");
    assert_eq!(redeemed.device, "dev-a");
    assert_eq!(redeemed.key, "sk-zzq-dev-a");
    assert_eq!(
        ended(&invite),
        Some(InviteOutcome::Redeemed {
            device: "dev-a".to_owned(),
            peer: DEVICE,
            label: Some("Laptop".to_owned()),
        })
    );
    assert!(invites.redeem(code, DEVICE, None).is_none(), "spent");
    assert_eq!(invites.count(), 0);
}

/// Nothing may tell a guesser that a code exists before it is armed, so an
/// unarmed code is an ordinary wrong code, and counts as one.
#[test]
fn an_unarmed_code_is_a_wrong_code() {
    let invites = Invites::default();
    let invite = invites.register("dev-a".to_owned(), "sk".to_owned(), later(), 1);
    let code = invite.code.as_str().as_bytes();

    assert!(invites.redeem(code, STRANGER, None).is_none(), "not armed");
    invites.arm(invite.id);
    assert!(
        invites.redeem(code, STRANGER, None).is_none(),
        "its one wrong code went on the unarmed presentation"
    );
    assert!(
        invites.redeem(code, DEVICE, None).is_some(),
        "another endpoint redeems"
    );
}

#[test]
fn wrong_codes_lock_out_one_endpoint_and_not_another() {
    let invites = Invites::default();
    let invite = armed(&invites, "dev-a", 3);
    let wrong = miss(&[&invite]);

    for _ in 0..3 {
        assert!(invites.redeem(wrong.as_bytes(), STRANGER, None).is_none());
    }
    assert!(
        invites
            .redeem(invite.code.as_str().as_bytes(), STRANGER, None)
            .is_none(),
        "locked out, right code or not"
    );
    assert_eq!(ended(&invite), None, "and the invite lives on");
    assert!(
        invites
            .redeem(invite.code.as_str().as_bytes(), DEVICE, None)
            .is_some()
    );
}

/// Counting stops at the bound, so no number of presentations wraps a count
/// round to fresh guesses.
#[test]
fn a_locked_out_endpoint_is_refused_however_often_it_presents() {
    let invites = Invites::default();
    let invite = armed(&invites, "dev-a", 3);
    let wrong = miss(&[&invite]);

    for _ in 0..300 {
        let _ = invites.redeem(wrong.as_bytes(), STRANGER, None);
    }
    assert_eq!(
        invites.lock().strikes.get(&STRANGER),
        Some(&3),
        "counting stopped at three"
    );
    assert!(
        invites
            .redeem(invite.code.as_str().as_bytes(), STRANGER, None)
            .is_none()
    );
}

#[test]
fn a_sixty_fifth_striker_burns_every_live_invite() {
    let invites = Invites::default();
    let first = armed(&invites, "dev-a", 3);
    let second = armed(&invites, "dev-b", 3);
    let wrong = miss(&[&first, &second]);

    for n in 0..64u8 {
        let striker = PeerId::from_bytes([n.wrapping_add(10); 32]);
        assert!(invites.redeem(wrong.as_bytes(), striker, None).is_none());
    }
    assert_eq!(invites.count(), 2, "sixty-four strikers burn nothing");
    assert!(
        invites
            .redeem(wrong.as_bytes(), PeerId::from_bytes([200; 32]), None)
            .is_none()
    );
    assert_eq!(ended(&first), Some(InviteOutcome::Burned));
    assert_eq!(ended(&second), Some(InviteOutcome::Burned));
    assert_eq!(invites.count(), 0);
}

#[test]
fn expiry_withdrawal_and_redemption_each_end_an_invite_once() {
    let invites = Invites::default();

    let expired = invites.register("dev-a".to_owned(), "k".to_owned(), Instant::now(), 3);
    invites.expire(expired.id);
    assert_eq!(ended(&expired), Some(InviteOutcome::Expired));
    invites.withdraw(expired.id);
    assert_eq!(
        ended(&expired),
        Some(InviteOutcome::Expired),
        "the first ending keeps"
    );

    let withdrawn = armed(&invites, "dev-b", 3);
    invites.withdraw_device("dev-b");
    assert_eq!(ended(&withdrawn), Some(InviteOutcome::Withdrawn));
    assert!(
        invites
            .redeem(withdrawn.code.as_str().as_bytes(), DEVICE, None)
            .is_none()
    );

    let redeemed = armed(&invites, "dev-c", 3);
    invites
        .redeem(redeemed.code.as_str().as_bytes(), DEVICE, None)
        .expect("redeems");
    invites.withdraw(redeemed.id);
    invites.expire(redeemed.id);
    assert!(matches!(
        ended(&redeemed),
        Some(InviteOutcome::Redeemed { .. })
    ));
}

/// An invite's timer is its clock: expiring it ends it, whatever the system
/// clock says of its deadline.
#[test]
fn an_invite_whose_timer_fires_expires_whatever_the_clock_reads() {
    let invites = Invites::default();
    let invite = armed(&invites, "dev-a", 3);
    invites.expire(invite.id);
    assert_eq!(ended(&invite), Some(InviteOutcome::Expired));
}

/// An invite whose time has passed is swept by the next presentation, even
/// before its expiry task has run.
#[test]
fn an_expired_invite_is_swept_by_the_next_presentation() {
    let invites = Invites::default();
    let invite = invites.register("dev-a".to_owned(), "k".to_owned(), Instant::now(), 3);
    invites.arm(invite.id);
    assert!(
        invites
            .redeem(invite.code.as_str().as_bytes(), DEVICE, None)
            .is_none()
    );
    assert_eq!(ended(&invite), Some(InviteOutcome::Expired));
}

#[test]
fn live_invites_never_share_a_code() {
    let invites = Invites::default();
    let registered: Vec<Registered> = (0..500)
        .map(|n| invites.register(format!("dev-{n}"), "k".to_owned(), later(), 3))
        .collect();
    let codes: HashSet<&str> = registered.iter().map(|r| r.code.as_str()).collect();
    assert_eq!(codes.len(), 500);
}

/// A code another live invite holds is drawn again, however often it comes
/// up.
#[test]
fn a_code_already_live_is_drawn_again() {
    let invites = Invites::default();
    let first = invites.register("dev-a".to_owned(), "k".to_owned(), later(), 3);
    let taken = first.code;
    let fresh: PairingCode = if taken.as_str() == "123456" {
        "654321"
    } else {
        "123456"
    }
    .parse()
    .expect("a code");
    // Drawn from the end: the live code twice, then a fresh one.
    let mut draws = vec![fresh.clone(), taken.clone(), taken];
    let second = invites.register_drawing("dev-b".to_owned(), "k".to_owned(), later(), 3, || {
        draws.pop().expect("drawn at most three times")
    });

    assert_eq!(second.code, fresh);
    assert!(
        draws.is_empty(),
        "the live code was drawn twice and redrawn each time"
    );
}

#[test]
fn strikes_are_forgotten_when_no_invite_is_live() {
    let invites = Invites::default();
    let first = armed(&invites, "dev-a", 1);
    let wrong = miss(&[&first]);
    let _ = invites.redeem(wrong.as_bytes(), STRANGER, None);
    invites.withdraw(first.id);

    let second = armed(&invites, "dev-b", 1);
    assert!(
        invites
            .redeem(second.code.as_str().as_bytes(), STRANGER, None)
            .is_some(),
        "a new round starts with no strikes"
    );
}
