//! Serve with the keyboard on: parked on the pipe as ever, and answering
//! `i`, `l` and `f` while it is.
//!
//! `park` is the loop for a serve nobody is typing at; this is the same
//! loop with three more things to wait on — a key, the code on offer
//! ending, and the second hand while one is on offer — and a window to
//! draw them in. It ends the way `park` ends: on the signal, or when the
//! pipe closes.

use std::future::Future;
use std::io::Write;
use std::time::Duration;

use modelpipe::PipeStatus;

use crate::controller::{Controller, Offer, clock};
use crate::keys::{Got, Keys};
use crate::park::{AsyncStatus, throttle_line};
use crate::screen::Screen;
use crate::serve_out::qr_of;

/// What the keys are, said once when the session starts and again on `?`.
pub(crate) const HINT: &str = "press i to invite a device, l to list them, f to forget one";

/// Run the session until `until` resolves or the pipe closes.
///
/// `until` is the shutdown signal in `main`, and whatever a test wants.
pub(crate) async fn run(
    mut status: impl AsyncStatus,
    mut controller: Controller,
    mut keys: Keys,
    until: impl Future<Output = anyhow::Result<()>>,
    out: impl Write,
) -> anyhow::Result<()> {
    let mut screen = Screen::new(out);
    let mut reported = 0;
    report(&mut screen, status.current(), &status, &mut reported);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut keyboard = true;
    let mut until = std::pin::pin!(until);
    loop {
        tokio::select! {
            r = &mut until => {
                r?;
                return Ok(());
            }
            next = status.changed() => {
                report(&mut screen, next, &status, &mut reported);
                if next == PipeStatus::Closed {
                    return Ok(());
                }
            }
            got = keys.next(), if keyboard => {
                match got {
                    Some(Got::Key(key)) => {
                        if !press(key, &mut controller, &mut keys, &mut screen).await {
                            keyboard = false;
                        }
                    }
                    Some(Got::Line(_) | Got::Closed) | None => keyboard = false,
                }
            }
            outcome = controller.ended() => {
                let said = controller.settle(&outcome);
                screen.footer(None);
                screen.say(&said);
            }
            _ = tick.tick(), if controller.left().is_some() => {
                screen.footer(controller.left().map(countdown));
            }
        }
    }
}

/// Act on a key. Whether the keyboard is still usable afterwards.
async fn press(
    key: char,
    controller: &mut Controller,
    keys: &mut Keys,
    screen: &mut Screen<impl Write>,
) -> bool {
    match key {
        'i' => match controller.invite() {
            Ok(offer) => show(&offer, screen),
            Err(e) => screen.say(&format!("could not invite a device: {e:#}")),
        },
        'l' => match controller.list() {
            Ok(lines) => screen.say(&lines.join("\n")),
            Err(e) => screen.say(&format!("could not read the devices: {e:#}")),
        },
        'f' => {
            match controller.list() {
                Ok(lines) => screen.say(&lines.join("\n")),
                Err(e) => screen.say(&format!("could not read the devices: {e:#}")),
            }
            screen.say("forget which? its number or name, or nothing to keep them all");
            // The line is typed on the bottom line, so the countdown gets
            // out of its way and comes back once the answer is in.
            screen.footer(None);
            let Some(who) = keys.line().await else {
                return false;
            };
            match controller.forget(&who) {
                Ok(done) => screen.say(&done),
                Err(e) => screen.say(&format!("{e:#}")),
            }
            screen.footer(controller.left().map(countdown));
        }
        '?' | 'h' => screen.say(HINT),
        _ => {}
    }
    true
}

/// Show a code: the pairing string, its QR, and the countdown under it.
fn show(offer: &Offer, screen: &mut Screen<impl Write>) {
    let lead = if offer.again {
        format!("the code for {} is still on offer", offer.device)
    } else {
        format!(
            "a code for {}: it works once, and expires unused",
            offer.device
        )
    };
    let mut text = format!("{lead}\npairing: {}", offer.pairing);
    if let Some(code) = qr_of(&offer.pairing) {
        text.push('\n');
        text.push_str(code.trim_end_matches('\n'));
    }
    text.push('\n');
    text.push_str("run modelpipe connect with the whole pairing string on the device");
    screen.say(&text);
    screen.footer(Some(countdown(offer.left)));
}

/// The bottom line while a code is on offer.
fn countdown(left: Duration) -> String {
    format!("code on offer, {} left — i shows it again", clock(left))
}

/// The status line `park` prints, and the relay correction under it when
/// there is news, into the window rather than straight to stderr.
fn report(
    screen: &mut Screen<impl Write>,
    status: PipeStatus,
    source: &impl AsyncStatus,
    reported: &mut u64,
) {
    let metrics = source.metrics();
    let mut text = format!("status: {}", status.as_str());
    if let Some(line) = throttle_line(*reported, metrics) {
        *reported = metrics.relay_connections_ratelimited;
        text.push('\n');
        text.push_str(&line);
    }
    screen.say(&text);
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod session_tests;
