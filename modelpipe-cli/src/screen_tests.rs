//! Tests for the window: lines above, the footer beneath, rewritten in
//! place.

use super::Screen;

const CLEAR: &str = "\r\x1b[K";

fn text(out: Vec<u8>) -> String {
    String::from_utf8(out).expect("text")
}

#[test]
fn a_line_with_no_footer_is_just_a_line() {
    let mut out = Vec::new();
    {
        let mut screen = Screen::new(&mut out);
        screen.say("status: idle");
        screen.say("two\nlines");
    }
    assert_eq!(text(out), "status: idle\ntwo\nlines\n");
}

#[test]
fn the_footer_is_drawn_in_place_and_put_back_under_every_line() {
    let mut out = Vec::new();
    {
        let mut screen = Screen::new(&mut out);
        screen.footer(Some("1:59 left".to_owned()));
        screen.say("paired: dev-0a1b2c3d");
        screen.footer(Some("1:58 left".to_owned()));
        screen.footer(None);
        screen.say("after");
    }
    assert_eq!(
        text(out),
        format!(
            "{CLEAR}1:59 left{CLEAR}paired: dev-0a1b2c3d\n1:59 left{CLEAR}1:58 left{CLEAR}after\n"
        )
    );
}

/// The shell's prompt lands on a fresh line, never beside a countdown.
#[test]
fn a_footer_is_cleared_when_the_window_closes() {
    let mut out = Vec::new();
    {
        let mut screen = Screen::new(&mut out);
        screen.footer(Some("0:03 left".to_owned()));
    }
    assert_eq!(text(out), format!("{CLEAR}0:03 left{CLEAR}"));
    let mut out = Vec::new();
    {
        let mut screen = Screen::new(&mut out);
        screen.say("nothing on offer");
    }
    assert_eq!(text(out), "nothing on offer\n");
}
