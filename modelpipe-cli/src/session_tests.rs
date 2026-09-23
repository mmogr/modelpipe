//! Tests for the session, driven through a scripted keyboard and a status
//! source under the test's control, over a real listener.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use modelpipe::{NetworkMetrics, PipeStatus, ServeOptions, TokenPolicy};

use super::{HINT, run};
use crate::controller::Controller;
use crate::keys::{Got, Keys};
use crate::park::AsyncStatus;

/// A pipe that reports `now` and then never changes.
struct Still(PipeStatus);

impl AsyncStatus for Still {
    fn current(&self) -> PipeStatus {
        self.0
    }

    fn metrics(&self) -> NetworkMetrics {
        NetworkMetrics::default()
    }

    async fn changed(&mut self) -> PipeStatus {
        std::future::pending().await
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "modelpipe-cli-session-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir.join("devices.json")
}

/// The keys are acted on in order, each answer reaches the window, and the
/// session ends when told to.
#[tokio::test]
async fn the_keys_invite_list_and_forget_and_the_window_says_so() {
    let mut opts = ServeOptions::default();
    opts.auth = TokenPolicy::Named;
    opts.port_mapping = false;
    opts.discovery = false;
    let serving = Arc::new(
        modelpipe::serve("http://127.0.0.1:9", opts)
            .await
            .expect("serve"),
    );
    let controller = Controller::new(Arc::clone(&serving), Some(scratch("keys")), None);
    let (done, over) = tokio::sync::oneshot::channel();
    let keys = Keys::scripted(
        &[
            Got::Key('l'),
            Got::Key('?'),
            Got::Key('i'),
            Got::Key('i'),
            Got::Key('l'),
            Got::Key('f'),
            Got::Line("1".to_owned()),
            Got::Key('l'),
            Got::Key('x'),
        ],
        done,
    );
    let mut out = Vec::new();
    let ended = tokio::time::timeout(
        Duration::from_secs(20),
        run(
            Still(PipeStatus::Idle),
            controller,
            keys,
            async {
                let _ = over.await;
                Ok(())
            },
            &mut out,
        ),
    )
    .await
    .expect("the session ends when told");
    ended.expect("cleanly");
    serving.shutdown().await;

    let shown = String::from_utf8(out).expect("text");
    let order = [
        "status: idle",
        "no devices yet",
        HINT,
        "a code for dev-",
        "pairing: pipe",
        "is still on offer",
        "code on offer",
        "forget which?",
        "its code is withdrawn",
        "no devices yet",
    ];
    let mut from = 0;
    for expected in order {
        let at = shown[from..]
            .find(expected)
            .unwrap_or_else(|| panic!("{expected:?} missing after byte {from}: {shown}"));
        from += at + expected.len();
    }
    assert!(serving.token_names().is_empty());
}
