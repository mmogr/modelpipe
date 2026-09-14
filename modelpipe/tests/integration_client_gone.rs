//! A client that hangs up, seen from the serve side's log, over a real pipe.
//!
//! The one integration binary that installs a subscriber, because the claim
//! is about what the serve side logs. Discovery and port mapping are off on
//! both sides.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{MockBackend, within};
use modelpipe::TokenPolicy;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

/// Everything logged in this binary.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("the log buffer")).into_owned()
    }
}

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("the log buffer")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl tracing_subscriber::fmt::MakeWriter<'_> for Captured {
    type Writer = Self;

    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn a_client_that_stops_reading_is_logged_as_gone_and_not_as_a_failure() {
    let log = Captured::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_writer(log.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    )
    .expect("the only subscriber in this binary");

    let (backend, _) = MockBackend::endless_stream().await;
    let mut serve_opts = common::serve_options();
    serve_opts.auth = TokenPolicy::Generate;
    let serving = within(
        "serve must bind",
        Box::pin(modelpipe::serve(&backend.url, serve_opts)),
    )
    .await
    .expect("serve");
    let token = serving.token().expect("a generated token");
    let connect_opts = common::connect_options();
    let connected = within(
        "connect must bind",
        Box::pin(modelpipe::connect(&serving.ticket(), connect_opts)),
    )
    .await
    .expect("connect");
    connected
        .wait_reachable(Duration::from_secs(20))
        .await
        .expect("the serve side is reached");

    // A client that reads the start of a streaming answer and hangs up, as
    // one ending a status subscription does.
    let url = connected.base_url();
    let authority = url
        .trim_start_matches("http://")
        .split('/')
        .next()
        .expect("authority");
    let mut client = TcpStream::connect(authority).await.expect("the local port");
    let request = format!(
        "GET /v1/events HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Bearer {token}\r\n\r\n"
    );
    client
        .write_all(request.as_bytes())
        .await
        .expect("the request");
    let mut start = [0u8; 64];
    let read = within("the answer must start", client.read(&mut start))
        .await
        .expect("a read");
    assert!(read > 0, "the answer started");
    drop(client);

    let text = within("the serve side must log the exchange's end", async {
        loop {
            let text = log.text();
            if text.contains("client_gone") || text.contains("exchange failed") {
                return text;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        text.contains("outcome=\"client_gone\""),
        "a client hanging up was not logged as gone:\n{text}"
    );
    assert!(
        !text.contains("exchange failed"),
        "a client hanging up was logged as a failure:\n{text}"
    );

    connected.shutdown().await;
    serving.shutdown().await;
}
