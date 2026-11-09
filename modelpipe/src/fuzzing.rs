//! Entry points for the coverage-guided targets in `fuzz/`.
//!
//! Compiled only under `cfg(fuzzing)`, which cargo-fuzz sets, so it is not
//! part of the API and no normal build sees it. Each function takes the
//! fuzzer's bytes and panics only where the edge broke one of its rules.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

use crate::backend::Backend;
use crate::caller::Caller;
use crate::credential::Credential;
use crate::peer_id::PeerId;
use crate::token_policy::TokenPolicy;
use crate::{exchange, framing, http_head, oracle};

/// The token the [`exchange`] target's listener enforces.
pub const TOKEN: &str = "sk-fuzz-the-credential";

/// `data[1..]` as a chunked body, `data[0]` bytes of it already read with
/// the head. If the edge accepts it, httparse must read the same body.
pub fn chunked_body(data: &[u8]) {
    let Some((&split, input)) = data.split_first() else {
        return;
    };
    let (forwarded, out) = oracle::forward_chunked(input, usize::from(split));
    if let Ok(total) = forwarded {
        let read = oracle::chunked(&out).expect("httparse reads what the edge forwarded");
        assert_eq!(read.len() as u64, total, "and reads the same length");
    }
}

/// `data` as a request head and as a response head, and the framing of a
/// request head that parses. None of it may panic.
pub fn head(data: &[u8]) {
    if let Ok(Some((head, _))) = http_head::parse_request(data) {
        let _ = framing::framing(&head.headers, false);
        let _ = http_head::expects_continue(&head.headers);
    }
    if let Ok(Some((head, _))) = http_head::parse_response(data) {
        let _ = framing::response_framing(head.status, "GET", &head.headers);
    }
}

/// `data` as everything a client sends, through the whole edge to a
/// backend that answers at once.
///
/// What reaches the backend, if anything does, is a head httparse reads
/// whole, carrying the listener's token in exactly one `Authorization`: a
/// request without the token never contacts the backend at all.
pub fn exchange(data: &[u8]) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime");
    let received = runtime.block_on(async {
        let (credential, _) =
            Credential::new(&TokenPolicy::Supplied(TOKEN.to_owned())).expect("a usable token");
        let backend = Recording::default();
        let caller = Caller {
            id: PeerId::from_bytes([0x3c; 32]),
            name: "3ca82708b995".into(),
            at: PeerId::from_bytes([0xd7; 32]),
        };
        let (mut edge, mut client) = duplex(64 * 1024);
        client
            .write_all(data)
            .await
            .expect("the client side takes the input");
        // The client stops sending, and stops reading too: the edge sees the
        // end of the request and every write it makes back fails, as it
        // would to a client that hung up.
        drop(client);
        let _ = exchange::serve_exchange(&mut edge, &credential, &backend, &caller).await;
        drop(edge);
        backend.received().await
    });
    let Some(received) = received else {
        return;
    };
    let mut fields = [httparse::EMPTY_HEADER; 128];
    let mut request = httparse::Request::new(&mut fields);
    let parsed = request.parse(&received);
    assert!(
        matches!(parsed, Ok(httparse::Status::Complete(_))),
        "the backend was sent a head httparse cannot read: {parsed:?}"
    );
    let authorization: Vec<&[u8]> = request
        .headers
        .iter()
        .filter(|field| field.name.eq_ignore_ascii_case("authorization"))
        .map(|field| field.value)
        .collect();
    assert_eq!(
        authorization.len(),
        1,
        "exactly one credential goes upstream"
    );
    assert!(
        authorization[0]
            .windows(TOKEN.len())
            .any(|window| window == TOKEN.as_bytes()),
        "and it is the listener's token"
    );
}

/// A backend that answers every connection at once and records what it was
/// sent.
#[derive(Default)]
struct Recording {
    sent: Arc<Mutex<Option<tokio::task::JoinHandle<Vec<u8>>>>>,
}

impl Recording {
    /// What the backend was sent, or `None` when nothing connected.
    async fn received(&self) -> Option<Vec<u8>> {
        let handle = self.sent.lock().expect("not poisoned").take()?;
        Some(handle.await.expect("the backend task finishes"))
    }
}

impl Backend for Recording {
    type Stream = DuplexStream;

    fn authority(&self) -> &'static str {
        "127.0.0.1:11434"
    }

    async fn connect(&self) -> std::io::Result<DuplexStream> {
        let (mine, mut theirs) = duplex(64 * 1024);
        let handle = tokio::spawn(async move {
            let _ = theirs
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .await;
            let mut sent = Vec::new();
            let _ = theirs.read_to_end(&mut sent).await;
            sent
        });
        *self.sent.lock().expect("not poisoned") = Some(handle);
        Ok(mine)
    }
}
