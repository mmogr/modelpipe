//! The edge's own answer to a pairing request.
//!
//! A request whose target is exactly [`PAIR_PATH`](crate::PAIR_PATH) never
//! reaches the backend. The steps run in the order `docs/pairing-v0.md` gives,
//! and every refusal is the same bytes. Steps 1 to 3 refuse before any
//! `100 Continue` and before the body is read, which tells a client only about
//! its own bearer and endpoint. Among the code's refusals nothing differs, and
//! the one difference a code makes is the 200.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::caller::Caller;
use crate::credential::{Credential, bearer};
use crate::framing::Framing;
use crate::http_head::{self, RequestHead};
use crate::invites::Redeemed;
use crate::outcome::Outcome;
use crate::peer_id::PeerId;
use crate::refusal;
use crate::request_body;

/// The largest body a pairing request may carry: a label, not a payload.
const MAX_BODY: u64 = 4 * 1024;

/// The longest label kept, in characters.
const MAX_LABEL: usize = 64;

/// Answer one pairing request on `stream`.
///
/// `deadline` is the one the head was read under, and the body has to arrive
/// inside it as well.
pub(crate) async fn answer<S>(
    stream: &mut S,
    head: &RequestHead,
    leftover: Vec<u8>,
    framing: Framing,
    credential: &Credential,
    peer: &Caller,
    deadline: tokio::time::Instant,
) -> std::io::Result<Outcome>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // 1 and 2. A POST, with nothing but a short label for a body.
    let length = match framing {
        _ if head.method != "POST" => None,
        Framing::Empty => Some(0),
        Framing::Length(n) if n <= MAX_BODY => Some(n),
        Framing::Length(_) | Framing::Chunked | Framing::UntilClose => None,
    };
    let Some(length) = length else {
        return refuse(stream).await;
    };
    // 3. A key this listener already holds, or an endpoint a pinned token
    //    names, belongs to a device that has paired. Its key must never count
    //    as a strike against a code.
    let offered = http_head::authorization(&head.headers);
    let holds = !credential.serves_open() && credential.admits(offered, peer.id).is_some();
    if holds || credential.pinned_to(peer.id) {
        return refuse(stream).await;
    }
    request_body::continue_if_expected(stream, http_head::expects_continue(&head.headers)).await?;
    // 4. The body, whole, before any code is looked at, so a redemption is
    //    never spent on a request that then fails.
    let Ok(Ok(body)) = tokio::time::timeout_at(deadline, read_body(stream, leftover, length)).await
    else {
        return refuse(stream).await;
    };
    let Ok(text) = String::from_utf8(body) else {
        return refuse(stream).await;
    };
    // 5. The code.
    let redeemed = bearer(offered).and_then(|presented| {
        credential
            .invites()
            .redeem(presented, peer.id, label(&text))
    });
    let Some(redeemed) = redeemed else {
        return refuse(stream).await;
    };
    tracing::Span::current().record("device", redeemed.device.as_str());
    stream.write_all(&paired(&redeemed, peer.at)).await?;
    stream.flush().await?;
    Ok(Outcome::Paired)
}

/// The one refusal, whatever refused.
async fn refuse<S: AsyncWrite + Unpin>(stream: &mut S) -> std::io::Result<Outcome> {
    refusal::send(stream, refusal::pairing_refused(), Outcome::Unauthorized).await
}

/// `length` bytes of body, starting with what arrived with the head.
async fn read_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    leftover: Vec<u8>,
    length: u64,
) -> std::io::Result<Vec<u8>> {
    let length = usize::try_from(length).map_err(std::io::Error::other)?;
    let mut body = leftover;
    if body.len() >= length {
        body.truncate(length);
        return Ok(body);
    }
    let start = body.len();
    body.resize(length, 0);
    stream.read_exact(&mut body[start..]).await?;
    Ok(body)
}

/// The 200 that hands a device its key.
///
/// Every value is from a safe alphabet — a minted key is base32, a name is a
/// token name, a peer id is hex — so nothing here needs escaping.
fn paired(redeemed: &Redeemed, serving: PeerId) -> Vec<u8> {
    let body = format!(
        r#"{{"api_key":"{}","device_id":"{}","peer":"{serving}"}}"#,
        redeemed.key, redeemed.device
    );
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// A label fit to keep: invisible characters dropped, cut to [`MAX_LABEL`]
/// characters, then trimmed. Empty means none.
fn label(text: &str) -> Option<String> {
    let cleaned: String = text
        .chars()
        .filter(|c| !is_invisible(*c))
        .take(MAX_LABEL)
        .collect();
    let trimmed = cleaned.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// Characters a label has no use for and a terminal or a browser would act
/// on: the controls, the bidirectional overrides and isolates, which let one
/// device's name render as another's, the zero-width characters, the line and
/// paragraph separators, and the byte-order mark.
fn is_invisible(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{feff}')
}

#[cfg(test)]
#[path = "pair_route_tests.rs"]
mod pair_route_tests;
