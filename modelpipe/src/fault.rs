//! Which half of a copy gave out.
//!
//! One question, asked by [`crate::request_body`] and answered nowhere
//! else. It lives apart because it is a different kind of thing from its
//! caller: that module orchestrates two streams against each other, and
//! this one is a plain wrapper that remembers a single fact about one of
//! them.
//!
//! The fact is not available any other way. [`crate::body::forward`] returns
//! one flat `io::Error` whether the source ran out or the sink refused, and
//! the crate has already ruled on telling two failures apart by inspecting
//! them — see [`crate::backend`], where `Unreachable` exists so that a
//! distinction is not left resting on message text. Wrapping the sink
//! instead makes the answer structural: every error either came from a call
//! this module saw or it did not, and the complement is exact.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;

/// Which half of the copy gave out.
///
/// A verdict rather than an error, because the errors themselves cannot
/// answer it: [`crate::body::forward`] returns one flat `io::Error` whether the
/// source ran out or the sink refused, and the crate has already ruled on
/// telling two failures apart by message text — see [`crate::backend`],
/// where `Unreachable` exists for exactly that reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fault {
    /// The client's bytes stopped early, or its framing was unreadable.
    Client,
    /// The backend stopped taking bytes.
    Backend,
}

/// A sink that remembers whether *it* was the half that gave out.
///
/// This is what makes the verdict complete rather than a heuristic. Every
/// error out of [`crate::body::forward`] either came from a `dst` call or it did
/// not, so marking the `dst` calls makes the complement *exactly* "the
/// client's bytes or the client's framing". Watching the source instead
/// could not work: the case that matters most — a body shorter than its
/// declared length — is not a source error at all. `Buffered::fill`
/// reports a clean end and [`crate::body::forward`] *synthesizes* the
/// `UnexpectedEof` afterwards, so a source-side watcher would see nothing.
pub(crate) struct Watched<'a, W> {
    inner: &'a mut W,
    failed: bool,
}

impl<'a, W> Watched<'a, W> {
    pub(crate) const fn new(inner: &'a mut W) -> Self {
        Self {
            inner,
            failed: false,
        }
    }

    /// Who to charge, read *before* any shutdown is attempted.
    ///
    /// The ordering is load-bearing and is pinned by a test.
    /// `poll_shutdown` can fail on its own account — `ENOTCONN` on a socket
    /// the peer has already reset is the ordinary case — and it goes
    /// through the same flag, so asking afterwards would turn every client
    /// fault on a reset connection into a backend one, which is a 502 in
    /// place of the 400 the client is owed.
    pub(crate) const fn fault(&self) -> Fault {
        if self.failed {
            Fault::Backend
        } else {
            Fault::Client
        }
    }
}

// Only the three methods are overridden, deliberately: leaving
// `poll_write_vectored` and `is_write_vectored` at their defaults routes
// every write through the watched `poll_write` above. Forwarding them to
// the inner stream would be the optimization that quietly opens a path
// where a sink failure is not seen — and `write_all`, which is all this
// module's sink ever gets, does not vector anyway.
impl<W: AsyncWrite + Unpin> AsyncWrite for Watched<'_, W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut *this.inner).poll_write(cx, buf);
        if matches!(polled, Poll::Ready(Err(_))) {
            this.failed = true;
        }
        polled
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut *this.inner).poll_flush(cx);
        if matches!(polled, Poll::Ready(Err(_))) {
            this.failed = true;
        }
        polled
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut *this.inner).poll_shutdown(cx);
        if matches!(polled, Poll::Ready(Err(_))) {
            this.failed = true;
        }
        polled
    }
}
