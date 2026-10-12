//! [`DataStream`]: one data connection with an inactivity timeout,
//! cancellation and completion flags the session reads afterwards.

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep},
};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use crate::control::BoxedStream;

/// The longest a TLS data connection waits for the server's side of the
/// shutdown (and session tickets) after an upload.
pub const SHUTDOWN_DRAIN: Duration = Duration::from_secs(5);

/// What happened on a data connection, shared between the stream handed to
/// the caller and the session that reads the final reply.
#[derive(Debug, Default)]
pub struct TransferFlags {
    eof: AtomicBool,
    shutdown: AtomicBool,
    bytes: AtomicU64,
    error: Mutex<Option<String>>,
}

impl TransferFlags {
    /// Whether the reader saw the end of the data.
    pub fn eof(&self) -> bool {
        self.eof.load(Ordering::Acquire)
    }

    /// Whether the writer was shut down cleanly.
    pub fn shut_down(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    /// Bytes moved over the connection.
    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// The I/O error that ended the transfer, if any.
    pub fn error(&self) -> Option<String> {
        self.error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn set_error(&self, err: &io::Error) {
        let mut slot = self.error.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(err.to_string());
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shutdown {
    Open,
    Closing,
    Draining,
    Done,
}

/// An open data connection (TCP or TLS over TCP).
///
/// - Fails with [`io::ErrorKind::TimedOut`] when nothing moves for the
///   timeout (only while a read or write is waiting, so a slow consumer
///   doesn't time out);
/// - fails with [`io::ErrorKind::Interrupted`] when the connection's token is
///   cancelled;
/// - records EOF, a clean shutdown and errors in its [`TransferFlags`];
/// - over TLS, a server closing without `close_notify` counts as EOF (the
///   `226` on the authenticated control connection confirms completeness),
///   and shutting down sends `close_notify` and then reads until the server
///   closes too, for at most [`SHUTDOWN_DRAIN`], so TLS 1.3 session tickets
///   sent on this connection are kept for the next one.
pub struct DataStream {
    inner: BoxedStream,
    timeout: Duration,
    sleep: Pin<Box<Sleep>>,
    waiting: bool,
    cancel: Pin<Box<WaitForCancellationFutureOwned>>,
    flags: Arc<TransferFlags>,
    tls: bool,
    shutdown: Shutdown,
}

impl std::fmt::Debug for DataStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataStream")
            .field("timeout", &self.timeout)
            .field("tls", &self.tls)
            .field("flags", &self.flags)
            .finish_non_exhaustive()
    }
}

impl DataStream {
    /// Wrap `inner`. `tls` turns on the TLS shutdown handling.
    pub fn new(
        inner: BoxedStream,
        timeout: Duration,
        cancel: CancellationToken,
        tls: bool,
    ) -> Self {
        Self {
            inner,
            timeout,
            sleep: Box::pin(tokio::time::sleep(timeout)),
            waiting: false,
            cancel: Box::pin(cancel.cancelled_owned()),
            flags: Arc::new(TransferFlags::default()),
            tls,
            shutdown: Shutdown::Open,
        }
    }

    /// The flags this stream reports into.
    pub fn flags(&self) -> Arc<TransferFlags> {
        Arc::clone(&self.flags)
    }

    /// Whether this is a TLS connection.
    pub fn is_tls(&self) -> bool {
        self.tls
    }

    fn start_wait(&mut self, wait: Duration) {
        if !self.waiting {
            self.waiting = true;
            self.sleep.as_mut().reset(Instant::now() + wait);
        }
    }

    fn progressed(&mut self) {
        self.waiting = false;
    }

    /// `Some(error)` when cancelled or timed out (registers the wakers).
    fn check_abort(&mut self, cx: &mut Context<'_>) -> Option<io::Error> {
        if self.cancel.as_mut().poll(cx).is_ready() {
            return Some(io::Error::new(
                io::ErrorKind::Interrupted,
                "the transfer was cancelled",
            ));
        }
        if self.sleep.as_mut().poll(cx).is_ready() {
            return Some(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "no data transferred for {} seconds",
                    self.timeout.as_secs_f32()
                ),
            ));
        }
        None
    }

    fn fail<T>(&self, err: io::Error) -> Poll<io::Result<T>> {
        self.flags.set_error(&err);
        Poll::Ready(Err(err))
    }

    /// Read and discard until EOF, an error or the deadline.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let mut scratch = [0u8; 4096];
        loop {
            if self.sleep.as_mut().poll(cx).is_ready() || self.cancel.as_mut().poll(cx).is_ready() {
                return Poll::Ready(());
            }
            let mut rb = ReadBuf::new(&mut scratch);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) if rb.filled().is_empty() => return Poll::Ready(()),
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(_)) => return Poll::Ready(()),
            }
        }
    }
}

impl AsyncRead for DataStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.flags.eof() {
            return Poll::Ready(Ok(()));
        }
        let timeout = this.timeout;
        this.start_wait(timeout);
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                this.progressed();
                let n = buf.filled().len() - before;
                if n == 0 {
                    this.flags.eof.store(true, Ordering::Release);
                } else {
                    this.flags.bytes.fetch_add(n as u64, Ordering::Relaxed);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) if this.tls && err.kind() == io::ErrorKind::UnexpectedEof => {
                // No close_notify: tolerated, the final reply decides.
                tracing::debug!("TLS data connection closed without close_notify");
                this.progressed();
                this.flags.eof.store(true, Ordering::Release);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                this.progressed();
                this.fail(err)
            }
            Poll::Pending => match this.check_abort(cx) {
                Some(err) => this.fail(err),
                None => Poll::Pending,
            },
        }
    }
}

impl AsyncWrite for DataStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let timeout = this.timeout;
        this.start_wait(timeout);
        match Pin::new(&mut this.inner).poll_write(cx, data) {
            Poll::Ready(Ok(n)) => {
                this.progressed();
                this.flags.bytes.fetch_add(n as u64, Ordering::Relaxed);
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(err)) => {
                this.progressed();
                this.fail(err)
            }
            Poll::Pending => match this.check_abort(cx) {
                Some(err) => this.fail(err),
                None => Poll::Pending,
            },
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let timeout = this.timeout;
        this.start_wait(timeout);
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(result) => {
                this.progressed();
                match result {
                    Ok(()) => Poll::Ready(Ok(())),
                    Err(err) => this.fail(err),
                }
            }
            Poll::Pending => match this.check_abort(cx) {
                Some(err) => this.fail(err),
                None => Poll::Pending,
            },
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            match this.shutdown {
                Shutdown::Done => return Poll::Ready(Ok(())),
                Shutdown::Open => {
                    this.shutdown = Shutdown::Closing;
                    this.waiting = false;
                }
                Shutdown::Closing => {
                    let timeout = this.timeout;
                    this.start_wait(timeout);
                    match Pin::new(&mut this.inner).poll_shutdown(cx) {
                        Poll::Ready(Ok(())) => {
                            this.progressed();
                            if this.tls {
                                this.shutdown = Shutdown::Draining;
                            } else {
                                this.shutdown = Shutdown::Done;
                                this.flags.shutdown.store(true, Ordering::Release);
                            }
                        }
                        Poll::Ready(Err(err)) => {
                            this.progressed();
                            return this.fail(err);
                        }
                        Poll::Pending => {
                            return match this.check_abort(cx) {
                                Some(err) => this.fail(err),
                                None => Poll::Pending,
                            };
                        }
                    }
                }
                Shutdown::Draining => {
                    this.start_wait(SHUTDOWN_DRAIN.min(this.timeout));
                    ready!(this.poll_drain(cx));
                    this.progressed();
                    this.shutdown = Shutdown::Done;
                    this.flags.shutdown.store(true, Ordering::Release);
                }
            }
        }
    }
}
