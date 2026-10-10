//! Pipelined file streams (T41b §3): up to [`MAX_OUTSTANDING`] `READ` or
//! `WRITE` requests in flight per file, on russh-sftp's raw request API.
//!
//! A request is sent the first time its future is polled, so a new request
//! is polled once right after it is queued; afterwards only the oldest one is
//! awaited, which keeps the replies in file order.

use std::{
    collections::VecDeque,
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
};

use courier_ftp_core::{Error, model::RemotePath};
use russh_sftp::{
    client::{RawSftpSession, error::Error as SftpError},
    protocol::StatusCode,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::client::map_error;

/// Requests in flight per file.
pub const MAX_OUTSTANDING: usize = 64;

type Pending<T> = Pin<Box<dyn Future<Output = Result<T, SftpError>> + Send>>;

/// Where a stream leaves its first error for
/// [`Backend::finish_transfer`](courier_ftp_core::backend::Backend::finish_transfer).
pub(crate) type Outcome = Arc<Mutex<Option<Error>>>;

fn record(outcome: &Outcome, err: Error) -> io::Error {
    let kind = match &err {
        Error::NotFound(_) => io::ErrorKind::NotFound,
        Error::PermissionDenied => io::ErrorKind::PermissionDenied,
        Error::Timeout => io::ErrorKind::TimedOut,
        Error::Connection(_) => io::ErrorKind::ConnectionAborted,
        _ => io::ErrorKind::Other,
    };
    let io = io::Error::new(kind, err.to_string());
    let mut slot = outcome
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if slot.is_none() {
        *slot = Some(err);
    }
    io
}

/// Close `handle` without waiting (a stream dropped before it finished).
fn close_detached(raw: &Arc<RawSftpSession>, handle: String) {
    let raw = Arc::clone(raw);
    if let Ok(rt) = tokio::runtime::Handle::try_current() {
        rt.spawn(async move {
            if let Err(err) = raw.close(handle).await {
                tracing::debug!(%err, "sftp: closing a dropped file handle");
            }
        });
    }
}

fn close_future(raw: &Arc<RawSftpSession>, handle: String) -> Pending<()> {
    let raw = Arc::clone(raw);
    Box::pin(async move { raw.close(handle).await.map(drop) })
}

struct PendingRead {
    offset: u64,
    len: u32,
    reply: Pending<Vec<u8>>,
}

enum ReadState {
    Reading,
    Closing(Pending<()>),
    Done,
}

/// A pipelined reader of one remote file.
pub(crate) struct SftpReader {
    raw: Arc<RawSftpSession>,
    handle: String,
    path: RemotePath,
    /// Bytes per request; lowered to what the server actually returns.
    chunk: u32,
    /// Only one request until the first reply showed the server's read size.
    probing: bool,
    next_offset: u64,
    pending: VecDeque<PendingRead>,
    buf: Vec<u8>,
    pos: usize,
    state: ReadState,
    outcome: Outcome,
}

impl SftpReader {
    pub(crate) fn new(
        raw: Arc<RawSftpSession>,
        handle: String,
        path: RemotePath,
        offset: u64,
        chunk: u32,
        outcome: Outcome,
    ) -> Self {
        Self {
            raw,
            handle,
            path,
            chunk: chunk.max(1),
            probing: true,
            next_offset: offset,
            pending: VecDeque::with_capacity(MAX_OUTSTANDING),
            buf: Vec::new(),
            pos: 0,
            state: ReadState::Reading,
            outcome,
        }
    }

    /// Queue requests up to the pipeline depth, sending each at once.
    fn fill(&mut self, cx: &mut Context<'_>) {
        let depth = if self.probing { 1 } else { MAX_OUTSTANDING };
        while self.pending.len() < depth {
            let raw = Arc::clone(&self.raw);
            let handle = self.handle.clone();
            let (offset, len) = (self.next_offset, self.chunk);
            let mut reply: Pending<Vec<u8>> =
                Box::pin(async move { raw.read(handle, offset, len).await.map(|d| d.data) });
            // The first poll sends the request; a reply can't be there yet,
            // but if it is (or the send failed) it is kept for later.
            let early = reply.as_mut().poll(cx);
            let reply = match early {
                Poll::Pending => reply,
                Poll::Ready(r) => Box::pin(std::future::ready(r)) as Pending<Vec<u8>>,
            };
            self.pending.push_back(PendingRead { offset, len, reply });
            self.next_offset = offset.saturating_add(u64::from(len));
        }
    }

    fn finish(&mut self) {
        self.pending.clear();
        self.state = ReadState::Closing(close_future(&self.raw, self.handle.clone()));
    }
}

impl AsyncRead for SftpReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.pos < this.buf.len() {
                let n = out.remaining().min(this.buf.len() - this.pos);
                out.put_slice(&this.buf[this.pos..this.pos + n]);
                this.pos += n;
                return Poll::Ready(Ok(()));
            }
            match &mut this.state {
                ReadState::Done => return Poll::Ready(Ok(())),
                ReadState::Closing(close) => {
                    let result = ready!(close.as_mut().poll(cx));
                    this.state = ReadState::Done;
                    if let Err(err) = result {
                        // Everything was read; a failed CLOSE only gets logged.
                        tracing::debug!(%err, "sftp: closing a file after reading");
                    }
                }
                ReadState::Reading => {
                    if out.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    this.fill(cx);
                    let Some(front) = this.pending.front_mut() else {
                        continue;
                    };
                    let result = ready!(front.reply.as_mut().poll(cx));
                    let (offset, len) = (front.offset, front.len);
                    this.pending.pop_front();
                    match result {
                        Ok(data) if data.is_empty() => this.finish(),
                        Ok(data) => {
                            let n = u32::try_from(data.len()).unwrap_or(u32::MAX);
                            if this.probing {
                                this.probing = false;
                                if n < len {
                                    // The server's read size (or the end of
                                    // the file, which the next read shows).
                                    this.chunk = n;
                                }
                            } else if n < len {
                                // A short read: re-request from the gap.
                                this.pending.clear();
                            }
                            if n < len {
                                this.next_offset = offset + u64::from(n);
                            }
                            this.buf = data;
                            this.pos = 0;
                        }
                        Err(SftpError::Status(s)) if s.status_code == StatusCode::Eof => {
                            this.finish();
                        }
                        Err(err) => {
                            this.pending.clear();
                            this.state = ReadState::Done;
                            let err = map_error(err, "read", Some(&this.path));
                            close_detached(&this.raw, std::mem::take(&mut this.handle));
                            return Poll::Ready(Err(record(&this.outcome, err)));
                        }
                    }
                }
            }
        }
    }
}

impl Drop for SftpReader {
    fn drop(&mut self) {
        if matches!(self.state, ReadState::Reading) {
            self.pending.clear();
            close_detached(&self.raw, std::mem::take(&mut self.handle));
        }
    }
}

/// A pipelined writer of one remote file.
pub(crate) struct SftpWriter {
    raw: Arc<RawSftpSession>,
    handle: String,
    path: RemotePath,
    chunk: usize,
    offset: u64,
    pending: VecDeque<Pending<()>>,
    closing: Option<Pending<()>>,
    closed: bool,
    outcome: Outcome,
}

impl SftpWriter {
    pub(crate) fn new(
        raw: Arc<RawSftpSession>,
        handle: String,
        path: RemotePath,
        offset: u64,
        chunk: u32,
        outcome: Outcome,
    ) -> Self {
        Self {
            raw,
            handle,
            path,
            chunk: usize::try_from(chunk.max(1)).unwrap_or(32 * 1024),
            offset,
            pending: VecDeque::with_capacity(MAX_OUTSTANDING),
            closing: None,
            closed: false,
            outcome,
        }
    }

    fn fail(&mut self, err: SftpError) -> io::Error {
        let err = map_error(err, "write", Some(&self.path));
        record(&self.outcome, err)
    }

    /// Wait for the oldest outstanding write.
    fn poll_oldest(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(front) = self.pending.front_mut() else {
            return Poll::Ready(Ok(()));
        };
        let result = ready!(front.as_mut().poll(cx));
        self.pending.pop_front();
        Poll::Ready(result.map_err(|e| self.fail(e)))
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            ready!(self.poll_oldest(cx))?;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SftpWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed || this.closing.is_some() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the file is already closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        while this.pending.len() >= MAX_OUTSTANDING {
            ready!(this.poll_oldest(cx))?;
        }
        let n = buf.len().min(this.chunk);
        let data = buf[..n].to_vec();
        let raw = Arc::clone(&this.raw);
        let handle = this.handle.clone();
        let offset = this.offset;
        let mut ack: Pending<()> =
            Box::pin(async move { raw.write(handle, offset, data).await.map(drop) });
        match ack.as_mut().poll(cx) {
            Poll::Pending => this.pending.push_back(ack),
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(this.fail(err))),
        }
        this.offset += n as u64;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_drain(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Ok(()));
        }
        if this.closing.is_none() {
            if let Err(err) = ready!(this.poll_drain(cx)) {
                this.closed = true;
                close_detached(&this.raw, std::mem::take(&mut this.handle));
                return Poll::Ready(Err(err));
            }
            this.closing = Some(close_future(&this.raw, this.handle.clone()));
        }
        let Some(close) = this.closing.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let result = ready!(close.as_mut().poll(cx));
        this.closing = None;
        this.closed = true;
        Poll::Ready(result.map_err(|e| this.fail(e)))
    }
}

impl Drop for SftpWriter {
    fn drop(&mut self) {
        if !self.closed && self.closing.is_none() {
            self.pending.clear();
            close_detached(&self.raw, std::mem::take(&mut self.handle));
        }
    }
}
