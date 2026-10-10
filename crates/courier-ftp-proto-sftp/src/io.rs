//! Pipelined transfer streams (T22, D11): [`SftpReader`] keeps up to `outstanding`
//! `READ` requests in flight and delivers data strictly in offset order;
//! [`SftpWriter`] keeps up to `outstanding` `WRITE` requests in flight and consumes the
//! acknowledgements in request order.
//!
//! Many requests share one channel because `RawSftpSession` methods take `&self`; the
//! request futures own an `Arc` of the session (`'static`) and sit in a
//! `FuturesOrdered`, which polls every new future once (that sends the request) and
//! yields results in push order.

use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};

use courier_ftp_core::{Error, backend::WriteMode, model::RemotePath};
use futures::{StreamExt as _, stream::FuturesOrdered};
use russh_sftp::{
    client::{RawSftpSession, error::Error as SftpError},
    protocol::{FileAttributes, OpenFlags, StatusCode},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    task::JoinHandle,
};

use crate::convert::{SftpOp, clone_error, io_error, is_status, map_status};

/// Smallest request size the reader adapts down to after a short read.
pub const MIN_CHUNK: u32 = 4096;

/// Request sizes and pipelining depth for one open file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoParams {
    /// Bytes per READ / WRITE request.
    pub chunk: u32,
    /// Requests in flight at most.
    pub outstanding: u32,
    /// Bytes in flight at most (8 MiB per open file).
    pub max_inflight_bytes: u32,
}

impl IoParams {
    /// Requests that fit the depth and the byte budget (at least 1).
    fn depth(&self) -> usize {
        let by_budget = self.max_inflight_bytes / self.chunk.max(1);
        usize::try_from(self.outstanding.min(by_budget).max(1)).unwrap_or(1)
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the backend keeps of the open (or last) stream: whether it is still alive,
/// its deferred error and the spawned `CLOSE`.
#[derive(Debug, Default)]
pub struct TransferState {
    open: AtomicBool,
    error: Mutex<Option<Error>>,
    close: Mutex<Option<JoinHandle<()>>>,
}

impl TransferState {
    fn new() -> Arc<Self> {
        let s = Self::default();
        s.open.store(true, Ordering::SeqCst);
        Arc::new(s)
    }

    /// The stream has not been dropped yet.
    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::SeqCst)
    }

    /// Store `err` unless an earlier error is stored (the first one wins).
    fn set_error(&self, err: Error) {
        let mut slot = lock(&self.error);
        if slot.is_none() {
            *slot = Some(err);
        }
    }

    /// Wait (at most `wait`) for the spawned `CLOSE`, then take the deferred error.
    pub async fn finish(&self, wait: Duration) -> Option<Error> {
        let close = lock(&self.close).take();
        if let Some(h) = close {
            let _ = tokio::time::timeout(wait, h).await;
        }
        lock(&self.error).take()
    }
}

/// Send `CLOSE` for `handle` on a spawned task (best effort; needs a runtime). With
/// `report`, a failure becomes the deferred error.
fn spawn_close(
    raw: &Arc<RawSftpSession>,
    handle: &str,
    path: &RemotePath,
    state: &Arc<TransferState>,
    report: bool,
) {
    let Ok(rt) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let (raw, handle, path, st) = (
        Arc::clone(raw),
        handle.to_owned(),
        path.clone(),
        Arc::clone(state),
    );
    let task = rt.spawn(async move {
        if let Err(e) = raw.close(handle).await
            && report
        {
            st.set_error(map_status(e, SftpOp::Close, &path));
        }
    });
    *lock(&state.close) = Some(task);
}

/// `FAILURE` on an exclusive create / mkdir / rename: `AlreadyExists` when `LSTAT`
/// finds the target, else the mapped error.
pub(crate) async fn probe_exists(
    raw: &RawSftpSession,
    err: SftpError,
    op: SftpOp,
    path: &RemotePath,
) -> Error {
    if is_status(&err, StatusCode::Failure) && raw.lstat(path.as_str()).await.is_ok() {
        return Error::AlreadyExists(path.clone());
    }
    map_status(err, op, path)
}

/// `SSH_FXF_*` flags for a write mode (T22 `open_write` table).
pub fn write_flags(mode: WriteMode) -> OpenFlags {
    match mode {
        WriteMode::Create => OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE,
        WriteMode::Truncate => OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
        WriteMode::Append | WriteMode::WriteAt(_) => OpenFlags::WRITE | OpenFlags::CREATE,
        WriteMode::ResumeAt(_) => OpenFlags::WRITE,
    }
}

type ReadFut = Pin<Box<dyn Future<Output = (u64, u32, Result<Vec<u8>, SftpError>)> + Send>>;
type WriteFut = Pin<Box<dyn Future<Output = (u32, Result<(), SftpError>)> + Send>>;
type CloseFut = Pin<Box<dyn Future<Output = Result<(), SftpError>> + Send>>;

/// The pipelined download stream returned by `open_read`.
pub struct SftpReader {
    raw: Arc<RawSftpSession>,
    handle: String,
    path: RemotePath,
    /// Offset of the next request.
    next: u64,
    /// No request at or beyond this offset (`offset + range_len`).
    end: Option<u64>,
    /// Size from `FSTAT` (avoids requests far past EOF).
    size: Option<u64>,
    chunk: u32,
    params: IoParams,
    pending: FuturesOrdered<ReadFut>,
    inflight: u64,
    buf: Vec<u8>,
    pos: usize,
    done: bool,
    failed: Option<Error>,
    closed: bool,
    state: Arc<TransferState>,
}

impl fmt::Debug for SftpReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SftpReader")
            .field("next", &self.next)
            .field("end", &self.end)
            .field("size", &self.size)
            .field("chunk", &self.chunk)
            .field("pending", &self.pending.len())
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl SftpReader {
    /// `OPEN path READ` → `FSTAT` → a reader from `offset` (at most `range_len` bytes).
    ///
    /// # Errors
    /// The mapped `OPEN` error (`NotFound`, `PermissionDenied`, …).
    pub async fn open(
        raw: Arc<RawSftpSession>,
        path: &RemotePath,
        offset: u64,
        range_len: Option<u64>,
        params: IoParams,
    ) -> Result<Self, Error> {
        let handle = raw
            .open(path.as_str(), OpenFlags::READ, FileAttributes::empty())
            .await
            .map_err(|e| map_status(e, SftpOp::Open, path))?
            .handle;
        let size = match raw.fstat(handle.as_str()).await {
            Ok(a) => a.attrs.size,
            Err(e @ (SftpError::Timeout | SftpError::IO(_))) => {
                let _ = raw.close(handle).await;
                return Err(map_status(e, SftpOp::Stat, path));
            }
            Err(_) => None,
        };
        Ok(Self {
            raw,
            handle,
            path: path.clone(),
            next: offset,
            end: range_len.map(|n| offset.saturating_add(n)),
            size,
            chunk: params.chunk.max(1),
            params,
            pending: FuturesOrdered::new(),
            inflight: 0,
            buf: Vec::new(),
            pos: 0,
            done: false,
            failed: None,
            closed: false,
            state: TransferState::new(),
        })
    }

    /// The size `FSTAT` reported.
    pub fn remote_size(&self) -> Option<u64> {
        self.size
    }

    /// The current request size (after short-read adaptation).
    pub fn chunk(&self) -> u32 {
        self.chunk
    }

    /// Shared with the backend (deferred error, close).
    pub fn state(&self) -> Arc<TransferState> {
        Arc::clone(&self.state)
    }

    /// Issue requests up to the depth, the byte budget, the range end and (when the
    /// size is known) one chunk past the end of the file.
    fn fill(&mut self) {
        let depth = self.params.depth();
        let budget = u64::from(self.params.max_inflight_bytes.max(self.chunk));
        while self.pending.len() < depth {
            let mut want = u64::from(self.chunk);
            if let Some(end) = self.end {
                if self.next >= end {
                    break;
                }
                want = want.min(end - self.next);
            }
            if let Some(size) = self.size
                && self.next >= size.saturating_add(u64::from(self.chunk))
                && !self.pending.is_empty()
            {
                break;
            }
            if self.inflight + want > budget && !self.pending.is_empty() {
                break;
            }
            let want = u32::try_from(want).unwrap_or(self.chunk);
            let (raw, handle, off) = (Arc::clone(&self.raw), self.handle.clone(), self.next);
            self.pending.push_back(Box::pin(async move {
                let res = raw.read(handle, off, want).await.map(|d| d.data);
                (off, want, res)
            }));
            self.inflight += u64::from(want);
            self.next += u64::from(want);
        }
    }

    fn close_now(&mut self, report: bool) {
        if !self.closed {
            self.closed = true;
            spawn_close(&self.raw, &self.handle, &self.path, &self.state, report);
        }
    }

    fn fail(&mut self, err: SftpError) -> io::Error {
        let e = map_status(err, SftpOp::Read, &self.path);
        self.state.set_error(clone_error(&e));
        let io = io_error(clone_error(&e));
        self.failed = Some(e);
        self.pending = FuturesOrdered::new();
        self.inflight = 0;
        io
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
                if this.pos == this.buf.len() {
                    this.buf.clear();
                    this.pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if let Some(e) = &this.failed {
                return Poll::Ready(Err(io_error(clone_error(e))));
            }
            if this.done {
                this.pending = FuturesOrdered::new();
                this.close_now(true);
                return Poll::Ready(Ok(()));
            }
            if out.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            this.fill();
            let Some((off, want, res)) = ready!(this.pending.poll_next_unpin(cx)) else {
                // Nothing left to request: the range end.
                this.done = true;
                continue;
            };
            this.inflight = this.inflight.saturating_sub(u64::from(want));
            match res {
                Ok(data) if data.is_empty() => this.done = true,
                Ok(mut data) => {
                    data.truncate(want as usize);
                    let got = data.len() as u64;
                    if got < u64::from(want) {
                        // Short read (server cap or end of file): drop the rest of
                        // the pipeline and continue right after the data.
                        this.pending = FuturesOrdered::new();
                        this.inflight = 0;
                        // A short read at the known end of the file is not a server cap.
                        let at_eof = this.size.is_some_and(|size| off + got >= size);
                        if !at_eof && got >= u64::from(MIN_CHUNK) && got < u64::from(this.chunk) {
                            this.chunk = u32::try_from(got).unwrap_or(this.chunk);
                        }
                        this.next = off + got;
                    }
                    if this.end.is_some_and(|end| off + got >= end) {
                        this.done = true;
                    }
                    this.buf = data;
                    this.pos = 0;
                }
                Err(e) if is_status(&e, StatusCode::Eof) => this.done = true,
                Err(e) => return Poll::Ready(Err(this.fail(e))),
            }
        }
    }
}

impl Drop for SftpReader {
    fn drop(&mut self) {
        self.state.open.store(false, Ordering::SeqCst);
        // Abandoned: nothing is reported. At EOF the close was already sent.
        self.close_now(false);
    }
}

/// The pipelined upload stream returned by `open_write`.
pub struct SftpWriter {
    raw: Arc<RawSftpSession>,
    handle: String,
    path: RemotePath,
    offset: u64,
    params: IoParams,
    pending: FuturesOrdered<WriteFut>,
    inflight: u64,
    failed: Option<Error>,
    closing: Option<CloseFut>,
    closed: bool,
    state: Arc<TransferState>,
}

impl fmt::Debug for SftpWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SftpWriter")
            .field("offset", &self.offset)
            .field("pending", &self.pending.len())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl SftpWriter {
    /// `OPEN path <flags>` (+ `FSTAT` for `Append` / `ResumeAt`, `FSETSTAT size` when
    /// resuming a longer file) → a writer at the mode's start offset.
    ///
    /// # Errors
    /// `AlreadyExists` (`Create` onto an existing file), `InvalidInput` (`ResumeAt`
    /// beyond the remote size), or the mapped `OPEN` error.
    pub async fn open(
        raw: Arc<RawSftpSession>,
        path: &RemotePath,
        mode: WriteMode,
        params: IoParams,
    ) -> Result<Self, Error> {
        let handle = match raw
            .open(path.as_str(), write_flags(mode), FileAttributes::empty())
            .await
        {
            Ok(h) => h.handle,
            Err(e) if mode == WriteMode::Create => {
                return Err(probe_exists(&raw, e, SftpOp::Open, path).await);
            }
            Err(e) => return Err(map_status(e, SftpOp::Open, path)),
        };
        let start = match Self::start_offset(&raw, &handle, path, mode).await {
            Ok(n) => n,
            Err(e) => {
                let _ = raw.close(handle).await;
                return Err(e);
            }
        };
        Ok(Self {
            raw,
            handle,
            path: path.clone(),
            offset: start,
            params: IoParams {
                chunk: params.chunk.max(1),
                ..params
            },
            pending: FuturesOrdered::new(),
            inflight: 0,
            failed: None,
            closing: None,
            closed: false,
            state: TransferState::new(),
        })
    }

    async fn start_offset(
        raw: &RawSftpSession,
        handle: &str,
        path: &RemotePath,
        mode: WriteMode,
    ) -> Result<u64, Error> {
        let size = || async {
            raw.fstat(handle)
                .await
                .map(|a| a.attrs.size.unwrap_or(0))
                .map_err(|e| map_status(e, SftpOp::Stat, path))
        };
        match mode {
            WriteMode::Create | WriteMode::Truncate => Ok(0),
            WriteMode::WriteAt(n) => Ok(n),
            WriteMode::Append => size().await,
            WriteMode::ResumeAt(n) => {
                let len = size().await?;
                if len < n {
                    return Err(Error::InvalidInput(
                        "Remote file is shorter than the resume offset".to_owned(),
                    ));
                }
                if len > n {
                    let attrs = FileAttributes {
                        size: Some(n),
                        ..FileAttributes::empty()
                    };
                    raw.fsetstat(handle, attrs)
                        .await
                        .map_err(|e| map_status(e, SftpOp::SetStat, path))?;
                }
                Ok(n)
            }
        }
    }

    /// The offset of the next byte.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Shared with the backend (deferred error, close).
    pub fn state(&self) -> Arc<TransferState> {
        Arc::clone(&self.state)
    }

    fn fail(&mut self, err: SftpError, op: SftpOp) -> io::Error {
        let e = map_status(err, op, &self.path);
        self.state.set_error(clone_error(&e));
        let io = io_error(clone_error(&e));
        self.failed = Some(e);
        self.pending = FuturesOrdered::new();
        self.inflight = 0;
        io
    }

    /// Consume finished acks without waiting. `Err` on the first failed ack.
    fn harvest(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        while let Poll::Ready(Some((len, res))) = self.pending.poll_next_unpin(cx) {
            self.inflight = self.inflight.saturating_sub(u64::from(len));
            if let Err(e) = res {
                return Err(self.fail(e, SftpOp::Write));
            }
        }
        Ok(())
    }
}

impl AsyncWrite for SftpWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(e) = &this.failed {
            return Poll::Ready(Err(io_error(clone_error(e))));
        }
        if this.closed || this.closing.is_some() {
            return Poll::Ready(Err(io::Error::other("write after shutdown")));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(this.params.chunk as usize);
        let depth = this.params.depth();
        let budget = u64::from(this.params.max_inflight_bytes.max(this.params.chunk));
        while this.pending.len() >= depth
            || (!this.pending.is_empty() && this.inflight + n as u64 > budget)
        {
            match ready!(this.pending.poll_next_unpin(cx)) {
                None => break,
                Some((len, res)) => {
                    this.inflight = this.inflight.saturating_sub(u64::from(len));
                    if let Err(e) = res {
                        return Poll::Ready(Err(this.fail(e, SftpOp::Write)));
                    }
                }
            }
        }
        let data = buf[..n].to_vec();
        let len = u32::try_from(n).unwrap_or(this.params.chunk);
        let (raw, handle, off) = (Arc::clone(&this.raw), this.handle.clone(), this.offset);
        this.pending.push_back(Box::pin(async move {
            let res = raw.write(handle, off, data).await.map(|_| ());
            (len, res)
        }));
        this.inflight += n as u64;
        this.offset += n as u64;
        // Sends the new request and takes any acks that already arrived.
        if let Err(e) = this.harvest(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if let Some(e) = &this.failed {
                return Poll::Ready(Err(io_error(clone_error(e))));
            }
            match ready!(this.pending.poll_next_unpin(cx)) {
                None => return Poll::Ready(Ok(())),
                Some((len, res)) => {
                    this.inflight = this.inflight.saturating_sub(u64::from(len));
                    if let Err(e) = res {
                        return Poll::Ready(Err(this.fail(e, SftpOp::Write)));
                    }
                }
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return match &self.failed {
                Some(e) => Poll::Ready(Err(io_error(clone_error(e)))),
                None => Poll::Ready(Ok(())),
            };
        }
        ready!(self.as_mut().poll_flush(cx))?;
        let this = self.get_mut();
        let fut = this.closing.get_or_insert_with(|| {
            let (raw, handle) = (Arc::clone(&this.raw), this.handle.clone());
            Box::pin(async move { raw.close(handle).await.map(|_| ()) })
        });
        let res = ready!(fut.as_mut().poll(cx));
        this.closing = None;
        this.closed = true;
        match res {
            Ok(()) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(this.fail(e, SftpOp::Close))),
        }
    }
}

impl Drop for SftpWriter {
    fn drop(&mut self) {
        self.state.open.store(false, Ordering::SeqCst);
        if !self.closed {
            // Cancelled transfer: pending acks are abandoned, nothing is reported.
            self.closed = true;
            spawn_close(&self.raw, &self.handle, &self.path, &self.state, false);
        }
    }
}

#[cfg(test)]
mod props;
