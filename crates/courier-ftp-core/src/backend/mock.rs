//! An in-memory backend for tests (feature `test-util`).
//!
//! A [`MockServer`] is a shared directory tree with counters and fault
//! injection; every [`MockBackend`] it creates is one "connection" to it.

use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use time::OffsetDateTime;
use tokio::io::AsyncWrite;
use tokio_util::sync::CancellationToken;

use super::{
    Backend, BackendFactory, Capabilities, ConnectInfo, Listing, ReadStream, TransferOpts,
    WriteMode, WriteStream,
};
use crate::{
    Error, Result,
    events::{EventSender, SessionId},
    model::{Entry, Permissions, Precision, Protocol, RemotePath, ServerAddress, Timestamp},
};

#[derive(Debug, Clone)]
struct Node {
    is_dir: bool,
    data: Vec<u8>,
    mode: u32,
    modified: OffsetDateTime,
}

#[derive(Debug, Default)]
struct State {
    nodes: BTreeMap<RemotePath, Node>,
    /// Errors returned by the next calls (any operation except `connect`).
    fail_next: VecDeque<Error>,
    /// Errors returned by the next `connect` calls.
    fail_connect: VecDeque<Error>,
    connects: u32,
    keepalives: u32,
    calls: u32,
    /// Artificial delay before every operation (T41 tests).
    latency: Duration,
    /// Streams move at most `.0` bytes per poll, each after a `.1` delay.
    stream_pace: Option<(usize, Duration)>,
    /// The next streams opened fail with this error kind after this many
    /// bytes.
    stream_faults: VecDeque<(u64, io::ErrorKind)>,
    /// `connect` fails with `421 Too many connections` at this many open
    /// connections.
    max_connections: Option<u32>,
    open_connections: u32,
    peak_connections: u32,
    open_streams: u32,
    peak_streams: u32,
    read_offsets: Vec<u64>,
    write_modes: Vec<WriteMode>,
}

/// A shared in-memory "server". Clone it freely; clones share the tree.
#[derive(Debug, Clone)]
pub struct MockServer {
    state: Arc<Mutex<State>>,
    address: ServerAddress,
}

impl Default for MockServer {
    fn default() -> Self {
        Self::new()
    }
}

impl MockServer {
    /// An empty server with only `/`.
    pub fn new() -> Self {
        let mut state = State::default();
        state.nodes.insert(RemotePath::root(), Node::dir());
        Self {
            state: Arc::new(Mutex::new(state)),
            address: ServerAddress::new(Protocol::Sftp, "mock.invalid"),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A new, disconnected connection to this server.
    pub fn backend(&self) -> MockBackend {
        MockBackend {
            server: self.clone(),
            connected: false,
        }
    }

    /// Create a file with `data`, creating missing parent directories.
    pub fn add_file(&self, path: &str, data: &[u8]) -> &Self {
        let path = RemotePath::new(path);
        let mut st = self.lock();
        let mut dir = path.parent();
        while let Some(d) = dir {
            st.nodes.entry(d.clone()).or_insert_with(Node::dir);
            dir = d.parent();
        }
        st.nodes.insert(path, Node::file(data.to_vec()));
        self
    }

    /// Create a directory and its parents.
    pub fn add_dir(&self, path: &str) -> &Self {
        let mut cur = Some(RemotePath::new(path));
        let mut st = self.lock();
        while let Some(d) = cur {
            st.nodes.entry(d.clone()).or_insert_with(Node::dir);
            cur = d.parent();
        }
        self
    }

    /// The contents of a file.
    pub fn read_file(&self, path: &str) -> Option<Vec<u8>> {
        let st = self.lock();
        st.nodes
            .get(&RemotePath::new(path))
            .filter(|n| !n.is_dir)
            .map(|n| n.data.clone())
    }

    /// Whether `path` exists.
    pub fn exists(&self, path: &str) -> bool {
        self.lock().nodes.contains_key(&RemotePath::new(path))
    }

    /// Make the next operation (other than `connect`) fail with `err`.
    pub fn fail_next(&self, err: Error) -> &Self {
        self.lock().fail_next.push_back(err);
        self
    }

    /// Make the next `connect` fail with `err`.
    pub fn fail_connect(&self, err: Error) -> &Self {
        self.lock().fail_connect.push_back(err);
        self
    }

    /// How many times any backend connected.
    pub fn connects(&self) -> u32 {
        self.lock().connects
    }

    /// How many keep-alives were sent.
    pub fn keepalives(&self) -> u32 {
        self.lock().keepalives
    }

    /// How many operations (other than connect and keep-alive) were attempted.
    pub fn calls(&self) -> u32 {
        self.lock().calls
    }

    /// Wait `latency` before every operation (including `connect`).
    pub fn set_latency(&self, latency: Duration) -> &Self {
        self.lock().latency = latency;
        self
    }

    /// Make streams slow: at most `chunk` bytes per read or write, each after
    /// waiting `delay` (tokio time, so `tokio::time::pause` applies).
    pub fn set_stream_pace(&self, chunk: usize, delay: Duration) -> &Self {
        self.lock().stream_pace = Some((chunk.max(1), delay));
        self
    }

    /// Make the next stream opened (read or write) fail with `kind` once
    /// `after` bytes went through it.
    pub fn fail_stream_after(&self, after: u64, kind: io::ErrorKind) -> &Self {
        self.lock().stream_faults.push_back((after, kind));
        self
    }

    /// Refuse connections beyond `max` open ones with
    /// `421 Too many connections`.
    pub fn set_max_connections(&self, max: u32) -> &Self {
        self.lock().max_connections = Some(max);
        self
    }

    /// Connections open right now.
    pub fn open_connections(&self) -> u32 {
        self.lock().open_connections
    }

    /// The most connections that were open at once.
    pub fn peak_connections(&self) -> u32 {
        self.lock().peak_connections
    }

    /// Streams open right now.
    pub fn open_streams(&self) -> u32 {
        self.lock().open_streams
    }

    /// The most streams that were open at once.
    pub fn peak_streams(&self) -> u32 {
        self.lock().peak_streams
    }

    /// The offset of every `open_read`, in order.
    pub fn read_offsets(&self) -> Vec<u64> {
        self.lock().read_offsets.clone()
    }

    /// The mode of every `open_write`, in order.
    pub fn write_modes(&self) -> Vec<WriteMode> {
        self.lock().write_modes.clone()
    }

    async fn delay(&self) {
        let latency = self.lock().latency;
        if !latency.is_zero() {
            tokio::time::sleep(latency).await;
        }
    }

    /// Counts a new stream and returns its pacing and fault.
    fn open_stream(&self) -> StreamGauge {
        let mut st = self.lock();
        st.open_streams += 1;
        st.peak_streams = st.peak_streams.max(st.open_streams);
        StreamGauge {
            server: self.clone(),
            pace: st.stream_pace,
            fault: st.stream_faults.pop_front(),
            sleep: None,
        }
    }
}

/// Pacing, fault injection and the open-stream count of one mock stream.
struct StreamGauge {
    server: MockServer,
    pace: Option<(usize, Duration)>,
    fault: Option<(u64, io::ErrorKind)>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl StreamGauge {
    /// How many bytes may move now at position `pos` (wanting `want`), or an
    /// error / pending.
    fn admit(&mut self, cx: &mut Context<'_>, pos: u64, want: usize) -> Poll<io::Result<usize>> {
        if let Some((at, kind)) = self.fault
            && pos >= at
        {
            return Poll::Ready(Err(io::Error::from(kind)));
        }
        let mut n = want;
        if let Some((chunk, delay)) = self.pace {
            if !delay.is_zero() {
                let sleep = self
                    .sleep
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(delay)));
                if sleep.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                self.sleep = None;
            }
            n = n.min(chunk);
        }
        if let Some((at, _)) = self.fault {
            n = n.min(usize::try_from(at - pos).unwrap_or(usize::MAX));
        }
        Poll::Ready(Ok(n))
    }
}

impl Drop for StreamGauge {
    fn drop(&mut self) {
        let mut st = self.server.lock();
        st.open_streams = st.open_streams.saturating_sub(1);
    }
}

/// Serves a file's bytes with the server's pacing and faults.
struct MockReader {
    data: Vec<u8>,
    pos: usize,
    gauge: StreamGauge,
}

impl tokio::io::AsyncRead for MockReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let left = this.data.len().saturating_sub(this.pos);
        if left == 0 || buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let want = left.min(buf.remaining());
        let n = match this.gauge.admit(cx, this.pos as u64, want) {
            Poll::Ready(Ok(n)) => n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };
        buf.put_slice(&this.data[this.pos..this.pos + n]);
        this.pos += n;
        Poll::Ready(Ok(()))
    }
}

impl BackendFactory for MockServer {
    fn create(&self, _: &ConnectInfo, _: SessionId, _: EventSender) -> Box<dyn Backend> {
        Box::new(self.backend())
    }
}

impl Node {
    fn dir() -> Self {
        Self {
            is_dir: true,
            data: Vec::new(),
            mode: 0o040_755,
            modified: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn file(data: Vec<u8>) -> Self {
        Self {
            is_dir: false,
            data,
            mode: 0o100_644,
            modified: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn entry(&self, name: &str) -> Entry {
        let mut e = if self.is_dir {
            Entry::dir(name)
        } else {
            Entry::file(name, self.data.len() as u64)
        };
        e.permissions = Some(Permissions::from_mode(self.mode));
        e.modified = Some(Timestamp::new(self.modified, Precision::Second));
        e
    }
}

/// One connection to a [`MockServer`].
#[derive(Debug)]
pub struct MockBackend {
    server: MockServer,
    connected: bool,
}

impl MockBackend {
    /// Start an operation: check the connection and injected faults.
    fn begin(&mut self) -> Result<MutexGuard<'_, State>> {
        let mut st = self.server.lock();
        st.calls += 1;
        if !self.connected {
            return Err(Error::Connection("not connected".into()));
        }
        if let Some(err) = st.fail_next.pop_front() {
            if matches!(err, Error::Connection(_)) {
                self.connected = false;
                st.open_connections = st.open_connections.saturating_sub(1);
            }
            return Err(err);
        }
        Ok(st)
    }

    fn mark_disconnected(&mut self) {
        if self.connected {
            self.connected = false;
            let mut st = self.server.lock();
            st.open_connections = st.open_connections.saturating_sub(1);
        }
    }
}

impl Drop for MockBackend {
    fn drop(&mut self) {
        self.mark_disconnected();
    }
}

fn not_found(path: &RemotePath) -> Error {
    Error::NotFound(path.clone())
}

fn parent_must_be_dir(st: &State, path: &RemotePath) -> Result<()> {
    let parent = path.parent().ok_or(Error::PermissionDenied)?;
    match st.nodes.get(&parent) {
        Some(n) if n.is_dir => Ok(()),
        _ => Err(not_found(&parent)),
    }
}

#[async_trait]
impl Backend for MockBackend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            chmod: true,
            set_mtime: true,
            resume_download: true,
            resume_upload: true,
            append: true,
            raw_commands: true,
            symlinks: false,
            server_side_rename_across_dirs: true,
            ascii_mode: false,
            parallel_connections_allowed: true,
        }
    }

    fn address(&self) -> Option<&ServerAddress> {
        Some(&self.server.address)
    }

    async fn connect(&mut self, cancel: CancellationToken) -> Result<()> {
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        self.server.delay().await;
        let mut st = self.server.lock();
        st.connects += 1;
        if let Some(err) = st.fail_connect.pop_front() {
            return Err(err);
        }
        if self.connected {
            return Ok(());
        }
        if st
            .max_connections
            .is_some_and(|max| st.open_connections >= max)
        {
            return Err(Error::reply(421, "Too many connections from this IP"));
        }
        st.open_connections += 1;
        st.peak_connections = st.peak_connections.max(st.open_connections);
        self.connected = true;
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.mark_disconnected();
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    async fn home_dir(&mut self) -> Result<RemotePath> {
        drop(self.begin()?);
        Ok(RemotePath::root())
    }

    async fn list(&mut self, dir: &RemotePath, cancel: CancellationToken) -> Result<Listing> {
        self.server.delay().await;
        let st = self.begin()?;
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        match st.nodes.get(dir) {
            Some(n) if n.is_dir => {}
            Some(_) => return Err(Error::InvalidInput(format!("{dir} is not a directory"))),
            None => return Err(not_found(dir)),
        }
        let entries = st
            .nodes
            .iter()
            .filter(|(p, _)| p.parent().as_ref() == Some(dir))
            .filter_map(|(p, n)| p.file_name().map(|name| n.entry(name)))
            .collect();
        Ok(Listing {
            dir: dir.clone(),
            entries,
            fetched_at: Instant::now(),
            raw: None,
        })
    }

    async fn stat(&mut self, path: &RemotePath) -> Result<Entry> {
        self.server.delay().await;
        let st = self.begin()?;
        let node = st.nodes.get(path).ok_or_else(|| not_found(path))?;
        Ok(node.entry(path.file_name().unwrap_or("/")))
    }

    async fn mkdir(&mut self, path: &RemotePath) -> Result<()> {
        let mut st = self.begin()?;
        if st.nodes.contains_key(path) {
            return Err(Error::AlreadyExists);
        }
        parent_must_be_dir(&st, path)?;
        st.nodes.insert(path.clone(), Node::dir());
        Ok(())
    }

    async fn rmdir(&mut self, path: &RemotePath) -> Result<()> {
        let mut st = self.begin()?;
        match st.nodes.get(path) {
            Some(n) if n.is_dir => {}
            Some(_) => return Err(Error::InvalidInput(format!("{path} is not a directory"))),
            None => return Err(not_found(path)),
        }
        if path.is_root() || st.nodes.keys().any(|p| p.parent().as_ref() == Some(path)) {
            return Err(Error::reply(550, "Directory not empty"));
        }
        st.nodes.remove(path);
        Ok(())
    }

    async fn remove_file(&mut self, path: &RemotePath) -> Result<()> {
        let mut st = self.begin()?;
        match st.nodes.get(path) {
            Some(n) if !n.is_dir => {
                st.nodes.remove(path);
                Ok(())
            }
            Some(_) => Err(Error::InvalidInput(format!("{path} is a directory"))),
            None => Err(not_found(path)),
        }
    }

    async fn rename(&mut self, from: &RemotePath, to: &RemotePath) -> Result<()> {
        let mut st = self.begin()?;
        if !st.nodes.contains_key(from) {
            return Err(not_found(from));
        }
        if st.nodes.contains_key(to) {
            return Err(Error::AlreadyExists);
        }
        if to.starts_with(from) {
            return Err(Error::InvalidInput(
                "cannot move a directory into itself".into(),
            ));
        }
        parent_must_be_dir(&st, to)?;
        let moved: Vec<RemotePath> = st
            .nodes
            .keys()
            .filter(|p| p.starts_with(from))
            .cloned()
            .collect();
        for old in moved {
            if let Some(node) = st.nodes.remove(&old) {
                let rest = old.strip_prefix(from).unwrap_or("");
                st.nodes.insert(to.join_path(rest), node);
            }
        }
        Ok(())
    }

    async fn chmod(&mut self, path: &RemotePath, mode: u32) -> Result<()> {
        let mut st = self.begin()?;
        let node = st.nodes.get_mut(path).ok_or_else(|| not_found(path))?;
        node.mode = (node.mode & !0o7777) | (mode & 0o7777);
        Ok(())
    }

    async fn set_mtime(&mut self, path: &RemotePath, time: OffsetDateTime) -> Result<()> {
        let mut st = self.begin()?;
        let node = st.nodes.get_mut(path).ok_or_else(|| not_found(path))?;
        node.modified = time;
        Ok(())
    }

    async fn open_read(
        &mut self,
        path: &RemotePath,
        offset: u64,
        _opts: &TransferOpts,
    ) -> Result<ReadStream> {
        self.server.delay().await;
        let mut st = self.begin()?;
        st.read_offsets.push(offset);
        let node = st.nodes.get(path).ok_or_else(|| not_found(path))?;
        if node.is_dir {
            return Err(Error::InvalidInput(format!("{path} is a directory")));
        }
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(node.data.len());
        let data = node.data[start..].to_vec();
        drop(st);
        Ok(Box::new(MockReader {
            data,
            pos: 0,
            gauge: self.server.open_stream(),
        }))
    }

    async fn open_write(
        &mut self,
        path: &RemotePath,
        mode: WriteMode,
        _opts: &TransferOpts,
    ) -> Result<WriteStream> {
        self.server.delay().await;
        let mut st = self.begin()?;
        st.write_modes.push(mode);
        parent_must_be_dir(&st, path)?;
        let existing = st.nodes.get(path);
        if existing.is_some_and(|n| n.is_dir) {
            return Err(Error::InvalidInput(format!("{path} is a directory")));
        }
        let mut data = existing.map(|n| n.data.clone()).unwrap_or_default();
        match mode {
            WriteMode::Create if existing.is_some() => return Err(Error::AlreadyExists),
            WriteMode::Create | WriteMode::Truncate => data.clear(),
            WriteMode::Append => {}
            WriteMode::ResumeAt(n) => data.truncate(usize::try_from(n).unwrap_or(usize::MAX)),
        }
        st.nodes.insert(path.clone(), Node::file(data));
        drop(st);
        Ok(Box::new(MockWriter {
            server: self.server.clone(),
            path: path.clone(),
            written: 0,
            gauge: self.server.open_stream(),
        }))
    }

    async fn finish_transfer(&mut self) -> Result<()> {
        self.server.delay().await;
        drop(self.begin()?);
        Ok(())
    }

    async fn raw_command(&mut self, cmd: &str) -> Result<String> {
        drop(self.begin()?);
        Ok(format!("200 {cmd}"))
    }

    async fn keepalive(&mut self) -> Result<()> {
        let mut st = self.server.lock();
        st.keepalives += 1;
        if !self.connected {
            return Err(Error::Connection("not connected".into()));
        }
        Ok(())
    }
}

/// Appends to the file on the shared server as bytes arrive.
struct MockWriter {
    server: MockServer,
    path: RemotePath,
    written: u64,
    gauge: StreamGauge,
}

impl AsyncWrite for MockWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = &mut *self;
        let n = match this.gauge.admit(cx, this.written, buf.len()) {
            Poll::Ready(Ok(n)) => n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };
        let mut st = this.server.lock();
        match st.nodes.get_mut(&this.path) {
            Some(node) => {
                node.data.extend_from_slice(&buf[..n]);
                this.written += n as u64;
                Poll::Ready(Ok(n))
            }
            None => Poll::Ready(Err(io::Error::from(io::ErrorKind::NotFound))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
