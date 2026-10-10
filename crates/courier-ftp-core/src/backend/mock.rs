//! An in-memory "server" ([`MockServer`]) and its sessions ([`MockBackend`]) for tests
//! (feature `test-util`).
//!
//! `MockBackend` is the reference implementation of the [`Backend`] contract: the
//! conformance suite ([`super::conformance`]) passes against it, and the session handle,
//! the transfer engine and the UI are tested with it. File data is stored as a sparse
//! chunk map, so files beyond 4 GiB cost no memory unless written.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use async_trait::async_trait;
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;
use tokio_util::sync::CancellationToken;

use super::conformance::ConformanceEnv;
use super::{
    Backend, BackendContext, BackendFactory, Capabilities, ConnectInfo, Listing, ReadStream,
    SessionSecurityInfo, TransferEnd, TransferOpts, WriteMode, WriteStream,
};
use crate::events::{
    EventReceiver, PromptKind, PromptResponse, SessionId, TrustAnswer, channel as event_channel,
};
use crate::model::{
    Entry, EntryKind, FtpEncryption, PathStyle, Permissions, Precision, Protocol, RemotePath,
    ServerAddress, SymlinkTarget, Timestamp,
};
use crate::settings::{DebugLevel, Settings, SharedSettings};
use crate::{Error, Result};

/// Size of one stored data chunk.
const CHUNK: u64 = 64 * 1024;
/// `read_file` refuses files larger than this.
const READ_FILE_MAX: u64 = 64 * 1024 * 1024;
/// Symlink hops before a path is treated as missing (loop).
const MAX_HOPS: usize = 40;
/// The mock server's home directory.
const HOME: &str = "/home/test";

/// One operation of [`MockBackend`], for failure injection and call counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MockOp {
    /// [`Backend::connect`].
    Connect,
    /// [`Backend::disconnect`].
    Disconnect,
    /// [`Backend::home_dir`].
    HomeDir,
    /// [`Backend::list`].
    List,
    /// [`Backend::stat`].
    Stat,
    /// [`Backend::mkdir`].
    Mkdir,
    /// [`Backend::rmdir`].
    Rmdir,
    /// [`Backend::remove_file`].
    RemoveFile,
    /// [`Backend::rename`].
    Rename,
    /// [`Backend::chmod`].
    Chmod,
    /// [`Backend::set_mtime`].
    SetMtime,
    /// [`Backend::open_read`].
    OpenRead,
    /// [`Backend::open_write`].
    OpenWrite,
    /// [`Backend::finish_transfer`].
    FinishTransfer,
    /// [`Backend::raw_command`].
    RawCommand,
    /// [`Backend::keepalive`].
    Keepalive,
}

// ---------------------------------------------------------------- sparse data

/// File contents as a map of 64 KiB chunks; missing chunks read as zeros. Invariant:
/// bytes at or beyond `len` inside stored chunks are zero.
#[derive(Clone, Default)]
struct SparseData {
    len: u64,
    chunks: BTreeMap<u64, Box<[u8]>>,
}

impl fmt::Debug for SparseData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SparseData")
            .field("len", &self.len)
            .field("chunks", &self.chunks.len())
            .finish()
    }
}

impl SparseData {
    fn from_bytes(data: &[u8]) -> Self {
        let mut d = Self::default();
        d.write_at(0, data);
        d
    }

    /// Copies up to `buf.len()` bytes from `off`; returns the count (0 at/after EOF).
    fn read_at(&self, off: u64, buf: &mut [u8]) -> usize {
        if off >= self.len {
            return 0;
        }
        let n = usize::try_from((self.len - off).min(buf.len() as u64)).unwrap_or(buf.len());
        let mut done = 0;
        while done < n {
            let pos = off + done as u64;
            let idx = pos / CHUNK;
            let within = (pos % CHUNK) as usize;
            let take = (n - done).min(CHUNK as usize - within);
            let dst = &mut buf[done..done + take];
            match self.chunks.get(&idx) {
                Some(chunk) => dst.copy_from_slice(&chunk[within..within + take]),
                None => dst.fill(0),
            }
            done += take;
        }
        n
    }

    fn write_at(&mut self, off: u64, data: &[u8]) {
        let mut done = 0;
        while done < data.len() {
            let pos = off + done as u64;
            let idx = pos / CHUNK;
            let within = (pos % CHUNK) as usize;
            let take = (data.len() - done).min(CHUNK as usize - within);
            let chunk = self
                .chunks
                .entry(idx)
                .or_insert_with(|| vec![0; CHUNK as usize].into_boxed_slice());
            chunk[within..within + take].copy_from_slice(&data[done..done + take]);
            done += take;
        }
        self.len = self.len.max(off + data.len() as u64);
    }

    fn truncate(&mut self, n: u64) {
        if n < self.len {
            let first_gone = n.div_ceil(CHUNK);
            let _ = self.chunks.split_off(&first_gone);
            if !n.is_multiple_of(CHUNK)
                && let Some(chunk) = self.chunks.get_mut(&(n / CHUNK))
            {
                chunk[(n % CHUNK) as usize..].fill(0);
            }
        }
        self.len = n;
    }

    fn to_vec(&self) -> Vec<u8> {
        let mut out = vec![0; usize::try_from(self.len).unwrap_or(0)];
        let n = self.read_at(0, &mut out);
        out.truncate(n);
        out
    }
}

// ---------------------------------------------------------------- server state

#[derive(Clone, Debug)]
enum NodeKind {
    Dir,
    File(SparseData),
    Symlink(String),
}

#[derive(Clone, Debug)]
struct Node {
    kind: NodeKind,
    mode: u32,
    mtime: Timestamp,
}

impl Node {
    fn new(kind: NodeKind) -> Self {
        let mode = match kind {
            NodeKind::Dir => 0o755,
            NodeKind::File(_) => 0o644,
            NodeKind::Symlink(_) => 0o777,
        };
        Self {
            kind,
            mode,
            mtime: now(),
        }
    }

    fn file(&self) -> Option<&SparseData> {
        match &self.kind {
            NodeKind::File(d) => Some(d),
            _ => None,
        }
    }
}

fn now() -> Timestamp {
    Timestamp::new(OffsetDateTime::now_utc(), Precision::Second)
}

/// Normalises a test-helper path string ("a//b/" → "/a/b").
fn norm(path: &str) -> String {
    let comps: Vec<&str> = path
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    format!("/{}", comps.join("/"))
}

fn child_key(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

fn parent_key(key: &str) -> String {
    match key.rfind('/') {
        Some(0) | None => "/".to_owned(),
        Some(i) => key[..i].to_owned(),
    }
}

fn name_of(key: &str) -> &str {
    key.rsplit('/').next().unwrap_or(key)
}

fn path_of(key: &str) -> RemotePath {
    RemotePath::parse(key).unwrap_or_else(|_| RemotePath::root())
}

#[derive(Debug)]
struct MockState {
    caps: Capabilities,
    nodes: BTreeMap<String, Node>,
    latency: Duration,
    bandwidth: Option<u64>,
    max_connections: Option<usize>,
    failures: HashMap<MockOp, VecDeque<fn() -> Error>>,
    calls: HashMap<MockOp, usize>,
    connected: usize,
    peak: usize,
    generation: u64,
    connect_prompt: Option<PromptKind>,
}

impl MockState {
    fn ci(&self) -> bool {
        self.caps.case_insensitive_names
    }

    /// Keys of the direct children of `dir`.
    fn children(&self, dir: &str) -> Vec<String> {
        let prefix = if dir == "/" {
            "/".to_owned()
        } else {
            format!("{dir}/")
        };
        self.nodes
            .range(prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix))
            .filter(|(k, _)| k.len() > prefix.len() && !k[prefix.len()..].contains('/'))
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// The key of the existing child `name` of `dir` (case-insensitive if configured).
    fn find_child(&self, dir: &str, name: &str) -> Option<String> {
        let key = child_key(dir, name);
        if self.nodes.contains_key(&key) {
            return Some(key);
        }
        if self.ci() {
            let lower = name.to_lowercase();
            return self
                .children(dir)
                .into_iter()
                .find(|k| name_of(k).to_lowercase() == lower);
        }
        None
    }

    /// Resolves `path` to the key of an existing node. Intermediate symlinks are always
    /// followed, the final one only with `follow_final`.
    fn walk(&self, path: &str, follow_final: bool) -> Option<String> {
        let mut queue: VecDeque<String> = path
            .split('/')
            .filter(|c| !c.is_empty())
            .map(str::to_owned)
            .collect();
        let mut cur = "/".to_owned();
        let mut hops = 0;
        while let Some(comp) = queue.pop_front() {
            match comp.as_str() {
                "." => continue,
                ".." => {
                    cur = parent_key(&cur);
                    continue;
                }
                _ => {}
            }
            if !matches!(self.nodes.get(&cur)?.kind, NodeKind::Dir) {
                return None;
            }
            let key = self.find_child(&cur, &comp)?;
            let node = self.nodes.get(&key)?;
            if let NodeKind::Symlink(target) = &node.kind
                && (!queue.is_empty() || follow_final)
            {
                hops += 1;
                if hops > MAX_HOPS {
                    return None;
                }
                if target.starts_with('/') {
                    cur = "/".to_owned();
                }
                for c in target.split('/').filter(|c| !c.is_empty()).rev() {
                    queue.push_front(c.to_owned());
                }
                continue;
            }
            cur = key;
        }
        Some(cur)
    }

    fn get(&self, path: &RemotePath, follow_final: bool) -> Result<(String, &Node)> {
        let key = self
            .walk(path.as_str(), follow_final)
            .ok_or_else(|| Error::NotFound(path.clone()))?;
        let node = self
            .nodes
            .get(&key)
            .ok_or_else(|| Error::NotFound(path.clone()))?;
        Ok((key, node))
    }

    /// Key a new or existing `path` would have: its parent must be an existing directory.
    fn target_key(&self, path: &RemotePath) -> Result<String> {
        let parent = path.parent().ok_or_else(|| {
            Error::PermissionDenied(format!("{path}: cannot replace the root directory"))
        })?;
        let name = path.file_name().unwrap_or_default();
        let (pkey, pnode) = self.get(&parent, true)?;
        if !matches!(pnode.kind, NodeKind::Dir) {
            return Err(Error::NotFound(parent));
        }
        Ok(self
            .find_child(&pkey, name)
            .unwrap_or_else(|| child_key(&pkey, name)))
    }

    fn entry(&self, key: &str, node: &Node) -> Entry {
        let name = if key == "/" { "/" } else { name_of(key) };
        let kind = match &node.kind {
            NodeKind::Dir => EntryKind::Dir,
            NodeKind::File(_) => EntryKind::File,
            NodeKind::Symlink(target) => {
                let target_kind = match self.walk(key, true).and_then(|k| self.nodes.get(&k)) {
                    Some(Node {
                        kind: NodeKind::Dir,
                        ..
                    }) => SymlinkTarget::Dir,
                    Some(Node {
                        kind: NodeKind::File(_),
                        ..
                    }) => SymlinkTarget::File,
                    Some(_) => SymlinkTarget::Other,
                    None => SymlinkTarget::Broken,
                };
                EntryKind::Symlink {
                    target: Some(target.clone()),
                    target_kind: Some(target_kind),
                }
            }
        };
        let mut e = Entry::new(name, kind);
        e.size = node.file().map(|d| d.len);
        e.modified = Some(node.mtime);
        e.permissions = Some(Permissions::from_mode(node.mode));
        e.owner = Some("test".into());
        e.group = Some("test".into());
        e.hidden = name.starts_with('.');
        e
    }

    fn add_dir_all(&mut self, key: &str) {
        let mut cur = "/".to_owned();
        for comp in key.split('/').filter(|c| !c.is_empty()) {
            cur = child_key(&cur, comp);
            self.nodes
                .entry(cur.clone())
                .or_insert_with(|| Node::new(NodeKind::Dir));
        }
    }

    fn insert(&mut self, path: &str, kind: NodeKind) {
        let key = norm(path);
        self.add_dir_all(&parent_key(&key));
        self.nodes.insert(key, Node::new(kind));
    }
}

fn default_caps() -> Capabilities {
    Capabilities {
        chmod: true,
        set_mtime: true,
        resume_download: true,
        resume_upload: true,
        append: true,
        raw_commands: false,
        symlinks: true,
        server_side_rename_across_dirs: true,
        ascii_mode: false,
        parallel_connections_allowed: true,
        positional_writes: true,
        case_insensitive_names: false,
        path_style: PathStyle::Unix,
    }
}

// ---------------------------------------------------------------- MockServer

/// An in-memory "server": a file tree shared by every [`MockBackend`] it creates.
#[derive(Clone, Debug)]
pub struct MockServer {
    state: Arc<Mutex<MockState>>,
}

impl Default for MockServer {
    fn default() -> Self {
        Self::new()
    }
}

impl MockServer {
    /// A server with "/" and the home directory "/home/test". Capabilities: everything
    /// except `raw_commands`, `ascii_mode` and `case_insensitive_names`; Unix paths.
    pub fn new() -> Self {
        let mut state = MockState {
            caps: default_caps(),
            nodes: BTreeMap::new(),
            latency: Duration::ZERO,
            bandwidth: None,
            max_connections: None,
            failures: HashMap::new(),
            calls: HashMap::new(),
            connected: 0,
            peak: 0,
            generation: 0,
            connect_prompt: None,
        };
        state.nodes.insert("/".into(), Node::new(NodeKind::Dir));
        state.add_dir_all(HOME);
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    fn lock(&self) -> MutexGuard<'_, MockState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Replaces the capabilities every session reports.
    pub fn with_capabilities(self, caps: Capabilities) -> Self {
        self.lock().caps = caps;
        self
    }

    /// `mkdir -p path`.
    pub fn add_dir(&self, path: &str) {
        self.lock().add_dir_all(&norm(path));
    }

    /// Adds (or replaces) a file, creating missing parent directories.
    pub fn add_file(&self, path: &str, data: impl Into<bytes::Bytes>) {
        let data = data.into();
        self.lock()
            .insert(path, NodeKind::File(SparseData::from_bytes(&data)));
    }

    /// A file of `len` zero bytes stored sparsely (> 4 GiB without memory).
    pub fn add_sparse_file(&self, path: &str, len: u64) {
        let data = SparseData {
            len,
            chunks: BTreeMap::new(),
        };
        self.lock().insert(path, NodeKind::File(data));
    }

    /// Adds a symlink at `path` pointing to `target` (absolute, or relative to the
    /// link's directory).
    pub fn add_symlink(&self, path: &str, target: &str) {
        self.lock()
            .insert(path, NodeKind::Symlink(target.to_owned()));
    }

    /// Sets the mode and/or modification time of an existing node.
    pub fn set_meta(&self, path: &str, mode: Option<u32>, mtime: Option<Timestamp>) {
        let mut s = self.lock();
        if let Some(node) = s.nodes.get_mut(&norm(path)) {
            if let Some(mode) = mode {
                node.mode = mode & 0o7777;
            }
            if let Some(mtime) = mtime {
                node.mtime = mtime;
            }
        }
    }

    /// Contents of a file (symlinks followed), for assertions. None when missing, not a
    /// file, or larger than 64 MiB.
    pub fn read_file(&self, path: &str) -> Option<Vec<u8>> {
        let s = self.lock();
        let key = s.walk(&norm(path), true)?;
        let data = s.nodes.get(&key)?.file()?;
        (data.len <= READ_FILE_MAX).then(|| data.to_vec())
    }

    /// Length of a file (symlinks followed).
    pub fn file_len(&self, path: &str) -> Option<u64> {
        let s = self.lock();
        let key = s.walk(&norm(path), true)?;
        s.nodes.get(&key)?.file().map(|d| d.len)
    }

    /// Whether anything exists at `path` (the final symlink is not followed).
    pub fn exists(&self, path: &str) -> bool {
        let s = self.lock();
        s.walk(&norm(path), false).is_some()
    }

    /// A new, not yet connected session.
    pub fn backend(&self, ctx: BackendContext) -> MockBackend {
        let address = ServerAddress {
            protocol: Protocol::Sftp,
            encryption: FtpEncryption::ExplicitIfAvailable,
            host: "mock.invalid".into(),
            port: None,
            user: Some("test".into()),
        };
        MockBackend {
            server: self.clone(),
            ctx,
            address,
            connected: false,
            generation: 0,
            transfer: None,
        }
    }

    /// Delay before every operation (`tokio::time::sleep`; works with paused time).
    pub fn set_latency(&self, d: Duration) {
        self.lock().latency = d;
    }

    /// Per-connection stream throughput limit in bytes/s (None = unlimited). Applies to
    /// streams opened afterwards.
    pub fn set_bandwidth(&self, bytes_per_sec: Option<u64>) {
        self.lock().bandwidth = bytes_per_sec.filter(|b| *b > 0);
    }

    /// `connect()` beyond `n` simultaneous sessions → `Error::ConnectionLimit`.
    pub fn set_max_connections(&self, n: Option<usize>) {
        self.lock().max_connections = n;
    }

    /// Queues a failure for the next call of `op` (FIFO, any session). The call is
    /// counted, waits the latency, then returns `make()`. A connection-lost error also
    /// disconnects the session.
    pub fn fail_next(&self, op: MockOp, make: fn() -> Error) {
        self.lock().failures.entry(op).or_default().push_back(make);
    }

    /// Every connected session loses its connection: the next operation fails with
    /// `Error::Connection` and `is_connected()` is false until `connect()`.
    pub fn drop_connections(&self) {
        let mut s = self.lock();
        s.generation += 1;
        s.connected = 0;
    }

    /// `connect()` raises this prompt via `ctx.events` and fails with `Cancelled` on
    /// Cancel (`HostKey` / `Tls` when a trust prompt is answered with Reject).
    pub fn set_connect_prompt(&self, kind: Option<PromptKind>) {
        self.lock().connect_prompt = kind;
    }

    /// How often `op` was called (including injected failures).
    pub fn calls(&self, op: MockOp) -> usize {
        self.lock().calls.get(&op).copied().unwrap_or(0)
    }

    /// Sessions connected now.
    pub fn connections(&self) -> usize {
        self.lock().connected
    }

    /// Most sessions connected at the same time so far.
    pub fn peak_connections(&self) -> usize {
        self.lock().peak
    }
}

impl BackendFactory for MockServer {
    /// `backend(ctx)` with the address of `info` (after [`ConnectInfo::validate`]).
    fn create(&self, info: Arc<ConnectInfo>, ctx: BackendContext) -> Result<Box<dyn Backend>> {
        info.validate()?;
        let mut backend = self.backend(ctx);
        backend.address = info.address.clone();
        Ok(Box::new(backend))
    }
}

// ---------------------------------------------------------------- helpers for tests

/// A [`BackendContext`] for tests (new session id, default settings, debug level
/// `Debug`) and the receiving end of its event bus.
pub fn test_context() -> (BackendContext, EventReceiver) {
    test_context_with(Settings::default())
}

/// As [`test_context`], with the given settings.
pub fn test_context_with(settings: Settings) -> (BackendContext, EventReceiver) {
    let (events, rx) = event_channel(DebugLevel::Debug);
    let (_tx, settings): (_, SharedSettings) = tokio::sync::watch::channel(Arc::new(settings));
    (
        BackendContext {
            session: SessionId::next(),
            events,
            settings,
        },
        rx,
    )
}

/// A conformance environment backed by a fresh [`MockServer`]: scratch directory
/// `/scratch`, large files enabled, symlinks created with [`MockServer::add_symlink`].
pub fn conformance_env() -> ConformanceEnv {
    let server = MockServer::new();
    server.add_dir("/scratch");
    let make_server = server.clone();
    let link_server = server;
    ConformanceEnv {
        scratch: path_of("/scratch"),
        make: Box::new(move || {
            let (ctx, _rx) = test_context();
            Ok(Box::new(make_server.backend(ctx)) as Box<dyn Backend>)
        }),
        large_files: true,
        skip: Vec::new(),
        make_symlink: Some(Box::new(move |link: &RemotePath, target: &str| {
            link_server.add_symlink(link.as_str(), target);
            Ok(())
        })),
    }
}

// ---------------------------------------------------------------- MockBackend

/// One session of a [`MockServer`].
#[derive(Debug)]
pub struct MockBackend {
    server: MockServer,
    ctx: BackendContext,
    address: ServerAddress,
    connected: bool,
    /// The server generation at connect (see [`MockServer::drop_connections`]).
    generation: u64,
    /// The open transfer: the stream holds a clone (alive while the stream lives); the
    /// flag turns false when the transfer is finished.
    transfer: Option<Arc<AtomicBool>>,
}

impl Drop for MockBackend {
    fn drop(&mut self) {
        self.mark_disconnected();
    }
}

impl MockBackend {
    fn lock(&self) -> MutexGuard<'_, MockState> {
        self.server.lock()
    }

    fn end_transfer(&mut self) {
        if let Some(t) = self.transfer.take() {
            t.store(false, Ordering::Release);
        }
    }

    fn mark_disconnected(&mut self) {
        self.end_transfer();
        if self.connected {
            self.connected = false;
            let mut s = self.lock();
            if s.generation == self.generation {
                s.connected = s.connected.saturating_sub(1);
            }
        }
    }

    fn unsupported(op: &str) -> Error {
        Error::Unsupported(format!("{op} is not supported by mock"))
    }

    /// Common start of every operation: count, latency, injected failure, connection
    /// state, transfer protocol.
    async fn begin(&mut self, op: MockOp, cancel: Option<&CancellationToken>) -> Result<()> {
        let latency = {
            let mut s = self.lock();
            *s.calls.entry(op).or_default() += 1;
            s.latency
        };
        if !latency.is_zero() {
            match cancel {
                Some(token) => tokio::select! {
                    () = token.cancelled() => return Err(Error::Cancelled),
                    () = tokio::time::sleep(latency) => {}
                },
                None => tokio::time::sleep(latency).await,
            }
        }
        let injected = self
            .lock()
            .failures
            .get_mut(&op)
            .and_then(VecDeque::pop_front);
        if let Some(make) = injected {
            let err = make();
            if err.is_connection_lost() {
                self.mark_disconnected();
            }
            return Err(err);
        }
        if matches!(op, MockOp::Connect | MockOp::Disconnect) {
            return Ok(());
        }
        if !self.connected {
            return Err(Error::Connection("not connected".into()));
        }
        if self.lock().generation != self.generation {
            self.mark_disconnected();
            return Err(Error::Connection("connection closed by server".into()));
        }
        if op != MockOp::FinishTransfer
            && let Some(t) = &self.transfer
        {
            if Arc::strong_count(t) > 1 {
                return Err(Error::Internal("transfer in progress".into()));
            }
            // Stream dropped without finish_transfer: implicit Abort.
            self.end_transfer();
        }
        Ok(())
    }

    fn throttle(&self) -> Throttle {
        Throttle::new(self.lock().bandwidth)
    }
}

#[async_trait]
impl Backend for MockBackend {
    fn capabilities(&self) -> Capabilities {
        self.lock().caps
    }

    fn address(&self) -> Option<&ServerAddress> {
        Some(&self.address)
    }

    fn is_connected(&self) -> bool {
        self.connected && self.lock().generation == self.generation
    }

    fn security_info(&self) -> SessionSecurityInfo {
        if !self.is_connected() {
            return SessionSecurityInfo::default();
        }
        SessionSecurityInfo {
            encrypted: false,
            summary: "mock".into(),
            server_software: Some("courier-ftp mock server".into()),
            ..SessionSecurityInfo::default()
        }
    }

    async fn connect(&mut self, cancel: CancellationToken) -> Result<()> {
        self.begin(MockOp::Connect, Some(&cancel)).await?;
        if self.is_connected() {
            return Ok(());
        }
        self.mark_disconnected();
        let prompt = self.lock().connect_prompt.clone();
        if let Some(kind) = prompt {
            let answer = self
                .ctx
                .events
                .prompt_with_cancel(self.ctx.session, kind, &cancel)
                .await?;
            match answer {
                PromptResponse::HostKey(TrustAnswer::Reject) => {
                    return Err(Error::HostKey("host key rejected by the user".into()));
                }
                PromptResponse::Certificate(TrustAnswer::Reject) => {
                    return Err(Error::Tls("certificate rejected by the user".into()));
                }
                _ => {}
            }
        }
        let mut s = self.lock();
        if let Some(max) = s.max_connections
            && s.connected >= max
        {
            return Err(Error::ConnectionLimit(format!(
                "too many connections (limit {max})"
            )));
        }
        s.connected += 1;
        s.peak = s.peak.max(s.connected);
        let generation = s.generation;
        drop(s);
        self.generation = generation;
        self.connected = true;
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.begin(MockOp::Disconnect, None).await?;
        self.mark_disconnected();
        Ok(())
    }

    async fn home_dir(&mut self) -> Result<RemotePath> {
        self.begin(MockOp::HomeDir, None).await?;
        RemotePath::parse(HOME)
    }

    async fn list(&mut self, dir: &RemotePath, cancel: CancellationToken) -> Result<Listing> {
        self.begin(MockOp::List, Some(&cancel)).await?;
        let (entries, raw) = {
            let s = self.lock();
            let (key, node) = s.get(dir, true)?;
            if !matches!(node.kind, NodeKind::Dir) {
                return Err(Error::Protocol {
                    code: None,
                    message: format!("{dir}: not a directory"),
                });
            }
            let mut entries = Vec::new();
            let mut raw = String::new();
            for child in s.children(&key) {
                if let Some(node) = s.nodes.get(&child) {
                    let e = s.entry(&child, node);
                    let rwx = e
                        .permissions
                        .as_ref()
                        .and_then(|p| p.ls_string(&e.kind))
                        .unwrap_or_default();
                    raw.push_str(&format!(
                        "{rwx} 1 test test {} {}\n",
                        e.size.unwrap_or(0),
                        e.name
                    ));
                    entries.push(e);
                }
            }
            (entries, raw)
        };
        Ok(Listing::build(
            dir.clone(),
            entries,
            Some(raw),
            Some(&self.ctx.log()),
        ))
    }

    async fn stat(&mut self, path: &RemotePath) -> Result<Entry> {
        self.begin(MockOp::Stat, None).await?;
        let s = self.lock();
        let (key, node) = s.get(path, false)?;
        Ok(s.entry(&key, node))
    }

    async fn mkdir(&mut self, path: &RemotePath) -> Result<()> {
        self.begin(MockOp::Mkdir, None).await?;
        let mut s = self.lock();
        let key = s.target_key(path)?;
        if s.nodes.contains_key(&key) {
            return Err(Error::AlreadyExists(path.clone()));
        }
        s.nodes.insert(key, Node::new(NodeKind::Dir));
        Ok(())
    }

    async fn rmdir(&mut self, path: &RemotePath) -> Result<()> {
        self.begin(MockOp::Rmdir, None).await?;
        let mut s = self.lock();
        let (key, node) = s.get(path, false)?;
        if !matches!(node.kind, NodeKind::Dir) {
            return Err(Error::Protocol {
                code: None,
                message: "not a directory".into(),
            });
        }
        if key == "/" {
            return Err(Error::PermissionDenied(
                "cannot remove the root directory".into(),
            ));
        }
        if !s.children(&key).is_empty() {
            return Err(Error::Protocol {
                code: None,
                message: "directory not empty".into(),
            });
        }
        s.nodes.remove(&key);
        Ok(())
    }

    async fn remove_file(&mut self, path: &RemotePath) -> Result<()> {
        self.begin(MockOp::RemoveFile, None).await?;
        let mut s = self.lock();
        let (key, node) = s.get(path, false)?;
        if matches!(node.kind, NodeKind::Dir) {
            return Err(Error::Protocol {
                code: None,
                message: "is a directory".into(),
            });
        }
        s.nodes.remove(&key);
        Ok(())
    }

    async fn rename(&mut self, from: &RemotePath, to: &RemotePath, replace: bool) -> Result<()> {
        self.begin(MockOp::Rename, None).await?;
        let mut s = self.lock();
        let (from_key, from_node) = s.get(from, false)?;
        let from_is_dir = matches!(from_node.kind, NodeKind::Dir);
        let to_key = s.target_key(to)?;
        if from_key == "/" {
            return Err(Error::PermissionDenied(
                "cannot rename the root directory".into(),
            ));
        }
        if from_key == to_key {
            return Ok(());
        }
        if !s.caps.server_side_rename_across_dirs && parent_key(&from_key) != parent_key(&to_key) {
            return Err(Self::unsupported("rename across directories"));
        }
        if to_key.starts_with(&format!("{from_key}/")) {
            return Err(Error::InvalidInput(format!(
                "cannot move {from} into itself"
            )));
        }
        if let Some(existing) = s.nodes.get(&to_key) {
            if !replace {
                return Err(Error::AlreadyExists(to.clone()));
            }
            if matches!(existing.kind, NodeKind::Dir) || from_is_dir {
                return Err(Error::Protocol {
                    code: None,
                    message: "cannot replace a directory".into(),
                });
            }
            s.nodes.remove(&to_key);
        }
        let prefix = format!("{from_key}/");
        let moved: Vec<String> = s
            .nodes
            .range(prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix))
            .map(|(k, _)| k.clone())
            .collect();
        if let Some(node) = s.nodes.remove(&from_key) {
            s.nodes.insert(to_key.clone(), node);
        }
        for old in moved {
            if let Some(node) = s.nodes.remove(&old) {
                let new = format!("{to_key}/{}", &old[prefix.len()..]);
                s.nodes.insert(new, node);
            }
        }
        Ok(())
    }

    async fn chmod(&mut self, path: &RemotePath, mode: u32) -> Result<()> {
        self.begin(MockOp::Chmod, None).await?;
        let mut s = self.lock();
        if !s.caps.chmod {
            return Err(Self::unsupported("chmod"));
        }
        let (key, _) = s.get(path, true)?;
        if let Some(node) = s.nodes.get_mut(&key) {
            node.mode = mode & 0o7777;
        }
        Ok(())
    }

    async fn set_mtime(&mut self, path: &RemotePath, time: OffsetDateTime) -> Result<()> {
        self.begin(MockOp::SetMtime, None).await?;
        let mut s = self.lock();
        if !s.caps.set_mtime {
            return Err(Self::unsupported("set_mtime"));
        }
        let (key, _) = s.get(path, true)?;
        if let Some(node) = s.nodes.get_mut(&key) {
            node.mtime = Timestamp::new(time, Precision::Second);
        }
        Ok(())
    }

    async fn open_read(
        &mut self,
        path: &RemotePath,
        offset: u64,
        opts: &TransferOpts,
    ) -> Result<ReadStream> {
        self.begin(MockOp::OpenRead, None).await?;
        let (key, end) = {
            let s = self.lock();
            if offset > 0 && !s.caps.resume_download {
                return Err(Self::unsupported("reading from an offset"));
            }
            let (key, node) = s.get(path, true)?;
            let len = match &node.kind {
                NodeKind::File(d) => d.len,
                _ => {
                    return Err(Error::Protocol {
                        code: None,
                        message: format!("{path}: not a regular file"),
                    });
                }
            };
            let end = match opts.range_len {
                Some(n) => len.min(offset.saturating_add(n)),
                None => len,
            };
            (key, end)
        };
        let valid = Arc::new(AtomicBool::new(true));
        self.transfer = Some(Arc::clone(&valid));
        Ok(Box::new(MockReader {
            server: self.server.clone(),
            key,
            pos: offset,
            end,
            valid,
            throttle: self.throttle(),
        }))
    }

    async fn open_write(
        &mut self,
        path: &RemotePath,
        mode: WriteMode,
        _opts: &TransferOpts,
    ) -> Result<WriteStream> {
        self.begin(MockOp::OpenWrite, None).await?;
        let (key, pos) = {
            let mut s = self.lock();
            let caps = s.caps;
            let needed = match mode {
                WriteMode::Append => (!caps.append).then_some("append"),
                WriteMode::ResumeAt(_) => (!caps.resume_upload).then_some("resume upload"),
                WriteMode::WriteAt(_) => (!caps.positional_writes).then_some("positional writes"),
                WriteMode::Create | WriteMode::Truncate => None,
            };
            if let Some(what) = needed {
                return Err(Self::unsupported(what));
            }
            // Follow a final symlink to its target when it exists.
            let key = match s.walk(path.as_str(), true) {
                Some(k) => k,
                None => s.target_key(path)?,
            };
            let existing = s.nodes.get(&key);
            if matches!(
                existing.map(|n| &n.kind),
                Some(NodeKind::Dir | NodeKind::Symlink(_))
            ) {
                return Err(Error::Protocol {
                    code: None,
                    message: format!("{path}: not a regular file"),
                });
            }
            let len = existing.and_then(Node::file).map(|d| d.len);
            if mode == WriteMode::Create && len.is_some() {
                return Err(Error::AlreadyExists(path.clone()));
            }
            if let WriteMode::ResumeAt(n) = mode
                && len.unwrap_or(0) < n
            {
                return Err(Error::InvalidInput(format!(
                    "{path} is shorter than the resume offset {n}"
                )));
            }
            let node = s
                .nodes
                .entry(key.clone())
                .or_insert_with(|| Node::new(NodeKind::File(SparseData::default())));
            node.mtime = now();
            let NodeKind::File(data) = &mut node.kind else {
                return Err(Error::Internal("mock node is not a file".into()));
            };
            let pos = match mode {
                WriteMode::Create | WriteMode::Truncate => {
                    data.truncate(0);
                    0
                }
                WriteMode::Append => data.len,
                WriteMode::ResumeAt(n) => {
                    data.truncate(n);
                    n
                }
                WriteMode::WriteAt(n) => n,
            };
            (key, pos)
        };
        let valid = Arc::new(AtomicBool::new(true));
        self.transfer = Some(Arc::clone(&valid));
        Ok(Box::new(MockWriter {
            server: self.server.clone(),
            key,
            pos,
            valid,
            throttle: self.throttle(),
        }))
    }

    async fn finish_transfer(&mut self, _end: TransferEnd) -> Result<()> {
        self.begin(MockOp::FinishTransfer, None).await?;
        self.end_transfer();
        Ok(())
    }

    async fn raw_command(&mut self, cmd: &str) -> Result<String> {
        self.begin(MockOp::RawCommand, None).await?;
        if !self.lock().caps.raw_commands {
            return Err(Self::unsupported("raw commands"));
        }
        Ok(format!("200 {cmd}"))
    }

    async fn keepalive(&mut self) -> Result<()> {
        self.begin(MockOp::Keepalive, None).await
    }
}

// ---------------------------------------------------------------- streams

/// Bandwidth limiter for one stream.
struct Throttle {
    bytes_per_sec: Option<u64>,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl Throttle {
    fn new(bytes_per_sec: Option<u64>) -> Self {
        Self {
            bytes_per_sec,
            sleep: None,
        }
    }

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if let Some(sleep) = &mut self.sleep {
            ready!(sleep.as_mut().poll(cx));
            self.sleep = None;
        }
        Poll::Ready(())
    }

    /// Largest piece to move in one call: about 1/10 s worth of data.
    fn max_piece(&self, want: usize) -> usize {
        match self.bytes_per_sec {
            Some(bps) => want.min(usize::try_from(bps / 10).unwrap_or(usize::MAX).max(1)),
            None => want,
        }
    }

    fn charge(&mut self, n: usize) {
        if let Some(bps) = self.bytes_per_sec
            && n > 0
        {
            let d = Duration::from_secs_f64(n as f64 / bps as f64);
            self.sleep = Some(Box::pin(tokio::time::sleep(d)));
        }
    }
}

fn finished() -> io::Error {
    io::Error::other("transfer already finished")
}

struct MockReader {
    server: MockServer,
    key: String,
    pos: u64,
    end: u64,
    valid: Arc<AtomicBool>,
    throttle: Throttle,
}

impl AsyncRead for MockReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.valid.load(Ordering::Acquire) {
            return Poll::Ready(Err(finished()));
        }
        ready!(this.throttle.poll_ready(cx));
        let left = this.end.saturating_sub(this.pos);
        if left == 0 || buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let want = usize::try_from(left)
            .unwrap_or(usize::MAX)
            .min(buf.remaining());
        let want = this.throttle.max_piece(want);
        let got = {
            let s = this.server.lock();
            let Some(data) = s.nodes.get(&this.key).and_then(Node::file) else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "file removed during the transfer",
                )));
            };
            let dst = buf.initialize_unfilled_to(want);
            data.read_at(this.pos, dst)
        };
        buf.advance(got);
        if got == 0 {
            // The file shrank: EOF.
            this.end = this.pos;
        }
        this.pos += got as u64;
        this.throttle.charge(got);
        Poll::Ready(Ok(()))
    }
}

struct MockWriter {
    server: MockServer,
    key: String,
    pos: u64,
    valid: Arc<AtomicBool>,
    throttle: Throttle,
}

impl AsyncWrite for MockWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if !this.valid.load(Ordering::Acquire) {
            return Poll::Ready(Err(finished()));
        }
        ready!(this.throttle.poll_ready(cx));
        let n = this.throttle.max_piece(buf.len());
        {
            let mut s = this.server.lock();
            let Some(Node {
                kind: NodeKind::File(data),
                ..
            }) = s.nodes.get_mut(&this.key)
            else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "file removed during the transfer",
                )));
            };
            data.write_at(this.pos, &buf[..n]);
        }
        this.pos += n as u64;
        this.throttle.charge(n);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_data_truncate_and_read() {
        let mut d = SparseData::from_bytes(&[1; 100_000]);
        d.truncate(70_000);
        d.write_at(80_000, &[2; 10]);
        let v = d.to_vec();
        assert_eq!(v.len(), 80_010);
        assert!(v[..70_000].iter().all(|b| *b == 1));
        assert!(v[70_000..80_000].iter().all(|b| *b == 0));
        assert!(v[80_000..].iter().all(|b| *b == 2));
        d.truncate(0);
        assert_eq!(d.len, 0);
        assert!(d.chunks.is_empty());
    }

    #[test]
    fn sparse_file_beyond_4gib_costs_no_memory() {
        let server = MockServer::new();
        server.add_sparse_file("/big", 5 << 30);
        assert_eq!(server.file_len("/big"), Some(5 << 30));
        assert_eq!(server.read_file("/big"), None);
    }

    #[test]
    fn walk_follows_symlinks_and_case_rules() {
        let server = MockServer::new();
        server.add_file("/a/Data.txt", "x");
        server.add_symlink("/link", "a");
        assert_eq!(server.read_file("/link/Data.txt"), Some(b"x".to_vec()));
        assert_eq!(server.read_file("/link/data.txt"), None);
        let mut caps = default_caps();
        caps.case_insensitive_names = true;
        let server = server.with_capabilities(caps);
        assert_eq!(server.read_file("/A/data.TXT"), Some(b"x".to_vec()));
    }
}
