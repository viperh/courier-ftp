//! An in-memory backend for tests (feature `test-util`).
//!
//! A [`MockServer`] is a shared directory tree with counters and fault
//! injection; every [`MockBackend`] it creates is one "connection" to it.

use std::{
    collections::{BTreeMap, VecDeque},
    io,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll},
    time::Instant,
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
            }
            return Err(err);
        }
        Ok(st)
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
        let mut st = self.server.lock();
        st.connects += 1;
        if let Some(err) = st.fail_connect.pop_front() {
            return Err(err);
        }
        self.connected = true;
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
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
        let st = self.begin()?;
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        match st.nodes.get(dir) {
            Some(n) if n.is_dir => {}
            Some(_) => return Err(Error::InvalidInput(format!("{dir} is not a directory"))),
            None => return Err(not_found(dir)),
        }
        let children: Vec<(&str, &Node)> = st
            .nodes
            .iter()
            .filter(|(p, _)| p.parent().as_ref() == Some(dir))
            .filter_map(|(p, n)| p.file_name().map(|name| (name, n)))
            .collect();
        // An MLSD-style raw listing, for the "show raw listing" diagnostic.
        let raw = children
            .iter()
            .map(|(name, n)| {
                let kind = if n.is_dir { "dir" } else { "file" };
                format!("type={kind};size={}; {name}\r\n", n.data.len())
            })
            .collect::<String>();
        let entries = children.iter().map(|(name, n)| n.entry(name)).collect();
        Ok(Listing {
            dir: dir.clone(),
            entries,
            fetched_at: Instant::now(),
            raw: Some(raw),
        })
    }

    async fn stat(&mut self, path: &RemotePath) -> Result<Entry> {
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
        let st = self.begin()?;
        let node = st.nodes.get(path).ok_or_else(|| not_found(path))?;
        if node.is_dir {
            return Err(Error::InvalidInput(format!("{path} is a directory")));
        }
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(node.data.len());
        Ok(Box::new(io::Cursor::new(node.data[start..].to_vec())))
    }

    async fn open_write(
        &mut self,
        path: &RemotePath,
        mode: WriteMode,
        _opts: &TransferOpts,
    ) -> Result<WriteStream> {
        let mut st = self.begin()?;
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
        }))
    }

    async fn finish_transfer(&mut self) -> Result<()> {
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
}

impl AsyncWrite for MockWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut st = self.server.lock();
        match st.nodes.get_mut(&self.path) {
            Some(node) => {
                node.data.extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
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
