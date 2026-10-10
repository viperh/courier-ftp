//! [`SftpBackend`]: the core `Backend` over SFTP protocol version 3 (T22).
//!
//! `connect` opens the SSH connection (T20, host keys via T21's verifier), starts the
//! `sftp` subsystem, reads the server's extensions (`posix-rename@openssh.com`,
//! `limits@openssh.com`) and sizes the pipelined transfers. Every operation is a short
//! sequence of SFTP requests on one `RawSftpSession` (see the T22 table); transfers
//! use the pipelined streams of [`crate::io`].

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use courier_ftp_core::{
    Error, Result,
    backend::{
        Backend, BackendContext, Capabilities, ConnectInfo, Listing, ReadStream,
        SessionSecurityInfo, TransferEnd, TransferOpts, WriteMode, WriteStream,
    },
    events::{HostKeyInfo, SessionLog},
    model::{
        Charset, Entry, EntryKind, PathStyle, RemotePath, ServerAddress, SymlinkTarget,
        TransferType,
    },
    settings::Settings,
};
use futures::{StreamExt as _, stream};
use russh_sftp::{
    client::{Config, RawSftpSession, error::Error as SftpError, rawsession::Limits},
    protocol::{FileAttributes, Packet, StatusCode},
};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::{
    agent::AgentConnector,
    convert::{SftpOp, entry_from_attrs, entry_from_name, is_status, map_status},
    io::{IoParams, SftpReader, SftpWriter, TransferState, probe_exists},
    ssh::{HostKeyVerifier, ServerKey, SshConnectParams, SshConnection, SshSessionInfo},
};

/// In-flight budget per open file (D11).
pub const MAX_INFLIGHT_BYTES: u32 = 8 * 1024 * 1024;
/// Largest request size (255 KiB: a DATA packet stays below 256 KiB).
pub const MAX_CHUNK: u32 = 261_120;
/// Smallest request size.
pub const MIN_CHUNK: u32 = 4096;
/// `max_packet_len` given to russh-sftp (264 KiB).
pub const MAX_PACKET_LEN: u32 = 270_336;
/// Symlinks resolved per listing.
pub const MAX_SYMLINKS_RESOLVED: usize = 1000;
/// Symlink resolutions in flight.
pub const SYMLINKS_IN_FLIGHT: usize = 16;
/// Listing entry cap.
pub const MAX_LISTING_ENTRIES: usize = 1_000_000;
/// Bound of the best-effort cleanup (directory `CLOSE` on cancel, disconnect).
pub const CLEANUP_WAIT: Duration = Duration::from_secs(2);

/// Values taken from Settings at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SftpTuning {
    /// `connection.timeout_secs` (20 s): every SFTP request.
    pub request_timeout: Duration,
    /// `sftp.max_outstanding_requests` (64; 1..=256).
    pub max_outstanding_requests: u32,
    /// `sftp.request_size` (32 KiB; 4 KiB..=255 KiB).
    pub request_size: u32,
    /// 8 MiB per open file.
    pub max_inflight_bytes: u32,
}

impl SftpTuning {
    /// From the settings (clamped to the documented ranges).
    pub fn from_settings(s: &Settings) -> Self {
        Self {
            request_timeout: Duration::from_secs(u64::from(s.connection.timeout_secs.max(1))),
            max_outstanding_requests: s.sftp.max_outstanding_requests.clamp(1, 256),
            request_size: s.sftp.request_size.clamp(MIN_CHUNK, MAX_CHUNK),
            max_inflight_bytes: MAX_INFLIGHT_BYTES,
        }
    }
}

impl Default for SftpTuning {
    fn default() -> Self {
        Self::from_settings(&Settings::default())
    }
}

/// `limits@openssh.com` values (0 = not limited).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerLimits {
    /// Largest packet the server accepts.
    pub max_packet_len: u64,
    /// Largest READ length.
    pub max_read_len: u64,
    /// Largest WRITE payload.
    pub max_write_len: u64,
    /// Open handles at most.
    pub max_open_handles: u64,
}

/// What the server advertised in `SSH_FXP_VERSION`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerExtensions {
    /// `posix-rename@openssh.com` = "1".
    pub posix_rename: bool,
    /// `statvfs@openssh.com` = "2".
    pub statvfs: bool,
    /// `fsync@openssh.com` = "1".
    pub fsync: bool,
    /// `hardlink@openssh.com` = "1".
    pub hardlink: bool,
    /// `limits@openssh.com` = "1", then queried.
    pub limits: Option<ServerLimits>,
    /// `check-file-name` / `check-file-handle` (T41b integrity).
    pub check_file: bool,
    /// Every advertised name (sorted), for the info dialog.
    pub other: Vec<String>,
}

impl ServerExtensions {
    /// Parse the extension pairs; returns whether `limits@openssh.com` was advertised
    /// (the values are queried separately).
    pub fn parse(pairs: &HashMap<String, String>) -> (Self, bool) {
        let has = |name: &str, version: &str| pairs.get(name).is_some_and(|v| v == version);
        let mut other: Vec<String> = pairs.keys().cloned().collect();
        other.sort();
        let ext = Self {
            posix_rename: has("posix-rename@openssh.com", "1"),
            statvfs: has("statvfs@openssh.com", "2"),
            fsync: has("fsync@openssh.com", "1"),
            hardlink: has("hardlink@openssh.com", "1"),
            limits: None,
            check_file: pairs.contains_key("check-file-name")
                || pairs.contains_key("check-file-handle"),
            other,
        };
        (ext, has("limits@openssh.com", "1"))
    }
}

/// Request sizes and depths per direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoSizes {
    /// READ length.
    pub read_chunk: u32,
    /// WRITE payload.
    pub write_chunk: u32,
    /// READs in flight.
    pub read_outstanding: u32,
    /// WRITEs in flight.
    pub write_outstanding: u32,
}

/// One direction's chunk: the server limit (capped at 255 KiB) or the setting; 0 means
/// "not limited"; clamped to 4 KiB..=255 KiB and never above a non-zero server limit.
fn chunk_for(request_size: u32, limit: Option<u64>) -> u32 {
    let raw = match limit {
        Some(l) if l > 0 => l.min(u64::from(MAX_CHUNK)),
        _ => u64::from(request_size),
    };
    let chunk = u32::try_from(raw)
        .unwrap_or(MAX_CHUNK)
        .clamp(MIN_CHUNK, MAX_CHUNK);
    match limit {
        Some(l) if l > 0 => chunk.min(u32::try_from(l).unwrap_or(u32::MAX)).max(1),
        _ => chunk,
    }
}

/// `clamp(min(max_outstanding, 8 MiB / chunk), 1, 256)`.
fn outstanding_for(t: &SftpTuning, chunk: u32) -> u32 {
    t.max_outstanding_requests
        .min(t.max_inflight_bytes / chunk.max(1))
        .clamp(1, 256)
}

/// The I/O sizes for `tuning` and the server's limits.
pub fn io_sizes(tuning: &SftpTuning, limits: Option<&ServerLimits>) -> IoSizes {
    let read_chunk = chunk_for(tuning.request_size, limits.map(|l| l.max_read_len));
    let write_chunk = chunk_for(tuning.request_size, limits.map(|l| l.max_write_len));
    IoSizes {
        read_chunk,
        write_chunk,
        read_outstanding: outstanding_for(tuning, read_chunk),
        write_outstanding: outstanding_for(tuning, write_chunk),
    }
}

/// Negotiated SSH algorithms and SFTP extensions.
#[derive(Debug, Clone)]
pub struct SftpServerInfo {
    /// T20's session info (empty for a test transport without SSH).
    pub ssh: SshSessionInfo,
    /// The version the server sent (we speak 3).
    pub sftp_version: u32,
    /// The advertised extensions.
    pub extensions: ServerExtensions,
    /// READ length.
    pub read_chunk: u32,
    /// WRITE payload.
    pub write_chunk: u32,
    /// READs in flight.
    pub outstanding: u32,
    /// WRITEs in flight.
    pub write_outstanding: u32,
}

/// The constant SFTP capabilities.
pub const SFTP_CAPABILITIES: Capabilities = Capabilities {
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
};

/// The live session.
struct Live {
    /// None: a test transport without SSH ([`SftpBackend::attach`]).
    ssh: Option<SshConnection>,
    raw: Arc<RawSftpSession>,
    server: SftpServerInfo,
    home: RemotePath,
    /// A request failed with a connection-level error.
    broken: Arc<AtomicBool>,
}

impl Live {
    fn is_open(&self) -> bool {
        !self.broken.load(Ordering::SeqCst) && self.ssh.as_ref().is_none_or(SshConnection::is_open)
    }

    fn lost(&self) -> Error {
        let cause = self
            .ssh
            .as_ref()
            .and_then(SshConnection::end_cause)
            .unwrap_or_else(|| "The SFTP session was closed".to_owned());
        Error::Connection(cause)
    }
}

/// The SFTP backend (one SSH connection, one SFTP session).
pub struct SftpBackend {
    info: Arc<ConnectInfo>,
    ctx: BackendContext,
    tuning: SftpTuning,
    verifier: Arc<dyn HostKeyVerifier>,
    agent: Option<Arc<dyn AgentConnector>>,
    live: Option<Live>,
    transfer: Option<Arc<TransferState>>,
    ascii_logged: bool,
}

impl std::fmt::Debug for SftpBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SftpBackend")
            .field("label", &self.info.label)
            .field("session", &self.ctx.session)
            .field("tuning", &self.tuning)
            .field("connected", &self.live.is_some())
            .finish_non_exhaustive()
    }
}

/// The text after "Error: <op> <path>: ".
fn user_message(err: &Error) -> String {
    match err {
        Error::NotFound(_) => "No such file or directory".to_owned(),
        Error::PermissionDenied(_) => "Permission denied".to_owned(),
        Error::AlreadyExists(_) => "File exists".to_owned(),
        Error::Protocol { message, .. } => message.clone(),
        other => other.to_string(),
    }
}

/// The `posix-rename@openssh.com` payload: two SSH strings.
fn posix_rename_data(from: &str, to: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + from.len() + to.len());
    for s in [from, to] {
        out.extend_from_slice(&u32::try_from(s.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(s.as_bytes());
    }
    out
}

fn kib(n: u32) -> String {
    if n.is_multiple_of(1024) {
        format!("{} KiB", n / 1024)
    } else {
        format!("{n} B")
    }
}

/// `SETSTAT` attributes for `set_mtime` (v3 stores u32 seconds).
///
/// # Errors
/// `InvalidInput` outside 1970..=2106.
pub fn mtime_attrs(t: OffsetDateTime) -> Result<FileAttributes> {
    let secs = u32::try_from(t.unix_timestamp()).map_err(|_| {
        Error::InvalidInput("SFTP v3 cannot store dates before 1970 or after 2106".to_owned())
    })?;
    Ok(FileAttributes {
        atime: Some(secs),
        mtime: Some(secs),
        ..FileAttributes::empty()
    })
}

/// `SETSTAT` attributes for `chmod`: only the permissions.
pub fn chmod_attrs(mode: u32) -> FileAttributes {
    FileAttributes {
        permissions: Some(mode & 0o7777),
        ..FileAttributes::empty()
    }
}

/// `SSH_FXP_VERSION` → extensions, limits, I/O sizes and the home directory.
async fn start_session(
    raw: RawSftpSession,
    tuning: &SftpTuning,
    log: &SessionLog,
) -> Result<(Arc<RawSftpSession>, SftpServerInfo, RemotePath)> {
    let root = RemotePath::root();
    let mut raw = raw;
    let version = raw
        .init()
        .await
        .map_err(|e| map_status(e, SftpOp::Connect, &root))?;
    if version.version != 3 {
        log.status(format!("SFTP protocol version {}", version.version));
    }
    let (mut extensions, has_limits) = ServerExtensions::parse(&version.extensions);
    if has_limits {
        match raw.limits().await {
            Ok(l) => {
                let limits = ServerLimits {
                    max_packet_len: l.max_packet_len,
                    max_read_len: l.max_read_len,
                    max_write_len: l.max_write_len,
                    max_open_handles: l.max_open_handles,
                };
                raw.set_limits(Limits::from(l));
                extensions.limits = Some(limits);
            }
            Err(e) => log.debug(2, format!("limits@openssh.com failed: {e}")),
        }
    }
    let sizes = io_sizes(tuning, extensions.limits.as_ref());
    log.debug(
        3,
        format!(
            "SFTP extensions: {}; read {} × {}, write {} × {}",
            if extensions.other.is_empty() {
                "none".to_owned()
            } else {
                extensions.other.join(", ")
            },
            kib(sizes.read_chunk),
            sizes.read_outstanding,
            kib(sizes.write_chunk),
            sizes.write_outstanding
        ),
    );
    let home = match raw.realpath(".").await {
        Ok(name) => name
            .files
            .first()
            .and_then(|f| RemotePath::parse(&f.filename).ok())
            .filter(|p| p.as_str().starts_with('/')),
        Err(e) => {
            let err = map_status(e, SftpOp::RealPath, &root);
            if err.is_connection_lost() {
                return Err(err);
            }
            None
        }
    };
    let home = home.unwrap_or_else(|| {
        log.status("Warning: the server's home directory could not be read; using /");
        RemotePath::root()
    });
    let server = SftpServerInfo {
        ssh: SshSessionInfo::default(),
        sftp_version: version.version,
        extensions,
        read_chunk: sizes.read_chunk,
        write_chunk: sizes.write_chunk,
        outstanding: sizes.read_outstanding,
        write_outstanding: sizes.write_outstanding,
    };
    Ok((Arc::new(raw), server, home))
}

impl SftpBackend {
    /// No I/O; `connect` does the work. Tuning is read from `ctx.settings` here.
    pub fn new(
        info: Arc<ConnectInfo>,
        ctx: BackendContext,
        verifier: Arc<dyn HostKeyVerifier>,
        agent: Option<Arc<dyn AgentConnector>>,
    ) -> Self {
        let tuning = SftpTuning::from_settings(&ctx.settings.borrow());
        Self {
            info,
            ctx,
            tuning,
            verifier,
            agent,
            live: None,
            transfer: None,
            ascii_logged: false,
        }
    }

    /// Negotiated SSH algorithms and SFTP extensions (None before `connect`).
    pub fn server_info(&self) -> Option<SftpServerInfo> {
        self.live.as_ref().map(|l| {
            let mut s = l.server.clone();
            if let Some(ssh) = &l.ssh {
                s.ssh = ssh.info().clone();
            }
            s
        })
    }

    /// The tuning read at construction.
    pub fn tuning(&self) -> SftpTuning {
        self.tuning
    }

    /// **Tests only**: run the backend over an SFTP session without SSH (e.g.
    /// `testing::duplex_sftp_pair`); does what `connect` does after the subsystem
    /// started.
    ///
    /// # Errors
    /// As `connect`.
    #[cfg(any(test, feature = "test-util"))]
    pub async fn attach(&mut self, raw: RawSftpSession) -> Result<()> {
        let log = self.ctx.log();
        let (raw, server, home) = start_session(raw, &self.tuning, &log).await?;
        self.live = Some(Live {
            ssh: None,
            raw,
            server,
            home,
            broken: Arc::default(),
        });
        Ok(())
    }

    fn log(&self) -> SessionLog {
        self.ctx.log()
    }

    async fn connect_inner(&mut self, cancel: &CancellationToken) -> Result<Live> {
        let settings = self.ctx.settings.borrow().clone();
        let log = self.log();
        let can_save = self.info.site_id.is_some() && settings.vault.store_passwords;
        let params = SshConnectParams::from_connect_info(&self.info, &settings, can_save)?;
        let ssh = SshConnection::connect(
            params,
            Arc::clone(&self.verifier),
            self.agent.clone(),
            &log,
            cancel.clone(),
        )
        .await?;
        let start = async {
            let stream = ssh.open_subsystem("sftp").await?;
            let timeout = self.tuning.request_timeout.as_secs().max(1);
            let raw = RawSftpSession::new_with_config(
                stream,
                Config {
                    request_timeout_secs: timeout,
                    max_packet_len: MAX_PACKET_LEN,
                    ..Config::default()
                },
            );
            start_session(raw, &self.tuning, &log).await
        };
        let started = tokio::select! {
            biased;
            () = cancel.cancelled() => Err(Error::Cancelled),
            r = start => r,
        };
        let (raw, server, home) = match started {
            Ok(v) => v,
            Err(e) => {
                ssh.disconnect().await;
                return Err(e);
            }
        };
        if let Charset::Custom(_) = self.info.charset {
            log.status("Warning: Custom character sets are not supported for SFTP; using UTF-8");
        }
        log.status(format!("Connected to {}", self.info.address.host));
        Ok(Live {
            ssh: Some(ssh),
            raw,
            server,
            home,
            broken: Arc::default(),
        })
    }

    /// Before an operation: the implicit abort of a dropped stream, the
    /// "transfer in progress" rule, and the connection check (no request is sent on a
    /// dead connection).
    async fn ready(&mut self) -> Result<Arc<RawSftpSession>> {
        if let Some(t) = &self.transfer {
            if t.is_open() {
                return Err(Error::Internal("transfer in progress".to_owned()));
            }
            let t = Arc::clone(t);
            self.transfer = None;
            let _ = t.finish(CLEANUP_WAIT).await;
        }
        let live = self
            .live
            .as_ref()
            .ok_or_else(|| Error::Connection("Not connected".to_owned()))?;
        if !live.is_open() {
            return Err(live.lost());
        }
        Ok(Arc::clone(&live.raw))
    }

    /// Log a failed operation (`Error: <op> <path>: <message>`) and note a lost
    /// connection.
    fn failed(&self, op: SftpOp, path: &RemotePath, err: Error) -> Error {
        if err.is_connection_lost()
            && let Some(live) = &self.live
        {
            live.broken.store(true, Ordering::SeqCst);
        }
        let quiet = matches!(
            (op, &err),
            (SftpOp::Stat, Error::NotFound(_)) | (_, Error::Cancelled)
        );
        if !quiet {
            self.log().error(format!(
                "{} {path}: {}",
                op.failure_text(),
                user_message(&err)
            ));
        }
        info!(
            session = self.ctx.session.get(),
            op = %op,
            code = err.code(),
            "sftp operation failed"
        );
        err
    }

    fn sizes(&self) -> (IoParams, IoParams) {
        let (rc, wc, ro, wo) = self.live.as_ref().map_or(
            (
                self.tuning.request_size,
                self.tuning.request_size,
                outstanding_for(&self.tuning, self.tuning.request_size),
                outstanding_for(&self.tuning, self.tuning.request_size),
            ),
            |l| {
                (
                    l.server.read_chunk,
                    l.server.write_chunk,
                    l.server.outstanding,
                    l.server.write_outstanding,
                )
            },
        );
        let p = |chunk, outstanding| IoParams {
            chunk,
            outstanding,
            max_inflight_bytes: self.tuning.max_inflight_bytes,
        };
        (p(rc, ro), p(wc, wo))
    }

    fn note_transfer_type(&mut self, opts: &TransferOpts) {
        if opts.transfer_type == TransferType::Ascii && !self.ascii_logged {
            self.ascii_logged = true;
            self.log()
                .debug(2, "SFTP has no ASCII mode; transferring as binary");
        }
    }

    async fn stat_inner(raw: &RawSftpSession, path: &RemotePath) -> Result<Entry> {
        let attrs = raw
            .lstat(path.as_str())
            .await
            .map_err(|e| map_status(e, SftpOp::Stat, path))?
            .attrs;
        let name = path.file_name().unwrap_or("/");
        let mut entry = entry_from_attrs(name, "", &attrs);
        if let EntryKind::Symlink { .. } = entry.kind {
            entry.kind = resolve_symlink(raw, path).await?;
        }
        Ok(entry)
    }

    async fn list_inner(
        raw: Arc<RawSftpSession>,
        dir: &RemotePath,
        log: &SessionLog,
        open_handle: &std::sync::Mutex<Option<String>>,
        session: u64,
    ) -> Result<Listing> {
        let handle = raw
            .opendir(dir.as_str())
            .await
            .map_err(|e| map_status(e, SftpOp::List, dir))?
            .handle;
        *lock(open_handle) = Some(handle.clone());
        let mut entries = Vec::new();
        let mut raw_text = String::new();
        let mut raw_ok = true;
        let mut skipped = 0usize;
        let mut total = 0usize;
        let res = loop {
            match raw.readdir(handle.as_str()).await {
                Ok(name) => {
                    total += name.files.len();
                    if total > MAX_LISTING_ENTRIES {
                        break Err(Error::Protocol {
                            code: None,
                            message: "Directory has more than 1 000 000 entries".to_owned(),
                        });
                    }
                    for f in name.files {
                        if raw_ok {
                            if raw_text.len() + f.longname.len() + 1 > Listing::RAW_MAX {
                                raw_ok = false;
                                raw_text = String::new();
                            } else {
                                if !raw_text.is_empty() {
                                    raw_text.push('\n');
                                }
                                raw_text.push_str(&f.longname);
                            }
                        }
                        match entry_from_name(&f.filename, &f.longname, &f.attrs) {
                            Some(e) => entries.push(e),
                            None if f.filename == "." || f.filename == ".." => {}
                            None => {
                                skipped += 1;
                                debug!(session, "skipped a listing entry with an invalid name");
                            }
                        }
                    }
                }
                Err(e) if is_status(&e, StatusCode::Eof) => break Ok(()),
                Err(e) => break Err(map_status(e, SftpOp::List, dir)),
            }
        };
        let close = raw.close(handle.as_str()).await;
        *lock(open_handle) = None;
        res?;
        if let Err(e) = close {
            let err = map_status(e, SftpOp::Close, dir);
            if err.is_connection_lost() {
                return Err(err);
            }
        }
        if skipped > 0 {
            let noun = if skipped == 1 { "entry" } else { "entries" };
            log.status(format!("Skipped {skipped} {noun} with invalid names"));
        }
        resolve_listing_symlinks(&raw, dir, &mut entries).await;
        let raw_listing = (raw_ok && !raw_text.is_empty()).then_some(raw_text);
        Ok(Listing::build(dir.clone(), entries, raw_listing, Some(log)))
    }
}

fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// `STAT` (follows) + `READLINK` of a symlink → its kind. A target that does not exist
/// is `Broken`; other `STAT` failures leave `target_kind` unresolved.
async fn resolve_symlink(raw: &RawSftpSession, path: &RemotePath) -> Result<EntryKind> {
    let (st, rl) = tokio::join!(raw.stat(path.as_str()), raw.readlink(path.as_str()));
    let target_kind = match st {
        Ok(a) => Some(match entry_from_attrs("x", "", &a.attrs).kind {
            EntryKind::Dir => SymlinkTarget::Dir,
            EntryKind::File => SymlinkTarget::File,
            _ => SymlinkTarget::Other,
        }),
        Err(e) if is_status(&e, StatusCode::NoSuchFile) => Some(SymlinkTarget::Broken),
        Err(e @ (SftpError::Timeout | SftpError::IO(_))) => {
            return Err(map_status(e, SftpOp::Stat, path));
        }
        Err(_) => None,
    };
    let target = rl
        .ok()
        .and_then(|n| n.files.into_iter().next())
        .map(|f| f.filename);
    Ok(EntryKind::Symlink {
        target,
        target_kind,
    })
}

/// Resolve the first [`MAX_SYMLINKS_RESOLVED`] symlinks, [`SYMLINKS_IN_FLIGHT`] at a time.
async fn resolve_listing_symlinks(raw: &RawSftpSession, dir: &RemotePath, entries: &mut [Entry]) {
    let links: Vec<(usize, RemotePath)> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e.kind, EntryKind::Symlink { .. }))
        .take(MAX_SYMLINKS_RESOLVED)
        .filter_map(|(i, e)| dir.join(&e.name).ok().map(|p| (i, p)))
        .collect();
    let resolved: Vec<(usize, Result<EntryKind>)> = stream::iter(links)
        .map(|(i, p)| async move { (i, resolve_symlink(raw, &p).await) })
        .buffer_unordered(SYMLINKS_IN_FLIGHT)
        .collect()
        .await;
    for (i, kind) in resolved {
        if let (Ok(kind), Some(e)) = (kind, entries.get_mut(i)) {
            e.kind = kind;
        }
    }
}

#[async_trait]
impl Backend for SftpBackend {
    fn capabilities(&self) -> Capabilities {
        SFTP_CAPABILITIES
    }

    fn address(&self) -> Option<&ServerAddress> {
        Some(&self.info.address)
    }

    fn is_connected(&self) -> bool {
        self.live.as_ref().is_some_and(Live::is_open)
    }

    fn security_info(&self) -> SessionSecurityInfo {
        let Some(live) = &self.live else {
            return SessionSecurityInfo::default();
        };
        let ssh = live
            .ssh
            .as_ref()
            .map(|s| s.info().clone())
            .unwrap_or_default();
        let key: Option<ServerKey> = live.ssh.as_ref().and_then(SshConnection::host_key);
        let peer: Option<SocketAddr> = live.ssh.as_ref().map(SshConnection::peer_addr);
        let ext = &live.server.extensions;
        let names = if ext.other.is_empty() {
            "none".to_owned()
        } else {
            ext.other.join(", ")
        };
        SessionSecurityInfo {
            encrypted: true,
            summary: "SSH".to_owned(),
            peer_addr: peer,
            server_software: (!ssh.server_version.is_empty()).then(|| ssh.server_version.clone()),
            tls: None,
            host_key: key.map(|k| HostKeyInfo {
                key_type: k.key_type,
                bits: k.bits,
                fingerprint_sha256: k.fingerprint_sha256,
            }),
            details: vec![
                ("Key exchange".to_owned(), ssh.kex.clone()),
                ("Cipher".to_owned(), ssh.cipher.clone()),
                ("MAC".to_owned(), ssh.mac.clone()),
                ("Compression".to_owned(), ssh.compression.clone()),
                ("Authentication".to_owned(), ssh.auth_method.clone()),
                ("SFTP version".to_owned(), "3".to_owned()),
                ("Extensions".to_owned(), names),
            ],
        }
    }

    async fn connect(&mut self, cancel: CancellationToken) -> Result<()> {
        if let Some(old) = self.live.take() {
            old.raw.close_session().ok();
            if let Some(ssh) = old.ssh {
                ssh.disconnect().await;
            }
        }
        self.transfer = None;
        let res = self.connect_inner(&cancel).await;
        match res {
            Ok(live) => {
                info!(session = self.ctx.session.get(), "sftp session started");
                self.live = Some(live);
                Ok(())
            }
            Err(e) => {
                info!(
                    session = self.ctx.session.get(),
                    code = e.code(),
                    "sftp connect failed"
                );
                Err(e)
            }
        }
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.transfer = None;
        if let Some(live) = self.live.take() {
            let raw = live.raw;
            let ssh = live.ssh;
            let _ = tokio::time::timeout(CLEANUP_WAIT, async move {
                raw.close_session().ok();
                if let Some(ssh) = ssh {
                    ssh.disconnect().await;
                }
            })
            .await;
        }
        Ok(())
    }

    async fn home_dir(&mut self) -> Result<RemotePath> {
        self.ready().await?;
        self.live
            .as_ref()
            .map(|l| l.home.clone())
            .ok_or_else(|| Error::Connection("Not connected".to_owned()))
    }

    async fn list(&mut self, dir: &RemotePath, cancel: CancellationToken) -> Result<Listing> {
        let raw = self.ready().await?;
        let log = self.log();
        let open_handle = std::sync::Mutex::new(None);
        let session = self.ctx.session.get();
        let res = tokio::select! {
            biased;
            () = cancel.cancelled() => Err(Error::Cancelled),
            r = Self::list_inner(Arc::clone(&raw), dir, &log, &open_handle, session) => r,
        };
        if let Some(handle) = lock(&open_handle).take() {
            // Cancelled mid-listing: close the handle in the background.
            tokio::spawn(async move {
                let _ = tokio::time::timeout(CLEANUP_WAIT, raw.close(handle)).await;
            });
        }
        res.map_err(|e| self.failed(SftpOp::List, dir, e))
    }

    async fn stat(&mut self, path: &RemotePath) -> Result<Entry> {
        let raw = self.ready().await?;
        Self::stat_inner(&raw, path)
            .await
            .map_err(|e| self.failed(SftpOp::Stat, path, e))
    }

    async fn mkdir(&mut self, path: &RemotePath) -> Result<()> {
        let raw = self.ready().await?;
        let res = match raw.mkdir(path.as_str(), FileAttributes::empty()).await {
            Ok(_) => Ok(()),
            Err(e) => Err(probe_exists(&raw, e, SftpOp::Mkdir, path).await),
        };
        res.map_err(|e| self.failed(SftpOp::Mkdir, path, e))
    }

    async fn rmdir(&mut self, path: &RemotePath) -> Result<()> {
        let raw = self.ready().await?;
        let res = raw
            .rmdir(path.as_str())
            .await
            .map(|_| ())
            .map_err(|e| map_status(e, SftpOp::Rmdir, path));
        res.map_err(|e| self.failed(SftpOp::Rmdir, path, e))
    }

    async fn remove_file(&mut self, path: &RemotePath) -> Result<()> {
        let raw = self.ready().await?;
        let res = raw
            .remove(path.as_str())
            .await
            .map(|_| ())
            .map_err(|e| map_status(e, SftpOp::Remove, path));
        res.map_err(|e| self.failed(SftpOp::Remove, path, e))
    }

    async fn rename(&mut self, from: &RemotePath, to: &RemotePath, replace: bool) -> Result<()> {
        let raw = self.ready().await?;
        let posix = self
            .live
            .as_ref()
            .is_some_and(|l| l.server.extensions.posix_rename);
        let res = async {
            if !replace {
                match raw.lstat(to.as_str()).await {
                    Ok(_) => return Err(Error::AlreadyExists(to.clone())),
                    Err(e) => {
                        let err = map_status(e, SftpOp::Stat, to);
                        if err.is_connection_lost() {
                            return Err(err);
                        }
                    }
                }
            }
            if replace && posix {
                let data = posix_rename_data(from.as_str(), to.as_str());
                return match raw.extended("posix-rename@openssh.com", data).await {
                    Ok(Packet::Status(s)) if s.status_code == StatusCode::Ok => Ok(()),
                    Ok(Packet::Status(s)) => {
                        Err(map_status(SftpError::Status(s), SftpOp::Rename, from))
                    }
                    Ok(_) => Err(Error::Protocol {
                        code: None,
                        message: "Unexpected reply to posix-rename".to_owned(),
                    }),
                    Err(e) => Err(map_status(e, SftpOp::Rename, from)),
                };
            }
            match raw.rename(from.as_str(), to.as_str()).await {
                Ok(_) => Ok(()),
                Err(e) => match probe_exists(&raw, e, SftpOp::Rename, to).await {
                    Error::AlreadyExists(p) => Err(Error::AlreadyExists(p)),
                    // Name the source for the other errors (NotFound = the source).
                    Error::NotFound(_) => Err(Error::NotFound(from.clone())),
                    other => Err(other),
                },
            }
        }
        .await;
        res.map_err(|e| self.failed(SftpOp::Rename, from, e))
    }

    async fn chmod(&mut self, path: &RemotePath, mode: u32) -> Result<()> {
        let raw = self.ready().await?;
        let res = raw
            .setstat(path.as_str(), chmod_attrs(mode))
            .await
            .map(|_| ())
            .map_err(|e| map_status(e, SftpOp::SetStat, path));
        res.map_err(|e| self.failed(SftpOp::SetStat, path, e))
    }

    async fn set_mtime(&mut self, path: &RemotePath, time: OffsetDateTime) -> Result<()> {
        let attrs = mtime_attrs(time)?;
        let raw = self.ready().await?;
        let res = raw
            .setstat(path.as_str(), attrs)
            .await
            .map(|_| ())
            .map_err(|e| map_status(e, SftpOp::SetStat, path));
        res.map_err(|e| self.failed(SftpOp::SetStat, path, e))
    }

    async fn open_read(
        &mut self,
        path: &RemotePath,
        offset: u64,
        opts: &TransferOpts,
    ) -> Result<ReadStream> {
        let raw = self.ready().await?;
        self.note_transfer_type(opts);
        let (read, _) = self.sizes();
        let reader = SftpReader::open(raw, path, offset, opts.range_len, read)
            .await
            .map_err(|e| self.failed(SftpOp::Open, path, e))?;
        self.transfer = Some(reader.state());
        Ok(Box::new(reader))
    }

    async fn open_write(
        &mut self,
        path: &RemotePath,
        mode: WriteMode,
        opts: &TransferOpts,
    ) -> Result<WriteStream> {
        let raw = self.ready().await?;
        self.note_transfer_type(opts);
        let (_, write) = self.sizes();
        let writer = SftpWriter::open(raw, path, mode, write)
            .await
            .map_err(|e| self.failed(SftpOp::Open, path, e))?;
        self.transfer = Some(writer.state());
        Ok(Box::new(writer))
    }

    async fn finish_transfer(&mut self, end: TransferEnd) -> Result<()> {
        let Some(t) = self.transfer.take() else {
            return Ok(());
        };
        if t.is_open() {
            self.transfer = Some(t);
            return Err(Error::Internal(
                "finish_transfer while the stream is still open".to_owned(),
            ));
        }
        let err = t.finish(self.tuning.request_timeout).await;
        match (end, err) {
            (TransferEnd::Complete, Some(e)) => {
                if e.is_connection_lost()
                    && let Some(live) = &self.live
                {
                    live.broken.store(true, Ordering::SeqCst);
                }
                Err(e)
            }
            _ => Ok(()),
        }
    }

    async fn raw_command(&mut self, _cmd: &str) -> Result<String> {
        Err(Error::Unsupported(
            "Custom commands are not available over SFTP".to_owned(),
        ))
    }

    async fn keepalive(&mut self) -> Result<()> {
        let raw = self.ready().await?;
        let root = RemotePath::root();
        let res = raw
            .realpath(".")
            .await
            .map(|_| ())
            .map_err(|e| map_status(e, SftpOp::RealPath, &root));
        res.map_err(|e| self.failed(SftpOp::RealPath, &root, e))
    }
}

#[cfg(test)]
mod tests;
