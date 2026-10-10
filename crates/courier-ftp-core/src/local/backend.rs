//! [`LocalBackend`]: the [`Backend`] trait over the local filesystem.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, ready};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::map_io;
use super::owners::OwnerCache;
use super::path_map::{from_native, to_native};
use crate::backend::{
    Backend, BackendContext, Capabilities, Listing, ReadStream, SessionSecurityInfo, TransferEnd,
    TransferOpts, WriteMode, WriteStream,
};
use crate::events::SessionLog;
use crate::model::{
    Entry, EntryKind, PathStyle, Permissions, Precision, RemotePath, ServerAddress, SymlinkTarget,
    Timestamp,
};
use crate::{Error, Result};

/// Files at least this long are synced once when their write stream is shut down.
pub(crate) const SYNC_THRESHOLD: u64 = 8 * 1024 * 1024;

/// How many entries `list` reads between cancellation checks.
const CANCEL_CHECK_EVERY: usize = 256;

/// `Debug(Info)` log level.
const DEBUG_INFO: u8 = 2;

/// Backend over the local filesystem. Always usable; `connect`/`disconnect` only flip
/// the [`is_connected`](Backend::is_connected) flag (no events).
#[derive(Debug)]
pub struct LocalBackend {
    ctx: BackendContext,
    owners: Arc<Mutex<OwnerCache>>,
    /// The open transfer: the stream holds a clone while it lives.
    transfer: Option<Arc<()>>,
    connected: bool,
    /// Test counter of `sync_all` calls made by this backend's write streams.
    #[cfg(test)]
    syncs: Arc<std::sync::atomic::AtomicUsize>,
}

fn lock(owners: &Mutex<OwnerCache>) -> MutexGuard<'_, OwnerCache> {
    owners.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Runs blocking filesystem work on the blocking pool.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Error::Internal(format!("filesystem task failed: {e}")))?
}

/// The capabilities of the local filesystem on this OS.
fn local_capabilities() -> Capabilities {
    Capabilities {
        chmod: cfg!(unix),
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
        // Default APFS / NTFS; per-volume detection is out of scope.
        case_insensitive_names: cfg!(any(windows, target_os = "macos")),
        path_style: PathStyle::Unix,
    }
}

fn timestamp(t: SystemTime) -> Option<Timestamp> {
    let nanos = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i128::try_from(d.as_nanos()).ok()?,
        Err(e) => -i128::try_from(e.duration().as_nanos()).ok()?,
    };
    let time = OffsetDateTime::from_unix_timestamp_nanos(nanos).ok()?;
    Some(Timestamp::new(time, Precision::Millis))
}

/// Hidden by name (Unix and macOS: dotfiles).
fn hidden_by_name(name: &str) -> bool {
    cfg!(unix) && name.starts_with('.')
}

/// An entry whose metadata could not be read (directory readable but not searchable).
fn opaque_entry(name: String) -> Entry {
    let hidden = hidden_by_name(&name);
    let mut e = Entry::new(name, EntryKind::Other);
    e.hidden = hidden;
    e
}

/// Builds an entry from `symlink_metadata` of `native` (symlink targets resolved).
fn entry_from_meta(name: String, native: &Path, meta: &Metadata, owners: &mut OwnerCache) -> Entry {
    let ft = meta.file_type();
    let mut size = None;
    let kind = if ft.is_symlink() {
        let target = fs::read_link(native)
            .ok()
            .map(|t| t.to_string_lossy().into_owned());
        let target_kind = match fs::metadata(native) {
            Ok(m) if m.is_dir() => SymlinkTarget::Dir,
            Ok(m) if m.is_file() => {
                size = Some(m.len());
                SymlinkTarget::File
            }
            Ok(_) => SymlinkTarget::Other,
            Err(_) => SymlinkTarget::Broken,
        };
        EntryKind::Symlink {
            target,
            target_kind: Some(target_kind),
        }
    } else if ft.is_dir() {
        EntryKind::Dir
    } else if ft.is_file() {
        size = Some(meta.len());
        EntryKind::File
    } else {
        EntryKind::Other
    };
    let mut e = Entry::new(name, kind);
    e.size = size;
    e.modified = meta.modified().ok().and_then(timestamp);
    platform_meta(&mut e, meta, owners);
    e
}

#[cfg(unix)]
fn platform_meta(e: &mut Entry, meta: &Metadata, owners: &mut OwnerCache) {
    use std::os::unix::fs::MetadataExt;
    e.permissions = Some(Permissions::from_mode(meta.mode()));
    e.owner = Some(owners.user(meta.uid()));
    e.group = Some(owners.group(meta.gid()));
    e.hidden = hidden_by_name(&e.name);
}

#[cfg(windows)]
fn platform_meta(e: &mut Entry, meta: &Metadata, _owners: &mut OwnerCache) {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    let readonly = meta.permissions().readonly();
    let dir = meta.is_dir();
    let mode = match (dir, readonly) {
        (true, true) => 0o555,
        (true, false) => 0o777,
        (false, true) => 0o444,
        (false, false) => 0o666,
    };
    e.permissions = Some(Permissions {
        mode: Some(mode),
        raw: Some(if readonly { "R" } else { "" }.to_owned()),
    });
    e.hidden = meta.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0;
}

#[cfg(not(any(unix, windows)))]
fn platform_meta(e: &mut Entry, _meta: &Metadata, _owners: &mut OwnerCache) {
    e.hidden = hidden_by_name(&e.name);
}

/// The blocking part of `list`: entries plus the number of non-UTF-8 names skipped.
fn list_blocking(
    native: &Path,
    dir: &RemotePath,
    owners: &Mutex<OwnerCache>,
    cancel: &CancellationToken,
) -> Result<(Vec<Entry>, usize)> {
    let read_dir = fs::read_dir(native).map_err(|e| map_io(e, dir))?;
    let mut owners = lock(owners);
    let mut entries = Vec::new();
    let mut not_utf8 = 0;
    for (i, item) in read_dir.enumerate() {
        if i % CANCEL_CHECK_EVERY == 0 && cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let item = item.map_err(|e| map_io(e, dir))?;
        let Ok(name) = item.file_name().into_string() else {
            not_utf8 += 1;
            continue;
        };
        let path = item.path();
        match fs::symlink_metadata(&path) {
            Ok(meta) => entries.push(entry_from_meta(name, &path, &meta, &mut owners)),
            // Removed meanwhile.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => entries.push(opaque_entry(name)),
        }
    }
    Ok((entries, not_utf8))
}

#[cfg(target_os = "linux")]
fn preallocate(file: &File, len: u64, log: &SessionLog) {
    use rustix::fs::{FallocateFlags, fallocate};
    if len == 0 {
        return;
    }
    if let Err(e) = fallocate(file, FallocateFlags::KEEP_SIZE, 0, len) {
        log.debug(DEBUG_INFO, format!("Preallocation skipped: {e}"));
    }
}

#[cfg(not(target_os = "linux"))]
fn preallocate(_file: &File, _len: u64, log: &SessionLog) {
    log.debug(
        DEBUG_INFO,
        "Preallocation skipped: not available on this platform",
    );
}

/// Opens `native` for writing as `mode` says (blocking).
fn open_for_write(
    native: &Path,
    path: &RemotePath,
    mode: WriteMode,
    preallocate_hint: Option<u64>,
    log: &SessionLog,
) -> Result<File> {
    let mut oo = OpenOptions::new();
    match mode {
        WriteMode::Create => oo.write(true).create_new(true),
        WriteMode::Truncate => oo.write(true).create(true).truncate(true),
        WriteMode::Append => oo.append(true).create(true),
        WriteMode::ResumeAt(_) => oo.write(true),
        WriteMode::WriteAt(_) => oo.write(true).create(true).truncate(false),
    };
    let mut file = oo.open(native).map_err(|e| map_io(e, path))?;
    match mode {
        WriteMode::ResumeAt(n) => {
            if file.metadata()?.len() < n {
                return Err(Error::InvalidInput(
                    "resume offset beyond end of file".into(),
                ));
            }
            file.set_len(n)?;
            file.seek(SeekFrom::Start(n))?;
        }
        WriteMode::WriteAt(n) => {
            file.seek(SeekFrom::Start(n))?;
        }
        WriteMode::Create | WriteMode::Truncate | WriteMode::Append => {}
    }
    if let Some(len) = preallocate_hint {
        preallocate(&file, len, log);
    }
    Ok(file)
}

impl LocalBackend {
    /// A backend for `ctx` (already "connected").
    pub fn new(ctx: BackendContext) -> Self {
        Self {
            ctx,
            owners: Arc::default(),
            transfer: None,
            connected: true,
            #[cfg(test)]
            syncs: Arc::default(),
        }
    }

    /// Native canonical path of `path` mapped back (symlinks resolved). T43 loop
    /// detection.
    ///
    /// # Errors
    ///
    /// `NotFound`, `PermissionDenied`, `Io`; `InvalidInput` when the canonical path
    /// cannot be mapped (non-UTF-8).
    pub async fn canonicalize(&self, path: &RemotePath) -> Result<RemotePath> {
        let native = to_native(path)?.into_path_buf();
        let path = path.clone();
        blocking(move || {
            let canon = fs::canonicalize(&native).map_err(|e| map_io(e, &path))?;
            from_native(&canon)
        })
        .await
    }

    /// Number of `sync_all` calls made by this backend's write streams.
    #[cfg(test)]
    pub(crate) fn sync_count(&self) -> usize {
        self.syncs.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Common start of every operation: the transfer protocol (T03).
    fn begin(&mut self) -> Result<()> {
        if let Some(t) = &self.transfer {
            if Arc::strong_count(t) > 1 {
                return Err(Error::Internal("transfer in progress".into()));
            }
            // Stream dropped without finish_transfer: implicit Abort (nothing to clean).
            self.transfer = None;
        }
        Ok(())
    }

    fn native(path: &RemotePath) -> Result<PathBuf> {
        to_native(path).map(crate::model::LocalPath::into_path_buf)
    }

    fn start_transfer(&mut self) -> Arc<()> {
        let guard = Arc::new(());
        self.transfer = Some(Arc::clone(&guard));
        guard
    }

    /// Windows virtual root: probes drives `A:`–`Z:` concurrently, 1 s overall.
    #[cfg(windows)]
    async fn list_drives(&self, cancel: CancellationToken) -> Result<Listing> {
        use std::time::Duration;
        let log = self.ctx.log();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let probes: Vec<(char, JoinHandle<bool>)> = ('A'..='Z')
            .map(|c| {
                let h = tokio::task::spawn_blocking(move || {
                    Path::new(&format!("{c}:\\")).try_exists().unwrap_or(false)
                });
                (c, h)
            })
            .collect();
        let mut entries = Vec::new();
        for (c, h) in probes {
            tokio::select! {
                () = cancel.cancelled() => return Err(Error::Cancelled),
                r = tokio::time::timeout_at(deadline, h) => match r {
                    Ok(Ok(true)) => entries.push(Entry::new(format!("{c}:"), EntryKind::Dir)),
                    Ok(_) => {}
                    Err(_) => log.debug(DEBUG_INFO, format!("Drive {c}: did not answer within 1 s")),
                },
            }
        }
        Ok(Listing::build(
            RemotePath::root(),
            entries,
            None,
            Some(&log),
        ))
    }
}

#[async_trait]
impl Backend for LocalBackend {
    fn capabilities(&self) -> Capabilities {
        local_capabilities()
    }

    fn address(&self) -> Option<&ServerAddress> {
        None
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn security_info(&self) -> SessionSecurityInfo {
        SessionSecurityInfo {
            encrypted: false,
            summary: "local".into(),
            ..SessionSecurityInfo::default()
        }
    }

    async fn connect(&mut self, _cancel: CancellationToken) -> Result<()> {
        self.connected = true;
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.transfer = None;
        self.connected = false;
        Ok(())
    }

    async fn home_dir(&mut self) -> Result<RemotePath> {
        self.begin()?;
        let home = directories::BaseDirs::new().and_then(|b| from_native(b.home_dir()).ok());
        Ok(home.unwrap_or_else(RemotePath::root))
    }

    async fn list(&mut self, dir: &RemotePath, cancel: CancellationToken) -> Result<Listing> {
        self.begin()?;
        #[cfg(windows)]
        if dir.is_root() {
            return self.list_drives(cancel).await;
        }
        let native = Self::native(dir)?;
        let owners = Arc::clone(&self.owners);
        let (d, token) = (dir.clone(), cancel.clone());
        let handle: JoinHandle<Result<(Vec<Entry>, usize)>> =
            tokio::task::spawn_blocking(move || list_blocking(&native, &d, &owners, &token));
        let (entries, not_utf8) = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(Error::Cancelled),
            r = handle => r.map_err(|e| Error::Internal(format!("listing task failed: {e}")))??,
        };
        let log = self.ctx.log();
        if not_utf8 > 0 {
            log.status(format!(
                "{not_utf8} entries with names that are not valid UTF-8 are not shown"
            ));
        }
        Ok(Listing::build(dir.clone(), entries, None, Some(&log)))
    }

    async fn stat(&mut self, path: &RemotePath) -> Result<Entry> {
        self.begin()?;
        #[cfg(windows)]
        if path.is_root() {
            return Ok(Entry::new("/", EntryKind::Dir));
        }
        let native = Self::native(path)?;
        let name = path.file_name().unwrap_or("/").to_owned();
        let owners = Arc::clone(&self.owners);
        let path = path.clone();
        blocking(move || {
            let meta = fs::symlink_metadata(&native).map_err(|e| map_io(e, &path))?;
            Ok(entry_from_meta(name, &native, &meta, &mut lock(&owners)))
        })
        .await
    }

    async fn mkdir(&mut self, path: &RemotePath) -> Result<()> {
        self.begin()?;
        let native = Self::native(path)?;
        let path = path.clone();
        blocking(move || fs::create_dir(&native).map_err(|e| map_io(e, &path))).await
    }

    async fn rmdir(&mut self, path: &RemotePath) -> Result<()> {
        self.begin()?;
        let native = Self::native(path)?;
        let path = path.clone();
        blocking(move || fs::remove_dir(&native).map_err(|e| map_io(e, &path))).await
    }

    async fn remove_file(&mut self, path: &RemotePath) -> Result<()> {
        self.begin()?;
        let native = Self::native(path)?;
        let path = path.clone();
        blocking(move || {
            #[cfg(windows)]
            {
                use std::os::windows::fs::FileTypeExt;
                if fs::symlink_metadata(&native).is_ok_and(|m| m.file_type().is_symlink_dir()) {
                    return fs::remove_dir(&native).map_err(|e| map_io(e, &path));
                }
            }
            fs::remove_file(&native).map_err(|e| map_io(e, &path))
        })
        .await
    }

    async fn rename(&mut self, from: &RemotePath, to: &RemotePath, replace: bool) -> Result<()> {
        self.begin()?;
        let (from_n, to_n) = (Self::native(from)?, Self::native(to)?);
        // A case-only rename on a case-insensitive filesystem finds `to` (= `from`).
        let case_only = from.parent() == to.parent()
            && from.file_name().map(str::to_lowercase) == to.file_name().map(str::to_lowercase)
            && from != to;
        let (from, to) = (from.clone(), to.clone());
        blocking(move || {
            if !replace && !case_only {
                match fs::symlink_metadata(&to_n) {
                    Ok(_) => return Err(Error::AlreadyExists(to)),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(map_io(e, &to)),
                }
            }
            fs::rename(&from_n, &to_n).map_err(|e| map_io(e, &from))
        })
        .await
    }

    async fn chmod(&mut self, path: &RemotePath, mode: u32) -> Result<()> {
        self.begin()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let native = Self::native(path)?;
            let path = path.clone();
            blocking(move || {
                fs::set_permissions(&native, fs::Permissions::from_mode(mode & 0o7777))
                    .map_err(|e| map_io(e, &path))
            })
            .await
        }
        #[cfg(not(unix))]
        {
            let _ = (path, mode);
            Err(Error::Unsupported(
                "changing permissions is not available for local files on this system".into(),
            ))
        }
    }

    async fn set_mtime(&mut self, path: &RemotePath, time: OffsetDateTime) -> Result<()> {
        self.begin()?;
        let native = Self::native(path)?;
        let path = path.clone();
        let mtime = filetime::FileTime::from_system_time(SystemTime::from(time));
        blocking(move || filetime::set_file_mtime(&native, mtime).map_err(|e| map_io(e, &path)))
            .await
    }

    async fn open_read(
        &mut self,
        path: &RemotePath,
        offset: u64,
        opts: &TransferOpts,
    ) -> Result<ReadStream> {
        self.begin()?;
        let native = Self::native(path)?;
        let p = path.clone();
        let file = blocking(move || {
            let mut f = File::open(&native).map_err(|e| map_io(e, &p))?;
            // Seeking past the end is fine: reads return EOF immediately.
            f.seek(SeekFrom::Start(offset))?;
            Ok(f)
        })
        .await?;
        let file = tokio::fs::File::from_std(file);
        let inner: ReadStream = match opts.range_len {
            Some(n) => Box::new(file.take(n)),
            None => Box::new(file),
        };
        let guard = self.start_transfer();
        Ok(Box::new(LocalReader {
            inner,
            _guard: guard,
        }))
    }

    async fn open_write(
        &mut self,
        path: &RemotePath,
        mode: WriteMode,
        opts: &TransferOpts,
    ) -> Result<WriteStream> {
        self.begin()?;
        let native = Self::native(path)?;
        let p = path.clone();
        let hint = opts.preallocate_hint;
        let log = self.ctx.log();
        let (file, sync_file) = blocking(move || {
            let f = open_for_write(&native, &p, mode, hint, &log)?;
            let dup = f.try_clone()?;
            Ok((f, dup))
        })
        .await?;
        let guard = self.start_transfer();
        Ok(Box::new(LocalWriter {
            file: tokio::fs::File::from_std(file),
            sync_file: Some(sync_file),
            shutdown: None,
            done: false,
            _guard: guard,
            #[cfg(test)]
            syncs: Arc::clone(&self.syncs),
        }))
    }

    async fn finish_transfer(&mut self, _end: TransferEnd) -> Result<()> {
        // Complete: large files were synced at shutdown. Abort: the partial file stays
        // for resume (FileZilla behaviour).
        self.transfer = None;
        Ok(())
    }

    async fn raw_command(&mut self, _cmd: &str) -> Result<String> {
        self.begin()?;
        Err(Error::Unsupported(
            "custom commands are not available for local files".into(),
        ))
    }

    async fn keepalive(&mut self) -> Result<()> {
        self.begin()
    }
}

/// The read stream: a `tokio::fs::File` (optionally limited to `range_len`) that keeps
/// the backend's transfer flag alive.
struct LocalReader {
    inner: ReadStream,
    _guard: Arc<()>,
}

impl AsyncRead for LocalReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

/// The write stream. Writes never sync; `shutdown` flushes and syncs once when the
/// file is at least [`SYNC_THRESHOLD`] long. Dropping without `shutdown` never syncs.
struct LocalWriter {
    file: tokio::fs::File,
    /// A second handle of the same file for the final length check and `sync_all`.
    sync_file: Option<File>,
    shutdown: Option<JoinHandle<io::Result<()>>>,
    done: bool,
    _guard: Arc<()>,
    #[cfg(test)]
    syncs: Arc<std::sync::atomic::AtomicUsize>,
}

impl AsyncWrite for LocalWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.file).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.file).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.done {
                return Poll::Ready(Ok(()));
            }
            if let Some(h) = self.shutdown.as_mut() {
                let r = ready!(Pin::new(h).poll(cx));
                self.shutdown = None;
                self.done = true;
                return Poll::Ready(r.map_err(io::Error::other).and_then(|r| r));
            }
            ready!(Pin::new(&mut self.file).poll_flush(cx))?;
            let sync_file = self.sync_file.take();
            #[cfg(test)]
            let syncs = Arc::clone(&self.syncs);
            self.shutdown = Some(tokio::task::spawn_blocking(move || {
                if let Some(f) = sync_file
                    && f.metadata()?.len() >= SYNC_THRESHOLD
                {
                    f.sync_all()?;
                    #[cfg(test)]
                    syncs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                Ok(())
            }));
        }
    }
}
