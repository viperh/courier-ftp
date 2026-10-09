//! The [`Backend`] trait and its plain data types.

use std::collections::HashSet;
use std::net::SocketAddr;

use async_trait::async_trait;
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

use crate::Result;
use crate::events::{HostKeyInfo, SessionLog, TlsSessionInfo};
use crate::model::{Entry, PathStyle, RemotePath, ServerAddress, TransferType};

/// The stream returned by [`Backend::open_read`].
pub type ReadStream = Box<dyn AsyncRead + Send + Unpin>;
/// The stream returned by [`Backend::open_write`].
pub type WriteStream = Box<dyn AsyncWrite + Send + Unpin>;

/// One session (one control connection / SSH connection / local handle).
///
/// One operation at a time (`&mut self`); parallel work uses several instances (T41).
/// See the [module docs](super) for the cancellation convention and the transfer
/// protocol.
#[async_trait]
pub trait Backend: Send {
    /// Current capabilities. Valid after `connect`; may shrink during a session
    /// (e.g. SITE CHMOD rejected → chmod = false and `CoreEvent::CapabilitiesChanged`).
    fn capabilities(&self) -> Capabilities;
    /// The server; None for the local backend.
    fn address(&self) -> Option<&ServerAddress>;
    /// Whether the session is open and usable.
    fn is_connected(&self) -> bool;
    /// For the status-bar lock and the server info dialog (T57). Before connect:
    /// `SessionSecurityInfo::default()`.
    fn security_info(&self) -> SessionSecurityInfo;

    /// Open the session: TCP/proxy (T07), TLS/SSH, host-key/cert trust and login
    /// prompts (T04).
    async fn connect(&mut self, cancel: CancellationToken) -> Result<()>;
    /// Polite close (FTP QUIT with 2 s wait, SSH disconnect). Never fails because the
    /// peer is gone.
    async fn disconnect(&mut self) -> Result<()>;

    /// Initial directory after login (FTP PWD, SFTP realpath("."), local home).
    async fn home_dir(&mut self) -> Result<RemotePath>;
    /// List `dir`. NotFound / PermissionDenied when the server says so.
    async fn list(&mut self, dir: &RemotePath, cancel: CancellationToken) -> Result<Listing>;
    /// Metadata of one path. Does NOT follow a final symlink, but fills `target_kind`.
    async fn stat(&mut self, path: &RemotePath) -> Result<Entry>;

    /// Create one directory (parent must exist). AlreadyExists if present.
    async fn mkdir(&mut self, path: &RemotePath) -> Result<()>;
    /// Remove one empty directory.
    async fn rmdir(&mut self, path: &RemotePath) -> Result<()>;
    /// Remove a file or a symlink (never its target).
    async fn remove_file(&mut self, path: &RemotePath) -> Result<()>;
    /// `replace = false`: AlreadyExists if `to` exists (checked with stat where the
    /// protocol has no atomic no-replace rename). `replace = true`: an existing file at
    /// `to` is overwritten where the protocol supports it; a backend that cannot
    /// overwrite returns AlreadyExists and leaves both files unchanged.
    async fn rename(&mut self, from: &RemotePath, to: &RemotePath, replace: bool) -> Result<()>;
    /// `mode` & 0o7777. Unsupported unless `capabilities().chmod`.
    async fn chmod(&mut self, path: &RemotePath, mode: u32) -> Result<()>;
    /// Unsupported unless `capabilities().set_mtime`.
    async fn set_mtime(&mut self, path: &RemotePath, time: OffsetDateTime) -> Result<()>;

    /// Start reading at `offset` (offset > 0 needs `capabilities().resume_download`).
    async fn open_read(
        &mut self,
        path: &RemotePath,
        offset: u64,
        opts: &TransferOpts,
    ) -> Result<ReadStream>;
    /// Start writing `path` as `mode` says.
    async fn open_write(
        &mut self,
        path: &RemotePath,
        mode: WriteMode,
        opts: &TransferOpts,
    ) -> Result<WriteStream>;
    /// End the open transfer (see the transfer protocol in the module docs). FTP reads
    /// the 226 / does ABOR.
    async fn finish_transfer(&mut self, end: TransferEnd) -> Result<()>;

    /// Custom command (§4, FTP only). Returns the reply lines joined with '\n'.
    async fn raw_command(&mut self, cmd: &str) -> Result<String>;
    /// Keep an idle connection alive (FTP: `NOOP` or a random harmless command, T10;
    /// SFTP: realpath(".")/no-op, T22).
    async fn keepalive(&mut self) -> Result<()>;
}

/// How [`Backend::finish_transfer`] ends a transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferEnd {
    /// All data was read to EOF, or written and shut down.
    Complete,
    /// Stopped early; clean up (FTP ABOR).
    Abort,
}

/// How [`Backend::open_write`] opens the target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteMode {
    /// Target does not exist (decided by T42). Local/SFTP: exclusive create
    /// (AlreadyExists if it appeared meanwhile). FTP has no exclusive create and behaves
    /// like Truncate.
    Create,
    /// Create or truncate to 0.
    Truncate,
    /// Append at the end (needs `capabilities().append`).
    Append,
    /// Truncate to `n` bytes, then write from `n` (needs `resume_upload`). Error
    /// InvalidInput if the existing file is shorter than `n` (local/SFTP/mock; FTP
    /// cannot check).
    ResumeAt(u64),
    /// Write from `n` without truncating; creates the file if missing (needs
    /// `positional_writes`; used for segmented uploads/downloads, T41b).
    WriteAt(u64),
}

/// Per-transfer options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferOpts {
    /// Ascii only matters for FTP (T11).
    pub transfer_type: TransferType,
    /// Writes: reserve this many bytes up front (local backend, T06). None = don't.
    pub preallocate_hint: Option<u64>,
    /// Reads: stop after this many bytes (EOF). Used by segmented downloads (T41b).
    pub range_len: Option<u64>,
}

impl Default for TransferOpts {
    /// Binary, no preallocation, no range.
    fn default() -> Self {
        Self {
            transfer_type: TransferType::Binary,
            preallocate_hint: None,
            range_len: None,
        }
    }
}

/// A directory listing.
#[derive(Clone, Debug, PartialEq)]
pub struct Listing {
    /// The listed directory.
    pub dir: RemotePath,
    /// Unsorted. Never contains "."/".."; every name satisfies `Entry::is_valid_name`;
    /// no duplicate names (first one kept).
    pub entries: Vec<Entry>,
    /// When the listing was received.
    pub fetched_at: tokio::time::Instant,
    /// Raw server text (FTP LIST/MLSD, SFTP longnames) for T71 "show raw listing"; None
    /// for local. The only place raw text lives. Capped at [`Listing::RAW_MAX`]: beyond
    /// that the text is truncated at a line boundary and ends with `"\n[truncated]"`.
    pub raw: Option<String>,
}

impl Listing {
    /// Maximum size of [`Listing::raw`] in bytes (16 MiB).
    pub const RAW_MAX: usize = 16 * 1024 * 1024;

    /// Applies the listing hygiene rules: drops entries with invalid names (including
    /// "." and "..") and later duplicates. Returns the kept entries and the number
    /// dropped.
    pub fn clean_entries(entries: Vec<Entry>) -> (Vec<Entry>, usize) {
        let total = entries.len();
        let mut seen = HashSet::with_capacity(total);
        let kept: Vec<Entry> = entries
            .into_iter()
            .filter(|e| Entry::is_valid_name(&e.name) && seen.insert(e.name.clone()))
            .collect();
        let dropped = total - kept.len();
        (kept, dropped)
    }

    /// Caps raw listing text at [`RAW_MAX`](Self::RAW_MAX) bytes: truncated at the last
    /// line boundary that fits, followed by `"\n[truncated]"`.
    pub fn cap_raw(raw: String) -> String {
        const MARK: &str = "\n[truncated]";
        if raw.len() <= Self::RAW_MAX {
            return raw;
        }
        let limit = Self::RAW_MAX - MARK.len();
        let mut cut = limit;
        while !raw.is_char_boundary(cut) {
            cut -= 1;
        }
        let cut = raw[..cut].rfind('\n').unwrap_or(cut);
        let mut out = raw;
        out.truncate(cut);
        out.push_str(MARK);
        out
    }

    /// Builds a listing with the hygiene rules applied (see
    /// [`clean_entries`](Self::clean_entries), [`cap_raw`](Self::cap_raw)) and logs
    /// `Ignored N entries with invalid names` as a Status line when entries were dropped.
    pub fn build(
        dir: RemotePath,
        entries: Vec<Entry>,
        raw: Option<String>,
        log: Option<&SessionLog>,
    ) -> Self {
        let (entries, dropped) = Self::clean_entries(entries);
        if dropped > 0
            && let Some(log) = log
        {
            let noun = if dropped == 1 { "entry" } else { "entries" };
            log.status(format!("Ignored {dropped} {noun} with invalid names"));
        }
        Self {
            dir,
            entries,
            fetched_at: tokio::time::Instant::now(),
            raw: raw.map(Self::cap_raw),
        }
    }
}

/// What a backend can do. A copy is cached by [`SessionHandle`](super::SessionHandle).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    /// [`Backend::chmod`].
    pub chmod: bool,
    /// [`Backend::set_mtime`].
    pub set_mtime: bool,
    /// `open_read` with offset > 0 (FTP REST STREAM; SFTP, local always). Also "ranged
    /// reads" (T41b).
    pub resume_download: bool,
    /// [`WriteMode::ResumeAt`].
    pub resume_upload: bool,
    /// [`WriteMode::Append`].
    pub append: bool,
    /// [`Backend::raw_command`].
    pub raw_commands: bool,
    /// The server reports symlinks.
    pub symlinks: bool,
    /// `rename` can move between directories.
    pub server_side_rename_across_dirs: bool,
    /// The backend converts line endings for `TransferType::Ascii` (FTP only).
    pub ascii_mode: bool,
    /// Several sessions to the server may run at once.
    pub parallel_connections_allowed: bool,
    /// [`WriteMode::WriteAt`].
    pub positional_writes: bool,
    /// Names differing only in case are the same file (local Windows/macOS, DOS-style
    /// FTP). T48.
    pub case_insensitive_names: bool,
    /// How the server spells paths.
    pub path_style: PathStyle,
}

impl Capabilities {
    /// Nothing supported; Unix paths.
    pub const NONE: Capabilities = Capabilities {
        chmod: false,
        set_mtime: false,
        resume_download: false,
        resume_upload: false,
        append: false,
        raw_commands: false,
        symlinks: false,
        server_side_rename_across_dirs: false,
        ascii_mode: false,
        parallel_connections_allowed: false,
        positional_writes: false,
        case_insensitive_names: false,
        path_style: PathStyle::Unix,
    };
}

/// What the status-bar lock and the server info dialog (T57) show for a session.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SessionSecurityInfo {
    /// Control/SSH channel encrypted.
    pub encrypted: bool,
    /// Short label: "TLS 1.3", "SSH", "plain", "local".
    pub summary: String,
    /// The connected peer (server, or the proxy when proxied, T07). None for local.
    pub peer_addr: Option<SocketAddr>,
    /// FTP greeting / SYST, SSH version string (sanitised).
    pub server_software: Option<String>,
    /// FTPS: negotiated TLS session incl. certificate chain (T12).
    pub tls: Option<TlsSessionInfo>,
    /// SFTP: host key summary (T21).
    pub host_key: Option<HostKeyInfo>,
    /// Other label/value rows in display order: FEAT summary, SSH kex/cipher/MAC/
    /// compression, data-channel protection, auth method.
    pub details: Vec<(String, String)>,
}
