//! The FTP/FTPS [`Backend`] (T14): [`FtpBackend`] on top of the control
//! connection (T10), data connections (T11), TLS (T12), the listing parsers
//! (T13) and FTP proxies (T15).
//!
//! | Backend method | FTP |
//! |---|---|
//! | `connect` | the T10 start sequence (+ `AUTH TLS`/implicit TLS, `PBSZ`/`PROT`) |
//! | `home_dir` | the `PWD` after login (cached) |
//! | `list` | `CWD dir` (skipped when already there), then `MLSD` or `LIST` without argument |
//! | `stat` | `MLST path`; else list the parent and find the entry; else `SIZE` + `MDTM` |
//! | `mkdir` | `MKD` (`257`/`250`); a failure where `CWD` then succeeds is [`Error::AlreadyExists`] |
//! | `rmdir`, `remove_file` | `RMD`, `DELE` |
//! | `rename` | `RNFR` → `350` → `RNTO` |
//! | `chmod` | `SITE CHMOD 644 path`; `500`/`502` turns the capability off for the session |
//! | `set_mtime` | `MFMT` → `MDTM time path` → `SITE UTIME`; when all are refused the capability is turned off |
//! | `open_read` | `TYPE`, `REST n` (n > 0), `RETR` |
//! | `open_write` | `STOR` / `APPE` / `REST n` + `STOR`; `Create` checks with `stat` first |
//! | `finish_transfer` | the `226` (or `ABOR` when the stream was dropped early) |
//! | `raw_command`, `keepalive` | T10 |
//!
//! # Errors
//!
//! Error replies become [`Error::NotFound`], [`Error::PermissionDenied`] or
//! [`Error::AlreadyExists`] when their text says so; a vague `550` ("Delete
//! operation failed") is checked with `stat`, so a missing file is
//! [`Error::NotFound`] on every server. Other replies are
//! [`Error::Protocol`] with the code (`4xx` transient, `5xx` permanent).
//!
//! # Paths
//!
//! Unix servers get absolute paths. DOS-style servers (`PWD` = `C:\…`) get
//! backslash paths. VMS and MVS servers (detected from `PWD`/`SYST`, or
//! forced with the site's server type) are sent `CWD` in their own syntax and
//! bare file names (see [`paths`]); MVS support is best effort.
//!
//! # Transfers
//!
//! One transfer at a time per backend: the next operation first completes or
//! aborts a transfer whose `finish_transfer` was never called. ASCII
//! transfers can't resume (offsets differ): asking for it is
//! [`Error::Unsupported`]. The site's default remote directory is applied by
//! the caller (quickconnect / Site Manager), which lists it after connecting.

pub mod errors;
pub mod paths;

#[cfg(test)]
mod tests;

use std::{
    sync::{Arc, Mutex, PoisonError},
    time::Instant,
};

use async_trait::async_trait;
use courier_ftp_core::{
    Error, Result,
    backend::{
        Backend, BackendFactory, Capabilities, ConnectInfo, Listing, ReadStream, SecurityInfo,
        SessionInfo, TransferOpts, TransferType, WriteMode, WriteStream,
    },
    events::{EventSender, LogKind, SessionId},
    model::{Entry, EntryKind, PathStyle, Precision, RemotePath, ServerAddress, Timestamp},
    settings::Settings,
};
use secrecy::SecretString;
use time::{OffsetDateTime, macros::format_description};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

use self::errors::{Meaning, meaning, reply_error};
use crate::{
    control::{self, ControlConnection, FtpContext, FtpOptions, KeepaliveCommand, Reply},
    data::{
        self, DataOpen, DataOptions, DataSession, TransferFlags,
        ascii::{AsciiReader, AsciiWriter},
    },
    listing::{ListCommand, ListingContext, parse_listing, parse_mlst_line},
    tls::TlsTrust,
};

/// The largest listing read into memory.
pub const MAX_LISTING: u64 = 256 * 1024 * 1024;

/// What the session learned about the server.
#[derive(Debug, Default, Clone, Copy)]
struct Learned {
    chmod_rejected: bool,
    mtime_rejected: bool,
    rest_rejected: bool,
    rest_ok: bool,
    list_a_rejected: bool,
    mlsd_rejected: bool,
    mlst_rejected: bool,
}

/// A transfer whose final reply hasn't been read.
#[derive(Debug)]
struct Pending {
    flags: Arc<TransferFlags>,
    upload: bool,
}

/// An FTP or FTPS session. See the [module docs](self).
pub struct FtpBackend {
    address: ServerAddress,
    opts: FtpOptions,
    settings: Settings,
    session: SessionId,
    events: EventSender,
    server_type: Option<PathStyle>,
    timezone_offset: time::Duration,
    data: DataSession,
    conn: Option<ControlConnection>,
    home: Option<RemotePath>,
    cwd: Option<RemotePath>,
    style: PathStyle,
    learned: Learned,
    pending: Option<Pending>,
}

impl std::fmt::Debug for FtpBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FtpBackend")
            .field("address", &self.address)
            .field("connected", &self.is_connected())
            .field("style", &self.style)
            .finish_non_exhaustive()
    }
}

fn not_connected() -> Error {
    Error::Connection("not connected".into())
}

/// `YYYYMMDDHHMMSS` in UTC.
fn ftp_time(t: OffsetDateTime) -> Result<String> {
    let format = format_description!("[year][month][day][hour][minute][second]");
    t.to_offset(time::UtcOffset::UTC)
        .format(&format)
        .map_err(|e| Error::InvalidInput(format!("time {t} can't be sent: {e}")))
}

/// A `213 YYYYMMDDHHMMSS[.sss]` reply's time.
fn parse_mdtm(text: &str) -> Option<Timestamp> {
    let digits = text.trim().get(..14)?;
    let format = format_description!("[year][month][day][hour][minute][second]");
    let t = time::PrimitiveDateTime::parse(digits, &format).ok()?;
    Some(Timestamp::new(t.assume_utc(), Precision::Second))
}

impl FtpBackend {
    /// A backend for `info` with `settings` (timeouts, proxies, `ftp.*`),
    /// certificate trust `tls`, reporting under `session`.
    pub fn new(
        info: &ConnectInfo,
        settings: &Settings,
        tls: Arc<TlsTrust>,
        session: SessionId,
        events: EventSender,
    ) -> Self {
        let mut opts = FtpOptions::from_connect_info(info, settings);
        opts.encryption = info.ftp_encryption().unwrap_or_default();
        opts.tls = Some(tls);
        let data = DataSession::new(DataOptions::new(
            settings,
            info.transfer_mode,
            opts.host.clone(),
            &opts.net,
            opts.timeout,
        ));
        Self {
            address: info.address.clone(),
            opts,
            settings: settings.clone(),
            session,
            events,
            server_type: info.server_type,
            timezone_offset: info.timezone_offset,
            data,
            conn: None,
            home: None,
            cwd: None,
            style: PathStyle::Unix,
            learned: Learned::default(),
            pending: None,
        }
    }

    /// The connection options used by the next `connect` (proxy passwords
    /// are set here).
    pub fn options_mut(&mut self) -> &mut FtpOptions {
        &mut self.opts
    }

    /// The control connection, when connected.
    pub fn control(&mut self) -> Option<&mut ControlConnection> {
        self.conn.as_mut().filter(|c| c.is_connected())
    }

    /// The path style in use.
    pub fn path_style(&self) -> PathStyle {
        self.style
    }

    fn log(&self, kind: LogKind, text: impl Into<String>) {
        self.events.log(self.session, kind, text);
    }

    fn conn(&mut self) -> Result<&mut ControlConnection> {
        match self.conn.as_mut() {
            Some(c) if c.is_connected() => Ok(c),
            _ => Err(not_connected()),
        }
    }

    fn listing_ctx(&self) -> ListingContext {
        ListingContext::new(self.timezone_offset)
    }

    /// Complete (or abort) a transfer left pending by the caller.
    async fn settle(&mut self) -> Result<()> {
        let Some(pending) = self.pending.take() else {
            return Ok(());
        };
        let conn = self.conn()?;
        match data::finish(conn, &pending.flags, pending.upload).await {
            Ok(_) => Ok(()),
            Err(err) if !conn.is_connected() => Err(err),
            Err(err) => {
                tracing::debug!(%err, "earlier transfer ended with an error");
                Ok(())
            }
        }
    }

    /// `CWD` to `dir` unless already there.
    async fn cwd_to(&mut self, dir: &RemotePath) -> Result<()> {
        if self.cwd.as_ref() == Some(dir) {
            return Ok(());
        }
        let arg = paths::dir_to_server(dir, self.style);
        let reply = self.conn()?.send(&format!("CWD {arg}")).await?;
        if reply.is_ok() {
            self.cwd = Some(dir.clone());
            return Ok(());
        }
        Err(match meaning(&reply) {
            Meaning::PermissionDenied => Error::PermissionDenied,
            _ if reply.is_permanent_err() => Error::NotFound(dir.clone()),
            _ => reply.to_error(),
        })
    }

    /// The argument naming `path` in a command: a full path, or (VMS, MVS)
    /// the bare name after `CWD` to the parent.
    async fn target(&mut self, path: &RemotePath) -> Result<String> {
        if paths::uses_cwd_for_files(self.style) {
            let parent = path.parent().unwrap_or_default();
            self.cwd_to(&parent).await?;
            Ok(path.file_name().unwrap_or_default().to_owned())
        } else {
            Ok(paths::file_to_server(path, self.style))
        }
    }

    /// The error for `reply` about `path`; a vague permanent error is
    /// checked with `stat` so a missing entry is always `NotFound`.
    async fn error_for(&mut self, reply: &Reply, path: &RemotePath) -> Error {
        let err = reply_error(reply, path);
        if matches!(err, Error::Protocol { .. })
            && reply.is_permanent_err()
            && matches!(self.stat_inner(path).await, Err(Error::NotFound(_)))
        {
            return Error::NotFound(path.clone());
        }
        err
    }

    /// Send `cmd`, expecting a `2xx`.
    async fn simple(&mut self, cmd: String, path: &RemotePath) -> Result<Reply> {
        let reply = self.conn()?.send(&cmd).await?;
        if reply.is_ok() {
            Ok(reply)
        } else {
            Err(self.error_for(&reply, path).await)
        }
    }

    /// Read a listing of `dir`.
    async fn list_inner(
        &mut self,
        dir: &RemotePath,
        cancel: &CancellationToken,
    ) -> Result<(Vec<Entry>, String)> {
        self.settle().await?;
        self.cwd_to(dir).await?;
        let ctx = self.listing_ctx();
        loop {
            let has_mlsd = self.conn()?.features().mlsd && !self.learned.mlsd_rejected;
            let cmd = ListCommand::choose(
                has_mlsd,
                self.settings.ftp.use_mlsd,
                self.settings.interface.force_show_hidden_remote,
                self.learned.list_a_rejected,
            );
            let Self { conn, data, .. } = self;
            let conn = match conn.as_mut() {
                Some(c) if c.is_connected() => c,
                _ => return Err(not_connected()),
            };
            conn.set_type(TransferType::Binary).await?;
            let open = data.open(conn, cmd.command(), None, cancel).await?;
            let stream = match open {
                DataOpen::Stream(s) => s,
                DataOpen::Done(_) => return Ok((Vec::new(), String::new())),
                DataOpen::Refused(reply) => {
                    let code = reply.code;
                    if cmd == ListCommand::ListAll && reply.is_permanent_err() {
                        self.learned.list_a_rejected = true;
                        continue;
                    }
                    if cmd == ListCommand::Mlsd && matches!(code, 500 | 501 | 502 | 504) {
                        self.learned.mlsd_rejected = true;
                        continue;
                    }
                    let text = reply.text().to_ascii_lowercase();
                    if matches!(code, 450 | 550)
                        && (text.contains("no files") || text.contains("empty"))
                    {
                        return Ok((Vec::new(), String::new()));
                    }
                    return Err(reply_error(&reply, dir));
                }
            };
            let flags = stream.flags();
            let mut bytes = Vec::new();
            let mut limited = stream.take(MAX_LISTING);
            let read = tokio::select! {
                biased;
                () = cancel.cancelled() => Err(Error::Cancelled),
                r = limited.read_to_end(&mut bytes) => r.map_err(Error::from),
            };
            drop(limited);
            if let Err(err) = read {
                // Aborts and keeps the control connection usable.
                let _ = data::finish(conn, &flags, false).await;
                return Err(match err {
                    Error::Io(e) if e.kind() == std::io::ErrorKind::TimedOut => Error::Timeout,
                    other => other,
                });
            }
            if let Err(err) = data::finish(conn, &flags, false).await {
                return Err(match err {
                    Error::Protocol { .. } if !flags.eof() => {
                        Error::Connection(format!("the listing is larger than {MAX_LISTING} bytes"))
                    }
                    other => other,
                });
            }
            let parsed = parse_listing(&bytes, conn.effective_charset(), cmd, &ctx);
            if parsed.unparsed > 0 {
                self.log(
                    LogKind::Debug(3),
                    format!("{} listing lines could not be parsed", parsed.unparsed),
                );
            }
            return Ok((parsed.entries, parsed.raw));
        }
    }

    async fn stat_inner(&mut self, path: &RemotePath) -> Result<Entry> {
        if path.is_root() {
            return Ok(Entry::new("/", EntryKind::Dir));
        }
        let name = path.file_name().unwrap_or_default().to_owned();
        self.settle().await?;
        if self.conn()?.features().mlst.is_some() && !self.learned.mlst_rejected {
            let target = self.target(path).await?;
            let reply = self.conn()?.send(&format!("MLST {target}")).await?;
            match reply.code {
                250 => {
                    if let Some(mut entry) = reply
                        .lines
                        .iter()
                        .skip(1)
                        .filter(|l| l.starts_with(' '))
                        .find_map(|l| parse_mlst_line(l))
                    {
                        entry.name = name;
                        entry.hidden = entry.name.starts_with('.');
                        return Ok(entry);
                    }
                }
                500 | 501 | 502 | 504 => self.learned.mlst_rejected = true,
                _ if reply.is_permanent_err() => {
                    return Err(match meaning(&reply) {
                        Meaning::PermissionDenied => Error::PermissionDenied,
                        _ => Error::NotFound(path.clone()),
                    });
                }
                _ => return Err(reply.to_error()),
            }
        }
        let parent = path.parent().unwrap_or_default();
        match self.list_inner(&parent, &CancellationToken::new()).await {
            Ok((entries, _)) => {
                return entries
                    .into_iter()
                    .find(|e| e.name == name)
                    .ok_or_else(|| Error::NotFound(path.clone()));
            }
            Err(Error::NotFound(_)) => return Err(Error::NotFound(path.clone())),
            Err(err @ (Error::Connection(_) | Error::Timeout | Error::Cancelled)) => {
                return Err(err);
            }
            Err(err) => tracing::debug!(%err, "listing the parent for stat failed"),
        }
        // SIZE + MDTM.
        let target = self.target(path).await?;
        let size = self.conn()?.send(&format!("SIZE {target}")).await?;
        if size.code == 213 {
            let mut entry = Entry::new(name, EntryKind::File);
            entry.size = size.first_line_text().trim().parse().ok();
            let mdtm = self.conn()?.send(&format!("MDTM {target}")).await?;
            if mdtm.code == 213 {
                entry.modified = parse_mdtm(mdtm.first_line_text());
            }
            return Ok(entry);
        }
        if self.cwd_to(path).await.is_ok() {
            return Ok(Entry::new(name, EntryKind::Dir));
        }
        Err(Error::NotFound(path.clone()))
    }

    /// Open a data connection for `cmd` and keep the transfer pending.
    async fn open_data(
        &mut self,
        cmd: String,
        rest: Option<u64>,
        path: &RemotePath,
        upload: bool,
    ) -> Result<Option<data::DataStream>> {
        let cancel = CancellationToken::new();
        let Self { conn, data, .. } = self;
        let conn = match conn.as_mut() {
            Some(c) if c.is_connected() => c,
            _ => return Err(not_connected()),
        };
        let open = match data.open(conn, &cmd, rest, &cancel).await {
            Err(Error::Unsupported(what)) if rest.is_some() => {
                self.learned.rest_rejected = true;
                return Err(Error::Unsupported(what));
            }
            other => other?,
        };
        if rest.is_some() {
            self.learned.rest_ok = true;
        }
        match open {
            DataOpen::Stream(stream) => {
                self.pending = Some(Pending {
                    flags: stream.flags(),
                    upload,
                });
                Ok(Some(stream))
            }
            DataOpen::Done(_) => Ok(None),
            DataOpen::Refused(reply) => Err(self.error_for(&reply, path).await),
        }
    }
}

#[async_trait]
impl Backend for FtpBackend {
    fn capabilities(&self) -> Capabilities {
        let features = self
            .conn
            .as_ref()
            .map(|c| c.features().clone())
            .unwrap_or_default();
        let resume = (features.rest_stream || self.learned.rest_ok) && !self.learned.rest_rejected;
        Capabilities {
            chmod: !self.learned.chmod_rejected,
            set_mtime: (features.mfmt || features.mdtm) && !self.learned.mtime_rejected,
            resume_download: resume,
            resume_upload: resume,
            append: true,
            raw_commands: true,
            symlinks: true,
            server_side_rename_across_dirs: true,
            ascii_mode: true,
            parallel_connections_allowed: true,
        }
    }

    fn address(&self) -> Option<&ServerAddress> {
        Some(&self.address)
    }

    async fn connect(&mut self, cancel: CancellationToken) -> Result<()> {
        if let Some(old) = self.conn.take() {
            old.quit().await;
        }
        self.pending = None;
        self.cwd = None;
        let token = CancellationToken::new();
        let ctx = FtpContext {
            session: self.session,
            events: self.events.clone(),
            cancel: token.clone(),
        };
        let result = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                token.cancel();
                Err(Error::Cancelled)
            }
            r = control::connect(&self.opts, ctx) => r,
        };
        let conn = result?;
        let pwd = conn.cwd().map(str::to_owned);
        self.style = self
            .server_type
            .unwrap_or_else(|| paths::detect_style(pwd.as_deref().unwrap_or("/"), conn.syst()));
        if self.style == PathStyle::Mvs {
            self.log(
                LogKind::Error,
                "Warning: MVS (z/OS) servers are only partly supported",
            );
        }
        self.home = pwd.as_deref().map(|p| paths::from_server(p, self.style));
        self.cwd.clone_from(&self.home);
        self.conn = Some(conn);
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        if self.pending.is_some() {
            let _ = self.settle().await;
        }
        if let Some(conn) = self.conn.take() {
            conn.quit().await;
        }
        self.cwd = None;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.conn
            .as_ref()
            .is_some_and(ControlConnection::is_connected)
    }

    async fn home_dir(&mut self) -> Result<RemotePath> {
        if let Some(home) = &self.home {
            return Ok(home.clone());
        }
        self.settle().await?;
        let pwd = self.conn()?.pwd().await?;
        let home = paths::from_server(&pwd, self.style);
        self.home = Some(home.clone());
        self.cwd = Some(home.clone());
        Ok(home)
    }

    async fn list(&mut self, dir: &RemotePath, cancel: CancellationToken) -> Result<Listing> {
        let (entries, raw) = self.list_inner(dir, &cancel).await?;
        if self.events.enabled(LogKind::ListingRaw) {
            for line in raw.lines() {
                self.log(LogKind::ListingRaw, line.trim_end_matches('\r').to_owned());
            }
        }
        self.log(
            LogKind::Status,
            format!("Directory listing of \"{dir}\" successful"),
        );
        Ok(Listing {
            dir: dir.clone(),
            entries,
            fetched_at: Instant::now(),
            raw: (!raw.is_empty()).then_some(raw),
        })
    }

    async fn stat(&mut self, path: &RemotePath) -> Result<Entry> {
        self.stat_inner(path).await
    }

    async fn mkdir(&mut self, path: &RemotePath) -> Result<()> {
        self.settle().await?;
        let target = self.target(path).await?;
        let reply = self.conn()?.send(&format!("MKD {target}")).await?;
        if reply.is_ok() {
            return Ok(());
        }
        if meaning(&reply) == Meaning::AlreadyExists {
            return Err(Error::AlreadyExists);
        }
        if reply.is_permanent_err() && self.cwd_to(path).await.is_ok() {
            return Err(Error::AlreadyExists);
        }
        Err(reply_error(&reply, path))
    }

    async fn rmdir(&mut self, path: &RemotePath) -> Result<()> {
        self.settle().await?;
        let target = self.target(path).await?;
        if self.cwd.as_ref().is_some_and(|c| c.starts_with(path)) {
            // Step out first: some servers refuse to remove the current
            // directory.
            let parent = path.parent().unwrap_or_default();
            self.cwd_to(&parent).await.ok();
        }
        self.simple(format!("RMD {target}"), path).await?;
        if self.cwd.as_ref().is_some_and(|c| c.starts_with(path)) {
            self.cwd = None;
        }
        Ok(())
    }

    async fn remove_file(&mut self, path: &RemotePath) -> Result<()> {
        self.settle().await?;
        let target = self.target(path).await?;
        self.simple(format!("DELE {target}"), path).await.map(drop)
    }

    async fn rename(&mut self, from: &RemotePath, to: &RemotePath) -> Result<()> {
        self.settle().await?;
        let source = self.target(from).await?;
        let reply = self.conn()?.send(&format!("RNFR {source}")).await?;
        if reply.code != 350 {
            return Err(self.error_for(&reply, from).await);
        }
        // RNTO must follow RNFR directly: a full path even on VMS/MVS when
        // the directories differ is not possible, so stay in `from`'s
        // directory and send the name when they share it.
        let dest = if paths::uses_cwd_for_files(self.style) {
            if from.parent() == to.parent() {
                to.file_name().unwrap_or_default().to_owned()
            } else {
                return Err(Error::Unsupported(
                    "moving between directories on this server type",
                ));
            }
        } else {
            paths::file_to_server(to, self.style)
        };
        let reply = self.conn()?.send(&format!("RNTO {dest}")).await?;
        if reply.is_ok() {
            if self.cwd.as_ref().is_some_and(|c| c.starts_with(from)) {
                self.cwd = None;
            }
            Ok(())
        } else {
            Err(reply_error(&reply, to))
        }
    }

    async fn chmod(&mut self, path: &RemotePath, mode: u32) -> Result<()> {
        if self.learned.chmod_rejected {
            return Err(Error::Unsupported("the server does not support SITE CHMOD"));
        }
        self.settle().await?;
        let target = self.target(path).await?;
        let reply = self
            .conn()?
            .send(&format!("SITE CHMOD {:03o} {target}", mode & 0o7777))
            .await?;
        if reply.is_ok() {
            return Ok(());
        }
        if matches!(reply.code, 500 | 502 | 504) {
            self.learned.chmod_rejected = true;
            self.log(
                LogKind::Status,
                "The server does not support changing permissions (SITE CHMOD)",
            );
            return Err(Error::Unsupported("the server does not support SITE CHMOD"));
        }
        Err(self.error_for(&reply, path).await)
    }

    async fn set_mtime(&mut self, path: &RemotePath, time: OffsetDateTime) -> Result<()> {
        if self.learned.mtime_rejected {
            return Err(Error::Unsupported(
                "the server can't set modification times",
            ));
        }
        self.settle().await?;
        let stamp = ftp_time(time)?;
        let target = self.target(path).await?;
        let features = self.conn()?.features().clone();
        let mut attempts = Vec::new();
        if features.mfmt {
            attempts.push(format!("MFMT {stamp} {target}"));
        }
        attempts.push(format!("MDTM {stamp} {target}"));
        attempts.push(format!("SITE UTIME {stamp} {target}"));
        let mut last = None;
        for cmd in attempts {
            let reply = self.conn()?.send(&cmd).await?;
            if reply.is_ok() {
                return Ok(());
            }
            if reply.is_permanent_err() && meaning(&reply) != Meaning::Unknown {
                return Err(reply_error(&reply, path));
            }
            last = Some(reply);
        }
        if matches!(self.stat_inner(path).await, Err(Error::NotFound(_))) {
            return Err(Error::NotFound(path.clone()));
        }
        self.learned.mtime_rejected = true;
        self.log(
            LogKind::Status,
            "The server can't set modification times (MFMT/MDTM/SITE UTIME refused)",
        );
        tracing::debug!(reply = ?last.map(|r| r.code), "set_mtime refused");
        Err(Error::Unsupported(
            "the server can't set modification times",
        ))
    }

    async fn open_read(
        &mut self,
        path: &RemotePath,
        offset: u64,
        opts: &TransferOpts,
    ) -> Result<ReadStream> {
        self.settle().await?;
        let ascii = opts.transfer_type == TransferType::Ascii;
        if ascii && offset > 0 {
            self.log(
                LogKind::Status,
                "ASCII transfers can't be resumed; transfer the whole file instead",
            );
            return Err(Error::Unsupported("resuming an ASCII transfer"));
        }
        let target = self.target(path).await?;
        self.conn()?.set_type(opts.transfer_type).await?;
        let rest = (offset > 0).then_some(offset);
        match self
            .open_data(format!("RETR {target}"), rest, path, false)
            .await?
        {
            None => Ok(Box::new(tokio::io::empty())),
            Some(stream) if ascii => Ok(Box::new(AsciiReader::new(stream))),
            Some(stream) => Ok(Box::new(stream)),
        }
    }

    async fn open_write(
        &mut self,
        path: &RemotePath,
        mode: WriteMode,
        opts: &TransferOpts,
    ) -> Result<WriteStream> {
        self.settle().await?;
        let ascii = opts.transfer_type == TransferType::Ascii;
        if mode == WriteMode::Create {
            match self.stat_inner(path).await {
                Ok(_) => return Err(Error::AlreadyExists),
                Err(err @ (Error::Connection(_) | Error::Timeout | Error::Cancelled)) => {
                    return Err(err);
                }
                Err(_) => {}
            }
        }
        if ascii && matches!(mode, WriteMode::ResumeAt(n) if n > 0) {
            self.log(
                LogKind::Status,
                "ASCII transfers can't be resumed; transfer the whole file instead",
            );
            return Err(Error::Unsupported("resuming an ASCII transfer"));
        }
        let target = self.target(path).await?;
        self.conn()?.set_type(opts.transfer_type).await?;
        let (cmd, rest) = match mode {
            WriteMode::Create | WriteMode::Truncate | WriteMode::ResumeAt(0) => {
                (format!("STOR {target}"), None)
            }
            WriteMode::Append => (format!("APPE {target}"), None),
            WriteMode::ResumeAt(n) => (format!("STOR {target}"), Some(n)),
        };
        match self.open_data(cmd, rest, path, true).await? {
            None => Ok(Box::new(tokio::io::sink())),
            Some(stream) if ascii => Ok(Box::new(AsciiWriter::new(stream))),
            Some(stream) => Ok(Box::new(stream)),
        }
    }

    async fn finish_transfer(&mut self) -> Result<()> {
        let Some(pending) = self.pending.take() else {
            return Ok(());
        };
        let conn = self.conn()?;
        data::finish(conn, &pending.flags, pending.upload)
            .await
            .map(drop)
    }

    async fn raw_command(&mut self, cmd: &str) -> Result<String> {
        self.settle().await?;
        let verb = cmd
            .split_ascii_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        let replies = self.conn()?.raw_command(cmd).await?;
        if matches!(verb.as_str(), "CWD" | "CDUP" | "XCWD" | "XCUP") {
            self.cwd = None;
        }
        Ok(replies
            .iter()
            .flat_map(|r| r.lines.iter().cloned())
            .collect::<Vec<_>>()
            .join("\n"))
    }

    async fn keepalive(&mut self) -> Result<()> {
        if self.pending.is_some() {
            return Ok(());
        }
        let which = KeepaliveCommand::from_setting(&self.settings.ftp.send_keepalive_command);
        self.conn()?.keepalive_with(which).await
    }

    fn session_info(&self) -> Option<SessionInfo> {
        let conn = self.conn.as_ref().filter(|c| c.is_connected())?;
        let server_software = conn
            .syst()
            .map(str::to_owned)
            .or_else(|| conn.welcome().map(|w| w.first_line_text().to_owned()));
        let security = conn
            .tls_session()
            .map_or(SecurityInfo::Plain, |t| t.security_info());
        Some(SessionInfo {
            address: self.address.clone(),
            server_software,
            security,
        })
    }
}

/// Creates [`FtpBackend`]s for FTP, explicit and implicit FTPS. The
/// binary's [`BackendFactory`] delegates to it for those protocols.
#[derive(Clone)]
pub struct FtpBackendFactory {
    settings: Arc<Mutex<Settings>>,
    tls: Arc<TlsTrust>,
    ftp_proxy_password: Arc<Mutex<Option<SecretString>>>,
}

impl std::fmt::Debug for FtpBackendFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FtpBackendFactory")
            .field("tls", &self.tls)
            .finish_non_exhaustive()
    }
}

impl FtpBackendFactory {
    /// A factory using `settings` and certificate trust `tls`.
    pub fn new(settings: Settings, tls: Arc<TlsTrust>) -> Self {
        Self {
            settings: Arc::new(Mutex::new(settings)),
            tls,
            ftp_proxy_password: Arc::new(Mutex::new(None)),
        }
    }

    /// Replace the settings used by backends created from now on.
    pub fn set_settings(&self, settings: Settings) {
        *self.settings.lock().unwrap_or_else(PoisonError::into_inner) = settings;
    }

    /// The FTP proxy password (read from the vault item the settings'
    /// `password_ref` names), or `None` to forget it (vault locked).
    pub fn set_ftp_proxy_password(&self, password: Option<SecretString>) {
        *self
            .ftp_proxy_password
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = password;
    }

    /// The certificate trust.
    pub fn tls(&self) -> &Arc<TlsTrust> {
        &self.tls
    }

    /// A new, not yet connected backend (the concrete type).
    pub fn create_ftp(
        &self,
        info: &ConnectInfo,
        session: SessionId,
        events: EventSender,
    ) -> FtpBackend {
        let settings = self
            .settings
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let mut backend = FtpBackend::new(info, &settings, Arc::clone(&self.tls), session, events);
        if let Some(password) = self
            .ftp_proxy_password
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            backend.options_mut().set_ftp_proxy_password(password);
        }
        backend
    }
}

impl BackendFactory for FtpBackendFactory {
    fn create(
        &self,
        info: &ConnectInfo,
        session: SessionId,
        events: EventSender,
    ) -> Box<dyn Backend> {
        Box::new(self.create_ftp(info, session, events))
    }
}
