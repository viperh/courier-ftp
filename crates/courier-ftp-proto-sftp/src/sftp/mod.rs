//! The SFTP [`Backend`] (T22): [`SftpBackend`] runs SFTP v3 (`russh-sftp`)
//! over an SSH session from [`crate::ssh::connect`].
//!
//! | Backend method | SFTP |
//! |---|---|
//! | `connect` | SSH connect + `sftp` subsystem + `INIT` (version and extensions logged) |
//! | `home_dir`, `keepalive` | `REALPATH "."` |
//! | `list` | `OPENDIR`/`READDIR`; owner/group names from `longname`; symlinks resolved with `READLINK` + `STAT`, [`SYMLINK_CONCURRENCY`] at a time |
//! | `stat` | `LSTAT` (+ link resolution) |
//! | `mkdir`, `rmdir`, `remove_file` | `MKDIR`, `RMDIR`, `REMOVE` |
//! | `rename` | `posix-rename@openssh.com` when announced; otherwise `RENAME`, and when the target exists `REMOVE` it and retry |
//! | `chmod`, `set_mtime` | `SETSTAT` (permissions; atime + mtime) |
//! | `open_read`, `open_write` | `OPEN` + pipelined `READ`/`WRITE`, [`MAX_OUTSTANDING`] in flight |
//! | `raw_command` | unsupported |
//!
//! # Rename overwrites
//!
//! Like the other backends (`rename(2)`, FTP `RNTO`), `rename` replaces an
//! existing file: asking the user first is the caller's job.
//!
//! # Charset
//!
//! `russh-sftp` decodes names as UTF-8 (invalid bytes become U+FFFD) and sends
//! names as UTF-8, so a site's custom charset can't be applied to SFTP names.
//!
//! # Timeouts and cancellation
//!
//! Every SFTP request is bounded by the connection timeout (russh-sftp's
//! per-request timeout); `connect` and `list` also stop when their token is
//! cancelled. A transfer is cancelled by dropping its stream (the handle is
//! closed in the background).

mod client;
mod convert;
mod stream;

#[cfg(test)]
pub(crate) mod test_server;
#[cfg(test)]
mod tests;

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use courier_ftp_core::{
    Error, Result,
    backend::{
        Backend, BackendFactory, Capabilities, ConnectInfo, Listing, ReadStream, SessionInfo,
        TransferOpts, WriteMode, WriteStream,
    },
    events::{EventSender, LogKind, SessionId},
    listing::ListingContext,
    model::{Entry, EntryKind, RemotePath, ServerAddress},
    settings::Settings,
};
use futures::StreamExt;
use russh_sftp::protocol::{FileAttributes, OpenFlags};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

pub use self::stream::MAX_OUTSTANDING;
use self::{
    client::Sftp,
    stream::{Outcome, SftpReader, SftpWriter},
};
use crate::ssh::{
    self, AgentConnector, CredentialCache, HostKeyVerifier, SshContext, SshOptions, SshSession,
    SystemAgent,
};

/// Symlinks resolved at once while listing.
pub const SYMLINK_CONCURRENCY: usize = 16;

struct Conn {
    ssh: SshSession,
    sftp: Sftp,
}

/// An SFTP session. See the [module docs](self).
pub struct SftpBackend {
    address: ServerAddress,
    timezone_offset: time::Duration,
    opts: SshOptions,
    ctx: SshContext,
    conn: Option<Conn>,
    outcome: Option<Outcome>,
}

impl std::fmt::Debug for SftpBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SftpBackend")
            .field("address", &self.address)
            .field("connected", &self.is_connected())
            .finish_non_exhaustive()
    }
}

impl SftpBackend {
    /// A backend for `info` (address, logon, proxy choice, key file or vault
    /// key, saved passphrase, timezone offset; see
    /// [`SshOptions::from_connect_info`]) with the timeouts and keep-alive
    /// from `settings`. `ctx` carries the event bus, the host-key verifier,
    /// the agent and the credential cache.
    pub fn new(info: &ConnectInfo, settings: &Settings, ctx: SshContext) -> Self {
        Self {
            address: info.address.clone(),
            timezone_offset: info.timezone_offset,
            opts: SshOptions::from_connect_info(info, settings),
            ctx,
            conn: None,
            outcome: None,
        }
    }

    /// The SSH options used by the next `connect`.
    pub fn options_mut(&mut self) -> &mut SshOptions {
        &mut self.opts
    }

    fn timeout(&self) -> Duration {
        self.opts.timeout
    }

    fn log(&self, kind: LogKind, text: impl Into<String>) {
        self.ctx.events.log(self.ctx.session, kind, text);
    }

    /// The live connection, or [`Error::Connection`].
    fn conn(&self) -> Result<&Conn> {
        match &self.conn {
            Some(c) if !c.ssh.is_closed() => Ok(c),
            Some(c) => Err(Error::Connection(
                c.ssh
                    .end_reason()
                    .unwrap_or_else(|| "the connection was closed".to_owned()),
            )),
            None => Err(Error::Connection("not connected".to_owned())),
        }
    }

    /// Turn a failure on a connection that has meanwhile closed into
    /// [`Error::Connection`], so the session handle reconnects.
    fn check<T>(&self, result: Result<T>) -> Result<T> {
        match result {
            Err(err) if !matches!(err, Error::Connection(_)) => match self.conn() {
                Err(conn) => Err(conn),
                Ok(_) => Err(err),
            },
            other => other,
        }
    }

    fn ctx(&self) -> ListingContext {
        ListingContext::new(self.timezone_offset)
    }

    async fn close_conn(&mut self) {
        if let Some(conn) = self.conn.take() {
            conn.sftp.close();
            conn.ssh.disconnect().await.ok();
        }
    }
}

/// Fill in a symlink's target and the target's kind (`None` when broken).
async fn resolve_link(sftp: &Sftp, path: &RemotePath) -> EntryKind {
    let target = sftp.readlink(path).await.ok();
    let target_kind = match sftp.stat(path).await {
        Ok(attrs) => convert::kind_of(&attrs).map(Box::new),
        Err(_) => None,
    };
    EntryKind::Symlink {
        target,
        target_kind,
    }
}

#[async_trait]
impl Backend for SftpBackend {
    fn capabilities(&self) -> Capabilities {
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
        }
    }

    fn address(&self) -> Option<&ServerAddress> {
        Some(&self.address)
    }

    async fn connect(&mut self, cancel: CancellationToken) -> Result<()> {
        self.close_conn().await;
        let ssh = ssh::connect(&self.opts, &self.ctx, &cancel).await?;
        let sftp = match Sftp::open(&ssh, self.timeout(), &cancel).await {
            Ok(sftp) => sftp,
            Err(err) => {
                self.log(LogKind::Error, format!("Could not start SFTP: {err}"));
                ssh.disconnect().await.ok();
                return Err(err);
            }
        };
        self.log(
            LogKind::Status,
            format!("SFTP protocol version {}", sftp.version),
        );
        if !sftp.extensions.is_empty() {
            let list: Vec<String> = sftp
                .extensions
                .iter()
                .map(|(name, ver)| format!("{name} ({ver})"))
                .collect();
            self.log(
                LogKind::Debug(3),
                format!("SFTP extensions: {}", list.join(", ")),
            );
        }
        self.log(
            LogKind::Debug(4),
            format!(
                "SFTP request size: read {} bytes, write {} bytes, {} in flight",
                sftp.read_len, sftp.write_len, MAX_OUTSTANDING
            ),
        );
        self.conn = Some(Conn { ssh, sftp });
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.close_conn().await;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.conn.as_ref().is_some_and(|c| !c.ssh.is_closed())
    }

    async fn home_dir(&mut self) -> Result<RemotePath> {
        let result = self.conn()?.sftp.realpath(".").await;
        self.check(result).map(RemotePath::new)
    }

    async fn list(&mut self, dir: &RemotePath, cancel: CancellationToken) -> Result<Listing> {
        let ctx = self.ctx();
        let conn = self.conn()?;
        let sftp = &conn.sftp;
        let work = async {
            let files = sftp.read_dir(dir).await?;
            let mut raw = Vec::new();
            let mut entries = Vec::new();
            for file in files {
                if file.filename == "." || file.filename == ".." || file.filename.contains('/') {
                    continue;
                }
                if !file.longname.is_empty() {
                    raw.push(file.longname.clone());
                }
                let longname = Some(file.longname.as_str());
                entries.push(convert::entry(file.filename, &file.attrs, longname, &ctx));
            }
            // Resolve symlinks, a bounded number at a time.
            let links: Vec<(usize, RemotePath)> = entries
                .iter()
                .enumerate()
                .filter(|(_, e)| e.kind.is_symlink())
                .filter_map(|(i, e)| dir.join(&e.name).ok().map(|p| (i, p)))
                .collect();
            let resolved: Vec<(usize, EntryKind)> = futures::stream::iter(links)
                .map(|(i, path)| async move { (i, resolve_link(sftp, &path).await) })
                .buffer_unordered(SYMLINK_CONCURRENCY)
                .collect()
                .await;
            for (i, kind) in resolved {
                if let Some(entry) = entries.get_mut(i) {
                    entry.kind = kind;
                }
            }
            Ok::<_, Error>((entries, raw))
        };
        let result = tokio::select! {
            biased;
            () = cancel.cancelled() => Err(Error::Cancelled),
            r = work => r,
        };
        let (entries, raw) = self.check(result)?;
        if self.ctx.events.enabled(LogKind::ListingRaw) {
            for line in &raw {
                self.log(LogKind::ListingRaw, line.clone());
            }
        }
        self.log(
            LogKind::Status,
            format!("Directory listing of \"{dir}\" successful"),
        );
        Ok(Listing {
            dir: dir.clone(),
            entries,
            fetched_at: std::time::Instant::now(),
            raw: (!raw.is_empty()).then(|| raw.join("\n")),
        })
    }

    async fn stat(&mut self, path: &RemotePath) -> Result<Entry> {
        let ctx = self.ctx();
        let conn = self.conn()?;
        let result = async {
            let attrs = conn.sftp.lstat(path).await?;
            let name = path.file_name().unwrap_or("/").to_owned();
            let mut entry = convert::entry(name, &attrs, None, &ctx);
            if entry.kind.is_symlink() {
                entry.kind = resolve_link(&conn.sftp, path).await;
            }
            Ok(entry)
        }
        .await;
        self.check(result)
    }

    async fn mkdir(&mut self, path: &RemotePath) -> Result<()> {
        let conn = self.conn()?;
        let result = match conn.sftp.mkdir(path).await {
            // SFTP v3 reports an existing directory as a plain failure.
            Err(Error::Protocol { .. }) if conn.sftp.lstat(path).await.is_ok() => {
                Err(Error::AlreadyExists)
            }
            other => other,
        };
        self.check(result)
    }

    async fn rmdir(&mut self, path: &RemotePath) -> Result<()> {
        let result = self.conn()?.sftp.rmdir(path).await;
        self.check(result)
    }

    async fn remove_file(&mut self, path: &RemotePath) -> Result<()> {
        let result = self.conn()?.sftp.remove(path).await;
        self.check(result)
    }

    async fn rename(&mut self, from: &RemotePath, to: &RemotePath) -> Result<()> {
        let conn = self.conn()?;
        let sftp = &conn.sftp;
        let result = if sftp.posix_rename {
            sftp.posix_rename(from, to).await
        } else {
            match sftp.rename(from, to).await {
                // SFTP v3 refuses to replace an existing target.
                Err(err @ Error::Protocol { .. }) => match sftp.lstat(to).await {
                    Ok(attrs) if convert::kind_of(&attrs) != Some(EntryKind::Dir) => {
                        sftp.remove(to).await?;
                        sftp.rename(from, to).await
                    }
                    _ => Err(err),
                },
                other => other,
            }
        };
        self.check(result)
    }

    async fn chmod(&mut self, path: &RemotePath, mode: u32) -> Result<()> {
        let attrs = FileAttributes {
            permissions: Some(mode & 0o7777),
            ..FileAttributes::empty()
        };
        let result = self.conn()?.sftp.setstat(path, attrs).await;
        self.check(result)
    }

    async fn set_mtime(&mut self, path: &RemotePath, time: OffsetDateTime) -> Result<()> {
        let mtime = u32::try_from(time.unix_timestamp()).map_err(|_| {
            Error::InvalidInput(format!("SFTP can't store the time {time} (1970–2106 only)"))
        })?;
        let conn = self.conn()?;
        let result = async {
            // SFTP v3 sets both times together: keep the access time.
            let atime = conn.sftp.stat(path).await?.atime.unwrap_or(mtime);
            let attrs = FileAttributes {
                atime: Some(atime),
                mtime: Some(mtime),
                ..FileAttributes::empty()
            };
            conn.sftp.setstat(path, attrs).await
        }
        .await;
        self.check(result)
    }

    async fn open_read(
        &mut self,
        path: &RemotePath,
        offset: u64,
        _opts: &TransferOpts,
    ) -> Result<ReadStream> {
        let outcome = Outcome::default();
        let conn = self.conn()?;
        let result = conn.sftp.open_file(path, OpenFlags::READ).await;
        let handle = self.check(result)?;
        let reader = SftpReader::new(
            Arc::clone(&conn.sftp.raw),
            handle,
            path.clone(),
            offset,
            conn.sftp.read_len,
            Arc::clone(&outcome),
        );
        self.outcome = Some(outcome);
        Ok(Box::new(reader))
    }

    async fn open_write(
        &mut self,
        path: &RemotePath,
        mode: WriteMode,
        _opts: &TransferOpts,
    ) -> Result<WriteStream> {
        let outcome = Outcome::default();
        let conn = self.conn()?;
        let sftp = &conn.sftp;
        let result = async {
            let base = OpenFlags::WRITE | OpenFlags::CREATE;
            let flags = match mode {
                WriteMode::Create => base | OpenFlags::EXCLUDE,
                WriteMode::Truncate => base | OpenFlags::TRUNCATE,
                WriteMode::Append => base | OpenFlags::APPEND,
                WriteMode::ResumeAt(_) => base,
            };
            let handle = match sftp.open_file(path, flags).await {
                Err(Error::Protocol { .. })
                    if mode == WriteMode::Create && sftp.lstat(path).await.is_ok() =>
                {
                    return Err(Error::AlreadyExists);
                }
                other => other?,
            };
            let offset = match mode {
                WriteMode::Create | WriteMode::Truncate => Ok(0),
                WriteMode::Append => sftp.fstat(&handle, path).await.map(|a| a.size.unwrap_or(0)),
                WriteMode::ResumeAt(n) => {
                    // Drop anything after the resume point.
                    let attrs = FileAttributes {
                        size: Some(n),
                        ..FileAttributes::empty()
                    };
                    match sftp.fsetstat(&handle, attrs, path).await {
                        Ok(()) => Ok(n),
                        Err(err @ Error::Connection(_)) => Err(err),
                        Err(err) => {
                            tracing::debug!(%err, "sftp: truncating before resume");
                            Ok(n)
                        }
                    }
                }
            };
            match offset {
                Ok(offset) => Ok((handle, offset)),
                Err(err) => {
                    sftp.close_handle(handle, path).await.ok();
                    Err(err)
                }
            }
        }
        .await;
        let (handle, offset) = self.check(result)?;
        let writer = SftpWriter::new(
            Arc::clone(&sftp.raw),
            handle,
            path.clone(),
            offset,
            sftp.write_len,
            Arc::clone(&outcome),
        );
        self.outcome = Some(outcome);
        Ok(Box::new(writer))
    }

    async fn finish_transfer(&mut self) -> Result<()> {
        let Some(outcome) = self.outcome.take() else {
            return Ok(());
        };
        let err = outcome
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        match err {
            Some(err) => self.check(Err(err)),
            None => Ok(()),
        }
    }

    async fn raw_command(&mut self, _cmd: &str) -> Result<String> {
        Err(Error::Unsupported(
            "custom commands are not available over SFTP",
        ))
    }

    async fn keepalive(&mut self) -> Result<()> {
        let result = self.conn()?.sftp.realpath(".").await;
        self.check(result).map(drop)
    }

    fn session_info(&self) -> Option<SessionInfo> {
        let conn = self.conn().ok()?;
        Some(SessionInfo {
            address: self.address.clone(),
            server_software: Some(conn.ssh.server_version()),
            security: conn.ssh.security_info(),
        })
    }
}

/// Creates [`SftpBackend`]s for SFTP [`ConnectInfo`]s. The binary's
/// [`BackendFactory`] delegates to it for [`Protocol::Sftp`]; it doesn't look
/// at the protocol itself.
///
/// [`Protocol::Sftp`]: courier_ftp_core::model::Protocol::Sftp
#[derive(Clone)]
pub struct SftpBackendFactory {
    settings: Arc<Mutex<Settings>>,
    verifier: Arc<dyn HostKeyVerifier>,
    agent: Arc<dyn AgentConnector>,
    credentials: Option<CredentialCache>,
}

impl std::fmt::Debug for SftpBackendFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SftpBackendFactory").finish_non_exhaustive()
    }
}

impl SftpBackendFactory {
    /// A factory using `settings` (timeouts, keep-alive, proxy) and
    /// `verifier` for host keys (production: `ssh::trust::TrustStoreVerifier`),
    /// with the system SSH agent and no credential cache.
    pub fn new(settings: Settings, verifier: Arc<dyn HostKeyVerifier>) -> Self {
        Self {
            settings: Arc::new(Mutex::new(settings)),
            verifier,
            agent: Arc::new(SystemAgent),
            credentials: None,
        }
    }

    /// Use `agent` for logon type Agent.
    #[must_use]
    pub fn with_agent(mut self, agent: Arc<dyn AgentConnector>) -> Self {
        self.agent = agent;
        self
    }

    /// Remember typed passwords and passphrases in `cache`.
    #[must_use]
    pub fn with_credentials(mut self, cache: CredentialCache) -> Self {
        self.credentials = Some(cache);
        self
    }

    /// Replace the settings used by backends created from now on.
    pub fn set_settings(&self, settings: Settings) {
        *self
            .settings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = settings;
    }

    /// A new, not yet connected backend (the concrete type).
    pub fn create_sftp(
        &self,
        info: &ConnectInfo,
        session: SessionId,
        events: EventSender,
    ) -> SftpBackend {
        let ctx = SshContext {
            session,
            events,
            verifier: Arc::clone(&self.verifier),
            agent: Arc::clone(&self.agent),
            credentials: self.credentials.clone(),
        };
        let settings = self
            .settings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        SftpBackend::new(info, &settings, ctx)
    }
}

impl BackendFactory for SftpBackendFactory {
    fn create(
        &self,
        info: &ConnectInfo,
        session: SessionId,
        events: EventSender,
    ) -> Box<dyn Backend> {
        Box::new(self.create_sftp(info, session, events))
    }
}
