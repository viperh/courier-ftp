//! [`Sftp`]: the SFTP v3 protocol session on an SSH channel, built on
//! `russh-sftp`'s raw request API, and the mapping of its errors.

use std::{sync::Arc, time::Duration};

use courier_ftp_core::{Error, Result, model::RemotePath};
use russh_sftp::{
    client::{Config, RawSftpSession, error::Error as SftpError, rawsession::Limits},
    extensions::{self, HardlinkExtension},
    protocol::{File, FileAttributes, OpenFlags, Packet, StatusCode},
};
use tokio_util::sync::CancellationToken;

use crate::ssh::{SshSession, bounded};

/// `posix-rename@openssh.com`: a rename that replaces an existing target.
pub(crate) const POSIX_RENAME: &str = "posix-rename@openssh.com";
/// Request size without `limits@openssh.com` (T41b §3).
pub(crate) const DEFAULT_REQUEST: u32 = 32 * 1024;
/// Upper bound of a read/write request when the server advertises larger
/// limits (OpenSSH: 255 KiB).
pub(crate) const MAX_REQUEST: u32 = 255 * 1024;
/// Largest incoming SFTP packet we accept.
const MAX_PACKET: u32 = 512 * 1024;
/// Header room kept free below the server's packet limit for a write.
const PACKET_OVERHEAD: u64 = 1024;

/// An initialised SFTP session. Cheap to share: requests take `&self`, so
/// several may be in flight at once (pipelining, symlink resolution).
pub(crate) struct Sftp {
    pub(crate) raw: Arc<RawSftpSession>,
    /// The negotiated protocol version (3 for every server in practice).
    pub(crate) version: u32,
    /// Extensions the server announced, sorted by name.
    pub(crate) extensions: Vec<(String, String)>,
    /// The server supports [`POSIX_RENAME`].
    pub(crate) posix_rename: bool,
    /// Bytes per read request.
    pub(crate) read_len: u32,
    /// Bytes per write request.
    pub(crate) write_len: u32,
}

impl Sftp {
    /// Open the `sftp` subsystem on `ssh` and run `INIT`/`VERSION` (and
    /// `limits@openssh.com` when announced). Every request afterwards is
    /// bounded by `timeout` (russh-sftp's per-request timeout).
    pub(crate) async fn open(
        ssh: &SshSession,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Result<Self> {
        let stream = ssh.open_subsystem_stream("sftp", timeout, cancel).await?;
        let config = Config {
            max_packet_len: MAX_PACKET,
            request_timeout_secs: timeout.as_secs().max(1),
            ..Config::default()
        };
        let mut raw = RawSftpSession::new_with_config(stream, config);
        let version = bounded(timeout, cancel, async {
            raw.init()
                .await
                .map_err(|e| map_error(e, "SFTP init", None))
        })
        .await?;
        let announced =
            |name: &str, ver: &str| version.extensions.get(name).is_some_and(|v| v == ver);
        let posix_rename = announced(POSIX_RENAME, "1");
        let mut read_len = DEFAULT_REQUEST;
        let mut write_len = DEFAULT_REQUEST;
        if announced(extensions::LIMITS, "1") {
            let limits = bounded(timeout, cancel, async {
                raw.limits()
                    .await
                    .map_err(|e| map_error(e, "limits@openssh.com", None))
            })
            .await?;
            let limits = Limits::from(limits);
            let cap = |v: Option<u64>| {
                let mut len = v.unwrap_or(u64::from(MAX_REQUEST));
                if let Some(packet) = limits.packet_len {
                    len = len.min(packet.saturating_sub(PACKET_OVERHEAD));
                }
                u32::try_from(len.min(u64::from(MAX_REQUEST)))
                    .unwrap_or(MAX_REQUEST)
                    .max(1)
            };
            read_len = cap(limits.read_len);
            write_len = cap(limits.write_len);
            raw.set_limits(limits);
        }
        let mut extensions: Vec<(String, String)> = version.extensions.into_iter().collect();
        extensions.sort();
        Ok(Self {
            raw: Arc::new(raw),
            version: version.version,
            extensions,
            posix_rename,
            read_len,
            write_len,
        })
    }

    /// End the SFTP channel.
    pub(crate) fn close(&self) {
        if let Err(err) = self.raw.close_session() {
            tracing::debug!(%err, "sftp: closing the channel");
        }
    }

    /// `REALPATH`.
    pub(crate) async fn realpath(&self, path: &str) -> Result<String> {
        let name = self
            .raw
            .realpath(path)
            .await
            .map_err(|e| map_error(e, "realpath", Some(&RemotePath::new(path))))?;
        name.files
            .into_iter()
            .next()
            .map(|f| f.filename)
            .ok_or_else(|| protocol("realpath: the server returned no name"))
    }

    /// `STAT` (follows symlinks).
    pub(crate) async fn stat(&self, path: &RemotePath) -> Result<FileAttributes> {
        self.raw
            .stat(path.as_str())
            .await
            .map(|a| a.attrs)
            .map_err(|e| map_error(e, "stat", Some(path)))
    }

    /// `LSTAT` (doesn't follow symlinks).
    pub(crate) async fn lstat(&self, path: &RemotePath) -> Result<FileAttributes> {
        self.raw
            .lstat(path.as_str())
            .await
            .map(|a| a.attrs)
            .map_err(|e| map_error(e, "lstat", Some(path)))
    }

    /// `READLINK`.
    pub(crate) async fn readlink(&self, path: &RemotePath) -> Result<String> {
        let name = self
            .raw
            .readlink(path.as_str())
            .await
            .map_err(|e| map_error(e, "readlink", Some(path)))?;
        name.files
            .into_iter()
            .next()
            .map(|f| f.filename)
            .ok_or_else(|| protocol("readlink: the server returned no name"))
    }

    /// `OPENDIR`, `READDIR` until EOF, `CLOSE`. Entries keep their `longname`.
    pub(crate) async fn read_dir(&self, path: &RemotePath) -> Result<Vec<File>> {
        let handle = self
            .raw
            .opendir(path.as_str())
            .await
            .map_err(|e| map_error(e, "opendir", Some(path)))?
            .handle;
        let mut files = Vec::new();
        let result = loop {
            match self.raw.readdir(handle.as_str()).await {
                Ok(name) => files.extend(name.files),
                Err(SftpError::Status(s)) if s.status_code == StatusCode::Eof => break Ok(()),
                Err(e) => break Err(map_error(e, "readdir", Some(path))),
            }
        };
        let closed = self.close_handle(handle, path).await;
        result.and(closed).map(|()| files)
    }

    /// `MKDIR` with default attributes.
    pub(crate) async fn mkdir(&self, path: &RemotePath) -> Result<()> {
        self.raw
            .mkdir(path.as_str(), FileAttributes::empty())
            .await
            .map(drop)
            .map_err(|e| map_error(e, "mkdir", Some(path)))
    }

    /// `RMDIR`.
    pub(crate) async fn rmdir(&self, path: &RemotePath) -> Result<()> {
        self.raw
            .rmdir(path.as_str())
            .await
            .map(drop)
            .map_err(|e| map_error(e, "rmdir", Some(path)))
    }

    /// `REMOVE`.
    pub(crate) async fn remove(&self, path: &RemotePath) -> Result<()> {
        self.raw
            .remove(path.as_str())
            .await
            .map(drop)
            .map_err(|e| map_error(e, "remove", Some(path)))
    }

    /// `RENAME` (SFTP v3: fails when `to` exists).
    pub(crate) async fn rename(&self, from: &RemotePath, to: &RemotePath) -> Result<()> {
        self.raw
            .rename(from.as_str(), to.as_str())
            .await
            .map(drop)
            .map_err(|e| map_error(e, "rename", Some(from)))
    }

    /// `posix-rename@openssh.com` (replaces `to`).
    pub(crate) async fn posix_rename(&self, from: &RemotePath, to: &RemotePath) -> Result<()> {
        // The request data is two strings, the same layout as hardlink's.
        let data: Vec<u8> = HardlinkExtension {
            oldpath: from.as_str().to_owned(),
            newpath: to.as_str().to_owned(),
        }
        .try_into()
        .map_err(|e| map_error(SftpError::from(e), "posix-rename", Some(from)))?;
        let reply = self
            .raw
            .extended(POSIX_RENAME, data)
            .await
            .map_err(|e| map_error(e, "posix-rename", Some(from)))?;
        match reply {
            Packet::Status(s) if s.status_code == StatusCode::Ok => Ok(()),
            Packet::Status(s) => Err(map_error(SftpError::Status(s), "posix-rename", Some(from))),
            _ => Err(protocol("posix-rename: unexpected reply")),
        }
    }

    /// `SETSTAT`.
    pub(crate) async fn setstat(&self, path: &RemotePath, attrs: FileAttributes) -> Result<()> {
        self.raw
            .setstat(path.as_str(), attrs)
            .await
            .map(drop)
            .map_err(|e| map_error(e, "setstat", Some(path)))
    }

    /// `OPEN`; returns the handle.
    pub(crate) async fn open_file(&self, path: &RemotePath, flags: OpenFlags) -> Result<String> {
        self.raw
            .open(path.as_str(), flags, FileAttributes::empty())
            .await
            .map(|h| h.handle)
            .map_err(|e| map_error(e, "open", Some(path)))
    }

    /// `FSTAT`.
    pub(crate) async fn fstat(&self, handle: &str, path: &RemotePath) -> Result<FileAttributes> {
        self.raw
            .fstat(handle)
            .await
            .map(|a| a.attrs)
            .map_err(|e| map_error(e, "fstat", Some(path)))
    }

    /// `FSETSTAT`.
    pub(crate) async fn fsetstat(
        &self,
        handle: &str,
        attrs: FileAttributes,
        path: &RemotePath,
    ) -> Result<()> {
        self.raw
            .fsetstat(handle, attrs)
            .await
            .map(drop)
            .map_err(|e| map_error(e, "fsetstat", Some(path)))
    }

    /// `CLOSE`.
    pub(crate) async fn close_handle(&self, handle: String, path: &RemotePath) -> Result<()> {
        self.raw
            .close(handle)
            .await
            .map(drop)
            .map_err(|e| map_error(e, "close", Some(path)))
    }
}

fn protocol(message: impl Into<String>) -> Error {
    Error::Protocol {
        code: None,
        message: message.into(),
    }
}

/// Map a russh-sftp error to a core error. `op` and `path` give a `Failure`
/// its context ("mkdir /a/b: Failure").
pub(crate) fn map_error(err: SftpError, op: &str, path: Option<&RemotePath>) -> Error {
    let context = || match path {
        Some(path) => format!("{op} {path}"),
        None => op.to_owned(),
    };
    match err {
        SftpError::Status(status) => {
            let message = if status.error_message.is_empty() {
                status.status_code.to_string()
            } else {
                status.error_message
            };
            match status.status_code {
                StatusCode::NoSuchFile => match path {
                    Some(path) => Error::NotFound(path.clone()),
                    None => protocol(format!("{}: {message}", context())),
                },
                StatusCode::PermissionDenied => Error::PermissionDenied,
                StatusCode::NoConnection | StatusCode::ConnectionLost => Error::Connection(message),
                StatusCode::OpUnsupported => protocol(format!(
                    "{}: not supported by the server ({message})",
                    context()
                )),
                StatusCode::Ok | StatusCode::Eof | StatusCode::Failure | StatusCode::BadMessage => {
                    protocol(format!("{}: {message}", context()))
                }
            }
        }
        SftpError::Timeout => Error::Timeout,
        // The channel is gone ("session closed", "sender dropped", I/O).
        SftpError::IO(message) | SftpError::UnexpectedBehavior(message) => {
            Error::Connection(format!("SFTP channel: {message}"))
        }
        SftpError::Limited(message) => protocol(format!("{}: {message}", context())),
        SftpError::UnexpectedPacket => protocol(format!("{}: unexpected reply", context())),
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use russh_sftp::protocol::Status;

    use super::*;

    fn status(code: StatusCode, msg: &str) -> SftpError {
        SftpError::Status(Status {
            id: 1,
            status_code: code,
            error_message: msg.to_owned(),
            language_tag: "en".to_owned(),
        })
    }

    #[test]
    fn maps_status_codes() {
        let p = RemotePath::new("/a/b");
        assert!(matches!(
            map_error(status(StatusCode::NoSuchFile, "x"), "stat", Some(&p)),
            Error::NotFound(q) if q == p
        ));
        assert!(matches!(
            map_error(status(StatusCode::PermissionDenied, "x"), "stat", Some(&p)),
            Error::PermissionDenied
        ));
        assert!(matches!(
            map_error(status(StatusCode::ConnectionLost, "gone"), "stat", Some(&p)),
            Error::Connection(m) if m == "gone"
        ));
        assert_eq!(
            map_error(status(StatusCode::Failure, ""), "mkdir", Some(&p)).to_string(),
            "protocol error: mkdir /a/b: Failure"
        );
        assert!(matches!(
            map_error(SftpError::Timeout, "stat", None),
            Error::Timeout
        ));
        assert!(matches!(
            map_error(
                SftpError::UnexpectedBehavior("session closed".into()),
                "stat",
                None
            ),
            Error::Connection(_)
        ));
    }
}
