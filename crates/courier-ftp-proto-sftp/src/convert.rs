//! Pure conversions between SFTP v3 wire data and core types (T22): one
//! `SSH_FXP_NAME` element → [`Entry`], the file type from a mode, and russh-sftp
//! errors → [`courier_ftp_core::Error`].
//!
//! Input is untrusted server data: nothing here panics or preallocates from a
//! server-reported size.

use std::{fmt, io};

use courier_ftp_core::{
    Error,
    listing::{ListingContext, unix},
    model::{Entry, EntryKind, Permissions, Precision, RemotePath, Timestamp},
    text::sanitize_server_text,
};
use russh_sftp::{
    client::error::Error as SftpError,
    protocol::{FileAttributes, StatusCode},
};
use time::OffsetDateTime;

/// Names longer than this many bytes are dropped (hostile server, T91).
pub const MAX_NAME_BYTES: usize = 4096;
/// Server messages are capped at this many characters.
pub const MAX_SERVER_MESSAGE: usize = 512;

/// `S_IFMT`.
const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;
const S_IFLNK: u32 = 0o120_000;

/// The operation a request belongs to (error mapping, fault injection, log text).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SftpOp {
    /// `INIT` / subsystem start.
    Connect,
    /// `OPENDIR` / `READDIR`.
    List,
    /// `STAT` / `LSTAT` / `FSTAT`.
    Stat,
    /// `MKDIR`.
    Mkdir,
    /// `RMDIR`.
    Rmdir,
    /// `REMOVE`.
    Remove,
    /// `RENAME` / `posix-rename@openssh.com`.
    Rename,
    /// `SETSTAT` / `FSETSTAT`.
    SetStat,
    /// `OPEN`.
    Open,
    /// `READ`.
    Read,
    /// `WRITE`.
    Write,
    /// `CLOSE`.
    Close,
    /// `REALPATH`.
    RealPath,
    /// `READLINK`.
    ReadLink,
}

impl SftpOp {
    /// The session-log prefix for a failure, e.g. "Could not create directory".
    pub fn failure_text(self) -> &'static str {
        match self {
            Self::Connect => "Could not start the SFTP session on",
            Self::List => "Could not list",
            Self::Stat => "Could not get the attributes of",
            Self::Mkdir => "Could not create directory",
            Self::Rmdir => "Could not remove directory",
            Self::Remove => "Could not delete",
            Self::Rename => "Could not rename",
            Self::SetStat => "Could not change the attributes of",
            Self::Open => "Could not open",
            Self::Read => "Could not read",
            Self::Write => "Could not write",
            Self::Close => "Could not close",
            Self::RealPath => "Could not resolve",
            Self::ReadLink => "Could not read the link",
        }
    }
}

impl fmt::Display for SftpOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Whether `name` may become an [`Entry`]: not empty, not `.`/`..`, no `/` or NUL,
/// at most [`MAX_NAME_BYTES`] bytes.
pub fn is_acceptable_name(name: &str) -> bool {
    name.len() <= MAX_NAME_BYTES && Entry::is_valid_name(name)
}

/// The kind from `S_IFMT` of `mode`; without a type in the mode, the first character
/// of `longname` (`d`, `l`, `-`), else `File`.
pub fn kind_from_mode(mode: Option<u32>, longname: &str) -> EntryKind {
    let symlink = || EntryKind::Symlink {
        target: None,
        target_kind: None,
    };
    match mode.map(|m| m & S_IFMT) {
        Some(S_IFDIR) => EntryKind::Dir,
        Some(S_IFREG) => EntryKind::File,
        Some(S_IFLNK) => symlink(),
        Some(t) if t != 0 => EntryKind::Other,
        _ => match longname.chars().next() {
            Some('d') => EntryKind::Dir,
            Some('l') => symlink(),
            _ => EntryKind::File,
        },
    }
}

/// UTC seconds → a second-precision timestamp.
pub fn timestamp(secs: u32) -> Option<Timestamp> {
    OffsetDateTime::from_unix_timestamp(i64::from(secs))
        .ok()
        .map(|t| Timestamp::new(t, Precision::Second))
}

/// One `SSH_FXP_NAME` element → [`Entry`]. `None` for `.`, `..`, and names that are
/// empty, contain `/` or NUL, or are longer than [`MAX_NAME_BYTES`] bytes.
pub fn entry_from_name(filename: &str, longname: &str, attrs: &FileAttributes) -> Option<Entry> {
    is_acceptable_name(filename).then(|| entry_from_attrs(filename, longname, attrs))
}

/// As [`entry_from_name`] without the name checks (`stat` of a path, the root `/`).
pub fn entry_from_attrs(filename: &str, longname: &str, attrs: &FileAttributes) -> Entry {
    let parsed = if longname.is_empty() {
        None
    } else {
        unix::parse_line(longname, &ListingContext::new(OffsetDateTime::now_utc(), 0))
    };
    let kind = kind_from_mode(attrs.permissions, longname);
    let size = match kind {
        EntryKind::Dir => None,
        _ => attrs.size,
    };
    let permissions = attrs
        .permissions
        .map(Permissions::from_mode)
        .or_else(|| parsed.as_ref().and_then(|p| p.permissions.clone()));
    let (owner, group) = match &parsed {
        Some(p) if p.owner.is_some() || p.group.is_some() => (p.owner.clone(), p.group.clone()),
        _ => (
            attrs.uid.map(|u| u.to_string()),
            attrs.gid.map(|g| g.to_string()),
        ),
    };
    Entry {
        name: filename.to_owned(),
        kind,
        size,
        modified: attrs.mtime.and_then(timestamp),
        permissions,
        owner,
        group,
        hidden: filename.starts_with('.'),
    }
}

/// The sanitized server text of a status, or the status code's name.
fn status_message(code: StatusCode, message: &str) -> String {
    let text = sanitize_server_text(message, MAX_SERVER_MESSAGE);
    if text.trim().is_empty() {
        code.to_string()
    } else {
        text
    }
}

/// The SFTP status code as a number.
pub fn status_number(code: StatusCode) -> u16 {
    match code {
        StatusCode::Ok => 0,
        StatusCode::Eof => 1,
        StatusCode::NoSuchFile => 2,
        StatusCode::PermissionDenied => 3,
        StatusCode::Failure => 4,
        StatusCode::BadMessage => 5,
        StatusCode::NoConnection => 6,
        StatusCode::ConnectionLost => 7,
        StatusCode::OpUnsupported => 8,
    }
}

/// russh-sftp error → core error (T22 "Errors" table). `FAILURE` is always
/// `Protocol { code: Some(4) }` here; the backend turns it into `AlreadyExists` after
/// its `LSTAT` probe.
pub fn map_status(err: SftpError, op: SftpOp, path: &RemotePath) -> Error {
    let _ = op;
    match err {
        SftpError::Status(status) => {
            let code = status.status_code;
            let message = status_message(code, &status.error_message);
            match code {
                StatusCode::NoSuchFile => Error::NotFound(path.clone()),
                StatusCode::PermissionDenied => Error::PermissionDenied(path.to_string()),
                StatusCode::NoConnection | StatusCode::ConnectionLost => Error::Connection(message),
                StatusCode::OpUnsupported => {
                    Error::Unsupported("The server does not support this operation".to_owned())
                }
                other => Error::Protocol {
                    code: Some(status_number(other)),
                    message,
                },
            }
        }
        SftpError::Timeout => Error::Timeout,
        SftpError::IO(msg) => Error::Connection(sanitize_server_text(&msg, MAX_SERVER_MESSAGE)),
        SftpError::UnexpectedBehavior(msg) if is_session_closed(&msg) => {
            Error::Connection("The SFTP session was closed".to_owned())
        }
        SftpError::Limited(msg) | SftpError::UnexpectedBehavior(msg) => Error::Protocol {
            code: None,
            message: sanitize_server_text(&msg, MAX_SERVER_MESSAGE),
        },
        SftpError::UnexpectedPacket => Error::Protocol {
            code: None,
            message: "Unexpected packet from the server".to_owned(),
        },
    }
}

/// russh-sftp's texts for a dead session ("session closed", a dropped reply sender).
fn is_session_closed(msg: &str) -> bool {
    msg == "session closed" || msg == "sender dropped" || msg.starts_with("SendError")
}

/// Whether `err` is the status `code`.
pub fn is_status(err: &SftpError, code: StatusCode) -> bool {
    matches!(err, SftpError::Status(s) if s.status_code == code)
}

/// A copy of `err` (core's `Error` is not `Clone`; `Io` keeps kind and text).
pub fn clone_error(err: &Error) -> Error {
    match err {
        Error::Connection(m) => Error::Connection(m.clone()),
        Error::ConnectionLimit(m) => Error::ConnectionLimit(m.clone()),
        Error::Timeout => Error::Timeout,
        Error::Cancelled => Error::Cancelled,
        Error::Auth(m) => Error::Auth(m.clone()),
        Error::Tls(m) => Error::Tls(m.clone()),
        Error::HostKey(m) => Error::HostKey(m.clone()),
        Error::Proxy(m) => Error::Proxy(m.clone()),
        Error::NotFound(p) => Error::NotFound(p.clone()),
        Error::PermissionDenied(m) => Error::PermissionDenied(m.clone()),
        Error::AlreadyExists(p) => Error::AlreadyExists(p.clone()),
        Error::Protocol { code, message } => Error::Protocol {
            code: *code,
            message: message.clone(),
        },
        Error::Unsupported(m) => Error::Unsupported(m.clone()),
        Error::Io(e) => Error::Io(io::Error::new(e.kind(), e.to_string())),
        Error::VaultLocked => Error::VaultLocked,
        Error::Vault(m) => Error::Vault(m.clone()),
        Error::InvalidInput(m) => Error::InvalidInput(m.clone()),
        other => Error::Internal(other.to_string()),
    }
}

/// A core error as an `io::Error` for the transfer streams. The kind lets
/// `Error::from(io)` keep its classification (`Connection` → `ConnectionReset`,
/// `Timeout` → `TimedOut`); the core error is the inner error ([`core_error`]
/// recovers it).
pub fn io_error(err: Error) -> io::Error {
    let kind = match &err {
        Error::Connection(_) => io::ErrorKind::ConnectionReset,
        Error::Timeout => io::ErrorKind::TimedOut,
        Error::NotFound(_) => io::ErrorKind::NotFound,
        Error::PermissionDenied(_) => io::ErrorKind::PermissionDenied,
        Error::Io(e) => e.kind(),
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, err)
}

/// The core error inside an `io::Error` made by [`io_error`].
pub fn core_error(err: &io::Error) -> Option<&Error> {
    err.get_ref().and_then(|e| e.downcast_ref::<Error>())
}

/// An `io::Error` from a transfer stream → core error: the carried core error when
/// there is one, else `Error::Io`.
pub fn from_io(err: io::Error) -> Error {
    match core_error(&err) {
        Some(e) => clone_error(e),
        None => Error::Io(err),
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod props;
