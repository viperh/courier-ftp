//! The crate-wide error type.

use crate::model::RemotePath;

/// Errors produced by the core and by every [`Backend`](crate::backend)
/// implementation.
///
/// Protocol crates map their own failures onto these variants and put the
/// protocol-specific detail into the message. The `courier-ftp` binary converts
/// them into `color_eyre` reports at the boundary, which is why this enum carries
/// no formatting or reporting concerns of its own.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The connection could not be established or was lost.
    #[error("connection failed: {0}")]
    Connection(String),
    /// An operation did not finish within its timeout.
    #[error("timed out")]
    Timeout,
    /// The operation was cancelled (by the user or a cancellation token).
    #[error("cancelled")]
    Cancelled,
    /// The server rejected the credentials.
    #[error("authentication failed: {0}")]
    Auth(String),
    /// TLS negotiation or certificate verification failed.
    #[error("TLS error: {0}")]
    Tls(String),
    /// The SSH host key is unknown, changed or was rejected.
    #[error("host key verification failed: {0}")]
    HostKey(String),
    /// The remote path does not exist.
    #[error("not found: {0}")]
    NotFound(RemotePath),
    /// The server or filesystem refused access.
    #[error("permission denied")]
    PermissionDenied,
    /// The target already exists.
    #[error("already exists")]
    AlreadyExists,
    /// The server sent an error reply or broke the protocol.
    ///
    /// `code` is the FTP reply code (e.g. `550`) or `None` when the protocol has
    /// no numeric code for this failure.
    #[error("{}", protocol_message(*.code, .message))]
    Protocol {
        /// FTP reply code, when there is one.
        code: Option<u16>,
        /// The server's message or a description of the violation.
        message: String,
    },
    /// The backend cannot do this (e.g. `chmod` on a server without `SITE CHMOD`).
    #[error("not supported: {0}")]
    Unsupported(&'static str),
    /// A local I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The vault is locked, corrupt or could not be opened.
    #[error("vault error: {0}")]
    Vault(String),
    /// Input from the user or a config file is invalid.
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

fn protocol_message(code: Option<u16>, message: &str) -> String {
    match code {
        Some(code) => format!("server replied {code}: {message}"),
        None => format!("protocol error: {message}"),
    }
}

impl Error {
    /// Whether retrying the operation may succeed (used by the retry logic, T41).
    ///
    /// Transient: timeouts, lost connections, FTP `4xx` replies ("transient
    /// negative completion") and I/O errors that mean the connection dropped.
    pub fn is_transient(&self) -> bool {
        use std::io::ErrorKind;
        match self {
            Error::Timeout | Error::Connection(_) => true,
            Error::Protocol {
                code: Some(code), ..
            } => (400..500).contains(code),
            Error::Io(err) => matches!(
                err.kind(),
                ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::ConnectionRefused
                    | ErrorKind::BrokenPipe
                    | ErrorKind::TimedOut
                    | ErrorKind::UnexpectedEof
                    | ErrorKind::Interrupted
                    | ErrorKind::NotConnected
            ),
            _ => false,
        }
    }

    /// Shorthand for [`Error::Protocol`] with a reply code.
    pub fn reply(code: u16, message: impl Into<String>) -> Self {
        Error::Protocol {
            code: Some(code),
            message: message.into(),
        }
    }
}

/// Convenience alias used throughout the workspace.
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use std::io;

    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn transient_errors() {
        assert!(Error::Timeout.is_transient());
        assert!(Error::Connection("reset".into()).is_transient());
        assert!(Error::reply(421, "too many users").is_transient());
        assert!(Error::reply(450, "busy").is_transient());
        assert!(Error::Io(io::Error::from(io::ErrorKind::ConnectionReset)).is_transient());
    }

    #[test]
    fn permanent_errors() {
        assert!(!Error::reply(550, "no such file").is_transient());
        assert!(!Error::reply(530, "login incorrect").is_transient());
        assert!(!Error::Auth("bad password".into()).is_transient());
        assert!(!Error::Cancelled.is_transient());
        assert!(!Error::NotFound(RemotePath::root()).is_transient());
        assert!(!Error::Io(io::Error::from(io::ErrorKind::PermissionDenied)).is_transient());
        assert!(
            !Error::Protocol {
                code: None,
                message: "garbage".into()
            }
            .is_transient()
        );
    }

    #[test]
    fn display() {
        assert_eq!(
            Error::reply(550, "No such file").to_string(),
            "server replied 550: No such file"
        );
        assert_eq!(
            Error::NotFound(RemotePath::new("/a/b")).to_string(),
            "not found: /a/b"
        );
    }
}
