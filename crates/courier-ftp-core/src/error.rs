//! The crate-wide [`Error`] and [`Result`] (re-exported at the crate root).
//!
//! `Error` is not `Clone` (it holds `io::Error`). Code that must keep or broadcast an
//! error (the queue's failed list, events) stores `err.to_string()` and [`Error::code`].
//!
//! Mapping guidance for backends: `NotFound`, `PermissionDenied` and `AlreadyExists`
//! when the protocol says so, `Protocol` for every other server reply, `Io` only for
//! local I/O.

use std::io;

use crate::model::RemotePath;

/// Errors produced by the core and the protocol crates.
///
/// The `courier-ftp` crate converts these into `color_eyre` reports at the boundary,
/// which is why this enum carries no reporting concerns of its own.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Could not connect, or the connection was lost (incl. FTP 421). The session
    /// handle reconnects (T03).
    #[error("connection error: {0}")]
    Connection(String),
    /// Server accepted no more connections from us: FTP 421/530 replies whose text says
    /// "too many connections" (T10), SSH disconnect reason 12 TOO_MANY_CONNECTIONS (T20).
    /// T41 lowers the per-server connection limit.
    #[error("too many connections: {0}")]
    ConnectionLimit(String),
    /// No data for `connection.timeout_secs`.
    #[error("timed out")]
    Timeout,
    /// The operation was cancelled through its `CancellationToken`.
    #[error("cancelled")]
    Cancelled,
    /// The server rejected the credentials.
    #[error("authentication failed: {0}")]
    Auth(String),
    /// TLS handshake or certificate failure.
    #[error("TLS error: {0}")]
    Tls(String),
    /// Host key rejected (revoked, or the user refused a changed key).
    #[error("host key rejected: {0}")]
    HostKey(String),
    /// HTTP/SOCKS/FTP proxy refused or failed the handshake (T07, T15).
    #[error("proxy error: {0}")]
    Proxy(String),
    /// The remote path does not exist.
    #[error("not found: {0}")]
    NotFound(RemotePath),
    /// The server (or local filesystem) refused access. The message is the server text
    /// or the path.
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    /// The remote path already exists.
    #[error("already exists: {0}")]
    AlreadyExists(RemotePath),
    /// A server reply that is not one of the cases above. `code` = FTP reply code, SFTP
    /// status code.
    #[error("{}", protocol_message(*code, message))]
    Protocol {
        /// FTP reply code or SFTP status code, when there is one.
        code: Option<u16>,
        /// The server text.
        message: String,
    },
    /// The server or backend cannot do this.
    #[error("not supported: {0}")]
    Unsupported(String),
    /// Local I/O.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// The vault is locked and the operation needs a secret or a vault write.
    #[error("the vault is locked")]
    VaultLocked,
    /// Other vault failures (T30 may add structured variants).
    #[error("vault error: {0}")]
    Vault(String),
    /// User input or untrusted data failed validation.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// A bug (state that should be impossible). Logged at error level.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Convenience alias used throughout the workspace.
pub type Result<T, E = Error> = std::result::Result<T, E>;

fn protocol_message(code: Option<u16>, message: &str) -> String {
    match code {
        Some(code) => format!("server error {code}: {message}"),
        None => format!("server error: {message}"),
    }
}

impl Error {
    /// Retry with backoff is worthwhile (T41): `Connection`, `ConnectionLimit`,
    /// `Timeout`, `Protocol` with a code in 400..=499, and `Io` with kind
    /// `ConnectionReset`, `ConnectionAborted`, `BrokenPipe`, `TimedOut`,
    /// `UnexpectedEof` or `Interrupted`. Everything else: false.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Connection(_) | Self::ConnectionLimit(_) | Self::Timeout => true,
            Self::Protocol { code, .. } => matches!(code, Some(400..=499)),
            Self::Io(e) => matches!(
                e.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::Interrupted
            ),
            _ => false,
        }
    }

    /// The session is unusable and must reconnect (T03 session handle): `Connection`,
    /// `Timeout`, and `Io` with kind `ConnectionReset`, `ConnectionAborted`,
    /// `BrokenPipe` or `UnexpectedEof`.
    pub fn is_connection_lost(&self) -> bool {
        match self {
            Self::Connection(_) | Self::Timeout => true,
            Self::Io(e) => matches!(
                e.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
            ),
            _ => false,
        }
    }

    /// Stable short code for logs at info level and above. It never contains host
    /// names, paths or server text (T91 §4).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Connection(_) => "connection",
            Self::ConnectionLimit(_) => "connection-limit",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::Auth(_) => "auth",
            Self::Tls(_) => "tls",
            Self::HostKey(_) => "host-key",
            Self::Proxy(_) => "proxy",
            Self::NotFound(_) => "not-found",
            Self::PermissionDenied(_) => "permission-denied",
            Self::AlreadyExists(_) => "already-exists",
            Self::Protocol { .. } => "protocol",
            Self::Unsupported(_) => "unsupported",
            Self::Io(_) => "io",
            Self::VaultLocked => "vault-locked",
            Self::Vault(_) => "vault",
            Self::InvalidInput(_) => "invalid-input",
            Self::Internal(_) => "internal",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn io(kind: io::ErrorKind) -> Error {
        Error::Io(io::Error::from(kind))
    }

    #[test]
    fn error_classification_table() {
        let p = RemotePath::root();
        // (error, is_transient, is_connection_lost, code)
        let rows: Vec<(Error, bool, bool, &str)> = vec![
            (Error::Connection("x".into()), true, true, "connection"),
            (
                Error::ConnectionLimit("x".into()),
                true,
                false,
                "connection-limit",
            ),
            (Error::Timeout, true, true, "timeout"),
            (Error::Cancelled, false, false, "cancelled"),
            (Error::Auth("x".into()), false, false, "auth"),
            (Error::Tls("x".into()), false, false, "tls"),
            (Error::HostKey("x".into()), false, false, "host-key"),
            (Error::Proxy("x".into()), false, false, "proxy"),
            (Error::NotFound(p.clone()), false, false, "not-found"),
            (
                Error::PermissionDenied("x".into()),
                false,
                false,
                "permission-denied",
            ),
            (Error::AlreadyExists(p), false, false, "already-exists"),
            (
                Error::Protocol {
                    code: Some(450),
                    message: "busy".into(),
                },
                true,
                false,
                "protocol",
            ),
            (
                Error::Protocol {
                    code: Some(499),
                    message: "x".into(),
                },
                true,
                false,
                "protocol",
            ),
            (
                Error::Protocol {
                    code: Some(550),
                    message: "x".into(),
                },
                false,
                false,
                "protocol",
            ),
            (
                Error::Protocol {
                    code: Some(399),
                    message: "x".into(),
                },
                false,
                false,
                "protocol",
            ),
            (
                Error::Protocol {
                    code: None,
                    message: "x".into(),
                },
                false,
                false,
                "protocol",
            ),
            (Error::Unsupported("x".into()), false, false, "unsupported"),
            (io(io::ErrorKind::ConnectionReset), true, true, "io"),
            (io(io::ErrorKind::ConnectionAborted), true, true, "io"),
            (io(io::ErrorKind::BrokenPipe), true, true, "io"),
            (io(io::ErrorKind::UnexpectedEof), true, true, "io"),
            (io(io::ErrorKind::TimedOut), true, false, "io"),
            (io(io::ErrorKind::Interrupted), true, false, "io"),
            (io(io::ErrorKind::NotFound), false, false, "io"),
            (io(io::ErrorKind::PermissionDenied), false, false, "io"),
            (Error::VaultLocked, false, false, "vault-locked"),
            (Error::Vault("x".into()), false, false, "vault"),
            (
                Error::InvalidInput("x".into()),
                false,
                false,
                "invalid-input",
            ),
            (Error::Internal("x".into()), false, false, "internal"),
        ];
        for (err, transient, lost, code) in rows {
            assert_eq!(err.is_transient(), transient, "is_transient {err:?}");
            assert_eq!(err.is_connection_lost(), lost, "is_connection_lost {err:?}");
            assert_eq!(err.code(), code, "code {err:?}");
        }
    }

    #[test]
    fn display_messages() {
        let e = Error::Protocol {
            code: Some(550),
            message: "No such file".into(),
        };
        assert_eq!(e.to_string(), "server error 550: No such file");
        let e = Error::Protocol {
            code: None,
            message: "odd".into(),
        };
        assert_eq!(e.to_string(), "server error: odd");
        assert_eq!(
            Error::NotFound(RemotePath::root()).to_string(),
            "not found: /"
        );
        let e: Error = io::Error::other("disk").into();
        assert_eq!(e.to_string(), "I/O error: disk");
    }
}
