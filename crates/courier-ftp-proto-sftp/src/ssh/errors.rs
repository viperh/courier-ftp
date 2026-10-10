//! Error mapping (T20 "Errors" table; adapted from sverb `ssh/errors.rs`, D13): every
//! way an SSH connection fails becomes an [`SshError`] and then a
//! [`courier_ftp_core::Error`] with the user-facing message.
//!
//! Messages may name the host (they are shown in the UI); `tracing` at info level and
//! above never does (T91 §4).

use std::fmt;

use courier_ftp_core::{Error, text::sanitize_server_text};

use super::algorithms::{AlgoKind, is_kex_extension};

/// Server text in error messages is capped at this many characters.
pub const MAX_REASON_CHARS: usize = 512;

/// The SSH disconnect reason code for "too many connections" (RFC 4253 §11.1).
pub const DISCONNECT_TOO_MANY_CONNECTIONS: u32 = 12;

/// Why an SSH connection failed or ended.
#[derive(Debug)]
#[non_exhaustive]
pub enum SshError {
    /// Bad input, found before any network I/O (logon type, user, key source, key file).
    InvalidInput(String),
    /// DNS / TCP / proxy failure from the network layer (T07), passed through.
    Net(Error),
    /// The handshake didn't finish within the timeout.
    HandshakeTimeout,
    /// No reply to an authentication request within the timeout.
    AuthTimeout,
    /// No algorithm in common with the server.
    Negotiation {
        /// The category.
        kind: AlgoKind,
        /// What the server offered.
        theirs: Vec<String>,
    },
    /// The host key was rejected (verifier or user).
    HostKey(String),
    /// Every authentication method failed, the attempt cap was hit, or the server lists
    /// no method we can use.
    Auth {
        /// Methods tried after `none`, in order.
        tried: Vec<&'static str>,
        /// The server's latest method list.
        accepts: Vec<String>,
    },
    /// Three wrong passphrases for the key.
    WrongPassphrase {
        /// The key's label.
        label: String,
        /// Prompts answered.
        attempts: u8,
    },
    /// The user or the token cancelled.
    Cancelled,
    /// No keepalive reply for `interval × 3` seconds.
    KeepaliveTimeout {
        /// The keepalive interval in seconds.
        interval_secs: u64,
    },
    /// The server disconnected with reason 12 (too many connections).
    TooManyConnections(String),
    /// The server disconnected (any other reason).
    RemoteDisconnect(String),
    /// The server closed the connection while a prompt was open (LoginGraceTime).
    ClosedWhilePrompting,
    /// Any other protocol or I/O failure.
    Protocol(String),
}

impl SshError {
    /// The message shown to the user (log `Error:` line and dialog).
    pub fn message(&self) -> String {
        match self {
            Self::InvalidInput(msg) | Self::HostKey(msg) => msg.clone(),
            Self::Net(err) => err.to_string(),
            Self::HandshakeTimeout => "Connection timed out during the SSH handshake".to_owned(),
            Self::AuthTimeout => {
                "Connection timed out waiting for the server's authentication reply".to_owned()
            }
            Self::Negotiation { kind, theirs } => negotiation_message(*kind, theirs),
            Self::Auth { tried, accepts } => auth_message(tried, accepts),
            Self::WrongPassphrase { label, attempts } => {
                format!("Wrong passphrase for key {label} ({attempts} attempts)")
            }
            Self::Cancelled => "Connection cancelled".to_owned(),
            Self::KeepaliveTimeout { interval_secs } => format!(
                "Connection lost (no response for {} s)",
                interval_secs.saturating_mul(3)
            ),
            Self::TooManyConnections(reason) => format!("Too many connections: {reason}"),
            Self::RemoteDisconnect(reason) if reason.is_empty() => {
                "Server closed the connection".to_owned()
            }
            Self::RemoteDisconnect(reason) => format!("Server closed the connection: {reason}"),
            Self::ClosedWhilePrompting => {
                "The server closed the connection while waiting for your answer".to_owned()
            }
            Self::Protocol(msg) => format!("SSH connection failed: {msg}"),
        }
    }

    /// The core error (T20 "Errors" table).
    pub fn into_core(self) -> Error {
        match self {
            Self::Net(err) => err,
            Self::InvalidInput(msg) => Error::InvalidInput(msg),
            Self::HandshakeTimeout | Self::AuthTimeout => Error::Timeout,
            Self::HostKey(msg) => Error::HostKey(msg),
            e @ (Self::Auth { .. } | Self::WrongPassphrase { .. }) => Error::Auth(e.message()),
            Self::Cancelled => Error::Cancelled,
            Self::TooManyConnections(reason) => Error::ConnectionLimit(reason),
            e @ (Self::Negotiation { .. }
            | Self::KeepaliveTimeout { .. }
            | Self::RemoteDisconnect(_)
            | Self::ClosedWhilePrompting
            | Self::Protocol(_)) => Error::Connection(e.message()),
        }
    }
}

impl fmt::Display for SshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for SshError {}

impl From<SshError> for Error {
    fn from(err: SshError) -> Self {
        err.into_core()
    }
}

/// "Permission denied (tried: password, keyboard-interactive; server accepts: publickey)".
pub fn auth_message(tried: &[&str], accepts: &[String]) -> String {
    let tried = if tried.is_empty() {
        "none".to_owned()
    } else {
        tried.join(", ")
    };
    let accepts = if accepts.is_empty() {
        "nothing".to_owned()
    } else {
        accepts.join(", ")
    };
    format!("Permission denied (tried: {tried}; server accepts: {accepts})")
}

/// "No common cipher: server offers aes128-cbc, 3des-cbc." (extension pseudo-algorithms
/// left out; server text sanitized).
pub fn negotiation_message(kind: AlgoKind, theirs: &[String]) -> String {
    let offered: Vec<&str> = theirs
        .iter()
        .map(String::as_str)
        .filter(|n| !(kind == AlgoKind::Kex && is_kex_extension(n)))
        .collect();
    let text = format!(
        "No common {}: server offers {}.",
        kind.noun(),
        offered.join(", ")
    );
    sanitize_server_text(&text, MAX_REASON_CHARS * 2)
}

/// How the transport ended, as seen by the handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndCause {
    /// The server sent `SSH_MSG_DISCONNECT` (reason code, sanitized description).
    Remote {
        /// RFC 4253 reason code.
        code: u32,
        /// The server's description (sanitized).
        message: String,
    },
    /// russh failed (the error's text).
    Error(String),
    /// No keepalive reply.
    KeepaliveTimeout,
}

impl EndCause {
    /// The error for this end of the connection.
    pub fn to_error(&self, keepalive_secs: u64) -> SshError {
        match self {
            Self::Remote { code, message } if *code == DISCONNECT_TOO_MANY_CONNECTIONS => {
                SshError::TooManyConnections(message.clone())
            }
            Self::Remote { message, .. } => SshError::RemoteDisconnect(message.clone()),
            Self::Error(msg) => SshError::Protocol(msg.clone()),
            Self::KeepaliveTimeout => SshError::KeepaliveTimeout {
                interval_secs: keepalive_secs,
            },
        }
    }

    /// The text for [`SshConnection::end_cause`](super::SshConnection::end_cause).
    pub fn describe(&self, keepalive_secs: u64) -> String {
        self.to_error(keepalive_secs).message()
    }
}

/// Map a russh error.
pub fn from_russh(err: &russh::Error, keepalive_secs: u64) -> SshError {
    use russh::Error as E;
    match err {
        E::NoCommonAlgo { kind, theirs, .. } => SshError::Negotiation {
            kind: match kind {
                russh::AlgorithmKind::Kex => AlgoKind::Kex,
                russh::AlgorithmKind::Key => AlgoKind::HostKey,
                russh::AlgorithmKind::Cipher => AlgoKind::Cipher,
                russh::AlgorithmKind::Compression => AlgoKind::Compression,
                russh::AlgorithmKind::Mac => AlgoKind::Mac,
            },
            theirs: theirs.clone(),
        },
        E::UnknownKey | E::KeyChanged { .. } => SshError::HostKey("Host key rejected".to_owned()),
        E::KeepaliveTimeout => SshError::KeepaliveTimeout {
            interval_secs: keepalive_secs,
        },
        E::ConnectionTimeout | E::Elapsed(_) => SshError::HandshakeTimeout,
        E::HUP | E::Disconnect => SshError::RemoteDisconnect(String::new()),
        other => SshError::Protocol(sanitize_server_text(&other.to_string(), MAX_REASON_CHARS)),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn s(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    /// Every row of the T20 Errors table: (error, core code, message).
    #[test]
    fn mapping_table() {
        let rows: Vec<(SshError, &str, &str)> = vec![
            (
                SshError::InvalidInput(
                    "Anonymous and Account logons are not available for SFTP".into(),
                ),
                "invalid-input",
                "Anonymous and Account logons are not available for SFTP",
            ),
            (
                SshError::Net(Error::Proxy("connection refused".into())),
                "proxy",
                "proxy error: connection refused",
            ),
            (
                SshError::HandshakeTimeout,
                "timeout",
                "Connection timed out during the SSH handshake",
            ),
            (
                from_russh(
                    &russh::Error::NoCommonAlgo {
                        kind: russh::AlgorithmKind::Cipher,
                        ours: s(&["aes128-gcm@openssh.com"]),
                        theirs: s(&["aes128-cbc", "3des-cbc"]),
                    },
                    30,
                ),
                "connection",
                "No common cipher: server offers aes128-cbc, 3des-cbc.",
            ),
            (
                SshError::HostKey("Host key rejected by the user".into()),
                "host-key",
                "Host key rejected by the user",
            ),
            (
                SshError::Auth {
                    tried: vec!["password", "keyboard-interactive"],
                    accepts: s(&["publickey"]),
                },
                "auth",
                "Permission denied (tried: password, keyboard-interactive; server accepts: publickey)",
            ),
            (
                SshError::WrongPassphrase {
                    label: "/home/a/.ssh/id".into(),
                    attempts: 3,
                },
                "auth",
                "Wrong passphrase for key /home/a/.ssh/id (3 attempts)",
            ),
            (
                SshError::InvalidInput(
                    "Not a private key format courier-ftp can read (OpenSSH, PEM, PKCS#8, PuTTY)"
                        .into(),
                ),
                "invalid-input",
                "Not a private key format courier-ftp can read (OpenSSH, PEM, PKCS#8, PuTTY)",
            ),
            (SshError::Cancelled, "cancelled", "Connection cancelled"),
            (
                from_russh(&russh::Error::KeepaliveTimeout, 30),
                "connection",
                "Connection lost (no response for 90 s)",
            ),
            (
                EndCause::Remote {
                    code: 12,
                    message: "MaxStartups".into(),
                }
                .to_error(30),
                "connection-limit",
                "Too many connections: MaxStartups",
            ),
            (
                EndCause::Remote {
                    code: 11,
                    message: "bye".into(),
                }
                .to_error(30),
                "connection",
                "Server closed the connection: bye",
            ),
            (
                from_russh(&russh::Error::Inconsistent, 30),
                "connection",
                "SSH connection failed: Inconsistent state of the protocol",
            ),
            (
                SshError::ClosedWhilePrompting,
                "connection",
                "The server closed the connection while waiting for your answer",
            ),
        ];
        for (err, code, msg) in rows {
            assert_eq!(err.message(), msg, "{err:?}");
            let core = err.into_core();
            assert_eq!(core.code(), code, "{msg}");
        }
        // The core messages carry the text.
        let core = SshError::Auth {
            tried: vec!["password"],
            accepts: s(&["publickey"]),
        }
        .into_core();
        assert!(matches!(&core, Error::Auth(m) if m.starts_with("Permission denied")));
        assert!(SshError::HandshakeTimeout.into_core().is_transient());
        assert!(!SshError::Cancelled.into_core().is_transient());
    }

    #[test]
    fn disconnect_reason_12_is_connection_limit() {
        let limit = EndCause::Remote {
            code: DISCONNECT_TOO_MANY_CONNECTIONS,
            message: "too many sessions".into(),
        };
        assert!(matches!(
            limit.to_error(30).into_core(),
            Error::ConnectionLimit(m) if m == "too many sessions"
        ));
        for code in [1, 2, 11, 13, 14] {
            let other = EndCause::Remote {
                code,
                message: "x".into(),
            };
            assert!(matches!(
                other.to_error(30).into_core(),
                Error::Connection(m) if m == "Server closed the connection: x"
            ));
        }
    }

    #[test]
    fn negotiation_drops_extensions_and_sanitizes() {
        let msg = negotiation_message(
            AlgoKind::Kex,
            &s(&[
                "diffie-hellman-group1-sha1",
                "ext-info-s",
                "kex-strict-s-v00@openssh.com",
            ]),
        );
        assert_eq!(
            msg,
            "No common key exchange: server offers diffie-hellman-group1-sha1."
        );
        let msg = negotiation_message(AlgoKind::Mac, &s(&["evil\u{1b}[2Jmac"]));
        assert_eq!(msg, "No common MAC: server offers evilmac.");
    }
}
