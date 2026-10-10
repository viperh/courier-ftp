//! Questions the core asks the user, and their answers.

use std::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};

use secrecy::SecretString;
use tokio::sync::oneshot;

use super::SessionId;
use crate::{
    model::{CertificateDetails, Direction, Entry, HostKeyFingerprint, LocalPath, RemotePath},
    settings::ExistsAction,
};

/// Identifies one prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PromptId(pub u64);

impl PromptId {
    /// A new id, unique within this process.
    pub fn next() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

/// A question the core waits on. The UI shows it and answers through `reply`.
///
/// Dropping the request without answering counts as "cancel": the waiting
/// operation fails with [`Error::Cancelled`](crate::Error::Cancelled).
#[derive(Debug)]
pub struct PromptRequest {
    /// The prompt's id.
    pub id: PromptId,
    /// The connection asking, if any.
    pub session: Option<SessionId>,
    /// What is being asked.
    pub kind: PromptKind,
    /// Where the answer goes.
    pub reply: oneshot::Sender<PromptResponse>,
}

/// What a prompt asks.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PromptKind {
    /// An SSH host key is not trusted yet (T21), or differs from the trusted
    /// one. Answered with [`PromptResponse::Trust`].
    TrustHostKey {
        /// `host:port`.
        host: String,
        /// The key the server offered.
        key: HostKeyFingerprint,
        /// The key trusted before, when the server now offers a different
        /// one (a possible man-in-the-middle attack). The UI then shows a
        /// warning and makes *Cancel* the default.
        known: Option<HostKeyFingerprint>,
        /// Whether the answer can be remembered. `false` while the vault is
        /// locked: the UI then never answers [`TrustDecision::Always`].
        can_remember: bool,
    },
    /// A TLS certificate is not trusted (T12), or differs from the trusted
    /// one. Answered with [`PromptResponse::Trust`].
    TrustCertificate {
        /// The chain, the TLS session and why verification failed.
        details: Box<CertificateDetails>,
        /// SHA-256 fingerprint of the certificate trusted before for this
        /// host, when it changed. The UI then shows a warning.
        known_sha256: Option<String>,
        /// Whether the answer can be remembered (`false` while the vault is
        /// locked).
        can_remember: bool,
    },
    /// A password is needed (logon type "ask for password").
    Password {
        /// What it is for, e.g. `bob@example.com`.
        for_: String,
    },
    /// A private key is encrypted.
    KeyPassphrase {
        /// The key file.
        path: LocalPath,
    },
    /// SSH keyboard-interactive authentication.
    KeyboardInteractive {
        /// The server's name for the request.
        name: String,
        /// The server's instructions.
        instructions: String,
        /// Each prompt and whether the answer may be echoed.
        prompts: Vec<(String, bool)>,
    },
    /// A transfer target already exists (T42).
    FileExists {
        /// Download or upload.
        direction: Direction,
        /// The source entry.
        source: Box<Entry>,
        /// The existing target entry.
        target: Box<Entry>,
        /// The local side of the transfer.
        local: LocalPath,
        /// The remote side of the transfer.
        remote: RemotePath,
    },
    /// Something to acknowledge.
    Message(String),
}

/// The answer to a [`PromptKind`].
#[non_exhaustive]
pub enum PromptResponse {
    /// For [`PromptKind::TrustHostKey`] and [`PromptKind::TrustCertificate`].
    Trust(TrustDecision),
    /// For [`PromptKind::Password`] and [`PromptKind::KeyPassphrase`].
    Secret(SecretString),
    /// For [`PromptKind::KeyboardInteractive`], one answer per prompt.
    Answers(Vec<SecretString>),
    /// For [`PromptKind::FileExists`].
    FileExists(FileExistsAnswer),
    /// For [`PromptKind::Message`].
    Ok,
}

impl fmt::Debug for PromptResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PromptResponse::Trust(d) => f.debug_tuple("Trust").field(d).finish(),
            PromptResponse::Secret(_) => f.write_str("Secret(****)"),
            PromptResponse::Answers(a) => write!(f, "Answers([{} × ****])", a.len()),
            PromptResponse::FileExists(a) => f.debug_tuple("FileExists").field(a).finish(),
            PromptResponse::Ok => f.write_str("Ok"),
        }
    }
}

/// Whether to trust a host key or certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrustDecision {
    /// Trust for this connection only.
    Once,
    /// Trust and remember (stored in the vault, T21/T69).
    Always,
    /// Don't connect.
    Reject,
}

/// The answer to a [`PromptKind::FileExists`] prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileExistsAnswer {
    /// What to do. `Ask` is not a valid answer and is treated as `Skip`.
    pub action: ExistsAction,
    /// How widely the answer applies.
    pub apply_to: ApplyTo,
    /// The new target name for [`ExistsAction::Rename`].
    pub new_name: Option<String>,
}

/// How widely a [`FileExistsAnswer`] applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApplyTo {
    /// This file only.
    Once,
    /// Every file in the queue.
    AllInQueue,
    /// Every file in the queue going the same direction.
    AllForDirection,
}
