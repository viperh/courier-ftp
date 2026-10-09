//! The event and message-log bus between the core, the protocol crates and the user
//! interface (T04).
//!
//! Backends, the transfer engine, the vault and the sync engine report through an
//! [`EventSender`]; the binary's main loop (T50) owns the single [`EventReceiver`].
//! The bus carries:
//!
//! - message-log lines ([`LogMessage`]), filtered by the debug level, sanitised and
//!   masked ([`mask_command`]);
//! - connection, queue and operation events ([`CoreEvent`]);
//! - transfer progress, coalesced to one pending value per transfer;
//! - prompts ([`PromptRequest`]): request/response pairs that cancel cleanly.
//!
//! The core never depends on the UI: everything here is plain data and channels.

mod channel;
mod ids;
mod log;
mod mask;
mod prompt;

use std::time::Duration;

pub use channel::{EventReceiver, EventSender, LogLevelHandle, SessionLog, channel};
pub use ids::{OperationId, PromptId, SessionId, TransferId};
pub use log::{LogKind, LogMessage, MAX_LINE_CHARS};
pub use mask::{mask_command, mask_secret};
pub use prompt::{
    ApplyTo, CertProblem, CertPromptDetails, CertificateDetails, DataProtection, FileExistsPrompt,
    HostKeyAnswer, HostKeyInfo, HostKeyPrompt, KbdField, KbdInteractivePrompt, MessagePrompt,
    OldKey, OldKeySource, PassphrasePrompt, PasswordPrompt, PasswordPurpose, PreviousCert,
    PromptKind, PromptRequest, PromptResponse, SecretCacheKey, TlsSessionInfo, TrustAnswer,
    TrustSource,
};

use crate::model::{RemotePath, ServerAddress, ServerIdentity};

/// Everything the core reports to the UI.
#[derive(Debug)]
#[non_exhaustive]
pub enum CoreEvent {
    /// A message-log line.
    Log(LogMessage),
    /// A session was created (T03); `label` = site name or `"user@host"` for the UI.
    SessionOpened {
        /// The new session.
        session: SessionId,
        /// What it is used for.
        purpose: SessionPurpose,
        /// Display label.
        label: String,
    },
    /// A session ended.
    SessionClosed {
        /// The session.
        session: SessionId,
    },
    /// The session started connecting.
    Connecting {
        /// The session.
        session: SessionId,
    },
    /// The session is connected and logged in.
    Connected {
        /// The session.
        session: SessionId,
        /// Where it is connected.
        address: ServerAddress,
    },
    /// The session's connection ended.
    Disconnected {
        /// The session.
        session: SessionId,
        /// Why.
        reason: DisconnectReason,
    },
    /// Backend capabilities changed (e.g. `SITE CHMOD` rejected, T14) — UI re-reads them.
    CapabilitiesChanged {
        /// The session.
        session: SessionId,
    },
    /// A cached listing changed (T46). `server` None = local filesystem.
    ListingUpdated {
        /// The server, or None for the local filesystem.
        server: Option<ServerIdentity>,
        /// The directory.
        dir: RemotePath,
    },
    /// Coalesced: at most one pending per [`TransferId`].
    TransferProgress(TransferProgress),
    /// Queue item state changed; the UI reads the new state from the queue (T40).
    TransferStateChanged {
        /// The queue item.
        id: TransferId,
    },
    /// Items added/removed/reordered (T40).
    QueueChanged,
    /// The queue ran and is now empty of queued and active items (T41/T45).
    QueueFinished {
        /// Totals of the run.
        stats: QueueStats,
    },
    /// Progress of a long-running non-transfer operation.
    OperationProgress {
        /// The operation.
        id: OperationId,
        /// What is being done.
        text: String,
        /// Units done.
        done: u64,
        /// Total units, when known.
        total: Option<u64>,
    },
    /// A long-running operation ended.
    OperationFinished {
        /// The operation.
        id: OperationId,
        /// Error Display text, if it failed.
        error: Option<String>,
    },
    /// Transient user-facing notice (toast / status-bar message): connection limit
    /// lowered, sync clock skew, resurrected item (T41, T88).
    Notice {
        /// Severity.
        level: NoticeLevel,
        /// Text.
        text: String,
    },
    /// A question to the user.
    Prompt(PromptRequest),
    /// The secret given for prompt `prompt_id` was accepted by the server (T20, T10):
    /// the UI may now cache/save what the user typed (T69). Carries no secret.
    CredentialAccepted {
        /// The session.
        session: SessionId,
        /// The secret prompt that was answered.
        prompt_id: PromptId,
    },
    // T88 adds `Sync(SyncStatus)`; the enum is non_exhaustive for that reason.
}

/// What a session is used for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionPurpose {
    /// A tab's browsing session.
    Browse,
    /// A transfer worker.
    Transfer,
    /// A remote search.
    Search,
    /// Anything else.
    Other,
}

/// Why a session's connection ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisconnectReason {
    /// `disconnect()` was called (user, tab closed, queue finished with Disconnect).
    Requested,
    /// The connection dropped; message = Error Display text.
    Lost(String),
    /// Connecting failed (after retries).
    Failed(String),
}

/// Progress of one transfer.
#[derive(Clone, Debug, PartialEq)]
pub struct TransferProgress {
    /// The queue item.
    pub id: TransferId,
    /// Bytes transferred so far.
    pub bytes_done: u64,
    /// File size, when known.
    pub total: Option<u64>,
    /// Exponential moving average (T41), bytes per second.
    pub speed_bps: u64,
    /// Estimated time remaining.
    pub eta: Option<Duration>,
}

/// Totals of one queue run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueueStats {
    /// Files transferred successfully.
    pub files_ok: u64,
    /// Files that failed.
    pub files_failed: u64,
    /// Bytes transferred.
    pub bytes: u64,
    /// Wall-clock duration.
    pub duration: Duration,
}

/// Severity of a notice or message prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoticeLevel {
    /// Informational.
    Info,
    /// Something the user should know.
    Warning,
    /// Something failed.
    Error,
}

#[cfg(test)]
mod tests;
