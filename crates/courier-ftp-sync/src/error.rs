//! Errors of the HTTP client, the token manager and the sync engine.

use courier_ftp_core::vault::VaultError;
use courier_ftp_proto::ErrorCode;

/// Why a sync request or step failed. Carries no secrets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SyncError {
    /// Sync is not set up on this device (no server URL, no tokens), or the
    /// URL is unusable. There is no default server: the user always enters
    /// their own.
    #[error("sync is not configured: {0}")]
    NotConfigured(&'static str),
    /// The refresh token was rejected (expired, revoked, reused, or the
    /// password was changed on another device): the user must sign in
    /// again. Sync pauses.
    #[error("sign-in required")]
    NeedsLogin,
    /// The server could not be reached (connect, TLS, timeout, broken body).
    #[error("server unreachable: {0}")]
    Transport(String),
    /// The server answered with an error envelope.
    #[error("server error {status} ({}): {message}", code.map_or("unknown", ErrorCode::as_str))]
    Api {
        /// HTTP status.
        status: u16,
        /// The envelope's code, if the body was one.
        code: Option<ErrorCode>,
        /// The envelope's message (never contains secrets).
        message: String,
        /// `Retry-After` / `retry_after_s`, for 429.
        retry_after_s: Option<u64>,
    },
    /// The local database failed.
    #[error("local storage: {0}")]
    Store(String),
    /// Local key material is unusable, or the vault is locked.
    #[error("local keys: {0}")]
    Crypto(String),
}

impl SyncError {
    /// Transient: the device is offline or the server is temporarily failing
    /// (transport errors, 5xx, 429). Retried with backoff; status `offline`.
    #[must_use]
    pub fn is_offline(&self) -> bool {
        match self {
            Self::Transport(_) => true,
            Self::Api { status, .. } => *status >= 500 || *status == 429,
            _ => false,
        }
    }

    /// The envelope code of an API error.
    #[must_use]
    pub const fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Api { code, .. } => *code,
            _ => None,
        }
    }

    /// An API error with this HTTP status.
    #[must_use]
    pub const fn is_status(&self, status: u16) -> bool {
        matches!(self, Self::Api { status: s, .. } if *s == status)
    }

    /// The envelope message of an API error.
    #[must_use]
    pub fn api_message(&self) -> Option<&str> {
        match self {
            Self::Api { message, .. } => Some(message),
            _ => None,
        }
    }
}

impl From<courier_ftp_store::StoreError> for SyncError {
    fn from(e: courier_ftp_store::StoreError) -> Self {
        Self::Store(e.to_string())
    }
}

impl From<VaultError> for SyncError {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::Storage(m) => Self::Store(m),
            VaultError::Busy => Self::Store(e.to_string()),
            other => Self::Crypto(other.to_string()),
        }
    }
}
