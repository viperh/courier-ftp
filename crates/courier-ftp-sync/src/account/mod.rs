//! Connecting a local vault to a sync account and managing it (T87).
//!
//! | Flow | Entry points |
//! |---|---|
//! | Local-only → new account | [`prepare_registration`], [`PreparedRegistration::confirm_words`], [`finish_registration`] |
//! | Log in (new device, device with local data, re-login after a password change elsewhere) | [`start_login`], [`LoginSession::commit`] |
//! | Duplicate preview and id-remapping import | [`ImportPreview`], [`DuplicateChoice`] |
//! | Online password change | [`SyncSession::change_password`](crate::SyncSession::change_password) |
//! | Forgotten password with the 24-word recovery key | [`request_recovery_code`], [`recover_account`], [`recover_locked_device`] |
//! | Devices | [`SyncSession::list_devices`](crate::SyncSession::list_devices), [`SyncSession::revoke_device`](crate::SyncSession::revoke_device) |
//! | Log out / disable sync (`--keep-local`) | [`SyncSession::logout`](crate::SyncSession::logout), [`logout_local`] |
//! | TOTP, delete account | [`SyncSession`](crate::SyncSession) |
//!
//! # One password, two derivations (D3)
//! The account password is the local master password:
//! * locally `Argon2id(local salt) → KEK → LMK` (T30, unchanged);
//! * on the server `OPAQUE → export_key → AKEK = HKDF(export_key,
//!   "courier-ftp/akek/v1")`, which opens the account key bundle.
//!
//! Registration uses the **current** master password (verified against the
//! LMK wrap). Logging in with a password that differs from the local one
//! re-wraps the LMK under it, after the UI showed
//! [`PASSWORD_ADOPT_WARNING`].
//!
//! # Local state
//! * `sync_state`: server URL, server-assigned device id, the tokens (sealed
//!   under the LMK by the vault engine);
//! * `meta.account`: `{user_id, email, key_version}` (JSON, not secret; makes
//!   `VaultStatus::sync_account` true so a locked device can offer recovery);
//! * `meta.account_keys_enc`: the account X25519/Ed25519 keys sealed like a
//!   private bundle under `HKDF(LMK, "courier-ftp/local-account-keys/v1")`.
//!
//! # Password changed on another device
//! Local unlock keeps working with the old password (the LMK wrap is
//! unchanged and unlock never contacts the server). The server revoked this
//! device's tokens, so the next request fails with
//! [`SyncError::NeedsLogin`] (and `account_changed` arrives over WebSocket);
//! sync pauses until the user logs in again with the new password
//! ([`start_login`]), which re-wraps the LMK.
//!
//! Adapted from sverb's `sverb-sync/src/account` (D13), without teams.

use std::sync::Arc;
use std::time::Duration;

use courier_ftp_core::vault::check_strength;
use courier_ftp_crypto::opaque::CourierKsf;
use courier_ftp_proto::ErrorCode;
use courier_ftp_proto::auth::{DeviceInfo, TOTP_REQUIRED_HINT};

use crate::error::SyncError;
use crate::http::{ApiClient, HTTP_TIMEOUT};

mod confirm;
mod local;
mod login;
mod logout;
pub mod merge_local;
mod opaque_flow;
mod recovery;
mod register;

pub use confirm::{CONFIRM_WORDS, RecoveryConfirm};
pub use local::{LocalAccount, load_account};
pub(crate) use local::{load_account_keys, seal_local_keys, write_account};
pub use login::{LoggedIn, LoginRequest, LoginSession, start_login};
pub use logout::{LogoutReport, logout_local};
pub use merge_local::{DuplicateChoice, DuplicateRow, ImportPreview};
pub(crate) use opaque_flow::{finish_registration_record as finish_record, opaque_login};
pub use recovery::{
    Recovered, recover_account, recover_device, recover_locked_device, request_recovery_code,
};
pub use register::{
    PERSONAL_VAULT_NAME, PreparedRegistration, Registered, RegistrationToken, finish_registration,
    prepare_registration,
};

/// The warning shown before a login re-wraps the LMK.
pub const PASSWORD_ADOPT_WARNING: &str =
    "Your local master password will be changed to your account password";

/// Shown at signup next to the recovery phrase (required).
pub const RECOVERY_WARNING: &str = "Write these 24 words down. They are shown only once. \
     Without this recovery key and without any logged-in device, your data is unrecoverable.";

/// Shown when a password change is tried offline.
pub const NEEDS_SERVER: &str =
    "changing the password of a synced account needs the server; connect and try again";

/// Settings shared by every flow.
#[derive(Debug, Clone)]
pub struct AccountConfig {
    /// The OPAQUE key-stretching function (production: `CourierKsf::default()`;
    /// test suites use the cheap test variant on both sides).
    pub ksf: Arc<CourierKsf>,
    /// This device, as registered on the server.
    pub device: DeviceInfo,
    /// TLS for HTTP and WebSocket (`None`: `ring` + the OS trust store).
    pub tls: Option<Arc<rustls::ClientConfig>>,
    /// HTTP request timeout (30 s).
    pub http_timeout: Duration,
}

impl AccountConfig {
    /// Production settings for a device called `device_name` (defaults to
    /// the host name in the UI).
    #[must_use]
    pub fn new(device_name: impl Into<String>) -> Self {
        Self {
            ksf: Arc::new(CourierKsf::default()),
            device: DeviceInfo {
                name: device_name.into(),
                platform: std::env::consts::OS.to_owned(),
            },
            tls: None,
            http_timeout: HTTP_TIMEOUT,
        }
    }

    pub(crate) fn client(&self, server_url: &str) -> Result<ApiClient, AccountError> {
        Ok(ApiClient::new(
            server_url,
            self.tls.clone(),
            self.http_timeout,
        )?)
    }
}

/// Why an account flow failed. Carries no secrets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AccountError {
    /// The server can't be reached (the flow needs it online).
    #[error("the server is unreachable: {0}")]
    Unreachable(String),
    /// The server speaks a protocol version this client does not support, or
    /// is not a courier-ftp server.
    #[error("incompatible server: {0}")]
    IncompatibleServer(String),
    /// The local master password is wrong.
    #[error("wrong master password")]
    WrongLocalPassword,
    /// OPAQUE failed: wrong email or password (the server can't tell which).
    #[error("invalid email or password")]
    LoginFailed,
    /// The account has TOTP enabled; ask for the code and retry.
    #[error("this account requires a TOTP code")]
    TotpRequired,
    /// The TOTP code was wrong or already used.
    #[error("invalid or already used TOTP code")]
    TotpInvalid,
    /// Registration on this server needs an invite or the setup token.
    #[error("registration requires an invite or setup token: {0}")]
    InviteRequired(String),
    /// An account with this email (or vault id) already exists.
    #[error("an account with this email already exists")]
    AlreadyRegistered,
    /// The new password is too weak (zxcvbn score below 3).
    #[error("{0}")]
    WeakPassword(String),
    /// The recovery words were not re-typed correctly yet.
    #[error("confirm the recovery words first")]
    RecoveryNotConfirmed,
    /// The recovery phrase does not parse, or does not open the bundle.
    #[error("invalid recovery phrase: {0}")]
    BadRecoveryPhrase(String),
    /// The recovery code is wrong or expired.
    #[error("invalid or expired recovery code")]
    BadRecoveryCode,
    /// This device is not signed in to a server.
    #[error("not signed in to a sync server")]
    NotSignedIn,
    /// The session's tokens were rejected: log in again.
    #[error("sign-in required")]
    NeedsLogin,
    /// The local data is not in the expected state (locked vault, already
    /// signed in, …).
    #[error("local vault: {0}")]
    Local(String),
    /// A grant or bundle does not verify / decrypt.
    #[error("account keys: {0}")]
    Crypto(String),
    /// Any other server or client error.
    #[error(transparent)]
    Sync(SyncError),
}

impl From<SyncError> for AccountError {
    fn from(e: SyncError) -> Self {
        match e {
            SyncError::Transport(m) => Self::Unreachable(m),
            SyncError::NeedsLogin => Self::NeedsLogin,
            SyncError::Crypto(m) => Self::Crypto(m),
            SyncError::Store(m) => Self::Local(m),
            SyncError::NotConfigured(m) => Self::Local(m.to_owned()),
            other @ SyncError::Api { .. } => Self::Sync(other),
        }
    }
}

impl From<courier_ftp_store::StoreError> for AccountError {
    fn from(e: courier_ftp_store::StoreError) -> Self {
        Self::Local(e.to_string())
    }
}

impl From<courier_ftp_crypto::CryptoError> for AccountError {
    fn from(e: courier_ftp_crypto::CryptoError) -> Self {
        Self::Crypto(e.to_string())
    }
}

impl From<courier_ftp_core::vault::VaultError> for AccountError {
    fn from(e: courier_ftp_core::vault::VaultError) -> Self {
        use courier_ftp_core::vault::VaultError as V;
        match e {
            V::WeakPassword(w) => Self::WeakPassword(w.to_string()),
            V::WrongPassword { .. } => Self::WrongLocalPassword,
            other => Self::Local(other.to_string()),
        }
    }
}

impl AccountError {
    /// Whether retrying later might help (server down or rate limited).
    #[must_use]
    pub fn is_offline(&self) -> bool {
        match self {
            Self::Unreachable(_) => true,
            Self::Sync(e) => e.is_offline(),
            _ => false,
        }
    }
}

/// zxcvbn ≥ 3 for a password that will protect the account.
pub(crate) fn require_strong(password: &str) -> Result<(), AccountError> {
    check_strength(password, &["courier-ftp", "courier"])
        .map(drop)
        .map_err(|w| AccountError::WeakPassword(w.to_string()))
}

/// Maps a `401 auth_required` from the login endpoints.
pub(crate) fn login_error(e: SyncError) -> AccountError {
    match &e {
        SyncError::Api {
            status: 401,
            message,
            ..
        } if message.starts_with(TOTP_REQUIRED_HINT) => AccountError::TotpRequired,
        SyncError::Api {
            status: 401,
            message,
            ..
        } if message.starts_with("totp_invalid") => AccountError::TotpInvalid,
        SyncError::Api {
            code: Some(ErrorCode::AuthRequired),
            ..
        }
        | SyncError::Api { status: 401, .. } => AccountError::LoginFailed,
        _ => e.into(),
    }
}

/// Checks the server is up and speaks a supported protocol version
/// (`GET /healthz`, `Courier-Proto` response header).
///
/// # Errors
/// [`AccountError::Unreachable`], [`AccountError::IncompatibleServer`],
/// [`AccountError::Local`] for a URL that is not `https://` (loopback
/// `http://` is allowed for development).
pub async fn probe_server(
    server_url: &str,
    cfg: &AccountConfig,
) -> Result<ApiClient, AccountError> {
    let api = cfg.client(server_url)?;
    match api.probe().await {
        Ok(Some(v)) if !courier_ftp_proto::version::is_supported(v) => Err(
            AccountError::IncompatibleServer(format!("server protocol version {v}")),
        ),
        Ok(_) => Ok(api),
        Err(SyncError::Api { status, .. }) => Err(AccountError::IncompatibleServer(format!(
            "this does not look like a courier-ftp server (HTTP {status} on /healthz)"
        ))),
        Err(e) => Err(e.into()),
    }
}

/// A valid-looking email address (trimmed).
pub(crate) fn check_email(email: &str) -> Result<String, AccountError> {
    let email = email.trim();
    if email.is_empty() || !email.contains('@') || email.chars().any(char::is_whitespace) {
        return Err(AccountError::Local("enter a valid email address".into()));
    }
    Ok(email.to_owned())
}
