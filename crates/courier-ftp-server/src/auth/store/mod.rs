//! Persistence for accounts, devices, tokens and server settings.
//!
//! [`Store`] has two backends with the same behaviour:
//! * [`Store::Pg`] ([`pg`], production): every multi-row change is one
//!   transaction, row locks serialize refresh-token rotation and the consumption
//!   of setup tokens and invites;
//! * [`Store::Mem`] ([`mem`]): an in-process model of the same tables used by the
//!   fast test suites. Each method takes the one lock for its whole body,
//!   validates first and applies its writes last, so it is all-or-nothing like
//!   the SQL transactions.
//!
//! Time is always passed in (`now`) from the injectable clock.

pub mod mem;
pub mod pg;

use std::sync::Arc;

use sqlx_postgres::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::extractor::AuthCtx;
use super::tokens::{IssuedTokens, TokenHash};
use crate::error::ApiError;

pub use mem::MemDb;

/// Message of a missing, used, expired or foreign reauth token (401).
pub const REAUTH_REQUIRED_MESSAGE: &str = "reauth required";
/// Message when the uploaded account key version is not the current one + 1 (409).
pub const KEY_VERSION_CHANGED_MESSAGE: &str = "account key version changed";
/// Message of a wrong, used or expired recovery code (401).
pub const RECOVERY_CODE_INVALID_MESSAGE: &str = "invalid or expired recovery code";

/// What a registrant presented besides email and password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationCredential<'a> {
    /// Nothing.
    None,
    /// The bootstrap setup token.
    SetupToken(&'a str),
    /// An invite token (instance invite, or an org invite for T89).
    InviteToken(&'a str),
}

/// The outcome of a registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RegisterOutcome {
    /// The setup token was used: the account is the instance admin.
    pub is_instance_admin: bool,
    /// The org invite that was presented (T89 adds the membership).
    pub org_invite: Option<Uuid>,
}

/// A device to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDevice {
    /// New id (UUIDv7).
    pub id: Uuid,
    /// Name.
    pub name: String,
    /// Platform.
    pub platform: String,
}

/// Which device a login is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceChoice {
    /// Create a device.
    New(NewDevice),
    /// Resume this device if it belongs to the user and is not revoked (its old
    /// tokens are deleted, name and platform updated); otherwise create the
    /// fallback.
    Existing(Uuid, NewDevice),
}

/// An `account_keys` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountKeysRow {
    /// X25519 public key.
    pub x25519_pub: Vec<u8>,
    /// Ed25519 public key.
    pub ed25519_pub: Vec<u8>,
    /// Private bundle (under the AKEK).
    pub private_bundle_enc: Vec<u8>,
    /// Recovery bundle (under the recovery key).
    pub recovery_bundle_enc: Option<Vec<u8>>,
    /// Account key version.
    pub version: i32,
}

/// Everything registration creates.
#[derive(Debug, Clone)]
pub struct NewAccount {
    /// User id (proposed by `register/start`).
    pub user_id: Uuid,
    /// Normalized email.
    pub email: String,
    /// OPAQUE record.
    pub opaque_record: Vec<u8>,
    /// Account keys.
    pub keys: AccountKeysRow,
    /// Personal vault id (client-generated).
    pub vault_id: Uuid,
    /// Vault name sealed under the vault key.
    pub vault_name_enc: Vec<u8>,
    /// Self-grant: wrapped vault key.
    pub grant_wrapped: Vec<u8>,
    /// Self-grant: signature.
    pub grant_signature: Vec<u8>,
    /// Vault key version (1).
    pub grant_key_version: i32,
    /// The registering device.
    pub device: NewDevice,
}

/// What login needs to know about an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginUser {
    /// Id.
    pub id: Uuid,
    /// Normalized email.
    pub email: String,
    /// OPAQUE record.
    pub opaque_record: Vec<u8>,
    /// Disabled by an admin.
    pub disabled: bool,
    /// Instance admin.
    pub is_instance_admin: bool,
    /// Sealed TOTP secret when TOTP is enabled.
    pub totp_secret_enc: Option<Vec<u8>>,
}

/// A stored OPAQUE login state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginStateRow {
    /// Handle given to the client.
    pub id: Uuid,
    /// The account; `None` for an unknown email (dummy record).
    pub user_id: Option<Uuid>,
    /// Sealed `ServerLoginState`.
    pub state_enc: Vec<u8>,
    /// Expiry.
    pub expires_at: OffsetDateTime,
}

/// Result of presenting a refresh token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// Rotated: the new pair is stored in the same family.
    Rotated {
        /// The device.
        device_id: Uuid,
    },
    /// The token had already been used: its whole family was deleted and an
    /// audit row written.
    Reused {
        /// The device the family belonged to.
        device_id: Uuid,
        /// The account.
        user_id: Uuid,
        /// The revoked family.
        family: Uuid,
    },
    /// Unknown, expired, or for a revoked device or disabled account.
    Invalid,
}

/// A `devices` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRow {
    /// Id.
    pub id: Uuid,
    /// Name.
    pub name: String,
    /// Platform.
    pub platform: String,
    /// Created.
    pub created_at: OffsetDateTime,
    /// Last token use.
    pub last_seen_at: Option<OffsetDateTime>,
    /// Revoked.
    pub revoked_at: Option<OffsetDateTime>,
}

/// TOTP columns of a user.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TotpState {
    /// Enabled secret (sealed).
    pub secret_enc: Option<Vec<u8>>,
    /// Pending secret awaiting confirmation (sealed).
    pub pending_enc: Option<Vec<u8>>,
}

/// What the recovery flow needs after a valid code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryInfo {
    /// Account.
    pub user_id: Uuid,
    /// Normalized email.
    pub email: String,
    /// Recovery bundle.
    pub recovery_bundle_enc: Option<Vec<u8>>,
    /// Current account key version.
    pub version: i32,
    /// Ed25519 public key (verifies the recovery proof).
    pub ed25519_pub: Vec<u8>,
}

/// The replacement credentials of a password change or recovery.
#[derive(Debug, Clone)]
pub struct NewCredentials {
    /// New OPAQUE record.
    pub opaque_record: Vec<u8>,
    /// Re-sealed private bundle.
    pub private_bundle_enc: Vec<u8>,
    /// Must be the current version + 1.
    pub version: i32,
}

/// An invite to store (T86 `admin invite`, tests).
#[derive(Debug, Clone)]
pub struct NewInvite {
    /// Id.
    pub id: Uuid,
    /// Org of an org invite (`None`: instance invite).
    pub org_id: Option<Uuid>,
    /// Bound email (normalized), if any.
    pub email: Option<String>,
    /// Granted org role (org invites).
    pub role: Option<String>,
    /// SHA-256 of the token ([`crate::registration::hash_token`]).
    pub token_hash: [u8; 32],
    /// Creator.
    pub created_by: Option<Uuid>,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Expiry.
    pub expires_at: OffsetDateTime,
}

/// One storage backend for every table (see the module docs).
#[derive(Debug, Clone)]
pub enum Store {
    /// In-memory model (tests).
    Mem(Arc<MemDb>),
    /// PostgreSQL.
    Pg(PgPool),
}

macro_rules! dispatch {
    ($self:ident, $method:ident ( $($arg:expr),* )) => {
        match $self {
            Store::Mem(m) => m.$method($($arg),*),
            Store::Pg(pool) => pg::$method(pool, $($arg),*).await,
        }
    };
}

impl Store {
    /// A fresh in-memory store (registration mode `invite-only`).
    #[must_use]
    pub fn mem() -> Self {
        Self::Mem(Arc::new(MemDb::new()))
    }

    /// The in-memory tables, when this is the memory backend.
    #[must_use]
    pub fn as_mem(&self) -> Option<&Arc<MemDb>> {
        match self {
            Self::Mem(m) => Some(m),
            Self::Pg(_) => None,
        }
    }

    /// The pool, when this is the PostgreSQL backend.
    #[must_use]
    pub const fn as_pg(&self) -> Option<&PgPool> {
        match self {
            Self::Pg(p) => Some(p),
            Self::Mem(_) => None,
        }
    }

    /// Runs the registration policy (and the email check) without consuming
    /// anything (`register/start`).
    ///
    /// # Errors
    /// `Forbidden` (policy), `Conflict` (email taken).
    pub async fn check_registration(
        &self,
        email: &str,
        cred: RegistrationCredential<'_>,
        now: OffsetDateTime,
    ) -> Result<(), ApiError> {
        dispatch!(self, check_registration(email, cred, now))
    }

    /// Creates the user, account keys, device, personal vault with self-grant and
    /// tokens atomically, consuming the invite or setup token.
    ///
    /// # Errors
    /// `Forbidden` (policy), `Conflict` (email or vault id taken).
    pub async fn register(
        &self,
        acct: &NewAccount,
        cred: RegistrationCredential<'_>,
        tokens: &IssuedTokens,
        family: Uuid,
        now: OffsetDateTime,
    ) -> Result<RegisterOutcome, ApiError> {
        dispatch!(self, register(acct, cred, tokens, family, now))
    }

    /// Looks a user up by normalized email.
    ///
    /// # Errors
    /// Store errors.
    pub async fn user_by_email(&self, email: &str) -> Result<Option<LoginUser>, ApiError> {
        dispatch!(self, user_by_email(email))
    }

    /// Looks a user up by id.
    ///
    /// # Errors
    /// Store errors.
    pub async fn user_by_id(&self, id: Uuid) -> Result<Option<LoginUser>, ApiError> {
        dispatch!(self, user_by_id(id))
    }

    /// Stores a login state and deletes up to 100 expired ones.
    ///
    /// # Errors
    /// Store errors.
    pub async fn put_login_state(
        &self,
        row: &LoginStateRow,
        now: OffsetDateTime,
    ) -> Result<(), ApiError> {
        dispatch!(self, put_login_state(row, now))
    }

    /// Removes a login state and returns it if unexpired (single use).
    ///
    /// # Errors
    /// Store errors.
    pub async fn take_login_state(
        &self,
        id: Uuid,
        now: OffsetDateTime,
    ) -> Result<Option<LoginStateRow>, ApiError> {
        dispatch!(self, take_login_state(id, now))
    }

    /// Atomically accepts TOTP `step` if it is greater than the last accepted one.
    ///
    /// # Errors
    /// Store errors.
    pub async fn consume_totp_step(&self, user: Uuid, step: i64) -> Result<bool, ApiError> {
        dispatch!(self, consume_totp_step(user, step))
    }

    /// Resumes or creates the device and issues a new token family for it.
    /// Returns the device id.
    ///
    /// # Errors
    /// Store errors.
    pub async fn start_session(
        &self,
        user: Uuid,
        choice: &DeviceChoice,
        tokens: &IssuedTokens,
        family: Uuid,
        now: OffsetDateTime,
    ) -> Result<Uuid, ApiError> {
        dispatch!(self, start_session(user, choice, tokens, family, now))
    }

    /// Resolves an access token: unexpired, device not revoked, user not
    /// disabled. Updates `last_seen_at` when older than 5 minutes.
    ///
    /// # Errors
    /// Store errors.
    pub async fn authenticate(
        &self,
        access_hash: &TokenHash,
        now: OffsetDateTime,
    ) -> Result<Option<AuthCtx>, ApiError> {
        dispatch!(self, authenticate(access_hash, now))
    }

    /// Rotates a refresh token, or detects reuse and revokes the family.
    ///
    /// # Errors
    /// Store errors.
    pub async fn refresh(
        &self,
        refresh_hash: &TokenHash,
        issued: &IssuedTokens,
        now: OffsetDateTime,
    ) -> Result<RefreshOutcome, ApiError> {
        dispatch!(self, refresh(refresh_hash, issued, now))
    }

    /// Logout: deletes the device's tokens and revokes it.
    ///
    /// # Errors
    /// Store errors.
    pub async fn logout(&self, device: Uuid, now: OffsetDateTime) -> Result<(), ApiError> {
        dispatch!(self, logout(device, now))
    }

    /// The user's devices, newest `created_at` first.
    ///
    /// # Errors
    /// Store errors.
    pub async fn list_devices(&self, user: Uuid) -> Result<Vec<DeviceRow>, ApiError> {
        dispatch!(self, list_devices(user))
    }

    /// Revokes an unrevoked device of the user (sets `revoked_at`, deletes its
    /// tokens). `false` for an unknown, foreign or already revoked device.
    ///
    /// # Errors
    /// Store errors.
    pub async fn revoke_device(
        &self,
        user: Uuid,
        device: Uuid,
        now: OffsetDateTime,
    ) -> Result<bool, ApiError> {
        dispatch!(self, revoke_device(user, device, now))
    }

    /// Stores a reauth token hash.
    ///
    /// # Errors
    /// Store errors.
    pub async fn insert_reauth(
        &self,
        hash: &TokenHash,
        user: Uuid,
        expires: OffsetDateTime,
    ) -> Result<(), ApiError> {
        dispatch!(self, insert_reauth(hash, user, expires))
    }

    /// Password change in one transaction: consumes the reauth token, checks
    /// `version = current + 1`, replaces the OPAQUE record, bundle and version, and
    /// deletes the tokens of the user's other devices. Returns those devices.
    ///
    /// # Errors
    /// `AuthRequired` (reauth), `Conflict` (version).
    pub async fn change_password(
        &self,
        ctx: AuthCtx,
        reauth: &TokenHash,
        new: &NewCredentials,
        now: OffsetDateTime,
    ) -> Result<Vec<Uuid>, ApiError> {
        dispatch!(self, change_password(ctx, reauth, new, now))
    }

    /// Stores a recovery code for `email` (replacing the previous one). `None`
    /// for an unknown email.
    ///
    /// # Errors
    /// Store errors.
    pub async fn issue_recovery_code(
        &self,
        email: &str,
        code_hash: &[u8; 32],
        expires: OffsetDateTime,
    ) -> Result<Option<Uuid>, ApiError> {
        dispatch!(self, issue_recovery_code(email, code_hash, expires))
    }

    /// Checks a recovery code without consuming it. A wrong code counts an
    /// attempt; the code is deleted after 5 wrong attempts or when expired.
    ///
    /// # Errors
    /// Store errors.
    pub async fn check_recovery_code(
        &self,
        email: &str,
        code_hash: &[u8; 32],
        now: OffsetDateTime,
    ) -> Result<Option<RecoveryInfo>, ApiError> {
        dispatch!(self, check_recovery_code(email, code_hash, now))
    }

    /// Recovery in one transaction: consumes the code, checks the version,
    /// replaces record + bundle + version, deletes all tokens and revokes all
    /// devices. Returns the devices revoked now.
    ///
    /// # Errors
    /// `AuthRequired` (code), `Conflict` (version).
    pub async fn finish_recovery(
        &self,
        user: Uuid,
        code_hash: &[u8; 32],
        new: &NewCredentials,
        now: OffsetDateTime,
    ) -> Result<Vec<Uuid>, ApiError> {
        dispatch!(self, finish_recovery(user, code_hash, new, now))
    }

    /// TOTP columns.
    ///
    /// # Errors
    /// Store errors.
    pub async fn totp_state(&self, user: Uuid) -> Result<TotpState, ApiError> {
        dispatch!(self, totp_state(user))
    }

    /// Stores a sealed pending TOTP secret.
    ///
    /// # Errors
    /// Store errors.
    pub async fn set_totp_pending(&self, user: Uuid, sealed: &[u8]) -> Result<(), ApiError> {
        dispatch!(self, set_totp_pending(user, sealed))
    }

    /// Enables TOTP with `secret_enc` (the confirmed pending secret, re-sealed),
    /// clears the pending secret and records `step` as used. `false` when there is
    /// no pending secret or TOTP is already enabled.
    ///
    /// # Errors
    /// Store errors.
    pub async fn confirm_totp(
        &self,
        user: Uuid,
        secret_enc: &[u8],
        step: i64,
    ) -> Result<bool, ApiError> {
        dispatch!(self, confirm_totp(user, secret_enc, step))
    }

    /// Disables TOTP.
    ///
    /// # Errors
    /// Store errors.
    pub async fn disable_totp(&self, user: Uuid) -> Result<(), ApiError> {
        dispatch!(self, disable_totp(user))
    }

    /// Deletes the account in one transaction (see `DELETE /v1/account`). Returns
    /// the devices that were not revoked yet.
    ///
    /// # Errors
    /// `AuthRequired` (reauth).
    pub async fn delete_account(
        &self,
        user: Uuid,
        reauth: &TokenHash,
        now: OffsetDateTime,
    ) -> Result<Vec<Uuid>, ApiError> {
        dispatch!(self, delete_account(user, reauth, now))
    }

    /// The account keys.
    ///
    /// # Errors
    /// Store errors.
    pub async fn account_keys(&self, user: Uuid) -> Result<Option<AccountKeysRow>, ApiError> {
        dispatch!(self, account_keys(user))
    }

    /// Reads a sealed `server_secrets` value.
    ///
    /// # Errors
    /// Store errors.
    pub async fn get_secret(&self, name: &str) -> Result<Option<Vec<u8>>, ApiError> {
        dispatch!(self, get_secret(name))
    }

    /// Every `server_secrets` row (name order).
    ///
    /// # Errors
    /// Store errors.
    pub async fn all_secrets(&self) -> Result<Vec<(String, Vec<u8>)>, ApiError> {
        dispatch!(self, all_secrets())
    }

    /// Inserts a sealed `server_secrets` value unless the row exists (first writer
    /// wins across replicas).
    ///
    /// # Errors
    /// Store errors.
    pub async fn insert_secret_if_absent(&self, name: &str, value: &[u8]) -> Result<(), ApiError> {
        dispatch!(self, insert_secret_if_absent(name, value))
    }

    /// Reads a `settings` value.
    ///
    /// # Errors
    /// Store errors.
    pub async fn setting(&self, key: &str) -> Result<Option<String>, ApiError> {
        dispatch!(self, setting(key))
    }

    /// Inserts or replaces a `settings` value.
    ///
    /// # Errors
    /// Store errors.
    pub async fn set_setting(
        &self,
        key: &str,
        value: &str,
        now: OffsetDateTime,
    ) -> Result<(), ApiError> {
        dispatch!(self, set_setting(key, value, now))
    }

    /// Number of accounts.
    ///
    /// # Errors
    /// Store errors.
    pub async fn user_count(&self) -> Result<u64, ApiError> {
        dispatch!(self, user_count())
    }

    /// Stores an invite (T86 `admin invite`, T89 org invites).
    ///
    /// # Errors
    /// Store errors.
    pub async fn insert_invite(&self, invite: &NewInvite) -> Result<(), ApiError> {
        dispatch!(self, insert_invite(invite))
    }
}
