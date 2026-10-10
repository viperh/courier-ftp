//! Vault errors, shared by the engine (`courier_ftp_store::vault`), the trust
//! stores and the UI.

use std::time::Duration;

use courier_ftp_crypto::CryptoError;

use super::password::WeakPassword;
use crate::model::item::{ItemId, ItemKind};

/// Everything that can go wrong with the vault. Carries no secrets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VaultError {
    /// No vault yet (`meta.kdf` is missing): run first-run setup.
    #[error("no vault exists yet; set a master password first")]
    NotInitialized,
    /// First-run setup on a database that already has a vault.
    #[error("the vault is already initialized")]
    AlreadyInitialized,
    /// The password did not unwrap the LMK (AEAD failure, deliberately without
    /// detail; a tampered `lmk_wrapped_pw` looks the same).
    #[error("wrong master password")]
    WrongPassword {
        /// Consecutive failures so far (persisted in `meta.unlock_failures`).
        failures: u32,
        /// The delay this failure imposed on the next attempt, if any.
        retry_after: Option<Duration>,
    },
    /// An attempt came before `meta.unlock_next_allowed_at`; Argon2 did not run.
    #[error("too many failed attempts; try again in {}s", retry_after.as_secs().max(1))]
    Backoff {
        /// Remaining delay.
        retry_after: Duration,
    },
    /// The new master password is too weak (zxcvbn score below 3).
    #[error(transparent)]
    WeakPassword(#[from] WeakPassword),
    /// The OS keyring could not provide or store the key (no keyring service,
    /// cancelled prompt, entry missing or not matching this database).
    #[error("keyring: {0}")]
    Keyring(String),
    /// Keyring unlock is not enabled on this device.
    #[error("keyring unlock is not enabled on this device")]
    KeyringNotEnabled,
    /// The operation needs an unlocked vault.
    #[error("the vault is locked")]
    Locked,
    /// The item was written by a newer courier-ftp and must not be modified.
    #[error("item {0} was written by a newer courier-ftp and is read-only")]
    ReadOnlyItem(ItemId),
    /// An existing item has another kind than the write expected.
    #[error("item {id} is a {found}, not a {expected}")]
    WrongKind {
        /// The item.
        id: ItemId,
        /// The kind the caller asked for.
        expected: ItemKind,
        /// The stored kind.
        found: ItemKind,
    },
    /// Another courier-ftp process held the database for too long.
    #[error("the database is busy (another courier-ftp may be writing); try again")]
    Busy,
    /// Stored vault data is damaged or was tampered with.
    #[error("vault data is corrupt: {0}")]
    Corrupt(String),
    /// The database failed.
    #[error("vault storage error: {0}")]
    Storage(String),
}

impl VaultError {
    /// Maps a crypto error from unwrapping or opening stored data. An
    /// authentication failure stays opaque.
    pub fn from_crypto(err: CryptoError, what: &str) -> Self {
        match err {
            CryptoError::Auth => Self::Corrupt(format!("{what} does not decrypt")),
            other => Self::Corrupt(format!("{what}: {other}")),
        }
    }

    /// The remaining backoff delay this error reports, for the unlock screen's
    /// countdown.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::WrongPassword { retry_after, .. } => *retry_after,
            Self::Backoff { retry_after } => Some(*retry_after),
            _ => None,
        }
    }
}

impl From<VaultError> for crate::Error {
    fn from(err: VaultError) -> Self {
        crate::Error::Vault(err.to_string())
    }
}
