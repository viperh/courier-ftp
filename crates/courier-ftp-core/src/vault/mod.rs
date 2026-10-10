//! The encrypted vault: master password unlock, optional keyring unlock, the item
//! cache and every vault write (T30; sverb `vault/` and `services/vault/`, D13).
//!
//! Everything sensitive (sites with their passwords, SSH keys, bookmarks, trusted host
//! keys and certificates, proxy credentials, history, the persisted queue) lives in one
//! SQLite file ([`courier_ftp_store::Store`]) as individually encrypted items.
//!
//! # Key hierarchy
//!
//! ```text
//! master password ──Argon2id(meta.kdf)──▶ KEK ──wrap(Lmk)──▶ meta.lmk_wrapped_pw
//! OS keyring (optional): random KEK_kr ──wrap(Lmk)──▶ meta.lmk_wrapped_keyring
//! LMK ──wrap(VaultKey(id))──▶ vaults.wrapped_key   (personal + each team vault)
//! LMK ──wrap(DeviceKey)──▶ meta.device_key_wrapped (device blobs)
//! VK ──HKDF(item id)──▶ per-item key (courier_ftp_crypto::envelope)
//! ```
//!
//! A wrong password is detected by the AEAD failing to unwrap the LMK; no verifier is
//! stored. The engine never contacts a server: unlocking works offline in every mode.
//!
//! - [`VaultEngine`] owns the keys (in [`Locked`](crate::hardening::Locked) pages),
//!   the state machine, the item cache and every write.
//! - [`kdf`], [`unlock`], [`password`], [`keyring`] and [`lock`] are pure helpers.
//! - [`backup`] is the encrypted backup container (T73, T32).
//!
//! Logs from this module carry counts, short ids and kinds only: never hostnames,
//! usernames, labels or values.

pub mod backup;
mod blobs;
mod cache;
mod engine;
mod items;
pub mod kdf;
pub mod keyring;
pub mod lock;
pub mod password;
pub mod policy;
mod trust;
pub mod unlock;

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub use blobs::DeviceBlobStore;
pub use courier_ftp_store::{ItemRow, VaultKind};
pub use engine::{VaultCrypto, VaultEngine};
pub use kdf::{Argon2Cost, KDF_ALG, KdfParams};
pub use keyring::{
    KEYRING_SERVICE, KeyringError, KeyringStore, MemKeyring, NoKeyring, keyring_account,
};
pub use lock::{AutoLock, LockReason, SuspendDetector};
pub use password::{
    MIN_SCORE, NO_RECOVERY_WARNING, PasswordStrength, USER_INPUTS, WeakPassword, check_strength,
    estimate,
};
pub use trust::VaultHostKeyStore;
pub use unlock::{BackoffState, FREE_ATTEMPTS, MAX_DELAY, backoff_delay};

use crate::model::LocalPath;
use crate::model::item::{
    ItemBody, ItemId, ItemKind, PhysicalClock, SystemClock, UnixMillis, VaultId,
};
use crate::settings::Settings;

/// Largest encoded item body (1 MiB).
pub const MAX_BODY_LEN: usize = 1_048_576;
/// Most items one `put_many` / `delete_many` call may touch.
pub const MAX_BATCH: usize = 10_000;
/// Device blob names in use.
pub mod blob_names {
    /// The persisted transfer queue (T40).
    pub const TRANSFER_QUEUE: &str = "transfer-queue";
    /// Open tabs (T61).
    pub const TABS: &str = "tabs";
}

/// Where the vault is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    /// No `meta.kdf` yet: the first-run screen (known after [`VaultEngine::status`]).
    Uninitialised,
    /// No keys in memory.
    Locked,
    /// An unlock (Argon2 or keyring) is running.
    Unlocking,
    /// Keys are in memory.
    Unlocked {
        /// How it was unlocked.
        method: UnlockMethod,
    },
}

/// How the vault was unlocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockMethod {
    /// Master password.
    Password,
    /// OS keyring.
    Keyring,
    /// First run created the vault.
    Created,
}

impl UnlockMethod {
    /// A stable lowercase name for logs.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Keyring => "keyring",
            Self::Created => "created",
        }
    }
}

/// What the unlock screen needs to know (no secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultStatus {
    /// Current state.
    pub state: VaultState,
    /// `meta.lmk_wrapped_keyring` exists.
    pub keyring_enabled: bool,
    /// The persisted backoff.
    pub backoff: BackoffState,
    /// Remaining wait before the next password attempt, if any.
    pub retry_after: Option<Duration>,
    /// Items that did not decrypt or decode (unlocked only).
    pub unreadable_items: usize,
    /// Items of a kind written by a newer courier-ftp (unlocked only).
    pub unknown_kind_items: usize,
}

/// Engine options (from `Settings.vault` and `Settings.sync`).
#[derive(Clone)]
pub struct VaultOptions {
    /// Argon2id cost for new wraps (first run, password change, cost upgrade).
    pub cost: Argon2Cost,
    /// `vault.store_passwords`.
    pub store_passwords: bool,
    /// `sync.history` (T88).
    pub sync_history: bool,
    /// The HLC's physical clock (`SystemClock` in production).
    pub physical_clock: Arc<dyn PhysicalClock>,
}

impl fmt::Debug for VaultOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultOptions")
            .field("cost", &self.cost)
            .field("store_passwords", &self.store_passwords)
            .field("sync_history", &self.sync_history)
            .finish_non_exhaustive()
    }
}

impl Default for VaultOptions {
    fn default() -> Self {
        Self {
            cost: Argon2Cost::STANDARD,
            store_passwords: true,
            sync_history: false,
            physical_clock: Arc::new(SystemClock),
        }
    }
}

impl VaultOptions {
    /// Options from the settings, with the system clock.
    pub fn from_settings(settings: &Settings) -> Self {
        Self {
            cost: Argon2Cost::from_preset(settings.vault.argon2_cost),
            store_passwords: settings.vault.store_passwords,
            sync_history: settings.sync.history,
            physical_clock: Arc::new(SystemClock),
        }
    }
}

/// Broadcast by [`VaultEngine::subscribe`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultChange {
    /// The vault was unlocked (or created).
    Unlocked(UnlockMethod),
    /// The vault was locked.
    Locked(LockReason),
    /// Items were written here or by another process / device.
    ItemsChanged {
        /// The items (sorted).
        ids: Vec<ItemId>,
        /// Their kinds (unknown kinds are not listed).
        kinds: BTreeSet<ItemKind>,
    },
}

/// A typed item read from the vault.
#[derive(Debug)]
pub struct Loaded<V> {
    /// The item.
    pub id: ItemId,
    /// Its vault.
    pub vault: VaultId,
    /// The typed view.
    pub view: V,
    /// Written by a newer courier-ftp: show, do not edit.
    pub read_only: bool,
    /// Whether secret fields hold their values (`get`) or only `Kept` (`list`).
    pub secrets_loaded: bool,
    /// Unix ms of the last local write of the row.
    pub updated_at: i64,
}

/// Result of [`VaultEngine::put`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PutOutcome {
    /// Whether anything was written.
    pub changed: bool,
}

/// A raw body with stamps and secrets.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadedBody {
    /// The item.
    pub id: ItemId,
    /// Its vault.
    pub vault: VaultId,
    /// The decrypted, migrated body.
    pub body: ItemBody,
    /// Written by a newer courier-ftp.
    pub read_only: bool,
    /// Server revision (0 = never synced).
    pub revision: i64,
}

/// What this device may do in a vault (T89).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VaultPermission {
    /// Pull only.
    Read,
    /// Pull and push.
    Write,
    /// Push, grant, revoke, rotate (the personal vault).
    Manage,
}

impl VaultPermission {
    /// Parses the `meta.vault_permission/<id>` value (`read|write|manage`).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "manage" => Some(Self::Manage),
            _ => None,
        }
    }
}

/// One vault whose key is loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultInfo {
    /// The vault.
    pub id: VaultId,
    /// Personal or shared.
    pub kind: VaultKind,
    /// This device's permission.
    pub permission: VaultPermission,
}

/// One write of [`VaultEngine::put_many`].
#[derive(Debug, Clone, PartialEq)]
pub struct BodyWrite {
    /// The vault the item lives in.
    pub vault: VaultId,
    /// The item.
    pub id: ItemId,
    /// What to write.
    pub body: BodyEdit,
}

/// How a [`BodyWrite`] combines with the stored body.
#[derive(Debug, Clone, PartialEq)]
pub enum BodyEdit {
    /// Field-level merge with the stored body (T81 `merge`).
    Merge(ItemBody),
    /// Replace the stored body.
    Replace(ItemBody),
}

/// What first run reports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InitReport {
    /// Keyring unlock was requested but could not be enabled (the vault was created
    /// without it); the reason.
    pub keyring_error: Option<String>,
}

/// What an unlock reports (no secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockReport {
    /// How it was unlocked.
    pub method: UnlockMethod,
    /// Items decrypted.
    pub items: usize,
    /// Items that did not decrypt or decode.
    pub unreadable_items: usize,
    /// Items of a kind this build does not know.
    pub unknown_kind_items: usize,
    /// Vaults whose key did not unwrap (skipped, e.g. a team vault awaiting a grant).
    pub skipped_vaults: usize,
}

/// Device-local data of an item (never synced; T82 `device_local`).
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceLocalInfo {
    /// When it was last connected to from this device.
    pub last_connected_at: Option<UnixMillis>,
    /// Frecency score at the last connect (decays with time).
    pub frecency: f64,
    /// Local directory override for this device.
    pub local_dir_override: Option<LocalPath>,
    /// Site Manager folder expansion on this device.
    pub tree_expanded: Option<bool>,
}

/// Vault errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VaultError {
    /// No `meta.kdf` yet: run the first-run setup.
    #[error("the vault is not set up yet")]
    NotInitialized,
    /// First run was requested on an initialised database.
    #[error("the vault already exists")]
    AlreadyInitialized,
    /// The password did not unwrap the LMK (AEAD failure; deliberately no detail).
    #[error("wrong master password")]
    WrongPassword {
        /// Consecutive failures so far (persisted).
        failures: u32,
        /// The delay before the next attempt, if any.
        retry_after: Option<Duration>,
    },
    /// An attempt during the backoff; Argon2 did not run.
    #[error("too many failed attempts; try again in {}s", retry_after.as_secs().max(1))]
    Backoff {
        /// Remaining delay.
        retry_after: Duration,
    },
    /// The new password is too weak (zxcvbn score < 3).
    #[error(transparent)]
    WeakPassword(#[from] WeakPassword),
    /// The keyring could not provide or store the KEK.
    #[error("keyring: {0}")]
    Keyring(String),
    /// Keyring unlock is not enabled for this database (or the vault was not unlocked
    /// with the keyring, for a password reset).
    #[error("keyring unlock is not enabled")]
    KeyringNotEnabled,
    /// No usable OS keyring on this system.
    #[error("no keyring is available on this system")]
    KeyringUnavailable,
    /// The operation needs an unlocked vault.
    #[error("the vault is locked")]
    Locked,
    /// Another unlock is running.
    #[error("an unlock is already in progress")]
    UnlockInProgress,
    /// The item was written by a newer courier-ftp.
    #[error("update courier-ftp to edit this item")]
    ReadOnlyItem(ItemId),
    /// The vault is shared with read permission only.
    #[error("read-only vault")]
    ReadOnlyVault(VaultId),
    /// No such item.
    #[error("item not found")]
    NotFound(ItemId),
    /// The encoded body exceeds [`MAX_BODY_LEN`].
    #[error("this entry is too large to save ({bytes} bytes)")]
    ItemTooLarge {
        /// Encoded size.
        bytes: usize,
    },
    /// A reference rule violation (T81).
    #[error("{0}")]
    CrossVaultReference(String),
    /// SQLite stayed busy past the timeout.
    #[error("another courier-ftp may be writing to the vault; retry")]
    Busy,
    /// Stored vault data is damaged.
    #[error("vault data is corrupt: {0}")]
    Corrupt(String),
    /// Another store error.
    #[error("vault storage error: {0}")]
    Storage(String),
}

impl From<courier_ftp_store::StoreError> for VaultError {
    fn from(e: courier_ftp_store::StoreError) -> Self {
        use courier_ftp_store::StoreError as S;
        match e {
            S::Busy => Self::Busy,
            S::Corrupt(what) => Self::Corrupt(what),
            other => Self::Storage(other.to_string()),
        }
    }
}

impl From<VaultError> for crate::Error {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::Locked => Self::VaultLocked,
            VaultError::CrossVaultReference(msg) => Self::InvalidInput(msg),
            other => Self::Vault(other.to_string()),
        }
    }
}

/// "Start over" (T60): renames `courier-ftp.db` and its `-wal`/`-shm` siblings to
/// `<name>.bak-<YYYYMMDD-HHMMSS>` (plus the sibling suffix). Never deletes anything.
/// Drop every engine and store on the file first. Returns the new database path.
///
/// # Errors
/// A rename failed (siblings already renamed stay renamed).
pub fn move_database_aside(path: &Path) -> io::Result<PathBuf> {
    let now = time::OffsetDateTime::now_utc();
    let stamp = format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    let with_suffix = |p: &Path, suffix: &str| {
        let mut s = p.as_os_str().to_owned();
        s.push(suffix);
        PathBuf::from(s)
    };
    let mut target = with_suffix(path, &format!(".bak-{stamp}"));
    let mut n = 1;
    while target.exists() {
        target = with_suffix(path, &format!(".bak-{stamp}-{n}"));
        n += 1;
    }
    for sibling in ["-wal", "-shm"] {
        let from = with_suffix(path, sibling);
        if from.exists() {
            std::fs::rename(&from, with_suffix(&target, sibling))?;
        }
    }
    std::fs::rename(path, &target)?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_mapping() {
        assert!(matches!(
            crate::Error::from(VaultError::Locked),
            crate::Error::VaultLocked
        ));
        assert!(matches!(
            crate::Error::from(VaultError::CrossVaultReference("x".into())),
            crate::Error::InvalidInput(m) if m == "x"
        ));
        assert!(matches!(
            crate::Error::from(VaultError::Busy),
            crate::Error::Vault(_)
        ));
        assert_eq!(
            VaultError::Backoff {
                retry_after: Duration::from_millis(10)
            }
            .to_string(),
            "too many failed attempts; try again in 1s"
        );
    }

    #[test]
    fn move_aside_keeps_files() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let db = dir.path().join("courier-ftp.db");
        std::fs::write(&db, b"db")?;
        std::fs::write(dir.path().join("courier-ftp.db-wal"), b"wal")?;
        let moved = move_database_aside(&db)?;
        assert!(!db.exists());
        assert_eq!(std::fs::read(&moved)?, b"db");
        let mut wal = moved.as_os_str().to_owned();
        wal.push("-wal");
        assert_eq!(std::fs::read(PathBuf::from(wal))?, b"wal");
        let name = moved
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        assert!(name.starts_with("courier-ftp.db.bak-"), "{name}");
        Ok(())
    }
}
