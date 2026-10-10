//! The OS keyring seam for keyring unlock (D3, sverb `vault/keyring.rs`).
//!
//! The vault engine talks to the OS keyring only through [`KeyringStore`]. The
//! real implementation (the `keyring` crate: macOS Keychain, Windows Credential
//! Manager, Secret Service on Linux) is `courier_ftp_store::vault::OsKeyring`;
//! tests use [`MemKeyring`] and never touch the OS keyring.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use zeroize::Zeroizing;

/// The service name every entry is stored under.
pub const KEYRING_SERVICE: &str = "courier-ftp";

/// The account used by [`KeyringStore::probe`].
pub const PROBE_ACCOUNT: &str = "probe";

/// The keyring account for the database with id `db_id` (`meta.db_id`), so
/// several data directories never share an entry.
pub fn keyring_account(db_id: &str) -> String {
    format!("lmk-kek:{db_id}")
}

/// A keyring failure, with a short reason for the user (never a secret).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct KeyringError(pub String);

/// A secret store keyed by account, under [`KEYRING_SERVICE`].
///
/// Calls may block (OS prompts, D-Bus); the engine runs them in
/// `spawn_blocking`.
pub trait KeyringStore: Send + Sync + fmt::Debug {
    /// The secret for `account`; `Ok(None)` when there is no entry.
    ///
    /// # Errors
    /// The keyring is unavailable, or the user cancelled the OS prompt.
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyringError>;

    /// Stores `secret` for `account`, replacing any entry.
    ///
    /// # Errors
    /// The keyring is unavailable or refused the write.
    fn set(&self, account: &str, secret: &[u8]) -> Result<(), KeyringError>;

    /// Deletes the entry for `account` (no error if it does not exist).
    ///
    /// # Errors
    /// The keyring is unavailable.
    fn delete(&self, account: &str) -> Result<(), KeyringError>;

    /// Whether the keyring works: writes and deletes a test entry. `false` on
    /// headless Linux without a Secret Service, where the UI hides the option.
    fn probe(&self) -> bool {
        self.set(PROBE_ACCOUNT, b"probe").is_ok() && self.delete(PROBE_ACCOUNT).is_ok()
    }
}

/// No keyring at all (`COURIER_FTP_KEYRING=off`, builds without the OS keyring).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoKeyring;

const UNAVAILABLE: &str = "no keyring is available";

impl KeyringStore for NoKeyring {
    fn get(&self, _account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyringError> {
        Err(KeyringError(UNAVAILABLE.into()))
    }

    fn set(&self, _account: &str, _secret: &[u8]) -> Result<(), KeyringError> {
        Err(KeyringError(UNAVAILABLE.into()))
    }

    fn delete(&self, _account: &str) -> Result<(), KeyringError> {
        Err(KeyringError(UNAVAILABLE.into()))
    }
}

/// An in-memory keyring for tests (this crate's, the store's and the UI's).
/// Clones share entries.
#[derive(Clone, Default)]
pub struct MemKeyring {
    inner: Arc<MemInner>,
}

#[derive(Default)]
struct MemInner {
    entries: Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
    gets: AtomicUsize,
    unavailable: AtomicBool,
}

impl fmt::Debug for MemKeyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemKeyring")
            .field("accounts", &self.accounts())
            .finish()
    }
}

impl MemKeyring {
    /// An empty, available keyring.
    pub fn new() -> Self {
        Self::default()
    }

    fn entries(&self) -> MutexGuard<'_, HashMap<String, Zeroizing<Vec<u8>>>> {
        self.inner
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The accounts that have an entry, sorted.
    pub fn accounts(&self) -> Vec<String> {
        let mut v: Vec<String> = self.entries().keys().cloned().collect();
        v.sort();
        v
    }

    /// Removes an entry behind courier-ftp's back (a user deleting it).
    pub fn remove(&self, account: &str) {
        self.entries().remove(account);
    }

    /// Replaces an entry's secret behind courier-ftp's back.
    pub fn overwrite(&self, account: &str, secret: &[u8]) {
        self.entries()
            .insert(account.to_owned(), Zeroizing::new(secret.to_vec()));
    }

    /// Makes every call fail (a locked or missing keyring service).
    pub fn set_unavailable(&self, unavailable: bool) {
        self.inner.unavailable.store(unavailable, Ordering::SeqCst);
    }

    /// How many times [`KeyringStore::get`] was called.
    pub fn get_calls(&self) -> usize {
        self.inner.gets.load(Ordering::SeqCst)
    }

    fn check(&self) -> Result<(), KeyringError> {
        if self.inner.unavailable.load(Ordering::SeqCst) {
            Err(KeyringError("keyring unavailable".into()))
        } else {
            Ok(())
        }
    }
}

impl KeyringStore for MemKeyring {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyringError> {
        self.inner.gets.fetch_add(1, Ordering::SeqCst);
        self.check()?;
        Ok(self.entries().get(account).cloned())
    }

    fn set(&self, account: &str, secret: &[u8]) -> Result<(), KeyringError> {
        self.check()?;
        self.overwrite(account, secret);
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<(), KeyringError> {
        self.check()?;
        self.remove(account);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_keyring_roundtrip_and_probe() {
        let k = MemKeyring::new();
        assert!(k.probe());
        assert!(k.accounts().is_empty(), "probe leaves nothing behind");
        assert!(k.set("a", b"CANARY-KR").is_ok());
        assert!(!format!("{k:?}").contains("CANARY"));
        assert!(k.set("a", b"s").is_ok());
        assert_eq!(
            k.get("a").ok().flatten().map(|s| s.to_vec()),
            Some(b"s".to_vec())
        );
        assert_eq!(k.get_calls(), 1);
        k.set_unavailable(true);
        assert!(k.get("a").is_err());
        assert!(!k.probe());
        assert!(!NoKeyring.probe());
    }

    #[test]
    fn keyring_accounts_differ_per_db() {
        assert_eq!(keyring_account("a"), "lmk-kek:a");
        assert_ne!(keyring_account("a"), keyring_account("b"));
    }
}
