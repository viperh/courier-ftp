//! Trusted host keys: the [`HostKeyStore`] trait, the in-memory store and a
//! slot to swap stores at run time.

use std::{
    fmt,
    sync::{
        Arc, Mutex, PoisonError, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

use async_trait::async_trait;
use time::OffsetDateTime;

use super::{HostKey, normalize_host};
use crate::{Error, Result};

/// One trusted host key ("Always trust"). The vault stores it as a
/// `known-host` item (T30/T81) with the fields `host`, `port`, `key_type`,
/// `public_key` and `added_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHost {
    /// Host name or IP address, lower case, without brackets.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// The key.
    pub key: HostKey,
    /// When the user trusted it.
    pub added_at: OffsetDateTime,
}

impl KnownHost {
    /// An entry for `host` (normalized: lower case, no brackets).
    pub fn new(host: &str, port: u16, key: HostKey, added_at: OffsetDateTime) -> Self {
        Self {
            host: normalize_host(host),
            port,
            key,
            added_at,
        }
    }

    /// An entry from its stored fields (`public_key` is OpenSSH base64).
    ///
    /// # Errors
    /// [`Error::InvalidInput`] when the key doesn't parse or isn't of type
    /// `key_type`.
    pub fn from_parts(
        host: &str,
        port: u16,
        key_type: &str,
        public_key: &str,
        added_at: OffsetDateTime,
    ) -> Result<Self> {
        Ok(Self::new(
            host,
            port,
            HostKey::from_openssh(key_type, public_key)?,
            added_at,
        ))
    }

    /// The key's algorithm, e.g. `ssh-ed25519`.
    pub fn key_type(&self) -> &str {
        self.key.algorithm()
    }

    /// The key in OpenSSH base64.
    pub fn public_key(&self) -> String {
        self.key.to_base64()
    }

    /// Whether this entry is for `host:port` and `key_type`.
    pub fn is_for(&self, host: &str, port: u16, key_type: &str) -> bool {
        self.port == port && self.key_type() == key_type && self.host == normalize_host(host)
    }
}

/// Where trusted host keys live.
///
/// T21 provides [`MemoryHostKeyStore`]; T30 implements it on `known-host`
/// vault items and swaps it in after unlock (see [`HostKeyStoreSlot`]).
/// Hosts passed in are normalized by the implementation (lower case, no
/// brackets; [`normalize_host`]). At most one key per `(host, port,
/// key_type)`: a host may have keys of several algorithms.
///
/// The methods are async so a store can do I/O (the vault runs SQLite in
/// `spawn_blocking`).
#[async_trait]
pub trait HostKeyStore: Send + Sync + fmt::Debug {
    /// Whether [`HostKeyStore::remember`] can store keys. `false` while the
    /// vault is locked or was skipped: the trust prompt then offers only
    /// "Trust once".
    async fn can_remember(&self) -> bool;

    /// The trusted keys for `host:port` (any algorithm).
    ///
    /// # Errors
    /// Storage errors.
    async fn keys_for(&self, host: &str, port: u16) -> Result<Vec<KnownHost>>;

    /// Trust `entry`, replacing a key of the same `(host, port, key_type)`.
    ///
    /// # Errors
    /// [`Error::Vault`] when the store can't remember (vault locked) or
    /// storage errors.
    async fn remember(&self, entry: KnownHost) -> Result<()>;

    /// Every trusted key, for the settings UI (T68), sorted by host, port and
    /// key type.
    ///
    /// # Errors
    /// Storage errors.
    async fn list(&self) -> Result<Vec<KnownHost>>;

    /// Stop trusting the key of `key_type` for `host:port`. `Ok(false)` when
    /// there was none.
    ///
    /// # Errors
    /// [`Error::Vault`] when the vault is locked, or storage errors.
    async fn forget(&self, host: &str, port: u16, key_type: &str) -> Result<bool>;
}

/// Host keys in memory, lost at exit: the store before the vault is unlocked
/// and in tests.
#[derive(Debug)]
pub struct MemoryHostKeyStore {
    entries: Mutex<Vec<KnownHost>>,
    can_remember: AtomicBool,
}

impl Default for MemoryHostKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryHostKeyStore {
    /// An empty store that remembers keys (for this run only).
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            can_remember: AtomicBool::new(true),
        }
    }

    /// An empty store that refuses to remember: the vault is locked or was
    /// skipped. Trust prompts then offer only "Trust once".
    pub fn locked() -> Self {
        let store = Self::new();
        store.set_can_remember(false);
        store
    }

    /// Allow or refuse [`HostKeyStore::remember`].
    pub fn set_can_remember(&self, can: bool) {
        self.can_remember.store(can, Ordering::Relaxed);
    }

    fn entries(&self) -> std::sync::MutexGuard<'_, Vec<KnownHost>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn check_writable(&self) -> Result<()> {
        if self.can_remember.load(Ordering::Relaxed) {
            Ok(())
        } else {
            Err(Error::Vault(
                "the vault is locked: host keys can't be saved".to_owned(),
            ))
        }
    }
}

#[async_trait]
impl HostKeyStore for MemoryHostKeyStore {
    async fn can_remember(&self) -> bool {
        self.can_remember.load(Ordering::Relaxed)
    }

    async fn keys_for(&self, host: &str, port: u16) -> Result<Vec<KnownHost>> {
        let host = normalize_host(host);
        Ok(self
            .entries()
            .iter()
            .filter(|e| e.port == port && e.host == host)
            .cloned()
            .collect())
    }

    async fn remember(&self, entry: KnownHost) -> Result<()> {
        self.check_writable()?;
        let entry = KnownHost::new(&entry.host, entry.port, entry.key, entry.added_at);
        let mut entries = self.entries();
        entries.retain(|e| !e.is_for(&entry.host, entry.port, entry.key_type()));
        entries.push(entry);
        Ok(())
    }

    async fn list(&self) -> Result<Vec<KnownHost>> {
        let mut all = self.entries().clone();
        all.sort_by(|a, b| (&a.host, a.port, a.key_type()).cmp(&(&b.host, b.port, b.key_type())));
        Ok(all)
    }

    async fn forget(&self, host: &str, port: u16, key_type: &str) -> Result<bool> {
        self.check_writable()?;
        let mut entries = self.entries();
        let before = entries.len();
        entries.retain(|e| !e.is_for(host, port, key_type));
        Ok(entries.len() != before)
    }
}

/// A [`HostKeyStore`] that forwards to a store which can be replaced while
/// connections hold the slot: the app starts with a locked
/// [`MemoryHostKeyStore`] and T30 puts the vault-backed store in after
/// unlock (and a locked one back after lock).
pub struct HostKeyStoreSlot {
    current: RwLock<Arc<dyn HostKeyStore>>,
}

impl HostKeyStoreSlot {
    /// A slot holding `store`.
    pub fn new(store: Arc<dyn HostKeyStore>) -> Self {
        Self {
            current: RwLock::new(store),
        }
    }

    /// Put `store` in; later calls go to it.
    pub fn replace(&self, store: Arc<dyn HostKeyStore>) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = store;
    }

    /// The store calls currently go to.
    pub fn current(&self) -> Arc<dyn HostKeyStore> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }
}

impl fmt::Debug for HostKeyStoreSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("HostKeyStoreSlot")
            .field(&self.current())
            .finish()
    }
}

#[async_trait]
impl HostKeyStore for HostKeyStoreSlot {
    async fn can_remember(&self) -> bool {
        self.current().can_remember().await
    }

    async fn keys_for(&self, host: &str, port: u16) -> Result<Vec<KnownHost>> {
        self.current().keys_for(host, port).await
    }

    async fn remember(&self, entry: KnownHost) -> Result<()> {
        self.current().remember(entry).await
    }

    async fn list(&self) -> Result<Vec<KnownHost>> {
        self.current().list().await
    }

    async fn forget(&self, host: &str, port: u16, key_type: &str) -> Result<bool> {
        self.current().forget(host, port, key_type).await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use pretty_assertions::assert_eq;
    use time::macros::datetime;

    use super::*;
    use crate::trust::host_key::tests::{blob, ed25519};

    const T: OffsetDateTime = datetime!(2026-10-10 12:00 UTC);

    fn ecdsa() -> HostKey {
        HostKey::from_blob(blob(&[b"ecdsa-sha2-nistp256", b"nistp256", b"q"])).unwrap()
    }

    #[tokio::test]
    async fn remember_lookup_list_forget() {
        let store = MemoryHostKeyStore::new();
        assert!(store.can_remember().await);
        store
            .remember(KnownHost::new("Example.com", 22, ed25519(1), T))
            .await
            .unwrap();
        store
            .remember(KnownHost::new("example.com", 22, ecdsa(), T))
            .await
            .unwrap();
        store
            .remember(KnownHost::new("[::1]", 2222, ed25519(2), T))
            .await
            .unwrap();
        // Same host and type: replaced.
        store
            .remember(KnownHost::new("EXAMPLE.COM", 22, ed25519(3), T))
            .await
            .unwrap();

        let keys = store.keys_for("example.COM", 22).await.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.iter().any(|k| k.key == ed25519(3)));
        assert!(keys.iter().any(|k| k.key == ecdsa()));
        assert!(
            store
                .keys_for("example.com", 2222)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store.keys_for("::1", 2222).await.unwrap()[0].key,
            ed25519(2)
        );

        let all = store.list().await.unwrap();
        let summary: Vec<(String, u16, String)> = all
            .iter()
            .map(|e| (e.host.clone(), e.port, e.key_type().to_owned()))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("::1".into(), 2222, "ssh-ed25519".into()),
                ("example.com".into(), 22, "ecdsa-sha2-nistp256".into()),
                ("example.com".into(), 22, "ssh-ed25519".into()),
            ]
        );

        assert!(
            store
                .forget("Example.com", 22, "ssh-ed25519")
                .await
                .unwrap()
        );
        assert!(
            !store
                .forget("example.com", 22, "ssh-ed25519")
                .await
                .unwrap()
        );
        assert_eq!(store.list().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_locked_store_refuses_to_remember() {
        let store = MemoryHostKeyStore::locked();
        assert!(!store.can_remember().await);
        let err = store
            .remember(KnownHost::new("h", 22, ed25519(1), T))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Vault(_)));
        assert!(store.list().await.unwrap().is_empty());
    }

    #[test]
    fn stored_fields_round_trip() {
        let e = KnownHost::new("H", 22, ed25519(4), T);
        let back =
            KnownHost::from_parts(&e.host, e.port, e.key_type(), &e.public_key(), e.added_at)
                .unwrap();
        assert_eq!(back, e);
        assert_eq!(back.host, "h");
        assert!(KnownHost::from_parts("h", 22, "ssh-rsa", &e.public_key(), T).is_err());
    }

    #[tokio::test]
    async fn the_slot_forwards_to_the_current_store() {
        let slot = HostKeyStoreSlot::new(Arc::new(MemoryHostKeyStore::locked()));
        assert!(!slot.can_remember().await);
        let vault = Arc::new(MemoryHostKeyStore::new());
        slot.replace(vault.clone());
        assert!(slot.can_remember().await);
        slot.remember(KnownHost::new("h", 22, ed25519(1), T))
            .await
            .unwrap();
        assert_eq!(vault.list().await.unwrap().len(), 1);
        assert_eq!(slot.keys_for("h", 22).await.unwrap().len(), 1);
        assert!(slot.forget("h", 22, "ssh-ed25519").await.unwrap());
        assert!(slot.list().await.unwrap().is_empty());
    }
}
