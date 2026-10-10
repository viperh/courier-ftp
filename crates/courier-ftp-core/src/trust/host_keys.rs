//! Trusted SSH host keys (T21): entries, stores and the per-process session trust.

use std::{
    collections::HashSet,
    fmt,
    sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use async_trait::async_trait;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::Error;

/// Id of a stored host key (UUIDv7; equals the vault `ItemId` once T30 stores it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KnownHostId(pub Uuid);

impl KnownHostId {
    /// A fresh UUIDv7 id.
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }
}

/// One trusted host key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownHost {
    /// The entry's id.
    pub id: KnownHostId,
    /// Host as configured by the user, normalised ([`normalize_host`]): ASCII-lowercase,
    /// no trailing dot, IPv6 literal without brackets. Never the resolved IP.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Key algorithm name: `"ssh-ed25519"`, `"ecdsa-sha2-nistp256"`, `"ssh-rsa"`, …
    pub key_type: String,
    /// Base64 public key blob (the OpenSSH known_hosts key field).
    pub public_key: String,
    /// When the key was trusted.
    #[serde(with = "time::serde::rfc3339")]
    pub added_at: OffsetDateTime,
    /// Free text (e.g. "imported from ~/.ssh/known_hosts"); shown in Settings (T68).
    pub comment: Option<String>,
}

impl KnownHost {
    /// `"SHA256:<base64 no padding>"` of the key blob, `"?"` if the blob does not decode.
    pub fn fingerprint_sha256(&self) -> String {
        match STANDARD.decode(self.public_key.trim()) {
            Ok(blob) => format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(&blob))),
            Err(_) => "?".to_owned(),
        }
    }
}

/// Normalise a host for lookups and storage: trimmed, ASCII-lowercase, without a
/// trailing dot and without the brackets of an IPv6 literal (`[::1]` → `::1`).
pub fn normalize_host(host: &str) -> String {
    let mut h = host.trim();
    if let Some(inner) = h.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        h = inner;
    }
    let h = h.strip_suffix('.').unwrap_or(h);
    h.to_ascii_lowercase()
}

/// Where trusted host keys live: memory (vault locked / before T30) or the vault (T30).
#[async_trait]
pub trait HostKeyStore: Send + Sync + fmt::Debug {
    /// Entries for `host:port` (a snapshot; never blocks on I/O: it is called during
    /// the handshake). `host` is already normalised.
    fn lookup(&self, host: &str, port: u16) -> Vec<KnownHost>;

    /// Every entry, sorted by (host, port, key_type) — for Settings (T68).
    fn list(&self) -> Vec<KnownHost>;

    /// Whether [`add`](Self::add) persists beyond this process (false → "Always trust"
    /// is disabled in the prompt).
    fn can_persist(&self) -> bool;

    /// Store `entry` and delete `replaces` in one operation (one vault transaction in
    /// T30).
    ///
    /// # Errors
    /// The store could not be written (T30: `Vault(..)`, `VaultLocked`).
    async fn add(&self, entry: KnownHost, replaces: Vec<KnownHostId>) -> Result<(), Error>;

    /// Delete the entry `id` (no error when it does not exist).
    ///
    /// # Errors
    /// The store could not be written.
    async fn remove(&self, id: KnownHostId) -> Result<(), Error>;
}

fn read<T>(l: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(PoisonError::into_inner)
}

fn write<T>(l: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(PoisonError::into_inner)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn sort_key(e: &KnownHost) -> (&str, u16, &str) {
    (&e.host, e.port, &e.key_type)
}

/// In-memory store. [`new`](Self::new) → `can_persist = false` (vault locked /
/// pre-T30); [`persistent_for_tests`](Self::persistent_for_tests) → `can_persist = true`.
#[derive(Debug, Default)]
pub struct MemoryHostKeyStore {
    entries: RwLock<Vec<KnownHost>>,
    can_persist: bool,
}

impl MemoryHostKeyStore {
    /// An empty store whose entries do not outlive the process (`can_persist = false`).
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty store that claims to persist (`can_persist = true`), for tests of the
    /// "Always trust" path.
    pub fn persistent_for_tests() -> Self {
        Self {
            entries: RwLock::default(),
            can_persist: true,
        }
    }

    /// A store holding `entries` (tests; `can_persist` as given).
    pub fn with_entries(entries: Vec<KnownHost>, can_persist: bool) -> Self {
        Self {
            entries: RwLock::new(entries),
            can_persist,
        }
    }
}

#[async_trait]
impl HostKeyStore for MemoryHostKeyStore {
    fn lookup(&self, host: &str, port: u16) -> Vec<KnownHost> {
        read(&self.entries)
            .iter()
            .filter(|e| e.host == host && e.port == port)
            .cloned()
            .collect()
    }

    fn list(&self) -> Vec<KnownHost> {
        let mut all = read(&self.entries).clone();
        all.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
        all
    }

    fn can_persist(&self) -> bool {
        self.can_persist
    }

    async fn add(&self, entry: KnownHost, replaces: Vec<KnownHostId>) -> Result<(), Error> {
        let mut entries = write(&self.entries);
        entries.retain(|e| !replaces.contains(&e.id) && e.id != entry.id);
        entries.push(entry);
        Ok(())
    }

    async fn remove(&self, id: KnownHostId) -> Result<(), Error> {
        write(&self.entries).retain(|e| e.id != id);
        Ok(())
    }
}

/// The store the verifier holds; T30 calls [`set`](Self::set) after unlock and on lock.
pub struct SwitchableHostKeyStore {
    current: RwLock<Arc<dyn HostKeyStore>>,
}

impl fmt::Debug for SwitchableHostKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SwitchableHostKeyStore")
            .field("current", &*read(&self.current))
            .finish()
    }
}

impl SwitchableHostKeyStore {
    /// Starts with `initial`.
    pub fn new(initial: Arc<dyn HostKeyStore>) -> Self {
        Self {
            current: RwLock::new(initial),
        }
    }

    /// Replace the store every later call goes to.
    pub fn set(&self, store: Arc<dyn HostKeyStore>) {
        *write(&self.current) = store;
    }

    fn current(&self) -> Arc<dyn HostKeyStore> {
        Arc::clone(&read(&self.current))
    }
}

#[async_trait]
impl HostKeyStore for SwitchableHostKeyStore {
    fn lookup(&self, host: &str, port: u16) -> Vec<KnownHost> {
        self.current().lookup(host, port)
    }

    fn list(&self) -> Vec<KnownHost> {
        self.current().list()
    }

    fn can_persist(&self) -> bool {
        self.current().can_persist()
    }

    async fn add(&self, entry: KnownHost, replaces: Vec<KnownHostId>) -> Result<(), Error> {
        self.current().add(entry, replaces).await
    }

    async fn remove(&self, id: KnownHostId) -> Result<(), Error> {
        self.current().remove(id).await
    }
}

/// Keys accepted with "Trust once" (and every accepted key) for the life of the
/// process, so the extra transfer connections (T41) don't ask again. Never persisted.
#[derive(Debug, Default)]
pub struct SessionTrust {
    keys: Mutex<HashSet<(String, u16, String, String)>>,
}

impl SessionTrust {
    fn key(host: &str, port: u16, key_type: &str, blob: &str) -> (String, u16, String, String) {
        (
            normalize_host(host),
            port,
            key_type.to_owned(),
            blob.trim().to_owned(),
        )
    }

    /// Whether this exact key was accepted for `host:port` in this process.
    pub fn contains(&self, host: &str, port: u16, key_type: &str, blob: &str) -> bool {
        lock(&self.keys).contains(&Self::key(host, port, key_type, blob))
    }

    /// Remember an accepted key.
    pub fn insert(&self, host: &str, port: u16, key_type: &str, blob: &str) {
        lock(&self.keys).insert(Self::key(host, port, key_type, blob));
    }

    /// Forget everything (called when the user removes a key in Settings, T68).
    pub fn clear(&self) {
        lock(&self.keys).clear();
    }
}
