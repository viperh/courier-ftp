//! The vault engine (T30, D3): first run, password and keyring unlock, the
//! persisted backoff, lock, password change, keyring enrolment, recovery
//! through the keyring, and encrypted item CRUD.
//!
//! Adapted from sverb's `sverb-tui::services::vault::engine` (D13). The pure
//! parts (backoff, strength, keyring seam, auto-lock, errors) live in
//! `courier_ftp_core::vault`; the engine sits here because it needs the store,
//! and the store depends on core. Core code uses it as an
//! `Arc<dyn courier_ftp_core::vault::ItemVault>`.
//!
//! - Argon2 and keyring calls run in `spawn_blocking`; SQLite goes through the
//!   store's blocking pool. **Nothing here contacts a sync server.**
//! - Keys (LMK, vault keys) exist only while unlocked, in zeroize-on-drop
//!   `Key32`s counted by a per-engine live-key counter ([`VaultEngine::live_keys`])
//!   so tests can prove [`VaultEngine::lock`] dropped every key. Decrypted items
//!   are scrubbed (text and byte values zeroized) when dropped.
//! - Every write is one IMMEDIATE transaction (T82); failed-attempt counting is
//!   a read-modify-write inside one, so several processes count every failure.

mod os_keyring;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use async_trait::async_trait;
use courier_ftp_core::model::item::{
    DeviceId, Hlc, HlcClock, ItemBody, ItemId, ItemKind, SystemClock, VaultId, current_schema,
    is_read_only, migrate,
};
use courier_ftp_core::vault::backup::{self, BackupItem};
use courier_ftp_core::vault::{
    BackoffState, ItemVault, ItemWrite, KeyringStore, UnlockMethod, VaultError, VaultItem,
    VaultState, VaultStatus, check_strength, keyring_account, scrub, strip_passwords,
};
use courier_ftp_crypto::envelope::{open_item, seal_item};
use courier_ftp_crypto::kdf::{Argon2Cost, KdfParams, argon2id};
use courier_ftp_crypto::keys::{os_rng, random_key32};
use courier_ftp_crypto::wrap::{WrapPurpose, unwrap_key32, wrap_key};
use courier_ftp_crypto::{CryptoError, Key32};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

#[cfg(feature = "os-keyring")]
pub use self::os_keyring::OsKeyring;
pub use self::os_keyring::{KEYRING_ENV, keyring_from_env};
use crate::meta::keys;
use crate::{ItemRow, Store, StoreError, VaultKind};

/// What a first run produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitReport {
    /// Keyring unlock was requested but couldn't be enabled; the vault was
    /// created without it. The reason, for the UI.
    pub keyring_error: Option<String>,
}

/// What an unlock found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnlockReport {
    /// How it was unlocked.
    pub method: UnlockMethod,
    /// Live items decrypted.
    pub items: usize,
    /// Items that didn't decrypt (tampered or sealed under a key this device
    /// doesn't have); logged by id and skipped.
    pub undecryptable: usize,
    /// Items from a newer courier-ftp (read-only).
    pub read_only: usize,
}

/// A key counted in the engine's live-key counter; zeroized on drop.
struct TrackedKey {
    key: Key32,
    live: Arc<AtomicUsize>,
}

impl TrackedKey {
    fn new(key: Key32, live: &Arc<AtomicUsize>) -> Self {
        live.fetch_add(1, Ordering::SeqCst);
        Self {
            key,
            live: Arc::clone(live),
        }
    }
}

impl Drop for TrackedKey {
    fn drop(&mut self) {
        // `Key32` zeroizes itself right after this.
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

struct VaultKeyEntry {
    key_version: u32,
    key: TrackedKey,
}

/// A decrypted item in the in-memory index. Its text and byte values are
/// zeroized when it is dropped.
struct Cached {
    vault_id: VaultId,
    body: ItemBody,
    read_only: bool,
}

impl Drop for Cached {
    fn drop(&mut self) {
        scrub(&mut self.body);
    }
}

/// The unlocked state: keys, clock and the decrypted index. Dropping it
/// zeroizes everything.
struct Unlocked {
    lmk: TrackedKey,
    vaults: BTreeMap<VaultId, VaultKeyEntry>,
    personal: VaultId,
    device: DeviceId,
    clock: HlcClock,
    method: UnlockMethod,
    items: BTreeMap<ItemId, Cached>,
}

impl Unlocked {
    fn item(&self, id: ItemId) -> Option<VaultItem> {
        self.items.get(&id).map(|c| VaultItem {
            id,
            vault_id: c.vault_id,
            body: c.body.clone(),
            read_only: c.read_only,
        })
    }

    fn seal(
        &self,
        vault: VaultId,
        id: ItemId,
        body: &ItemBody,
    ) -> Result<(u32, Vec<u8>), VaultError> {
        let entry = self.vaults.get(&vault).ok_or(VaultError::Locked)?;
        let cbor = Zeroizing::new(
            body.to_cbor()
                .map_err(|e| VaultError::Corrupt(format!("item body: {e}")))?,
        );
        let env = seal_item(
            &entry.key.key,
            vault.as_bytes(),
            id.as_bytes(),
            entry.key_version,
            &cbor,
            &mut os_rng(),
        )
        .map_err(|e| VaultError::from_crypto(e, "item"))?;
        Ok((entry.key_version, env))
    }

    fn open(&self, row: &ItemRow) -> Result<ItemBody, VaultError> {
        let entry = self.vaults.get(&row.vault_id).ok_or(VaultError::Locked)?;
        let lookup = |v: u32| (v == entry.key_version).then_some(&entry.key.key);
        let plain = open_item(
            lookup,
            row.vault_id.as_bytes(),
            row.id.as_bytes(),
            &row.envelope,
        )
        .map_err(|e| VaultError::from_crypto(e, "item"))?;
        ItemBody::from_cbor(&plain).map_err(|e| VaultError::Corrupt(format!("item body: {e}")))
    }
}

struct Inner {
    store: Store,
    keyring: Arc<dyn KeyringStore>,
    cost: Argon2Cost,
    kdf_runs: AtomicUsize,
    live_keys: Arc<AtomicUsize>,
    store_passwords: AtomicBool,
    state: tokio::sync::RwLock<Option<Unlocked>>,
}

/// The vault engine. Cheap to clone (clones share the state); see the module
/// docs.
#[derive(Clone)]
pub struct VaultEngine {
    inner: Arc<Inner>,
}

impl fmt::Debug for VaultEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultEngine")
            .field("store", &self.inner.store)
            .field("keyring", &self.inner.keyring)
            .field("cost", &self.inner.cost)
            .field("live_keys", &self.live_keys())
            .finish_non_exhaustive()
    }
}

fn storage(e: StoreError) -> VaultError {
    match e {
        StoreError::Busy => VaultError::Busy,
        StoreError::ReadOnlyItem(id) => VaultError::ReadOnlyItem(id),
        other => VaultError::Storage(other.to_string()),
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, VaultError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| VaultError::Storage(format!("background task failed: {e}")))
}

/// Raw `meta` values read in one snapshot.
#[derive(Default)]
struct Meta {
    kdf: Option<Vec<u8>>,
    lmk_pw: Option<Vec<u8>>,
    lmk_keyring: Option<Vec<u8>>,
    failures: Option<Vec<u8>>,
    next_allowed: Option<Vec<u8>>,
    db_id: Option<Vec<u8>>,
}

impl Meta {
    fn backoff(&self) -> BackoffState {
        BackoffState::decode(self.failures.as_deref(), self.next_allowed.as_deref())
    }

    fn db_id(&self) -> Result<String, VaultError> {
        self.db_id
            .clone()
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or_else(|| VaultError::Corrupt("meta.db_id is missing".into()))
    }
}

impl VaultEngine {
    /// An engine over `store`, using `keyring` for keyring unlock and `cost`
    /// for new password wraps (first run, password change, and re-wrapping on
    /// unlock when the stored cost differs). Production passes
    /// `Argon2Cost::DEFAULT` and [`keyring_from_env()`].
    pub fn new(store: Store, keyring: Arc<dyn KeyringStore>, cost: Argon2Cost) -> Self {
        Self {
            inner: Arc::new(Inner {
                store,
                keyring,
                cost,
                kdf_runs: AtomicUsize::new(0),
                live_keys: Arc::new(AtomicUsize::new(0)),
                store_passwords: AtomicBool::new(true),
                state: tokio::sync::RwLock::new(None),
            }),
        }
    }

    /// The store.
    pub fn store(&self) -> &Store {
        &self.inner.store
    }

    /// How many times Argon2 ran (test hook: proves backoff and tamper checks
    /// refuse before the KDF).
    pub fn kdf_runs(&self) -> usize {
        self.inner.kdf_runs.load(Ordering::SeqCst)
    }

    /// Keys currently in memory (LMK + vault keys); 0 while locked.
    pub fn live_keys(&self) -> usize {
        self.inner.live_keys.load(Ordering::SeqCst)
    }

    /// `vault.store_passwords`: when `false`, site and history password
    /// fields are erased on every write (`strip_passwords`).
    pub fn set_store_passwords(&self, store: bool) {
        self.inner.store_passwords.store(store, Ordering::SeqCst);
    }

    async fn meta(&self) -> Result<Meta, VaultError> {
        self.inner
            .store
            .read(|r| {
                Ok(Meta {
                    kdf: r.get_meta(keys::KDF)?,
                    lmk_pw: r.get_meta(keys::LMK_WRAPPED_PW)?,
                    lmk_keyring: r.get_meta(keys::LMK_WRAPPED_KEYRING)?,
                    failures: r.get_meta(keys::UNLOCK_FAILURES)?,
                    next_allowed: r.get_meta(keys::UNLOCK_NEXT_ALLOWED_AT)?,
                    db_id: r.get_meta(keys::DB_ID)?,
                })
            })
            .await
            .map_err(storage)
    }

    /// Uninitialised / locked / unlocked, keyring, and the backoff countdown.
    ///
    /// # Errors
    /// [`VaultError::Storage`].
    pub async fn status(&self) -> Result<VaultStatus, VaultError> {
        let m = self.meta().await?;
        let backoff = m.backoff();
        let method = self.inner.state.read().await.as_ref().map(|u| u.method);
        let state = match (m.kdf.is_some(), method.is_some()) {
            (false, _) => VaultState::Uninitialised,
            (true, false) => VaultState::Locked,
            (true, true) => VaultState::Unlocked,
        };
        Ok(VaultStatus {
            state,
            keyring_enabled: m.lmk_keyring.is_some(),
            backoff,
            retry_after: backoff.check(self.inner.store.now()).err(),
            unlock_method: method,
        })
    }

    /// Whether keys are loaded.
    pub async fn is_unlocked(&self) -> bool {
        self.inner.state.read().await.is_some()
    }

    /// Whether the OS keyring works (writes and deletes a test entry). `false`
    /// on headless Linux without a Secret Service: the UI hides the option.
    pub async fn keyring_available(&self) -> bool {
        let keyring = Arc::clone(&self.inner.keyring);
        let ok = blocking(move || keyring.probe()).await.unwrap_or(false);
        if !ok {
            tracing::debug!("OS keyring unavailable; keyring unlock hidden");
        }
        ok
    }

    /// The keyring account of this database (`None` before first run).
    ///
    /// # Errors
    /// [`VaultError::Storage`].
    pub async fn keyring_account(&self) -> Result<Option<String>, VaultError> {
        Ok(self
            .meta()
            .await?
            .db_id()
            .ok()
            .map(|id| keyring_account(&id)))
    }

    /// The personal vault (`None` while locked).
    pub async fn personal_vault(&self) -> Option<VaultId> {
        self.inner.state.read().await.as_ref().map(|u| u.personal)
    }

    /// This device's id (`None` while locked).
    pub async fn device_id(&self) -> Option<DeviceId> {
        self.inner.state.read().await.as_ref().map(|u| u.device)
    }

    async fn derive(
        &self,
        password: &SecretString,
        params: KdfParams,
    ) -> Result<Key32, VaultError> {
        let pw = Zeroizing::new(password.expose_secret().as_bytes().to_vec());
        self.inner.kdf_runs.fetch_add(1, Ordering::SeqCst);
        blocking(move || argon2id(&pw, &params))
            .await?
            .map_err(|e| VaultError::Corrupt(format!("meta.kdf: {e}")))
    }

    fn track(&self, key: Key32) -> TrackedKey {
        TrackedKey::new(key, &self.inner.live_keys)
    }

    /// First run: checks the password's strength, then creates the LMK, salt
    /// and KEK, the personal vault and its key, the device id, the database id
    /// and the HLC, written in **one** transaction. `enable_keyring` also
    /// stores a keyring KEK (if that fails the vault is created without it and
    /// the reason is reported). Leaves the engine unlocked.
    ///
    /// # Errors
    /// [`VaultError::WeakPassword`] (Argon2 does not run),
    /// [`VaultError::AlreadyInitialized`], [`VaultError::Storage`].
    pub async fn initialize(
        &self,
        password: &SecretString,
        enable_keyring: bool,
    ) -> Result<InitReport, VaultError> {
        check_strength(password.expose_secret(), &[])?;
        if self.meta().await?.kdf.is_some() {
            return Err(VaultError::AlreadyInitialized);
        }
        let mut rng = os_rng();
        let lmk = random_key32(&mut rng);
        let params = KdfParams::generate(self.inner.cost, &mut rng);
        let kek = self.derive(password, params).await?;
        let lmk_pw = wrap_key(&kek, &WrapPurpose::Lmk, lmk.expose_secret(), &mut rng)
            .map_err(|e| VaultError::from_crypto(e, "lmk"))?;
        drop(kek);

        let vault_id = VaultId::new();
        let vk = random_key32(&mut rng);
        let wrapped_vk = wrap_key(
            &lmk,
            &WrapPurpose::VaultKey(*vault_id.as_bytes()),
            vk.expose_secret(),
            &mut rng,
        )
        .map_err(|e| VaultError::from_crypto(e, "vault key"))?;
        let device = DeviceId::new();
        let mut clock = HlcClock::new(SystemClock);
        let hlc_last = clock.now();
        let db_id = DeviceId::new().to_string();

        // Optional keyring KEK: stored before the transaction; removed again
        // if the transaction fails.
        let mut keyring_error = None;
        let mut lmk_keyring = None;
        if enable_keyring {
            let kr_kek = random_key32(&mut rng);
            let keyring = Arc::clone(&self.inner.keyring);
            let secret = Zeroizing::new(kr_kek.expose_secret().to_vec());
            let account = keyring_account(&db_id);
            match blocking(move || keyring.set(&account, &secret)).await? {
                Ok(()) => {
                    lmk_keyring = Some(
                        wrap_key(&kr_kek, &WrapPurpose::Lmk, lmk.expose_secret(), &mut rng)
                            .map_err(|e| VaultError::from_crypto(e, "lmk"))?,
                    );
                }
                Err(e) => {
                    tracing::debug!(error = %e, "keyring unlock could not be enabled at first run");
                    keyring_error = Some(e.0);
                }
            }
        }

        let kdf = params.to_cbor();
        let db_id_bytes = db_id.clone().into_bytes();
        let had_keyring = lmk_keyring.is_some();
        let wrote = self
            .inner
            .store
            .write(move |w| {
                if w.as_read().get_meta(keys::KDF)?.is_some() {
                    return Ok(false);
                }
                w.set_meta(keys::KDF, &kdf)?;
                w.set_meta(keys::LMK_WRAPPED_PW, &lmk_pw)?;
                if let Some(kr) = &lmk_keyring {
                    w.set_meta(keys::LMK_WRAPPED_KEYRING, kr)?;
                }
                w.set_meta(keys::DB_ID, &db_id_bytes)?;
                w.set_device_id(device)?;
                w.set_hlc_last(hlc_last)?;
                w.delete_meta(keys::UNLOCK_FAILURES)?;
                w.delete_meta(keys::UNLOCK_NEXT_ALLOWED_AT)?;
                w.create_vault(vault_id, VaultKind::Personal, None, 1, &wrapped_vk)?;
                Ok(true)
            })
            .await;
        let wrote = match wrote {
            Ok(w) => w,
            Err(e) => {
                if had_keyring {
                    self.delete_keyring_entry(&db_id).await;
                }
                return Err(storage(e));
            }
        };
        if !wrote {
            if had_keyring {
                self.delete_keyring_entry(&db_id).await;
            }
            return Err(VaultError::AlreadyInitialized);
        }
        let mut vaults = BTreeMap::new();
        vaults.insert(
            vault_id,
            VaultKeyEntry {
                key_version: 1,
                key: self.track(vk),
            },
        );
        *self.inner.state.write().await = Some(Unlocked {
            lmk: self.track(lmk),
            vaults,
            personal: vault_id,
            device,
            clock,
            method: UnlockMethod::Created,
            items: BTreeMap::new(),
        });
        tracing::info!(vault = %vault_id.short(), "vault created");
        Ok(InitReport { keyring_error })
    }

    async fn delete_keyring_entry(&self, db_id: &str) {
        let keyring = Arc::clone(&self.inner.keyring);
        let account = keyring_account(db_id);
        if let Ok(Err(e)) = blocking(move || keyring.delete(&account)).await {
            tracing::debug!(error = %e, "could not delete the keyring entry");
        }
    }

    /// Checks `password` against `meta.lmk_wrapped_pw` with the persisted
    /// backoff. Returns the LMK and the stored KDF params on success (and
    /// resets the counter).
    async fn try_password(
        &self,
        password: &SecretString,
    ) -> Result<(Key32, KdfParams), VaultError> {
        let m = self.meta().await?;
        let (Some(kdf), Some(wrapped)) = (&m.kdf, &m.lmk_pw) else {
            return Err(VaultError::NotInitialized);
        };
        // Bounds are checked here, before Argon2 can run.
        let params =
            KdfParams::from_cbor(kdf).map_err(|e| VaultError::Corrupt(format!("meta.kdf: {e}")))?;
        let backoff = m.backoff();
        if let Err(retry_after) = backoff.check(self.inner.store.now()) {
            return Err(VaultError::Backoff { retry_after });
        }
        let kek = self.derive(password, params).await?;
        match unwrap_key32(&kek, &WrapPurpose::Lmk, wrapped) {
            Ok(lmk) => {
                if backoff.failures > 0 {
                    self.inner
                        .store
                        .write(|w| {
                            w.delete_meta(keys::UNLOCK_FAILURES)?;
                            w.delete_meta(keys::UNLOCK_NEXT_ALLOWED_AT)
                        })
                        .await
                        .map_err(storage)?;
                }
                Ok((lmk, params))
            }
            Err(CryptoError::Auth | CryptoError::Malformed(_)) => {
                // Read-modify-write in one transaction so concurrent processes
                // count every failure.
                let next = self
                    .inner
                    .store
                    .write(|w| {
                        let r = w.as_read();
                        let cur = BackoffState::decode(
                            r.get_meta(keys::UNLOCK_FAILURES)?.as_deref(),
                            r.get_meta(keys::UNLOCK_NEXT_ALLOWED_AT)?.as_deref(),
                        );
                        let next = cur.after_failure(w.now());
                        w.set_meta(keys::UNLOCK_FAILURES, &next.failures_bytes())?;
                        w.set_meta(keys::UNLOCK_NEXT_ALLOWED_AT, &next.next_allowed_at_bytes())?;
                        Ok(next)
                    })
                    .await
                    .map_err(storage)?;
                tracing::info!(failures = next.failures, "vault unlock failed");
                Err(VaultError::WrongPassword {
                    failures: next.failures,
                    retry_after: next.current_delay(),
                })
            }
            Err(other) => Err(VaultError::from_crypto(other, "meta.lmk_wrapped_pw")),
        }
    }

    /// Checks `password` without loading anything (e.g. before enabling
    /// keyring unlock). Counts toward the backoff like an unlock.
    ///
    /// # Errors
    /// As [`VaultEngine::unlock`].
    pub async fn verify_password(&self, password: &SecretString) -> Result<(), VaultError> {
        self.try_password(password).await.map(drop)
    }

    /// Unlocks with the master password: honours the backoff (Argon2 doesn't
    /// run while it is active), derives the KEK, unwraps the LMK and every
    /// vault key, decrypts every item and runs item migrations. When the
    /// stored Argon2 cost differs from the engine's, the LMK is re-wrapped
    /// with the engine's cost.
    ///
    /// # Errors
    /// [`VaultError::NotInitialized`], [`VaultError::Backoff`],
    /// [`VaultError::WrongPassword`] (counter persisted, nothing else
    /// changed), [`VaultError::Corrupt`] (e.g. `meta.kdf` out of bounds),
    /// [`VaultError::Storage`], [`VaultError::Busy`].
    pub async fn unlock(&self, password: &SecretString) -> Result<UnlockReport, VaultError> {
        let (lmk, params) = self.try_password(password).await?;
        if params.cost() != self.inner.cost {
            if let Err(e) = self.rewrap_password(&lmk, password).await {
                tracing::warn!(error = %e, "could not re-wrap the vault key with the new Argon2 cost");
            } else {
                tracing::info!("vault key re-wrapped with the configured Argon2 cost");
            }
        }
        self.open_vaults(lmk, UnlockMethod::Password).await
    }

    async fn keyring_kek(&self, m: &Meta) -> Result<Key32, VaultError> {
        let account = keyring_account(&m.db_id()?);
        let keyring = Arc::clone(&self.inner.keyring);
        let secret = blocking(move || keyring.get(&account))
            .await?
            .map_err(|e| VaultError::Keyring(e.0))?
            .ok_or_else(|| VaultError::Keyring("the keyring entry is missing".into()))?;
        Key32::from_slice(&secret)
            .map_err(|_| VaultError::Keyring("the keyring entry is malformed".into()))
    }

    async fn keyring_lmk(&self) -> Result<Key32, VaultError> {
        let m = self.meta().await?;
        if m.kdf.is_none() {
            return Err(VaultError::NotInitialized);
        }
        let wrapped = m.lmk_keyring.clone().ok_or(VaultError::KeyringNotEnabled)?;
        let kek = self.keyring_kek(&m).await?;
        unwrap_key32(&kek, &WrapPurpose::Lmk, &wrapped).map_err(|_| {
            VaultError::Keyring("the keyring entry does not match this database".into())
        })
    }

    /// Unlocks with the OS keyring (at start, when enabled on this device). No
    /// backoff: the OS gates the keyring. On any error the UI falls back to
    /// the password prompt.
    ///
    /// # Errors
    /// [`VaultError::KeyringNotEnabled`], [`VaultError::Keyring`] (entry
    /// missing, prompt cancelled, wrong entry, no keyring service),
    /// [`VaultError::NotInitialized`].
    pub async fn unlock_with_keyring(&self) -> Result<UnlockReport, VaultError> {
        let lmk = self.keyring_lmk().await?;
        self.open_vaults(lmk, UnlockMethod::Keyring).await
    }

    /// "Forgot password?" for local-only users with keyring unlock: checks
    /// `new_password`'s strength, unlocks through the keyring and re-wraps the
    /// LMK under the new password (new salt). Leaves the engine unlocked.
    ///
    /// # Errors
    /// [`VaultError::WeakPassword`] (nothing else happens),
    /// [`VaultError::KeyringNotEnabled`], [`VaultError::Keyring`],
    /// [`VaultError::Storage`].
    pub async fn reset_password_with_keyring(
        &self,
        new_password: &SecretString,
    ) -> Result<UnlockReport, VaultError> {
        check_strength(new_password.expose_secret(), &[])?;
        let lmk = self.keyring_lmk().await?;
        self.rewrap_password(&lmk, new_password).await?;
        tracing::info!("master password reset through the keyring");
        self.open_vaults(lmk, UnlockMethod::Keyring).await
    }

    /// Changes the master password (local-only; with sync this goes through
    /// the server flow, T87): `old` is verified by unwrapping (with the
    /// backoff), then the LMK is re-wrapped under a KEK from `new` with a new
    /// salt and the engine's Argon2 cost. The keyring wrap is unchanged.
    ///
    /// # Errors
    /// [`VaultError::WeakPassword`] (checked first), [`VaultError::WrongPassword`],
    /// [`VaultError::Backoff`], [`VaultError::Storage`].
    pub async fn change_password(
        &self,
        old: &SecretString,
        new: &SecretString,
    ) -> Result<(), VaultError> {
        check_strength(new.expose_secret(), &[])?;
        let (lmk, _) = self.try_password(old).await?;
        if let Some(u) = self.inner.state.read().await.as_ref()
            && u.lmk.key != lmk
        {
            return Err(VaultError::Corrupt(
                "the password unlocks a different vault".into(),
            ));
        }
        self.rewrap_password(&lmk, new).await?;
        tracing::info!("master password changed");
        Ok(())
    }

    async fn rewrap_password(
        &self,
        lmk: &Key32,
        password: &SecretString,
    ) -> Result<(), VaultError> {
        let mut rng = os_rng();
        let params = KdfParams::generate(self.inner.cost, &mut rng);
        let kek = self.derive(password, params).await?;
        let lmk_pw = wrap_key(&kek, &WrapPurpose::Lmk, lmk.expose_secret(), &mut rng)
            .map_err(|e| VaultError::from_crypto(e, "lmk"))?;
        let kdf = params.to_cbor();
        self.inner
            .store
            .write(move |w| {
                w.set_meta(keys::KDF, &kdf)?;
                w.set_meta(keys::LMK_WRAPPED_PW, &lmk_pw)?;
                w.delete_meta(keys::UNLOCK_FAILURES)?;
                w.delete_meta(keys::UNLOCK_NEXT_ALLOWED_AT)
            })
            .await
            .map_err(storage)
    }

    /// Turns keyring unlock on for this device (a new random keyring KEK under
    /// service `courier-ftp`, account `lmk-kek:<db_id>`, plus
    /// `meta.lmk_wrapped_keyring`) or off (the wrap and the entry are deleted).
    /// Needs an unlocked vault.
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::Keyring`], [`VaultError::Storage`].
    pub async fn set_keyring_unlock(&self, enable: bool) -> Result<(), VaultError> {
        let db_id = self.meta().await?.db_id()?;
        let account = keyring_account(&db_id);
        let keyring = Arc::clone(&self.inner.keyring);
        if enable {
            let mut rng = os_rng();
            let kek = random_key32(&mut rng);
            let wrapped = {
                let state = self.inner.state.read().await;
                let u = state.as_ref().ok_or(VaultError::Locked)?;
                wrap_key(&kek, &WrapPurpose::Lmk, u.lmk.key.expose_secret(), &mut rng)
                    .map_err(|e| VaultError::from_crypto(e, "lmk"))?
            };
            let secret = Zeroizing::new(kek.expose_secret().to_vec());
            blocking(move || keyring.set(&account, &secret))
                .await?
                .map_err(|e| VaultError::Keyring(e.0))?;
            self.inner
                .store
                .write(move |w| w.set_meta(keys::LMK_WRAPPED_KEYRING, &wrapped))
                .await
                .map_err(storage)?;
            tracing::info!("keyring unlock enabled");
            Ok(())
        } else {
            if !self.is_unlocked().await {
                return Err(VaultError::Locked);
            }
            self.inner
                .store
                .write(|w| w.delete_meta(keys::LMK_WRAPPED_KEYRING))
                .await
                .map_err(storage)?;
            tracing::info!("keyring unlock disabled");
            blocking(move || keyring.delete(&account))
                .await?
                .map_err(|e| VaultError::Keyring(e.0))
        }
    }

    /// Unwraps every vault key, decrypts and migrates every item, loads the
    /// device id and the HLC, and stores the unlocked state.
    async fn open_vaults(
        &self,
        lmk: Key32,
        method: UnlockMethod,
    ) -> Result<UnlockReport, VaultError> {
        let lmk = self.track(lmk);
        let (rows, items, device, hlc) = self
            .inner
            .store
            .read(|r| {
                Ok((
                    r.list_vaults()?,
                    r.list_all_items()?,
                    r.get_device_id()?,
                    r.get_hlc_last()?,
                ))
            })
            .await
            .map_err(storage)?;
        let mut vaults = BTreeMap::new();
        let mut personal = None;
        for row in rows {
            let purpose = WrapPurpose::VaultKey(*row.id.as_bytes());
            match unwrap_key32(&lmk.key, &purpose, &row.wrapped_key) {
                Ok(vk) => {
                    if row.kind == VaultKind::Personal {
                        personal = Some(row.id);
                    }
                    vaults.insert(
                        row.id,
                        VaultKeyEntry {
                            key_version: row.key_version,
                            key: self.track(vk),
                        },
                    );
                }
                // Not wrapped under the LMK (e.g. a team vault awaiting a grant).
                Err(e) => {
                    tracing::warn!(vault = %row.id.short(), error = %e, "vault key does not unwrap");
                }
            }
        }
        let personal = personal
            .ok_or_else(|| VaultError::Corrupt("the personal vault key is missing".into()))?;
        let device =
            device.ok_or_else(|| VaultError::Corrupt("meta.device_id is missing".into()))?;
        let clock = HlcClock::new(SystemClock).with_last(hlc.unwrap_or(Hlc::ZERO));
        let mut unlocked = Unlocked {
            lmk,
            vaults,
            personal,
            device,
            clock,
            method,
            items: BTreeMap::new(),
        };
        let mut report = UnlockReport {
            method,
            items: 0,
            undecryptable: 0,
            read_only: 0,
        };
        for row in &items {
            match unlocked.open(row) {
                Ok(body) => {
                    let outcome = migrate(body);
                    self.inner.store.set_read_only(row.id, outcome.read_only);
                    if outcome.read_only {
                        report.read_only += 1;
                    }
                    if row.deleted || outcome.body.is_deleted() {
                        continue;
                    }
                    report.items += 1;
                    unlocked.items.insert(
                        row.id,
                        Cached {
                            vault_id: row.vault_id,
                            body: outcome.body,
                            read_only: outcome.read_only,
                        },
                    );
                }
                Err(e) => {
                    report.undecryptable += 1;
                    tracing::warn!(item = %row.id.short(), error = %e, "item does not decrypt");
                }
            }
        }
        *self.inner.state.write().await = Some(unlocked);
        tracing::info!(
            items = report.items,
            undecryptable = report.undecryptable,
            read_only = report.read_only,
            "vault unlocked"
        );
        Ok(report)
    }

    /// Locks: drops (and zeroizes) every key and every decrypted item. Only
    /// ciphertext stays.
    pub async fn lock(&self) {
        let taken = self.inner.state.write().await.take();
        if taken.is_some() {
            drop(taken);
            tracing::info!("vault locked");
        }
    }

    /// Every live item, decrypted, for a `.cftp-backup` (T73).
    ///
    /// # Errors
    /// [`VaultError::Locked`].
    pub async fn backup_items(&self) -> Result<Vec<BackupItem>, VaultError> {
        let state = self.inner.state.read().await;
        let u = state.as_ref().ok_or(VaultError::Locked)?;
        Ok(u.items
            .iter()
            .map(|(id, c)| BackupItem {
                id: *id,
                vault_id: c.vault_id,
                body: c.body.clone(),
            })
            .collect())
    }

    /// Every live item sealed into a `.cftp-backup` file protected by
    /// `password` (with the engine's Argon2 cost).
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::Corrupt`].
    pub async fn export_backup(&self, password: &SecretString) -> Result<Vec<u8>, VaultError> {
        let items = self.backup_items().await?;
        let password = SecretString::from(password.expose_secret().to_owned());
        let cost = self.inner.cost;
        let now = self.inner.store.now();
        self.inner.kdf_runs.fetch_add(1, Ordering::SeqCst);
        blocking(move || backup::seal(&items, &password, cost, now, &mut os_rng()))
            .await?
            .map_err(|e| VaultError::Corrupt(e.to_string()))
    }
}

#[async_trait]
impl ItemVault for VaultEngine {
    async fn is_unlocked(&self) -> bool {
        VaultEngine::is_unlocked(self).await
    }

    async fn get(&self, id: ItemId) -> Result<Option<VaultItem>, VaultError> {
        let state = self.inner.state.read().await;
        Ok(state.as_ref().ok_or(VaultError::Locked)?.item(id))
    }

    async fn list(&self, kind: ItemKind) -> Result<Vec<VaultItem>, VaultError> {
        let state = self.inner.state.read().await;
        let u = state.as_ref().ok_or(VaultError::Locked)?;
        Ok(u.items
            .iter()
            .filter(|(_, c)| c.body.kind == kind)
            .filter_map(|(id, _)| u.item(*id))
            .collect())
    }

    async fn put(&self, write: ItemWrite) -> Result<bool, VaultError> {
        let store_passwords = self.inner.store_passwords.load(Ordering::SeqCst);
        let mut state = self.inner.state.write().await;
        let u = state.as_mut().ok_or(VaultError::Locked)?;
        let (vault, before) = match u.items.get(&write.id) {
            Some(c) if c.read_only => return Err(VaultError::ReadOnlyItem(write.id)),
            Some(c) if c.body.kind != write.kind => {
                return Err(VaultError::WrongKind {
                    id: write.id,
                    expected: write.kind,
                    found: c.body.kind,
                });
            }
            Some(c) => (c.vault_id, Some(c.body.clone())),
            None => (write.vault.unwrap_or(u.personal), None),
        };
        if !u.vaults.contains_key(&vault) {
            return Err(VaultError::Corrupt(format!(
                "vault {} is not loaded",
                vault.short()
            )));
        }
        let mut body = before
            .clone()
            .unwrap_or_else(|| ItemBody::new(write.kind, current_schema(write.kind)));
        let device = u.device;
        (write.edit)(&mut body, &mut u.clock, device);
        if !store_passwords {
            strip_passwords(&mut body, &mut u.clock, device);
        }
        if before.as_ref() == Some(&body) {
            if let Some(mut b) = before {
                scrub(&mut b);
            }
            return Ok(false);
        }
        if let Some(mut b) = before {
            scrub(&mut b);
        }
        let id = write.id;
        let (key_version, env) = u.seal(vault, id, &body)?;
        let deleted = body.is_deleted();
        let hlc = u.clock.last();
        self.inner
            .store
            .write(move |w| {
                w.put_item(vault, id, key_version, &env, deleted)?;
                w.set_hlc_last(hlc)
            })
            .await
            .map_err(storage)?;
        if deleted {
            u.items.remove(&id);
        } else {
            let read_only = is_read_only(&body);
            u.items.insert(
                id,
                Cached {
                    vault_id: vault,
                    body,
                    read_only,
                },
            );
        }
        tracing::debug!(item = %id.short(), kind = %write.kind, "item written");
        Ok(true)
    }

    async fn delete(&self, id: ItemId) -> Result<bool, VaultError> {
        let mut state = self.inner.state.write().await;
        let u = state.as_mut().ok_or(VaultError::Locked)?;
        let Some(cached) = u.items.get(&id) else {
            return Ok(false);
        };
        if cached.read_only {
            return Err(VaultError::ReadOnlyItem(id));
        }
        let vault = cached.vault_id;
        let mut body = cached.body.clone();
        let device = u.device;
        body.delete(&mut u.clock, device);
        let sealed = u.seal(vault, id, &body);
        scrub(&mut body);
        let (key_version, env) = sealed?;
        let hlc = u.clock.last();
        self.inner
            .store
            .write(move |w| {
                w.put_item(vault, id, key_version, &env, true)?;
                w.set_hlc_last(hlc)
            })
            .await
            .map_err(storage)?;
        u.items.remove(&id);
        tracing::debug!(item = %id.short(), "item deleted");
        Ok(true)
    }
}
