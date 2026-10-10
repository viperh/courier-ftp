//! The vault engine: state machine, first run, password and keyring unlock, the
//! persisted backoff, password change, keyring enrolment and lock (sverb
//! `services/vault/engine.rs`, D13).
//!
//! Argon2 and keyring calls run in `spawn_blocking`; SQLite goes through the store's
//! own blocking pool. Keys live only in the [`Session`] of an unlocked vault, each in a
//! [`TrackedKey`] (`Locked<Key32>`, counted per engine so tests can prove that
//! [`VaultEngine::lock`] dropped them all).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use courier_ftp_crypto::envelope::{open_item, seal_item};
use courier_ftp_crypto::kdf::argon2id;
use courier_ftp_crypto::random::{os_rng, random_key32, random_salt16};
use courier_ftp_crypto::wrap::{WrapPurpose, unwrap_key, unwrap_key32, wrap_key};
use courier_ftp_crypto::{CryptoError, Key32};
use courier_ftp_store::meta::keys;
use courier_ftp_store::{ItemRow, Store, VaultKind, VaultRow};
use parking_lot::{Mutex, RwLock};
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use super::cache::{self, ItemCache, OpenFailure};
use super::trust::VaultHostKeyStore;
use super::{
    BackoffState, DeviceLocalInfo, InitReport, KdfParams, KeyringStore, LockReason, USER_INPUTS,
    UnlockMethod, UnlockReport, VaultChange, VaultError, VaultInfo, VaultOptions, VaultPermission,
    VaultState, VaultStatus, check_strength, keyring_account,
};
use crate::hardening::Locked;
use crate::model::LocalPath;
use crate::model::item::{
    DeviceId, Hlc, HlcClock, ItemBody, ItemId, PhysicalClock, UnixMillis, VaultId,
};
use crate::secret::SecretString;
use crate::trust::{HostKeyStore, MemoryHostKeyStore, SwitchableHostKeyStore};

/// Capacity of the [`VaultChange`] broadcast.
const CHANGE_CAPACITY: usize = 256;
/// How often the change poller checks `PRAGMA data_version`.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// How long [`VaultEngine::lock`] waits for in-flight writes.
const LOCK_WAIT: Duration = Duration::from_secs(5);
/// `meta` key prefix of a shared vault's permission (T89).
const PERMISSION_PREFIX: &str = "vault_permission/";

/// A key counted in the engine's live-key counter, in `mlock`ed pages where the OS
/// allows it; zeroized on drop.
pub(crate) struct TrackedKey {
    key: Locked<Key32>,
    live: Arc<AtomicUsize>,
}

impl TrackedKey {
    pub(crate) fn new(key: Key32, live: &Arc<AtomicUsize>) -> Self {
        live.fetch_add(1, Ordering::SeqCst);
        Self {
            key: Locked::new(key),
            live: Arc::clone(live),
        }
    }

    pub(crate) fn key(&self) -> &Key32 {
        &self.key
    }
}

impl Drop for TrackedKey {
    fn drop(&mut self) {
        // `Locked<Key32>` zeroizes the key when it is dropped right after this.
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(crate) struct VaultKeyEntry {
    pub kind: VaultKind,
    pub key_version: u32,
    pub key: TrackedKey,
}

/// An unlocked vault: keys, the item cache and the device-local caches.
pub(crate) struct Session {
    pub lmk: TrackedKey,
    pub vaults: RwLock<BTreeMap<VaultId, VaultKeyEntry>>,
    pub device_key: TrackedKey,
    pub device_id: DeviceId,
    pub method: UnlockMethod,
    pub clock: Mutex<HlcClock>,
    pub cache: RwLock<ItemCache>,
    pub approvals: RwLock<HashSet<(ItemId, String, [u8; 32])>>,
    pub device_local: RwLock<HashMap<ItemId, DeviceLocalInfo>>,
    pub permissions: RwLock<HashMap<VaultId, VaultPermission>>,
    pub data_version: AtomicI64,
    pub skipped_vaults: usize,
}

impl Session {
    /// Seals `body` for `id` in `vault` under the vault's current key.
    pub(crate) fn seal(
        &self,
        vault: VaultId,
        id: ItemId,
        body: &ItemBody,
    ) -> Result<(u32, Vec<u8>), VaultError> {
        let cbor = Zeroizing::new(
            body.to_cbor()
                .map_err(|e| VaultError::Corrupt(format!("item body: {e}")))?,
        );
        if cbor.len() > super::MAX_BODY_LEN {
            return Err(VaultError::ItemTooLarge { bytes: cbor.len() });
        }
        let map = self.vaults.read();
        let entry = map.get(&vault).ok_or(VaultError::Locked)?;
        let env = seal_item(
            entry.key.key(),
            vault.as_bytes(),
            id.as_bytes(),
            entry.key_version,
            &cbor,
            &mut os_rng(),
        )
        .map_err(|e| from_crypto(e, "item"))?;
        Ok((entry.key_version, env))
    }

    /// Decrypts and decodes a stored row.
    pub(crate) fn decode_row(&self, row: &ItemRow) -> Result<(ItemBody, bool), OpenFailure> {
        let vault = VaultId::from_bytes(row.vault_id);
        let plain = {
            let map = self.vaults.read();
            let entry = map
                .get(&vault)
                .ok_or_else(|| OpenFailure::Unreadable("vault key not loaded".into()))?;
            let lookup = |v: u32| (v == entry.key_version).then_some(entry.key.key());
            open_item(lookup, &row.vault_id, &row.id, &row.envelope)
                .map_err(|e| OpenFailure::Unreadable(e.to_string()))?
        };
        cache::decode_body(&plain)
    }

    /// [`Session::decode_row`] for reads and writes that need the body.
    pub(crate) fn open(&self, row: &ItemRow) -> Result<(ItemBody, bool), VaultError> {
        let id = ItemId::from_bytes(row.id);
        self.decode_row(row).map_err(|e| match e {
            OpenFailure::UnknownKind => VaultError::ReadOnlyItem(id),
            OpenFailure::Unreadable(why) => {
                VaultError::Corrupt(format!("item {} does not decrypt: {why}", id.short()))
            }
        })
    }

    pub(crate) fn permission(&self, vault: VaultId) -> VaultPermission {
        match self.vaults.read().get(&vault).map(|e| e.kind) {
            Some(VaultKind::Personal) => VaultPermission::Manage,
            _ => self
                .permissions
                .read()
                .get(&vault)
                .copied()
                .unwrap_or(VaultPermission::Write),
        }
    }

    pub(crate) fn personal(&self) -> Option<VaultId> {
        self.vaults
            .read()
            .iter()
            .find(|(_, e)| e.kind == VaultKind::Personal)
            .map(|(id, _)| *id)
    }

    pub(crate) fn has_vault(&self, vault: VaultId) -> bool {
        self.vaults.read().contains_key(&vault)
    }
}

pub(crate) fn from_crypto(err: CryptoError, what: &str) -> VaultError {
    match err {
        CryptoError::Auth => VaultError::Corrupt(format!("{what} does not decrypt")),
        other => VaultError::Corrupt(format!("{what}: {other}")),
    }
}

/// The HLC's physical clock behind the options' shared one.
#[derive(Debug)]
struct SharedPhysical(Arc<dyn PhysicalClock>);

impl PhysicalClock for SharedPhysical {
    fn now(&self) -> Duration {
        self.0.now()
    }
}

struct Slot {
    state: VaultState,
    session: Option<Arc<Session>>,
}

pub(crate) struct Inner {
    pub store: Store,
    keyring: Arc<dyn KeyringStore>,
    pub opts: RwLock<VaultOptions>,
    host_keys: Arc<SwitchableHostKeyStore>,
    slot: RwLock<Slot>,
    unlock_lock: tokio::sync::Mutex<()>,
    /// In-flight operations hold a read guard; `lock` takes the write guard.
    gate: tokio::sync::RwLock<()>,
    pub changes: broadcast::Sender<VaultChange>,
    pub local_changes: watch::Sender<u64>,
    kdf_runs: AtomicUsize,
    pub live_keys: Arc<AtomicUsize>,
    pub poller: Mutex<Option<JoinHandle<()>>>,
    background: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(h) = self.poller.get_mut().take() {
            h.abort();
        }
    }
}

/// An operation on the unlocked vault: holds the operation gate (so `lock` waits for
/// it) and the session.
pub(crate) struct Op<'a> {
    _gate: tokio::sync::RwLockReadGuard<'a, ()>,
    pub s: Arc<Session>,
}

/// The vault engine. Cheap to clone; every clone is the same engine.
#[derive(Clone)]
pub struct VaultEngine {
    pub(crate) inner: Arc<Inner>,
}

impl fmt::Debug for VaultEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultEngine")
            .field("state", &self.state())
            .field("keyring", &self.inner.keyring)
            .field("live_keys", &self.live_keys())
            .finish_non_exhaustive()
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, VaultError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| VaultError::Storage(format!("background task failed: {e}")))
}

/// Raw meta values read in one snapshot.
#[derive(Default)]
struct Meta {
    kdf: Option<Vec<u8>>,
    lmk_pw: Option<Vec<u8>>,
    lmk_keyring: Option<Vec<u8>>,
    failures: Option<Vec<u8>>,
    next_allowed: Option<Vec<u8>>,
    db_id: Option<Vec<u8>>,
}

fn db_id_text(db_id: Option<Vec<u8>>) -> Result<String, VaultError> {
    db_id
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or_else(|| VaultError::Corrupt("meta.db_id is missing".into()))
}

/// Everything `open_session` reads in one snapshot.
struct OpenData {
    vaults: Vec<VaultRow>,
    items: Vec<ItemRow>,
    device_id: Option<Vec<u8>>,
    hlc_last: Option<Vec<u8>>,
    device_key: Option<Vec<u8>>,
    locals: Vec<courier_ftp_store::DeviceLocal>,
    approvals: Vec<courier_ftp_store::LocalApproval>,
    permissions: Vec<(VaultId, Option<Vec<u8>>)>,
}

pub(crate) fn device_local_info(l: &courier_ftp_store::DeviceLocal) -> DeviceLocalInfo {
    DeviceLocalInfo {
        last_connected_at: l.last_connected_at.map(UnixMillis),
        frecency: l.frecency,
        local_dir_override: l.local_dir_override.as_deref().map(LocalPath::new),
        tree_expanded: l.tree_expanded,
    }
}

pub(crate) fn hlc_from_meta(bytes: Option<&[u8]>) -> Hlc {
    bytes
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map_or(Hlc::ZERO, |b| Hlc::from_u64(u64::from_be_bytes(b)))
}

impl VaultEngine {
    /// An engine over `store`. `host_keys` is the switchable store the SSH verifier
    /// holds: the engine points it at the vault on unlock and back at a fresh memory
    /// store on lock.
    pub fn new(
        store: Store,
        keyring: Arc<dyn KeyringStore>,
        opts: VaultOptions,
        host_keys: Arc<SwitchableHostKeyStore>,
    ) -> Self {
        let (changes, _) = broadcast::channel(CHANGE_CAPACITY);
        let (local_changes, _) = watch::channel(0);
        Self {
            inner: Arc::new(Inner {
                store,
                keyring,
                opts: RwLock::new(opts),
                host_keys,
                slot: RwLock::new(Slot {
                    state: VaultState::Locked,
                    session: None,
                }),
                unlock_lock: tokio::sync::Mutex::new(()),
                gate: tokio::sync::RwLock::new(()),
                changes,
                local_changes,
                kdf_runs: AtomicUsize::new(0),
                live_keys: Arc::new(AtomicUsize::new(0)),
                poller: Mutex::new(None),
                background: Mutex::new(None),
            }),
        }
    }

    /// The settings changed (T68).
    pub fn set_options(&self, opts: VaultOptions) {
        *self.inner.opts.write() = opts;
    }

    pub(crate) fn opts(&self) -> VaultOptions {
        self.inner.opts.read().clone()
    }

    pub(crate) fn store(&self) -> &Store {
        &self.inner.store
    }

    /// The current state (no I/O). A fresh database reads `Locked` until
    /// [`VaultEngine::status`] (or an unlock attempt) found it uninitialised.
    pub fn state(&self) -> VaultState {
        self.inner.slot.read().state
    }

    /// Subscribes to [`VaultChange`]s.
    pub fn subscribe(&self) -> broadcast::Receiver<VaultChange> {
        self.inner.changes.subscribe()
    }

    /// Bumped after every committed local write (T88).
    pub fn local_changes(&self) -> watch::Receiver<u64> {
        self.inner.local_changes.subscribe()
    }

    /// How many times Argon2 ran (test hook).
    pub fn kdf_runs(&self) -> usize {
        self.inner.kdf_runs.load(Ordering::SeqCst)
    }

    /// Keys currently held by this engine (test hook).
    pub fn live_keys(&self) -> usize {
        self.inner.live_keys.load(Ordering::SeqCst)
    }

    /// The switchable host-key store this engine drives.
    pub fn host_key_store(&self) -> Arc<SwitchableHostKeyStore> {
        Arc::clone(&self.inner.host_keys)
    }

    /// Waits for the background cost upgrade started by the last unlock (tests).
    #[doc(hidden)]
    pub async fn wait_background(&self) {
        let handle = self.inner.background.lock().take();
        if let Some(h) = handle {
            let _ = h.await;
        }
    }

    pub(crate) fn emit(&self, change: VaultChange) {
        // No receivers is fine.
        let _ = self.inner.changes.send(change);
    }

    /// The unlocked session, holding the operation gate.
    pub(crate) async fn op(&self) -> Result<Op<'_>, VaultError> {
        let gate = self.inner.gate.read().await;
        let s = self
            .inner
            .slot
            .read()
            .session
            .clone()
            .ok_or(VaultError::Locked)?;
        Ok(Op { _gate: gate, s })
    }

    /// Runs `f` on the unlocked session (sync methods; no I/O).
    pub(crate) fn with_session<T>(
        &self,
        f: impl FnOnce(&Session) -> Result<T, VaultError>,
    ) -> Result<T, VaultError> {
        let slot = self.inner.slot.read();
        let s = slot.session.as_deref().ok_or(VaultError::Locked)?;
        f(s)
    }

    pub(crate) fn weak(&self) -> Weak<Inner> {
        Arc::downgrade(&self.inner)
    }

    pub(crate) fn from_inner(inner: Arc<Inner>) -> Self {
        Self { inner }
    }

    async fn meta(&self) -> Result<Meta, VaultError> {
        Ok(self
            .inner
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
            .await?)
    }

    /// The vault's state, keyring setting, backoff and (unlocked) unreadable counts.
    ///
    /// # Errors
    /// [`VaultError::Storage`], [`VaultError::Busy`].
    pub async fn status(&self) -> Result<VaultStatus, VaultError> {
        let m = self.meta().await?;
        let backoff = BackoffState::decode(m.failures.as_deref(), m.next_allowed.as_deref());
        let state = {
            let mut slot = self.inner.slot.write();
            match (slot.state, m.kdf.is_some()) {
                (VaultState::Locked, false) => slot.state = VaultState::Uninitialised,
                (VaultState::Uninitialised, true) => slot.state = VaultState::Locked,
                _ => {}
            }
            slot.state
        };
        let (unreadable_items, unknown_kind_items) = self
            .with_session(|s| {
                let c = s.cache.read();
                Ok((c.unreadable(), c.unknown_kind()))
            })
            .unwrap_or((0, 0));
        Ok(VaultStatus {
            state,
            keyring_enabled: m.lmk_keyring.is_some(),
            backoff,
            retry_after: backoff.check(self.inner.store.now()).err(),
            unreadable_items,
            unknown_kind_items,
        })
    }

    /// Whether the OS keyring works (writes and deletes a probe entry).
    pub async fn keyring_available(&self) -> bool {
        let keyring = Arc::clone(&self.inner.keyring);
        let ok = blocking(move || keyring.probe()).await.unwrap_or(false);
        if !ok {
            tracing::debug!("no usable OS keyring; keyring unlock unavailable");
        }
        ok
    }

    async fn derive(
        &self,
        password: &SecretString,
        params: KdfParams,
    ) -> Result<Key32, VaultError> {
        let pw = Zeroizing::new(password.expose().as_bytes().to_vec());
        self.inner.kdf_runs.fetch_add(1, Ordering::SeqCst);
        let started = std::time::Instant::now();
        let key = blocking(move || argon2id(&pw, &params.argon2()))
            .await?
            .map_err(|e| VaultError::Corrupt(format!("meta.kdf: {e}")))?;
        tracing::debug!(
            m_kib = params.m_kib,
            t = params.t,
            ms = started.elapsed().as_millis() as u64,
            "argon2id"
        );
        Ok(key)
    }

    fn track(&self, key: Key32) -> TrackedKey {
        TrackedKey::new(key, &self.inner.live_keys)
    }

    /// First run: LMK, salt, KEK, personal vault, device key, device id, database id
    /// and HLC, written in one transaction. `enable_keyring` also stores a keyring KEK
    /// (a keyring failure does not fail first run; see [`InitReport::keyring_error`]).
    ///
    /// # Errors
    /// [`VaultError::WeakPassword`], [`VaultError::AlreadyInitialized`],
    /// [`VaultError::UnlockInProgress`], [`VaultError::Storage`], [`VaultError::Busy`].
    pub async fn initialize(
        &self,
        password: SecretString,
        enable_keyring: bool,
    ) -> Result<InitReport, VaultError> {
        check_strength(password.expose(), &USER_INPUTS)?;
        let _unlocking = self
            .inner
            .unlock_lock
            .try_lock()
            .map_err(|_| VaultError::UnlockInProgress)?;
        if self.meta().await?.kdf.is_some() {
            return Err(VaultError::AlreadyInitialized);
        }
        let opts = self.opts();
        let mut rng = os_rng();
        let lmk = random_key32(&mut rng);
        let params = opts.cost.with_salt(random_salt16(&mut rng));
        let kek = self.derive(&password, params).await?;
        let lmk_pw = wrap_key(&kek, &WrapPurpose::Lmk, lmk.expose_secret(), &mut rng)
            .map_err(|e| from_crypto(e, "lmk"))?;
        drop(kek);

        let vault_id = VaultId::new();
        let vk = random_key32(&mut rng);
        let wrapped_vk = wrap_key(
            &lmk,
            &WrapPurpose::VaultKey(*vault_id.as_bytes()),
            vk.expose_secret(),
            &mut rng,
        )
        .map_err(|e| from_crypto(e, "vault key"))?;
        let device_key = random_key32(&mut rng);
        let device_key_wrapped = wrap_key(
            &lmk,
            &WrapPurpose::DeviceKey,
            device_key.expose_secret(),
            &mut rng,
        )
        .map_err(|e| from_crypto(e, "device key"))?;
        let device_id = DeviceId::new();
        let mut clock = HlcClock::new(SharedPhysical(Arc::clone(&opts.physical_clock)));
        let hlc_last = clock.now();
        let db_id = uuid::Uuid::now_v7().to_string();

        // Optional keyring KEK: stored before the transaction, removed if it fails.
        let mut keyring_error = None;
        let mut lmk_keyring = None;
        let account = keyring_account(&db_id);
        if enable_keyring {
            let kr_kek = random_key32(&mut rng);
            let keyring = Arc::clone(&self.inner.keyring);
            let secret = Zeroizing::new(kr_kek.expose_secret().to_vec());
            let acct = account.clone();
            match blocking(move || keyring.set(&acct, &secret)).await? {
                Ok(()) => {
                    lmk_keyring = Some(
                        wrap_key(&kr_kek, &WrapPurpose::Lmk, lmk.expose_secret(), &mut rng)
                            .map_err(|e| from_crypto(e, "lmk"))?,
                    );
                }
                Err(e) => {
                    tracing::debug!("keyring enrolment at first run failed");
                    keyring_error = Some(e.0);
                }
            }
        }

        let kdf = params.to_cbor();
        let device_bytes = *device_id.as_bytes();
        let had_keyring = lmk_keyring.is_some();
        let db_id_w = db_id.clone();
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
                w.set_meta(keys::DEVICE_KEY_WRAPPED, &device_key_wrapped)?;
                w.set_meta(keys::DB_ID, db_id_w.as_bytes())?;
                w.set_meta(keys::DEVICE_ID, &device_bytes)?;
                w.set_meta(keys::HLC_LAST, &hlc_last.as_u64().to_be_bytes())?;
                w.delete_meta(keys::UNLOCK_FAILURES)?;
                w.delete_meta(keys::UNLOCK_NEXT_ALLOWED_AT)?;
                w.create_vault(
                    *vault_id.as_bytes(),
                    VaultKind::Personal,
                    None,
                    1,
                    &wrapped_vk,
                )?;
                Ok(true)
            })
            .await;
        let wrote = match wrote {
            Ok(w) => w,
            Err(e) => {
                self.forget_keyring_entry(had_keyring, account).await;
                return Err(e.into());
            }
        };
        if !wrote {
            self.forget_keyring_entry(had_keyring, account).await;
            return Err(VaultError::AlreadyInitialized);
        }
        let data_version = self.inner.store.data_version().await.unwrap_or(0);

        let mut vaults = BTreeMap::new();
        vaults.insert(
            vault_id,
            VaultKeyEntry {
                kind: VaultKind::Personal,
                key_version: 1,
                key: self.track(vk),
            },
        );
        let session = Arc::new(Session {
            lmk: self.track(lmk),
            vaults: RwLock::new(vaults),
            device_key: self.track(device_key),
            device_id,
            method: UnlockMethod::Created,
            clock: Mutex::new(clock),
            cache: RwLock::new(ItemCache::default()),
            approvals: RwLock::new(HashSet::new()),
            device_local: RwLock::new(HashMap::new()),
            permissions: RwLock::new(HashMap::new()),
            data_version: AtomicI64::new(data_version),
            skipped_vaults: 0,
        });
        self.activate(session);
        Ok(InitReport { keyring_error })
    }

    async fn forget_keyring_entry(&self, had: bool, account: String) {
        if had {
            let keyring = Arc::clone(&self.inner.keyring);
            let _ = blocking(move || keyring.delete(&account)).await;
        }
    }

    /// Checks `password` against `meta.lmk_wrapped_pw` with the persisted backoff.
    /// Returns the LMK and the `meta.kdf` bytes on success (and resets the counter).
    async fn try_password(&self, password: &SecretString) -> Result<(Key32, Vec<u8>), VaultError> {
        let m = self.meta().await?;
        let (Some(kdf), Some(wrapped)) = (m.kdf, m.lmk_pw) else {
            return Err(VaultError::NotInitialized);
        };
        // Bounds are checked before Argon2 runs.
        let params = KdfParams::from_cbor(&kdf)?;
        let backoff = BackoffState::decode(m.failures.as_deref(), m.next_allowed.as_deref());
        if let Err(retry_after) = backoff.check(self.inner.store.now()) {
            return Err(VaultError::Backoff { retry_after });
        }
        let kek = self.derive(password, params).await?;
        match unwrap_key32(&kek, &WrapPurpose::Lmk, &wrapped) {
            Ok(lmk) => {
                if backoff.failures > 0 {
                    self.inner
                        .store
                        .write(|w| {
                            w.delete_meta(keys::UNLOCK_FAILURES)?;
                            w.delete_meta(keys::UNLOCK_NEXT_ALLOWED_AT)
                        })
                        .await?;
                }
                Ok((lmk, kdf))
            }
            Err(CryptoError::Auth | CryptoError::Malformed(_)) => {
                // Read-modify-write in one transaction so concurrent processes count
                // every failure.
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
                    .await?;
                tracing::debug!(failures = next.failures, "wrong master password");
                Err(VaultError::WrongPassword {
                    failures: next.failures,
                    retry_after: next.current_delay(),
                })
            }
            Err(other) => Err(from_crypto(other, "meta.lmk_wrapped_pw")),
        }
    }

    /// Checks the master password (counts toward the backoff like an unlock; loads no
    /// keys).
    ///
    /// # Errors
    /// As [`VaultEngine::unlock`].
    pub async fn verify_password(&self, password: SecretString) -> Result<(), VaultError> {
        self.try_password(&password).await.map(drop)
    }

    fn report(&self) -> Result<UnlockReport, VaultError> {
        self.with_session(|s| {
            let c = s.cache.read();
            Ok(UnlockReport {
                method: s.method,
                items: c.items.len(),
                unreadable_items: c.unreadable(),
                unknown_kind_items: c.unknown_kind(),
                skipped_vaults: s.skipped_vaults,
            })
        })
    }

    /// Starts an unlock: refuses a second concurrent one, and marks `Unlocking`.
    fn begin_unlock(&self) -> Result<(tokio::sync::MutexGuard<'_, ()>, VaultState), VaultError> {
        let guard = self
            .inner
            .unlock_lock
            .try_lock()
            .map_err(|_| VaultError::UnlockInProgress)?;
        let mut slot = self.inner.slot.write();
        let prev = slot.state;
        if !matches!(prev, VaultState::Unlocked { .. }) {
            slot.state = VaultState::Unlocking;
        }
        Ok((guard, prev))
    }

    fn end_unlock_failed(&self, prev: VaultState, err: &VaultError) {
        let mut slot = self.inner.slot.write();
        if slot.session.is_none() {
            slot.state = if *err == VaultError::NotInitialized || prev == VaultState::Uninitialised
            {
                VaultState::Uninitialised
            } else {
                VaultState::Locked
            };
        }
    }

    /// Unlocks with the master password. On an already unlocked vault the password is
    /// still checked and the current report returned.
    ///
    /// # Errors
    /// [`VaultError::NotInitialized`], [`VaultError::Backoff`] (Argon2 did not run),
    /// [`VaultError::WrongPassword`] (counter persisted), [`VaultError::Corrupt`],
    /// [`VaultError::UnlockInProgress`], [`VaultError::Storage`], [`VaultError::Busy`].
    pub async fn unlock(&self, password: SecretString) -> Result<UnlockReport, VaultError> {
        let (_guard, prev) = self.begin_unlock()?;
        let result = async {
            let (lmk, kdf) = self.try_password(&password).await?;
            if matches!(prev, VaultState::Unlocked { .. }) {
                return self.report();
            }
            let report = self.open_session(lmk, UnlockMethod::Password).await?;
            self.maybe_upgrade_cost(password, kdf);
            Ok(report)
        }
        .await;
        if let Err(e) = &result {
            self.end_unlock_failed(prev, e);
        }
        result
    }

    async fn keyring_kek(&self, db_id: Option<Vec<u8>>) -> Result<Key32, VaultError> {
        let account = keyring_account(&db_id_text(db_id)?);
        let keyring = Arc::clone(&self.inner.keyring);
        let secret = blocking(move || keyring.get(&account))
            .await?
            .map_err(|e| VaultError::Keyring(e.0))?
            .ok_or_else(|| VaultError::Keyring("the keyring entry is missing".into()))?;
        Key32::from_slice(&secret)
            .map_err(|_| VaultError::Keyring("the keyring entry is malformed".into()))
    }

    /// Unlocks with the OS keyring. No backoff (the OS gates the keyring). T60 falls
    /// back to the password screen on any error.
    ///
    /// # Errors
    /// [`VaultError::KeyringNotEnabled`], [`VaultError::Keyring`] (entry missing,
    /// prompt cancelled, keyring unavailable, wrong entry),
    /// [`VaultError::NotInitialized`], [`VaultError::UnlockInProgress`].
    pub async fn unlock_with_keyring(&self) -> Result<UnlockReport, VaultError> {
        let (_guard, prev) = self.begin_unlock()?;
        let result = async {
            let m = self.meta().await?;
            if m.kdf.is_none() {
                return Err(VaultError::NotInitialized);
            }
            let wrapped = m.lmk_keyring.ok_or(VaultError::KeyringNotEnabled)?;
            let kek = self.keyring_kek(m.db_id).await?;
            let lmk = unwrap_key32(&kek, &WrapPurpose::Lmk, &wrapped).map_err(|_| {
                VaultError::Keyring("the keyring entry does not match this database".into())
            })?;
            if matches!(prev, VaultState::Unlocked { .. }) {
                return self.report();
            }
            self.open_session(lmk, UnlockMethod::Keyring).await
        }
        .await;
        if let Err(e) = &result {
            self.end_unlock_failed(prev, e);
        }
        result
    }

    /// Unwraps every vault key and the device key, decrypts every item into the cache
    /// and activates the session.
    async fn open_session(
        &self,
        lmk: Key32,
        method: UnlockMethod,
    ) -> Result<UnlockReport, VaultError> {
        let started = std::time::Instant::now();
        let lmk = self.track(lmk);
        let data_version = self.inner.store.data_version().await?;
        let data = self
            .inner
            .store
            .read(|r| {
                let vaults = r.list_vaults()?;
                let mut permissions = Vec::new();
                for v in vaults.iter().filter(|v| v.kind == VaultKind::Shared) {
                    let id = VaultId::from_bytes(v.id);
                    permissions.push((
                        id,
                        r.get_meta(&format!("{PERMISSION_PREFIX}{}", id.uuid()))?,
                    ));
                }
                Ok(OpenData {
                    items: r.list_all_items()?,
                    device_id: r.get_meta(keys::DEVICE_ID)?,
                    hlc_last: r.get_meta(keys::HLC_LAST)?,
                    device_key: r.get_meta(keys::DEVICE_KEY_WRAPPED)?,
                    locals: r.list_device_local()?,
                    approvals: r.list_local_approvals()?,
                    vaults,
                    permissions,
                })
            })
            .await?;
        let mut vaults = BTreeMap::new();
        let mut skipped = 0;
        for row in &data.vaults {
            let id = VaultId::from_bytes(row.id);
            match unwrap_key32(lmk.key(), &WrapPurpose::VaultKey(row.id), &row.wrapped_key) {
                Ok(vk) => {
                    vaults.insert(
                        id,
                        VaultKeyEntry {
                            kind: row.kind,
                            key_version: row.key_version,
                            key: self.track(vk),
                        },
                    );
                }
                // Not wrapped under this LMK (e.g. a team vault awaiting a grant).
                Err(_) => {
                    skipped += 1;
                    tracing::warn!(vault = %id.short(), "vault key does not unwrap; vault skipped");
                }
            }
        }
        let device_key_wrapped = data
            .device_key
            .ok_or_else(|| VaultError::Corrupt("meta.device_key_wrapped is missing".into()))?;
        let device_key = unwrap_key32(lmk.key(), &WrapPurpose::DeviceKey, &device_key_wrapped)
            .map_err(|e| from_crypto(e, "meta.device_key_wrapped"))?;
        let device_id = data
            .device_id
            .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
            .map(DeviceId::from_bytes)
            .ok_or_else(|| VaultError::Corrupt("meta.device_id is missing".into()))?;
        let hlc_last = hlc_from_meta(data.hlc_last.as_deref());
        let physical = Arc::clone(&self.inner.opts.read().physical_clock);
        let permissions = data
            .permissions
            .into_iter()
            .filter_map(|(id, v)| {
                let text = String::from_utf8(v?).ok()?;
                Some((id, VaultPermission::parse(&text)?))
            })
            .collect();
        let session = Arc::new(Session {
            lmk,
            vaults: RwLock::new(vaults),
            device_key: self.track(device_key),
            device_id,
            method,
            clock: Mutex::new(HlcClock::new(SharedPhysical(physical)).with_last(hlc_last)),
            cache: RwLock::new(ItemCache::default()),
            approvals: RwLock::new(
                data.approvals
                    .into_iter()
                    .map(|a| (ItemId::from_bytes(a.item_id), a.field, a.value_sha256))
                    .collect(),
            ),
            device_local: RwLock::new(
                data.locals
                    .iter()
                    .map(|l| (ItemId::from_bytes(l.item_id), device_local_info(l)))
                    .collect(),
            ),
            permissions: RwLock::new(permissions),
            data_version: AtomicI64::new(data_version),
            skipped_vaults: skipped,
        });
        // Decrypt every item off the runtime threads.
        let s = Arc::clone(&session);
        let items = data.items;
        let cache = blocking(move || {
            let mut cache = ItemCache::default();
            for row in &items {
                let decoded = s.decode_row(row);
                if let Err(OpenFailure::Unreadable(_)) = &decoded {
                    tracing::warn!(item = %ItemId::from_bytes(row.id).short(), "item does not decrypt");
                }
                cache
                    .items
                    .insert(ItemId::from_bytes(row.id), cache::entry_for_row(row, decoded));
            }
            cache
        })
        .await?;
        *session.cache.write() = cache;
        tracing::debug!(
            ms = started.elapsed().as_millis() as u64,
            skipped_vaults = skipped,
            "vault keys and items loaded"
        );
        self.activate(session);
        self.report()
    }

    /// Makes `session` current: host keys, poller, state, broadcast.
    fn activate(&self, session: Arc<Session>) {
        let method = session.method;
        {
            let mut slot = self.inner.slot.write();
            slot.session = Some(session);
            slot.state = VaultState::Unlocked { method };
        }
        let store: Arc<dyn HostKeyStore> = Arc::new(VaultHostKeyStore::new(self.weak()));
        self.inner.host_keys.set(store);
        self.start_poller();
        tracing::info!("vault unlocked ({})", method.as_str());
        self.emit(VaultChange::Unlocked(method));
    }

    /// Re-derives with a new salt and `opts.cost` when the stored cost differs
    /// (background; failure logged at `debug`, retried at the next unlock).
    fn maybe_upgrade_cost(&self, password: SecretString, old_kdf: Vec<u8>) {
        let cost = self.opts().cost;
        let Ok(params) = KdfParams::from_cbor(&old_kdf) else {
            return;
        };
        if params.cost() == cost {
            return;
        }
        let engine = self.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = engine.upgrade_cost(password, old_kdf, cost).await {
                tracing::debug!(error = %e, "argon2 cost upgrade failed; retried at next unlock");
            }
        });
        *self.inner.background.lock() = Some(handle);
    }

    async fn upgrade_cost(
        &self,
        password: SecretString,
        old_kdf: Vec<u8>,
        cost: super::Argon2Cost,
    ) -> Result<(), VaultError> {
        let mut rng = os_rng();
        let params = cost.with_salt(random_salt16(&mut rng));
        let kek = self.derive(&password, params).await?;
        drop(password);
        let op = self.op().await?;
        let lmk_pw = wrap_key(
            &kek,
            &WrapPurpose::Lmk,
            op.s.lmk.key().expose_secret(),
            &mut rng,
        )
        .map_err(|e| from_crypto(e, "lmk"))?;
        drop(kek);
        let kdf = params.to_cbor();
        let done = self
            .inner
            .store
            .write(move |w| {
                // A password change in between wins.
                if w.as_read().get_meta(keys::KDF)?.as_deref() != Some(old_kdf.as_slice()) {
                    return Ok(false);
                }
                w.set_meta(keys::KDF, &kdf)?;
                w.set_meta(keys::LMK_WRAPPED_PW, &lmk_pw)?;
                Ok(true)
            })
            .await?;
        if done {
            tracing::debug!(m_kib = cost.m_kib, t = cost.t, "argon2 cost upgraded");
        }
        Ok(())
    }

    /// Locks: new operations fail with `Locked` at once; waits up to 5 s for in-flight
    /// writes; stops the poller; drops the cache and every key (zeroized); points the
    /// host-key store back at a fresh memory store; broadcasts `Locked(reason)`.
    pub async fn lock(&self, reason: LockReason) {
        let session = {
            let mut slot = self.inner.slot.write();
            if !matches!(slot.state, VaultState::Unlocked { .. }) && slot.session.is_none() {
                return;
            }
            slot.state = VaultState::Locked;
            slot.session.take()
        };
        let poller = self.inner.poller.lock().take();
        if let Some(h) = poller {
            h.abort();
        }
        if tokio::time::timeout(LOCK_WAIT, self.inner.gate.write())
            .await
            .is_err()
        {
            tracing::debug!("lock: in-flight vault operations did not finish within 5 s");
        }
        self.inner
            .host_keys
            .set(Arc::new(MemoryHostKeyStore::new()));
        drop(session);
        tracing::info!("vault locked ({})", reason.as_str());
        self.emit(VaultChange::Locked(reason));
    }

    /// Changes the master password. `Some(current)` is verified through the backoff
    /// path and must unwrap the same LMK; `None` is allowed only after a keyring unlock
    /// (local recovery). New salt, `opts.cost`; the keyring wrap is unchanged.
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::WeakPassword`],
    /// [`VaultError::WrongPassword`], [`VaultError::Backoff`],
    /// [`VaultError::KeyringNotEnabled`], [`VaultError::Storage`].
    pub async fn change_password(
        &self,
        current: Option<SecretString>,
        new: SecretString,
    ) -> Result<(), VaultError> {
        if !matches!(self.state(), VaultState::Unlocked { .. }) {
            return Err(VaultError::Locked);
        }
        check_strength(new.expose(), &USER_INPUTS)?;
        let verified = match &current {
            Some(pw) => Some(self.try_password(pw).await?.0),
            None => None,
        };
        let opts = self.opts();
        let mut rng = os_rng();
        let params = opts.cost.with_salt(random_salt16(&mut rng));
        let kek = self.derive(&new, params).await?;
        let op = self.op().await?;
        match verified {
            Some(lmk) if lmk != *op.s.lmk.key() => {
                return Err(VaultError::Corrupt(
                    "the password unlocks a different key".into(),
                ));
            }
            Some(_) => {}
            None if op.s.method == UnlockMethod::Keyring => {}
            None => return Err(VaultError::KeyringNotEnabled),
        }
        let lmk_pw = wrap_key(
            &kek,
            &WrapPurpose::Lmk,
            op.s.lmk.key().expose_secret(),
            &mut rng,
        )
        .map_err(|e| from_crypto(e, "lmk"))?;
        drop(kek);
        let kdf = params.to_cbor();
        self.inner
            .store
            .write(move |w| {
                w.set_meta(keys::KDF, &kdf)?;
                w.set_meta(keys::LMK_WRAPPED_PW, &lmk_pw)?;
                w.delete_meta(keys::UNLOCK_FAILURES)?;
                w.delete_meta(keys::UNLOCK_NEXT_ALLOWED_AT)
            })
            .await?;
        tracing::info!("master password changed");
        Ok(())
    }

    /// Turns keyring unlock on (probe, new keyring KEK, `meta.lmk_wrapped_keyring`) or
    /// off (keyring entry and meta key deleted; the meta key is deleted even when the
    /// keyring delete fails, which is then reported).
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::KeyringUnavailable`],
    /// [`VaultError::Keyring`], [`VaultError::Storage`].
    pub async fn set_keyring_unlock(&self, enable: bool) -> Result<(), VaultError> {
        let op = self.op().await?;
        let account = keyring_account(&db_id_text(self.meta().await?.db_id)?);
        let keyring = Arc::clone(&self.inner.keyring);
        if enable {
            let probe = Arc::clone(&keyring);
            if !blocking(move || probe.probe()).await? {
                return Err(VaultError::KeyringUnavailable);
            }
            let mut rng = os_rng();
            let kek = random_key32(&mut rng);
            let wrapped = wrap_key(
                &kek,
                &WrapPurpose::Lmk,
                op.s.lmk.key().expose_secret(),
                &mut rng,
            )
            .map_err(|e| from_crypto(e, "lmk"))?;
            let secret = Zeroizing::new(kek.expose_secret().to_vec());
            blocking(move || keyring.set(&account, &secret))
                .await?
                .map_err(|e| VaultError::Keyring(e.0))?;
            self.inner
                .store
                .write(move |w| w.set_meta(keys::LMK_WRAPPED_KEYRING, &wrapped))
                .await?;
            tracing::info!("keyring unlock enabled");
            Ok(())
        } else {
            self.inner
                .store
                .write(|w| w.delete_meta(keys::LMK_WRAPPED_KEYRING))
                .await?;
            tracing::info!("keyring unlock disabled");
            blocking(move || keyring.delete(&account))
                .await?
                .map_err(|e| VaultError::Keyring(e.0))
        }
    }

    /// The personal vault.
    ///
    /// # Errors
    /// [`VaultError::Locked`]; [`VaultError::Corrupt`] when its key did not unwrap.
    pub fn personal_vault(&self) -> Result<VaultId, VaultError> {
        self.with_session(|s| {
            s.personal()
                .ok_or_else(|| VaultError::Corrupt("the personal vault key is missing".into()))
        })
    }

    /// Every vault whose key is loaded.
    ///
    /// # Errors
    /// [`VaultError::Locked`].
    pub fn vaults(&self) -> Result<Vec<VaultInfo>, VaultError> {
        self.with_session(|s| {
            let ids: Vec<(VaultId, VaultKind)> = s
                .vaults
                .read()
                .iter()
                .map(|(id, e)| (*id, e.kind))
                .collect();
            Ok(ids
                .into_iter()
                .map(|(id, kind)| VaultInfo {
                    id,
                    kind,
                    permission: s.permission(id),
                })
                .collect())
        })
    }

    /// This device's permission in `vault` (personal → `Manage`; a shared vault reads
    /// `meta.vault_permission/<id>`, default `Write`; unknown → `Read`).
    pub fn vault_permission(&self, vault: VaultId) -> VaultPermission {
        self.with_session(|s| {
            Ok(if s.has_vault(vault) {
                s.permission(vault)
            } else {
                VaultPermission::Read
            })
        })
        .unwrap_or(VaultPermission::Read)
    }

    /// This device's id.
    ///
    /// # Errors
    /// [`VaultError::Locked`].
    pub fn device_id(&self) -> Result<DeviceId, VaultError> {
        self.with_session(|s| Ok(s.device_id))
    }

    /// The seal/open/wrap handle for sync (T87/T88/T89).
    ///
    /// # Errors
    /// [`VaultError::Locked`].
    pub fn crypto(&self) -> Result<VaultCrypto, VaultError> {
        self.with_session(|_| {
            Ok(VaultCrypto {
                engine: self.clone(),
            })
        })
    }
}

/// Seal/open/wrap handle for T87/T88/T89. Every call fails with
/// [`VaultError::Locked`] once the vault is locked.
#[derive(Clone)]
pub struct VaultCrypto {
    engine: VaultEngine,
}

impl fmt::Debug for VaultCrypto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultCrypto").finish_non_exhaustive()
    }
}

impl VaultCrypto {
    /// Seals `body` under the vault's current key: `(key_version, envelope)`.
    ///
    /// # Errors
    /// [`VaultError::Locked`] (also for a vault whose key is not loaded),
    /// [`VaultError::ItemTooLarge`], [`VaultError::Corrupt`].
    pub fn seal(
        &self,
        vault: VaultId,
        id: ItemId,
        body: &ItemBody,
    ) -> Result<(u32, Vec<u8>), VaultError> {
        self.engine.with_session(|s| s.seal(vault, id, body))
    }

    /// Decrypts and decodes a stored or pulled row (migrated).
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::ReadOnlyItem`] (unknown kind),
    /// [`VaultError::Corrupt`].
    pub fn open(&self, row: &ItemRow) -> Result<ItemBody, VaultError> {
        self.engine.with_session(|s| s.open(row).map(|(b, _)| b))
    }

    /// Wraps `secret` under the LMK.
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::Corrupt`].
    pub fn wrap_lmk(&self, purpose: &WrapPurpose, secret: &[u8]) -> Result<Vec<u8>, VaultError> {
        self.engine.with_session(|s| {
            wrap_key(s.lmk.key(), purpose, secret, &mut os_rng())
                .map_err(|e| from_crypto(e, "wrap"))
        })
    }

    /// Unwraps a value wrapped by [`VaultCrypto::wrap_lmk`].
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::Corrupt`] (tampered or wrong purpose).
    pub fn unwrap_lmk(
        &self,
        purpose: &WrapPurpose,
        wrapped: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        self.engine.with_session(|s| {
            unwrap_key(s.lmk.key(), purpose, wrapped).map_err(|e| from_crypto(e, "wrapped value"))
        })
    }

    /// Loads (or replaces with a newer version) the key of a vault adopted while
    /// unlocked.
    ///
    /// # Errors
    /// [`VaultError::Locked`].
    pub fn add_vault_key(
        &self,
        id: VaultId,
        kind: VaultKind,
        key_version: u32,
        vk: Key32,
    ) -> Result<(), VaultError> {
        self.engine.with_session(|s| {
            let mut map = s.vaults.write();
            if map.get(&id).is_some_and(|e| e.key_version > key_version) {
                return Ok(());
            }
            map.insert(
                id,
                VaultKeyEntry {
                    kind,
                    key_version,
                    key: TrackedKey::new(vk, &s.lmk.live),
                },
            );
            Ok(())
        })
    }
}
