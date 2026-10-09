# T30 — Vault (local encrypted store and unlock)

**Phase:** D Vault & sites · **Milestone:** M2 · **Depends on:** T05, T21, T80, T81, T82 · **Crate(s):** `courier-ftp-core` (`vault`, `hardening` modules), `courier-ftp` (`services/keyring.rs`) · **Decisions:** D3, D4, D13 · **FEATURES.md:** §2 (password storage options: save, don't save, protect with a master password)
**Related (integrates with, not blocking):** T12, T31, T60, T91
**Reference:** sverb `crates/sverb-tui/src/services/vault/{engine,os_keyring}.rs`, `crates/sverb-core/src/vault/{mod,unlock,lock,password,keyring}.rs`, `crates/sverb-core/src/secret.rs`, `crates/sverb-core/src/hardening/{mod,unix,windows}.rs`, `crates/sverb-core/src/{importers,exporters}/backup.rs`, SPEC §5.3, §11.2, §11.5, `docs/threat-model.md` — copy and adapt (D13).

## Goal

Everything sensitive — sites with their passwords, key passphrases, SSH keys, bookmarks,
trusted host keys and certificates, proxy credentials, quickconnect history and the persisted
transfer queue — lives in an encrypted local vault inside one SQLite file. The vault unlocks
with the **master password** at TUI start or, only if the user enabled it on this device, with
the **OS keyring** (D3). It uses sverb's design and formats, so the same items sync between
devices (T87/T88) and teams (T89) without a format change, and unlocking never needs the
network.

## Context

- Before: T80 (Argon2id, key wrap, item envelopes, device blobs), T81 (`ItemBody`, HLC,
  merge, migrations, `ItemView`, item kinds), T82 (`Store`: meta, vaults, items, outbox,
  device-local, device blobs), T05 (`Settings`, gains the `vault` section here), T02
  (`secret::{Secret, SecretString, SecretBytes}`, `Error::{VaultLocked, Vault}`), T21
  (`trust::{HostKeyStore, KnownHost, MemoryHostKeyStore, SwitchableHostKeyStore}`).
- **Dependency change:** T21 was "Related"; it is a hard dependency because this task
  implements T21's `HostKeyStore` trait on `known-host` items (T21 precedes T30 in M2).
- After: T60 drives first run, unlock, keyring, lock overlay and recovery screens through
  `VaultEngine`; T31/T33 store sites, folders, bookmarks and history; T40 persists the queue
  through `DeviceBlobStore`; T61 stores tabs as a device blob; T12 adds the `CertTrustStore`
  implementation on `trusted-cert` items through the API below (T12 lands in M3, after this
  task); T73/T32 use the backup container; T87/T88 use `VaultCrypto` to seal, open and wrap;
  T91 adds the CI checks around `hardening` and secrets.

## Technical specification

### Types and APIs

Module `courier_ftp_core::vault` (files `mod.rs`, `engine.rs`, `kdf.rs`, `unlock.rs`,
`lock.rs`, `password.rs`, `keyring.rs`, `cache.rs`, `trust.rs`, `blobs.rs`, `backup.rs`,
`policy.rs`) and `courier_ftp_core::hardening` (`mod.rs`, `unix.rs`, `windows.rs`).

```rust
// ---- kdf.rs (sverb vault/mod.rs) ----
/// Argon2id cost without salt.
pub struct Argon2Cost { pub m_kib: u32, pub t: u32, pub p: u32 }
impl Argon2Cost {
    pub const LIGHT: Self    = Self { m_kib: 65_536,    t: 3, p: 1 };   // 64 MiB
    pub const STANDARD: Self = Self { m_kib: 262_144,   t: 3, p: 1 };   // 256 MiB (default)
    pub const STRONG: Self   = Self { m_kib: 1_048_576, t: 4, p: 1 };   // 1 GiB
    /// Tests only. Equals T80's minimum bounds (m_kib 19 456, t 1, p 1), so a vault
    /// created with it passes `KdfParams::from_cbor` / `Argon2Params::validate` on load.
    pub const TEST: Self     = Self { m_kib: 19_456,    t: 1, p: 1 };
    pub fn from_preset(p: Argon2Preset) -> Self;
    pub const fn with_salt(self, salt: [u8; 16]) -> KdfParams;
}
// Argon2Preset { Light, Standard*, Strong } is T05's settings enum (`vault.argon2_cost`,
// snake_case values `light` | `standard` | `strong`); not redefined here.
/// `meta.kdf`: CBOR map {alg: "argon2id", m_kib, t, p, salt: bstr(16)}.
pub struct KdfParams { pub m_kib: u32, pub t: u32, pub p: u32, pub salt: [u8; 16] } // Debug hides salt
impl KdfParams { pub fn to_cbor(&self) -> Vec<u8>; pub fn from_cbor(&[u8]) -> Result<Self, VaultError>; pub fn cost(&self) -> Argon2Cost; }

// ---- unlock.rs ----
pub const FREE_ATTEMPTS: u32 = 4;
pub const MAX_DELAY: Duration = Duration::from_secs(30);
pub fn backoff_delay(failures: u32) -> Duration;
pub struct BackoffState { pub failures: u32, pub next_allowed_at: i64 }   // Unix ms
impl BackoffState { pub fn decode(..) -> Self; pub fn check(&self, now_ms: i64) -> Result<(), Duration>;
                    pub fn after_failure(&self, now_ms: i64) -> Self; pub fn current_delay(&self) -> Option<Duration>; }

// ---- password.rs ----
pub const MIN_SCORE: u8 = 3;
pub const USER_INPUTS: [&str; 3] = ["courier-ftp", "courier", "ftp"];
pub const NO_RECOVERY_WARNING: &str;   // text below
pub struct PasswordStrength { pub score: u8, pub warning: Option<String>, pub suggestions: Vec<String> }
pub struct WeakPassword { pub strength: PasswordStrength }
pub fn estimate(password: &str, user_inputs: &[&str]) -> PasswordStrength;
pub fn check_strength(password: &str, user_inputs: &[&str]) -> Result<PasswordStrength, WeakPassword>;

// ---- keyring.rs ----
pub const KEYRING_SERVICE: &str = "courier-ftp";
pub fn keyring_account(db_id: &str) -> String;          // "lmk-kek:<db_id>"
pub struct KeyringError(pub String);
pub trait KeyringStore: Send + Sync + Debug {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyringError>;
    fn set(&self, account: &str, secret: &[u8]) -> Result<(), KeyringError>;
    fn delete(&self, account: &str) -> Result<(), KeyringError>;   // Ok if missing
    fn probe(&self) -> bool;                                         // set+delete "probe"
}
pub struct NoKeyring;  pub struct MemKeyring { .. }   // MemKeyring: set_unavailable, remove, get_calls
// courier-ftp/src/services/keyring.rs (binary): OsKeyring (keyring crate) and
/// `COURIER_FTP_KEYRING`: unset → OsKeyring; `off|0|none|disabled|false` → NoKeyring;
/// `file:<dir>` → FileKeyring(dir) **only in builds with the `test-hooks` feature** (T76 PTY
/// tests); in other builds `file:<dir>` → NoKeyring + one `warn` log.
pub fn keyring_from_env() -> Arc<dyn KeyringStore>;
/// Test-hooks only: one file per account in `dir` (0600), contents = the secret bytes.
#[cfg(feature = "test-hooks")] pub struct FileKeyring { dir: PathBuf }

// ---- lock.rs ----
pub enum LockReason { Manual, Idle, Suspend, Shutdown }
/// Reset-on-input idle timer (pure; driven by the app loop, T50/T60).
pub struct AutoLock { .. }
impl AutoLock { pub fn new(minutes: u32) -> Self; pub fn on_input(&mut self, now: Instant);
                pub fn set_minutes(&mut self, minutes: u32); pub fn due(&self, now: Instant) -> bool; }
/// Suspend/resume detector (pure; fed every second by the app loop).
pub struct SuspendDetector { .. }
impl SuspendDetector { pub fn tick(&mut self, wall: SystemTime, mono: Instant) -> bool; } // true = resumed

// ---- engine.rs ----
pub enum VaultState { Uninitialised, Locked, Unlocking, Unlocked { method: UnlockMethod } }
pub enum UnlockMethod { Password, Keyring, Created }
pub struct VaultStatus {
    pub state: VaultState,
    pub keyring_enabled: bool,          // meta.lmk_wrapped_keyring exists
    pub backoff: BackoffState,
    pub retry_after: Option<Duration>,
    pub unreadable_items: usize,        // did not decrypt / decode
    pub unknown_kind_items: usize,      // written by a newer courier-ftp
}
pub struct VaultOptions {
    pub cost: Argon2Cost,               // for new wraps (first run, password change, upgrade)
    pub store_passwords: bool,          // vault.store_passwords
    pub sync_history: bool,             // sync.history (T88)
    pub physical_clock: Arc<dyn PhysicalClock>,   // T81; SystemClock in production
}
pub enum VaultChange { Unlocked(UnlockMethod), Locked(LockReason), ItemsChanged { ids: Vec<ItemId>, kinds: BTreeSet<ItemKind> } }
pub struct Loaded<V> { pub id: ItemId, pub vault: VaultId, pub view: V, pub read_only: bool,
                       pub secrets_loaded: bool, pub updated_at: i64 }
pub struct PutOutcome { pub changed: bool }
pub struct LoadedBody { pub id: ItemId, pub vault: VaultId, pub body: ItemBody, pub read_only: bool, pub revision: i64 }
pub enum VaultPermission { Read, Write, Manage }
pub struct VaultInfo { pub id: VaultId, pub kind: VaultKind, pub permission: VaultPermission }

#[derive(Clone)] pub struct VaultEngine { inner: Arc<Inner> }
impl VaultEngine {
    pub fn new(store: Store, keyring: Arc<dyn KeyringStore>, opts: VaultOptions,
               host_keys: Arc<SwitchableHostKeyStore>) -> Self;
    pub fn set_options(&self, opts: VaultOptions);         // settings changed (T68)
    pub fn state(&self) -> VaultState;                      // cheap, no I/O
    pub async fn status(&self) -> Result<VaultStatus, VaultError>;
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<VaultChange>;  // capacity 256
    pub async fn keyring_available(&self) -> bool;

    pub async fn initialize(&self, password: SecretString, enable_keyring: bool) -> Result<InitReport, VaultError>;
    pub async fn unlock(&self, password: SecretString) -> Result<UnlockReport, VaultError>;
    pub async fn unlock_with_keyring(&self) -> Result<UnlockReport, VaultError>;
    pub async fn verify_password(&self, password: SecretString) -> Result<(), VaultError>;
    pub async fn lock(&self, reason: LockReason);
    /// `current = None` only after a keyring unlock (local recovery path).
    pub async fn change_password(&self, current: Option<SecretString>, new: SecretString) -> Result<(), VaultError>;
    pub async fn set_keyring_unlock(&self, enable: bool) -> Result<(), VaultError>;

    // items (typed)
    pub fn list<V: ItemView>(&self) -> Result<Vec<Loaded<V>>, VaultError>;       // cache, secrets not loaded
    pub async fn get<V: ItemView>(&self, id: ItemId) -> Result<Option<Loaded<V>>, VaultError>; // decrypts, secrets loaded
    pub async fn put<V: ItemView + Send + 'static>(&self, vault: VaultId, id: ItemId, view: V) -> Result<PutOutcome, VaultError>;
    pub async fn put_many(&self, writes: Vec<BodyWrite>) -> Result<usize, VaultError>;  // one transaction (imports)
    pub async fn delete(&self, id: ItemId) -> Result<(), VaultError>;
    pub async fn delete_many(&self, ids: Vec<ItemId>) -> Result<usize, VaultError>;     // one transaction
    pub async fn restore(&self, id: ItemId) -> Result<(), VaultError>;
    /// Raw body with stamps and secrets (approval checks, export, copy).
    pub async fn get_body(&self, id: ItemId) -> Result<Option<LoadedBody>, VaultError>;

    // device-local approvals of synced values that act locally (T91 §8, T82 local_approvals)
    pub fn is_approved(&self, id: ItemId, field: &str, value_sha256: &[u8; 32]) -> bool;  // cached
    pub async fn approve(&self, id: ItemId, field: &str, value_sha256: [u8; 32]) -> Result<(), VaultError>;
    pub fn personal_vault(&self) -> Result<VaultId, VaultError>;
    pub fn vaults(&self) -> Result<Vec<VaultInfo>, VaultError>;
    pub fn device_id(&self) -> Result<DeviceId, VaultError>;

    // device-local data (T82 device_local)
    pub async fn touch_connected(&self, id: ItemId) -> Result<(), VaultError>;
    pub async fn set_local_dir_override(&self, id: ItemId, dir: Option<LocalPath>) -> Result<(), VaultError>;
    pub async fn set_tree_expanded(&self, id: ItemId, expanded: Option<bool>) -> Result<(), VaultError>;
    pub fn device_local(&self, id: ItemId) -> Option<DeviceLocalInfo>;      // cached

    // trust stores
    pub fn host_key_store(&self) -> Arc<SwitchableHostKeyStore>;

    // sync and other crates (T87/T88/T89) — signatures fixed here; T87/T88/T89 implement
    // the bodies in this module (no network code). VaultCrypto covers seal/open/wrap only;
    // the methods below are the rest of the sync-facing surface.
    pub fn crypto(&self) -> Result<VaultCrypto, VaultError>;
    pub async fn reload_items(&self, ids: Vec<ItemId>) -> Result<(), VaultError>;
    /// T87: store handle, LMK clone, shared HLC, device id, personal vault id. Locked when locked.
    pub fn sync_handles(&self) -> Result<SyncHandles, VaultError>;
    /// T87: new salt + KEK for `password`; returns the meta rows (`kdf`, `lmk_wrapped_pw`)
    /// for the caller's transaction. Keyring wrap unchanged.
    pub async fn lmk_rewrap_rows(&self, password: &SecretString) -> Result<Vec<(String, Vec<u8>)>, VaultError>;
    /// T87: re-read vaults and all items after an external transaction (login, logout).
    pub async fn reload(&self) -> Result<(), VaultError>;
    /// T88: bumped after every committed local write (put/delete/import/transfer).
    pub fn local_changes(&self) -> tokio::sync::watch::Receiver<u64>;
    /// T88: `reload_items(items)` for one vault after a pull, then `ItemsChanged`.
    pub async fn apply_remote(&self, vault: VaultId, items: &[ItemId]) -> Result<(), VaultError>;
    /// T89: permission of a vault (personal → Manage). Read-only check: put/delete/move-out
    /// on a `Read` vault → `ReadOnlyVault(id)` (enforced in put/put_many/delete/transfer).
    pub fn vault_permission(&self, vault: VaultId) -> VaultPermission;
    /// T89: copy or move items between vaults in one transaction. Cross-vault reference
    /// check: a team-vault item referencing an item in another vault →
    /// `CrossVaultReference(msg)` (also enforced by put/put_many).
    pub async fn transfer(&self, plan: TransferPlan) -> Result<Vec<ItemId>, VaultError>;

    // test hooks (always compiled, cheap)
    pub fn kdf_runs(&self) -> usize;
    pub fn live_keys(&self) -> usize;
}
pub struct BodyWrite { pub vault: VaultId, pub id: ItemId, pub body: BodyEdit }
pub enum BodyEdit { Merge(ItemBody), Replace(ItemBody) }   // Merge: T81 merge with the stored body
/// Seal/open/wrap handle for T87/T88/T89; fails with Locked after lock().
pub struct VaultCrypto { .. }
impl VaultCrypto {
    pub fn seal(&self, vault: VaultId, id: ItemId, body: &ItemBody) -> Result<(u32, Vec<u8>), VaultError>;
    pub fn open(&self, row: &ItemRow) -> Result<ItemBody, VaultError>;
    pub fn wrap_lmk(&self, purpose: &WrapPurpose, secret: &[u8]) -> Result<Vec<u8>, VaultError>;
    pub fn unwrap_lmk(&self, purpose: &WrapPurpose, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError>;
    pub fn add_vault_key(&self, id: VaultId, kind: VaultKind, key_version: u32, vk: Key32) -> Result<(), VaultError>;
}

// ---- blobs.rs: implements T40's trait ----
impl DeviceBlobStore for VaultEngine { put_blob, get_blob, delete_blob }

// ---- trust.rs ----
pub struct VaultHostKeyStore { engine: VaultEngine }   // impl trust::HostKeyStore (T21)

// ---- policy.rs ----
pub fn mark_dirty(kind: ItemKind, opts: &VaultOptions) -> bool;   // false only for history-entry without sync.history

// ---- backup.rs (container; payload sections are T73's) ----
pub const FORMAT: &str = "courier-ftp-backup";  pub const VERSION: u32 = 1;
pub const AAD: &[u8] = b"courier-ftp-backup-v1"; pub const EXTENSION: &str = "cftp-backup";
pub const MAX_PAYLOAD: u64 = 1 << 30;
pub struct ContainerSpec { pub format: &'static str, pub aad: &'static [u8], pub extension: &'static str }
pub const BACKUP: ContainerSpec;
pub struct KdfHeader { pub alg: String, pub m_kib: u32, pub t: u32, pub p: u32, pub salt_b64: String }
pub struct BackupFile { pub format: String, pub version: u32, pub kdf: KdfHeader, pub nonce_b64: String,
                        pub ciphertext_b64: String, pub created_at: String, pub app_version: String }
pub struct BackupVault { pub id: VaultId, pub kind: String }
pub struct BackupItem { pub id: ItemId, pub vault: VaultId, pub body: ItemBody }
pub struct BackupPayload { pub vaults: Vec<BackupVault>, pub items: Vec<BackupItem> }
pub enum BackupError { NotABackup(String), UnsupportedVersion(u32), Decrypt, Corrupt(String), Kdf(String), WeakPassword(String), Encode(String) }
pub fn encrypt_with<P: Serialize>(spec: &ContainerSpec, payload: &P, password: &SecretString, cost: Argon2Cost, created_at: OffsetDateTime) -> Result<String, BackupError>;
pub fn decrypt_with<P: DeserializeOwned>(spec: &ContainerSpec, text: &str, password: &SecretString) -> Result<P, BackupError>;
pub fn encrypt<P: Serialize>(..) / decrypt<P: DeserializeOwned>(..);   // = *_with(&BACKUP, ..)
pub fn read_header(spec: &ContainerSpec, text: &str) -> Result<BackupFile, BackupError>;
pub fn kdf_params(kdf: &KdfHeader) -> Result<Argon2Params, BackupError>;
#[doc(hidden)] pub fn fuzz_backup_decrypt(data: &[u8]);

// ---- errors ----
#[non_exhaustive]
pub enum VaultError {
    NotInitialized, AlreadyInitialized,
    WrongPassword { failures: u32, retry_after: Option<Duration> },
    Backoff { retry_after: Duration },
    WeakPassword(WeakPassword),
    Keyring(String), KeyringNotEnabled, KeyringUnavailable,
    Locked, UnlockInProgress, ReadOnlyItem(ItemId), ReadOnlyVault(VaultId), NotFound(ItemId),
    ItemTooLarge { bytes: usize }, CrossVaultReference(String),
    Busy, Corrupt(String), Storage(String),
}
impl From<VaultError> for crate::Error;   // Locked → VaultLocked; CrossVaultReference →
                                           // InvalidInput(msg); others → Vault(to_string())
```

`courier_ftp_core::hardening` (sverb `hardening/`):

```rust
pub struct HardeningReport { pub core_dumps_disabled: bool, pub non_dumpable: bool, pub failures: Vec<String> }
pub fn harden_process() -> HardeningReport;      // first call in main (T50 wires it)
pub fn is_dumpable() -> Option<bool>;  pub fn core_dump_limit() -> Option<u64>;
pub fn set_memlock_limit(soft_bytes: u64) -> io::Result<()>;   // tests
pub fn locked_page_count() -> usize;
/// Heap value in mlock'ed/VirtualLock'ed pages (best effort), zeroized before unlock.
pub struct Locked<T: Zeroize> { .. }   // Deref/DerefMut, Debug = "Locked([REDACTED])", is_locked()
```

### Behaviour

**Key hierarchy** (sverb SPEC §5.3, §11.2.1):

```
master password ──Argon2id(meta.kdf)──▶ KEK ──wrap(Lmk)──▶ meta.lmk_wrapped_pw
OS keyring (optional, per device): random 32-byte KEK_kr ──wrap(Lmk)──▶ meta.lmk_wrapped_keyring
LMK (random 256-bit) ──wrap(VaultKey(vault_id))──▶ vaults.wrapped_key   (personal + each team vault)
LMK ──wrap(SyncTokens)──▶ sync_state.tokens_enc                         (T87)
LMK ──wrap(DeviceKey)──▶ meta.device_key_wrapped  (random 32-byte key for device blobs)
VK  ──HKDF(salt = item_id, info = "courier-ftp/item/v1")──▶ per-item key (T80 envelope)
```

A wrong password is detected by the AEAD failing to unwrap the LMK; no verifier or password
hash is stored. The engine **never contacts the sync server** (works offline in every mode).

**State machine**: `Uninitialised` (no `meta.kdf`) → `initialize` → `Unlocked{Created}`;
`Locked` → `unlock`/`unlock_with_keyring` → `Unlocking` → `Unlocked` or back to `Locked`;
`Unlocked` → `lock` → `Locked`. Only one unlock runs at a time (`Unlocking` refuses a second
with `VaultError::UnlockInProgress`). Item and blob operations in any state but `Unlocked` return
`VaultError::Locked`. Every transition is broadcast as `VaultChange`.

**`initialize(password, enable_keyring)`**: `check_strength(password, USER_INPUTS)` (zxcvbn
score ≥ 3) → refuse if `meta.kdf` exists (`AlreadyInitialized`) → generate LMK, 16-byte salt,
KEK = Argon2id(`opts.cost`), personal `VaultId` (UUIDv7) and VK, device key, `device_id`
(UUIDv7), `db_id` (UUIDv7 text), initial HLC. If `enable_keyring`: random KEK_kr stored in the
keyring **before** the transaction (removed again if the transaction fails); a keyring error
does not fail initialisation and is returned in `InitReport::keyring_error`. One IMMEDIATE
transaction writes `kdf`, `lmk_wrapped_pw`, optional `lmk_wrapped_keyring`, `device_key_wrapped`,
`db_id`, `device_id`, `hlc_last`, deletes the backoff keys and creates the personal vault row
(`key_version = 1`); it re-checks `meta.kdf` inside the transaction so two processes can't both
initialise.

**`unlock(password)`** (sverb `try_password` + `open_vaults`):
1. Read `kdf`, `lmk_wrapped_pw`, backoff keys. `KdfParams::from_cbor` validates bounds
   (T80) **before** Argon2 runs; out-of-range → `Corrupt("meta.kdf: parameters out of range")`.
2. Backoff check against `store.now()`: refused attempts return `Backoff { retry_after }` and do
   **not** run Argon2.
3. Argon2id in `spawn_blocking` (`kdf_runs += 1`), unwrap LMK. Failure: one IMMEDIATE
   transaction reads the current counter, applies `after_failure(now)` and writes both meta keys
   (so concurrent processes count every failure); returns `WrongPassword { failures, retry_after }`.
   Nothing else is modified. Success with `failures > 0` deletes both keys.
4. Unwrap every vault key (a vault whose key does not unwrap is skipped with a `warn` log
   naming its short id — e.g. a team vault awaiting a grant), unwrap the device key, read
   `device_id` and `hlc_last` (`HlcClock::with_last`).
5. Decrypt every item row (`open_item`), decode (`ItemBody::from_cbor`), run `migrate` (T81);
   record read-only marks; unreadable rows and unknown kinds are counted and kept untouched.
   Bodies are cached **with secret fields removed** (`SECRET_FIELDS`, T81); the cache records
   which secret keys were non-null.
6. Swap the host-key store: `host_keys.set(Arc::new(VaultHostKeyStore))`.
7. If `meta.kdf`'s cost differs from `opts.cost`, re-derive with a **new salt** and re-wrap the
   LMK in the background (one extra Argon2 run; failure logged at `debug`, retried next unlock).
8. Start the change poller (below); state `Unlocked{Password}`; broadcast.

**`unlock_with_keyring()`**: requires `meta.lmk_wrapped_keyring` (`KeyringNotEnabled`) and
`meta.db_id`; reads `keyring_account(db_id)` in `spawn_blocking`; missing entry, cancelled OS
prompt, unavailable service or an entry that does not unwrap → `Keyring(reason)`. No backoff
(the OS gates the keyring). Then steps 4–8 with method `Keyring`. T60 falls back to the password
screen on any error. `COURIER_FTP_KEYRING=off` (CI, tests) selects `NoKeyring`;
`COURIER_FTP_KEYRING=file:<dir>` selects `FileKeyring` in `test-hooks` builds only (T76 PTY
tests of keyring unlock).

**`set_keyring_unlock(enable)`** (only while unlocked): enable = `probe()` must succeed
(`KeyringUnavailable` otherwise) → random KEK_kr → keyring `set` → write
`lmk_wrapped_keyring`; disable = delete the keyring entry **and** the meta key (the meta key is
deleted even if the keyring delete fails; the failure is reported). Headless Linux without
Secret Service: `keyring_available()` is false and T60 hides the option (logged at `debug`).

**`change_password(current, new)`**: `check_strength(new)`; `Some(current)` is verified through
the same backoff path and must unwrap the same LMK (compare constant-time); `None` is allowed only
when the current unlock method is `Keyring` (local recovery: "Forgot password?" → keyring unlock
→ new password), else `KeyringNotEnabled`. New salt, `opts.cost`, re-wrap the LMK, write `kdf` +
`lmk_wrapped_pw` and clear backoff in one transaction. The keyring wrap is unchanged. With sync
enabled T87 runs the server flow first and then calls this.

**Item operations**:
- `list::<V>()` returns cached views (secrets not loaded: secret fields read as
  `SecretField::Kept` when stored, `Absent` otherwise — see T81 `SecretField`), skipping deleted
  items, sorted by id. Cost: no I/O.
- `get::<V>(id)` reads the row, decrypts, migrates and returns the full view
  (`secrets_loaded = true`). Used by editors and the connect path.
- `put(vault, id, view)`: refuses `Locked`, `ReadOnlyVault` (team vault with `Read`
  permission), `ReadOnlyItem` (newer schema). Inside **one** IMMEDIATE write transaction:
  read `meta.hlc_last` and the current row; decrypt it (or start `ItemBody::new(V::KIND, current)`);
  `clock.observe` the stored `hlc_last` so stamps stay monotonic across processes; `view.apply_to`
  with a `FieldWriter` (device id, clock); if `vault.store_passwords` is false, new secret
  values (`SecretField::Value`) of `site`, `credential-override` and `history-entry` are not
  written (clearing to `Absent` still is); check cross-vault references
  (T81 `check_vault_refs`); if nothing changed return `changed = false` without writing;
  otherwise encode, reject bodies > 1 MiB (`ItemTooLarge`), seal under the vault's current key,
  `put_item(mark_dirty = policy::mark_dirty(kind))`, write `hlc_last`. After commit update the
  cache and broadcast `ItemsChanged`.
- `delete(id)`: same transaction shape: set every non-null secret field to `null` (stamped),
  then `ItemBody::delete` (tombstone after every field), seal, `put_item(deleted = true)`,
  delete the item's `device_local` row and approvals. Deleting a `site-folder` does not cascade
  here (T31 deletes children first).
- `delete_many(ids)` tombstones up to 10 000 items in one transaction (folder deletes, T31;
  history cap, T33).
- `restore(id)` clears a tombstone (undo, T31/T33).
- `approve`/`is_approved` store and check `(item_id, field, sha256(value))` rows in
  `local_approvals` (cached in memory while unlocked; never synced). `put` from this device
  records approvals for the local-acting fields it writes (T31 lists them), so values typed
  here are pre-approved.
- `put_many` applies up to 10 000 `BodyWrite`s in one transaction (imports, T32/T73);
  `Merge` uses T81 `merge` with the stored body.
- Writes to a vault whose key is missing → `Locked`.

**Change poller**: while unlocked, every 2 s `store.data_version()`; when it changed, diff
`item_markers()` against the cache (id, `updated_at`, `revision`, `deleted`), re-decrypt
changed rows, drop removed ones, broadcast `ItemsChanged`. This keeps two courier-ftp processes
on one database consistent. T88 calls `reload_items(ids)` directly after applying a page.

**Lock** (`lock(reason)`, sverb `lock.rs`): state becomes `Locked` immediately (new operations
fail with `Locked`); waits up to 5 s for in-flight writes (they hold a read guard of an
operation gate); stops the poller; drops the cache, the LMK, every VK and the device key
(zeroized; `Locked<Key32>`); swaps the host-key store back to a fresh `MemoryHostKeyStore`
(`can_persist = false`); broadcasts `Locked(reason)`. After `lock().await` returns,
`live_keys() == 0`. Connections and running transfers continue unless
`vault.lock_disconnects = true` (T60/T41 react to the broadcast); a transfer that needs a secret
waits for unlock. Unsaved dialogs are discarded by the UI (T60).

**Auto-lock and suspend**: `AutoLock` fires when `vault.auto_lock_minutes` (default 15,
0 = off, max 1440) elapse without input; every key press calls `on_input`. Manual lock is
`Ctrl-x Ctrl-l` (T51). `SuspendDetector::tick` is called once per second by the app loop and
returns true (→ `lock(Suspend)` when `vault.lock_on_suspend`, default true) when
`wall_delta − mono_delta > 10 s` (the wall clock moved but the monotonic clock did not: Linux
and macOS suspend) or `mono_delta > 30 s` (the process was frozen; covers Windows, where the
monotonic clock may include sleep). Wall-clock jumps backwards never lock.

**Brute-force backoff** (sverb `unlock.rs`): failures 1–4 no delay; failures 5, 6, 7, 8, 9 →
1, 2, 4, 8, 16 s; from 10 on 30 s (cap). `meta.unlock_failures` (u32 BE) and
`meta.unlock_next_allowed_at` (i64 BE Unix ms) persist across restarts; a missing or malformed
value counts as zero; a next-allowed time more than 30 s ahead (clock moved back) is clamped
to 30 s. Reset on success.

**Saving passwords** (`vault.store_passwords`, default true, FileZilla's "save passwords"
option): passwords, account values and key passphrases are stored **inside** the encrypted item
(plaintext only inside the envelope). When false: secret fields of `site`,
`credential-override` and `history-entry` are never written, and T31 treats a stored password as
absent (logon `Normal` behaves like `AskForPassword`). Existing stored secrets stay in the vault
until removed (see Open questions).

**Device blobs** (`DeviceBlobStore` for T40, also used by T61): `put_blob(name, plaintext)`
seals with T80 `seal_device_blob(device_key, name, …)` and writes `device_blobs`; `get_blob`
opens it; both `Locked` when locked (T40 maps to `Error::VaultLocked` and retries). Names in use:
`transfer-queue` (T40), `tabs` (T61). Blobs never sync.

**Trust store**: `VaultHostKeyStore` implements T21's `HostKeyStore`: `lookup`/`list` read the
cache of `known-host` items (host normalised by T21 `normalize_host`, case-insensitive),
`can_persist() = true`, `add(entry, replaces)` writes the new item (`ItemId` = `entry.id`) and
tombstones `replaces` in **one** transaction, `remove` tombstones. Conversion between
`KnownHostItem` (T81) and `trust::KnownHost` (T21) is field by field (`added_at` UnixMillis ↔
`OffsetDateTime`). T12 adds the analogous `CertTrustStore` implementation on `TrustedCertItem`
using `list`/`put`/`delete`.

**Recovery** (sverb SPEC §11.2): sync account → 24-word recovery key (T87/T90); local-only with
keyring → keyring unlock then `change_password(None, new)`; local-only without keyring → no
recovery: `NO_RECOVERY_WARNING` = "There is no way to recover this password. If you forget it,
your saved sites and passwords are lost unless you enable keyring unlock or sync with a recovery
key." (shown on first run and next to the keyring setting, T60). Starting over: T60 calls
`move_database_aside(path) -> io::Result<PathBuf>` (renames `courier-ftp.db` and its `-wal`/`-shm`
to `courier-ftp.db.bak-<YYYYMMDD-HHMMSS>`; never deletes) after dropping the engine.

**Multiple processes**: no lock file; SQLite WAL + 5 s busy timeout + IMMEDIATE transactions
(T82); `Busy` → `VaultError::Busy` → T60 "Another courier-ftp may be writing to the vault.
Retry?".

**Hardening** (sverb `hardening/`, `secret.rs`): `harden_process()` is the first call in `main`
after the panic hook: Linux `prctl(PR_SET_DUMPABLE, 0)`; every Unix `setrlimit(RLIMIT_CORE, 0)`
(soft and hard); Windows `SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX)` and
`WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP)`. Report logged at `debug`. LMK, VKs and the device
key live in `Locked<Key32>` (per-page reference-counted `mlock`/`VirtualLock`, zeroize before
unlock; if `RLIMIT_MEMLOCK` is too low the key stays usable and one `debug` line is logged).
`hardening/unix.rs` and `hardening/windows.rs` are the only files allowed
`#![allow(unsafe_code)]`, every block with a `SAFETY:` comment (T91 enforces). Each held key is
counted in a per-engine live-key counter (`TrackedKey`), so tests can prove `lock()` dropped all.

### Data formats and configuration

`meta` keys written by this task: `kdf`, `lmk_wrapped_pw`, `lmk_wrapped_keyring`,
`device_key_wrapped`, `unlock_failures`, `unlock_next_allowed_at`, `device_id`, `db_id`,
`hlc_last` (encodings in T82). `meta.kdf` example (CBOR diagnostic):
`{"alg": "argon2id", "m_kib": 262144, "t": 3, "p": 1, "salt": h'…16 bytes…'}`; any other `alg`,
a salt not 16 bytes, or values outside T80's bounds → `Corrupt` before Argon2 runs.

OS keyring entry: service `courier-ftp`, account `lmk-kek:<db_id>` (one entry per database, so
several `COURIER_FTP_HOME`s never share it), secret = 32 raw bytes.

Settings (T05 `Settings.vault`, `#[serde(default)]`):

| Key | Type | Default | Range / notes |
|---|---|---|---|
| `vault.store_passwords` | bool | `true` | FileZilla "save passwords" |
| `vault.auto_lock_minutes` | u32 | `15` | 0 = off, max 1440 (validation clamps, warns) |
| `vault.lock_on_suspend` | bool | `true` | |
| `vault.lock_disconnects` | bool | `false` | close sessions on lock |
| `vault.argon2_cost` | `light` \| `standard` \| `strong` | `standard` | applied on next password unlock or change |

Environment: `COURIER_FTP_KEYRING` (`off`/`0`/`none`/`disabled`/`false` → no keyring;
`file:<dir>` → file-backed test keyring, `test-hooks` builds only, ignored with a warning
otherwise).

Backup container (`.cftp-backup`, sverb `.sverb-backup`), one JSON document:

```json
{ "format": "courier-ftp-backup", "version": 1,
  "kdf": { "alg": "argon2id", "m_kib": 262144, "t": 3, "p": 1, "salt_b64": "…" },
  "nonce_b64": "…", "ciphertext_b64": "…",
  "created_at": "2026-10-09T12:00:00Z", "app_version": "0.1.0" }
```

`ciphertext = XChaCha20-Poly1305(Argon2id(password, kdf), nonce, AAD, zstd_level3(cbor(payload)))`,
base64 standard alphabet with padding, AAD = `spec.aad`. Readers check `format`, then `version`
(`UnsupportedVersion` if newer), then KDF bounds **before** Argon2, cap the decompressed payload
at `MAX_PAYLOAD` = 1 GiB and the file at 2 GiB. The base payload is
`BackupPayload { vaults: [{ id, kind }], items: [{ id, vault, body }] }` (bodies with stamps and
secrets, so a restore keeps ids and HLC history); T73 adds sections, T32 reuses the container
with its own `ContainerSpec`. Export passwords need zxcvbn ≥ 3 (`WeakPassword`).

Cargo additions to core: `courier-ftp-crypto`, `courier-ftp-store`, `ciborium`, `zxcvbn 3.1.0`
(`default-features = false`), `base64`, `serde_json`, `zstd`, `parking_lot`, `libc` (unix),
`windows-sys 0.61` (features `Win32_System_Diagnostics_Debug`,
`Win32_System_ErrorReporting`, `Win32_System_Memory`, `Win32_System_SystemInformation`).
Binary: `keyring 4.2.0`.

### Errors

| `VaultError` | When | User sees (T60) |
|---|---|---|
| `NotInitialized` | unlock before first run | first-run screen |
| `AlreadyInitialized` | second `initialize` | "The vault already exists" |
| `WrongPassword { failures, retry_after }` | LMK did not unwrap | "Wrong master password" + attempt count + countdown |
| `Backoff { retry_after }` | attempt during backoff (Argon2 not run) | countdown, Unlock disabled |
| `WeakPassword` | zxcvbn < 3 | meter + zxcvbn feedback |
| `Keyring(reason)` / `KeyringUnavailable` / `KeyringNotEnabled` | keyring paths | one-line reason, password screen |
| `Locked` | operation while locked | unlock prompt; maps to `Error::VaultLocked` |
| `UnlockInProgress` | second unlock while one runs | ignored by T60 (button disabled) |
| `ReadOnlyItem` / `ReadOnlyVault` | newer schema / `read` permission | "Update courier-ftp to edit this item" / "Read-only vault" |
| `NotFound` | id not in vault | — |
| `ItemTooLarge { bytes }` | body > 1 MiB | "This entry is too large to save" |
| `CrossVaultReference` | T81 ref rule | field-level error in the editor |
| `Busy` | SQLite busy > 5 s | "Another courier-ftp may be writing. Retry?" |
| `Corrupt(what)` | bad meta/key/kdf | startup error with the database path and "restore from backup" |
| `Storage(msg)` | other store errors | error dialog |

`From<VaultError> for courier_ftp_core::Error`: `Locked` → `Error::VaultLocked`, everything
else → `Error::Vault(err.to_string())`.

### Security and logging

- Passwords enter as `SecretString` and are exposed only to Argon2 (copied into a `Zeroizing`
  buffer inside `spawn_blocking`). Keys are `Key32` inside `Locked`; plaintext item bodies are
  `Zeroizing` buffers until decoded; the cache never holds secret field values.
- `Debug` of `VaultEngine`, `VaultCrypto`, `KdfParams` (salt omitted), `MemKeyring` (accounts
  only), `Loaded<V>` (via the view's redacting `Debug`) contains no secret.
- Logging: `debug` only for internals (counts, short ids, schema versions, timings); `info` for
  "vault unlocked (method)", "vault locked (reason)" with no paths or ids of remote hosts;
  `warn` for unreadable items (short id only). Never hostnames, usernames, item labels or values
  at any level in this module.
- Untrusted inputs: the database file (bounds-checked KDF, length-checked meta values, AEAD on
  everything else) and backup files (format/version/KDF checks before Argon2, size caps, fuzzed).
- Approval of synced local-acting values (T91 §8) is enforced on the connect path (T31) using
  `local_approvals`; this task only stores bodies.

## Implementation steps

1. `hardening` module (port sverb, adapt names) + tests; wire `harden_process()` into `main`.
2. `vault::{kdf, unlock, password, keyring, lock}` pure modules with unit tests (`AutoLock`,
   `SuspendDetector`).
3. `VaultEngine` skeleton: state machine, `initialize`, `unlock`, `lock`, `status`, live-key
   counter, `Locked<Key32>` keys; integration tests with `Argon2Cost::TEST` and `MemKeyring`.
4. Keyring unlock, `set_keyring_unlock`, `change_password` (incl. keyring recovery path), cost
   upgrade; `OsKeyring` + `keyring_from_env` in the binary.
5. Item cache, `list`/`get`/`put`/`delete`/`restore`/`put_many`, write policy
   (`store_passwords`, `mark_dirty`), change poller, `VaultChange` broadcast.
6. Device-local helpers and `DeviceBlobStore` impl.
7. `VaultHostKeyStore` and the switch on unlock/lock.
8. `VaultCrypto` for T87/T88/T89. The other sync-facing methods are added by T87/T88/T89
   with exactly the signatures listed above (not stubbed here).
9. Backup container (`backup.rs`) with KAT, tamper and fuzz tests (`fuzz/fuzz_targets/backup_decrypt.rs`).
10. `Settings.vault` section in T05's struct with validation and docs.

## Acceptance criteria

- [ ] AC1 `initialize` → put 3 sites, 2 known hosts, 1 bookmark → `lock` → `unlock` returns
  byte-identical `ItemBody`s (secrets included via `get`).
- [ ] AC2 With `MemKeyring`: keyring unlock succeeds silently; with the keyring set unavailable
  or the entry removed it returns `Keyring(_)` and password unlock still works; after keyring
  unlock `change_password(None, new)` succeeds and the new password unlocks, the old one fails.
- [ ] AC3 A wrong password changes only `meta.unlock_failures` and `meta.unlock_next_allowed_at`
  (SHA-256 of every other meta value, vault row and item row unchanged).
- [ ] AC4 Backoff: with a `ManualClock`, failures 1–4 have no delay; failure 5 → 1 s, 6 → 2 s,
  7 → 4 s, 8 → 8 s, 9 → 16 s, 10 and 20 → 30 s; an attempt during backoff returns `Backoff` and
  `kdf_runs()` does not increase; two engines on the same file share the counter (failures from
  both add up).
- [ ] AC5 `AutoLock(15)` is due exactly after 15 min without input and not due 14 min 59 s
  after the last `on_input`; `SuspendDetector` returns true for a 60 s wall jump with 1 s
  monotonic, and for a 31 s monotonic gap, false for a backwards wall jump.
- [ ] AC6 After `lock().await`, `live_keys() == 0`, `list` returns `Locked`, and the host-key
  store reports `can_persist() == false`.
- [ ] AC7 `meta.kdf` with `m_kib = 1024`, `m_kib = 8 GiB`, `t = 0`, `t = 65`, `p = 17` or
  `alg = "scrypt"` makes `unlock` return `Corrupt` with `kdf_runs() == 0`.
- [ ] AC8 `initialize("password123")` returns `WeakPassword` with non-empty zxcvbn feedback;
  `"correct horse battery staple violin"` is accepted.
- [ ] AC9 Canary test: after a full unlock/put/get/lock cycle with `COURIER_FTP_LOG_LEVEL=trace`,
  the canary password appears in no log line, no `Debug` output of engine types, and not in the
  `.db`/`-wal`/`-shm` files (T91 `canary-scan.sh`).
- [ ] AC10 Flipping one byte of `lmk_wrapped_pw`, of a `vaults.wrapped_key` or of an item
  envelope gives respectively `WrongPassword`, a skipped vault with a `warn`, and an unreadable
  item counted in `status().unreadable_items`, never a panic.
- [ ] AC11 With `vault.store_passwords = false`, putting a site with a password stores no
  `password` field (decrypted body has none) and `history-entry` items are written with
  `dirty = 0` when `sync.history = false`.
- [ ] AC12 Two engines on one file: an item put by engine A appears in engine B's `list` within
  3 s (change poller), and both can write 100 items concurrently without errors.
- [ ] AC13 Backup: `encrypt` → `decrypt` round-trips a payload; a wrong password → `Decrypt`;
  a header with `m_kib = 4 GiB + 1` → `Kdf` without running Argon2; a payload decompressing to
  > 1 GiB → `Corrupt`; the `backup_decrypt` fuzz target runs 30 s clean.
- [ ] AC14 Linux: after `harden_process()`, `is_dumpable() == Some(false)` and
  `core_dump_limit() == Some(0)`; `check-unsafe.py` passes with `unsafe` only in
  `hardening/{unix,windows}.rs`.
- [ ] AC15 Unlock of a vault with 10 000 items (excluding Argon2) finishes in < 500 ms in the
  release-mode bench `vault_unlock_10k` (gated in `bench-gates.toml`).
- [ ] AC16 CI gates `fmt`, `clippy`, `docs`, `test-local-only`, `test-os`, `unsafe-check`,
  `canary`, `fuzz` pass.
- [ ] AC17 `Argon2Cost::TEST` and all presets pass T80's `Argon2Params::validate`; a vault
  initialised with `TEST` unlocks again (load-time bound check passes).
- [ ] AC18 `keyring_from_env`: `off` → `NoKeyring`; `file:<dir>` → `FileKeyring` with the
  `test-hooks` feature (keyring unlock works across two engine instances) and `NoKeyring`
  without it.

## Tests

### Unit tests
- `vault::kdf::tests::{kdf_params_cbor_roundtrip, kdf_params_rejects_bad_input, presets_within_bounds}` (AC7).
- `vault::unlock::tests::{backoff_schedule, state_roundtrip_and_gate}` — table of AC4 (AC4).
- `vault::password::tests::{weak_password_is_rejected_with_feedback, strong_password_is_accepted}` (AC8).
- `vault::keyring::tests::{mem_keyring_roundtrip_and_probe, accounts_differ_per_db}`.
- `vault::kdf::tests::test_cost_within_load_bounds` (AC17).
- binary `services::keyring::tests::{env_off_is_no_keyring, env_file_requires_test_hooks}`
  (`#[cfg(feature = "test-hooks")] file_keyring_roundtrip`) (AC18).
- `vault::lock::tests::{auto_lock_due_after_timeout, input_resets, zero_disables,
  suspend_detected_by_wall_jump, frozen_process_detected, backwards_wall_jump_ignored}` (AC5).
- `vault::backup::tests::{roundtrip, wrong_password, kdf_bounds_before_argon2, bomb_rejected,
  newer_version_rejected}` (AC13).
- `hardening::tests::{locked_value_zeroized_on_drop, page_refcounts, debug_redacted}`.

### Property / fuzz tests
- `tests/vault_props.rs::random_put_delete_restore_survives_relock` (proptest, 200 cases,
  `Argon2Cost::TEST`): random operation sequences; after lock/unlock the visible items equal a
  model map (AC1).
- Fuzz target `backup_decrypt` (body `fuzz_backup_decrypt`, also run by
  `backup::tests::fuzz_body_never_panics` with 10 000 inputs) (AC13).

### Snapshot tests
Not applicable (screens are T60).

### Integration tests
(`crates/courier-ftp-core/tests/vault.rs`, temp dirs, `Argon2Cost::TEST`, `MemKeyring`)
- `t01_initialize_lock_unlock_roundtrip` (AC1).
- `t02_keyring_unlock_fallback_and_recovery` (AC2).
- `t03_wrong_password_touches_only_backoff` (AC3).
- `t04_backoff_shared_between_engines` with `ManualClock` (AC4).
- `t05_lock_drops_every_key` (AC6).
- `t06_tampered_kdf_rejected_before_argon2` (AC7).
- `t07_tampered_wraps_and_envelopes` (AC10).
- `t08_store_passwords_off_and_history_not_dirty` (AC11).
- `t09_two_engines_see_each_other` (AC12).
- `t10_change_password_rewraps_and_old_fails`.
- `t11_cost_upgrade_on_unlock` — stored LIGHT-test cost, options with another cost → after
  unlock `meta.kdf` has the new cost and salt and the password still unlocks.
- `t12_device_blob_roundtrip_and_locked` — `put_blob`/`get_blob`, `Locked` after lock.
- `t13_host_key_store_add_replace_remove` — `add(entry, replaces)` is one transaction.
- `t14_initialize_race` — two engines call `initialize` concurrently: exactly one succeeds.
- `tests/canary.rs::vault_cycle_leaks_nothing` (AC9).
- `tests/hardening.rs::{t01_process_not_dumpable, t02_core_limit_zero}` (Linux, AC14).
- `benches/vault_unlock.rs::vault_unlock_10k` (AC15).

### End-to-end tests
- `courier-ftp-e2e/tests/vault_pty.rs::first_run_unlock_and_lock` (`#[ignore]`, `PtyApp`, T76):
  first run creates the vault, quit, restart shows the unlock screen, unlock, `Ctrl-x Ctrl-l`
  shows the lock overlay. Runs once T60 exists.

## Out of scope

- All screens (T60), settings UI (T68).
- Server-side password change, recovery key and account login (T87).
- Sync pull/push (T88), team grants and rotation (T89).
- Certificate trust store implementation (T12, on this API).
- FileZilla's own master-password scheme (T32).

## Open questions

1. When the user turns `vault.store_passwords` off, should existing saved passwords be deleted
   (FileZilla asks and deletes them)? Current spec: they are kept but ignored until the user
   runs "Delete saved passwords" (a T68 button calling `put` with secrets cleared). Owner to
   decide whether turning the setting off should offer deletion immediately.
2. Resolved: T12 implements `VaultCertTrustStore` itself on this API and T81's
   `TrustedCertItem`.
