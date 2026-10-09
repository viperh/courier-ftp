# T82 — Local store (SQLite)

**Phase:** H Sync (also used by the local vault) · **Milestone:** M2 · **Depends on:** T80, T81 · **Crate(s):** new `courier-ftp-store` · **Decisions:** D4, D13 · **FEATURES.md:** §2 (password storage), §5 (queue persistence, via T40)
**Related (integrates with, not blocking):** T40
**Reference:** sverb `crates/sverb-store/src/{db,items,outbox,sync_state,vaults,meta,approvals,pins,device_local,schema,error,clock}.rs`, `crates/sverb-store/migrations/000{1,2,3}_*.sql`, `crates/sverb-store/tests/{store,approvals,pins}.rs`, SPEC §5.2.

## Goal

The client database: one SQLite file holding encrypted items, vault keys wrapped under the
LMK, sync bookkeeping and device-local data. It only ever sees ciphertext, works the same with
or without sync (so turning sync on later pushes everything that already exists), survives
several courier-ftp processes using it at once, and refuses databases from newer versions
instead of corrupting them.

## Context

- Before: T80 gives `envelope::{parse_header, FORMAT_V1, MIN_LEN}` (used to refuse plaintext)
  and `canon::Id16`. T81 defines what the envelopes contain and the dirty/outbox semantics this
  store implements.
- **Layering decision**: `courier-ftp-store` depends on `courier-ftp-crypto` only, not on
  `courier-ftp-core`. Ids cross its API as `Id16` (`[u8; 16]`). This lets `courier-ftp-core`
  depend on the store, so `VaultEngine` (T30) and the sites/bookmarks logic (T31, T33) live in
  core as their tasks require (sverb has the opposite direction and keeps its engine in the
  TUI crate). Typed ids are converted with `ItemId::as_bytes()` / `ItemId::from_bytes()` in
  core and in `courier-ftp-sync`.
- After: T30 is the only caller in core (meta, vaults, items, device blobs); T40 stores the
  queue as the device blob `queue`; T61 stores tabs as `tabs`; T31/T33 use `device_local`;
  T87 uses `sync_state` and `meta`; T88 uses `items`, `outbox`, `vaults.sync_cursor`; T89 uses
  `pinned_keys`; T91 §8 uses `local_approvals`.

## Technical specification

### Types and APIs

Crate `courier_ftp_store`:

```rust
pub type Id16 = courier_ftp_crypto::canon::Id16;

/// The client database. Cheap to clone; clones share one writer and the reader pool.
#[derive(Clone)] pub struct Store { .. }
impl Store {
    /// Opens (creating if needed) `path` with the system clock.
    pub fn open(path: impl AsRef<Path>) -> Result<Store>;
    pub fn open_with_clock(path: impl AsRef<Path>, clock: Arc<dyn Clock>) -> Result<Store>;
    #[doc(hidden)] pub fn open_with_migrations(path, clock, extra: &[&'static str]) -> Result<Store>;
    pub fn path(&self) -> &Path;
    pub fn now(&self) -> i64;                                   // Unix ms from the clock
    /// One IMMEDIATE write transaction on the writer connection (spawn_blocking).
    pub async fn write<F, T>(&self, f: F) -> Result<T>
        where F: FnOnce(&WriteTx<'_>) -> Result<T> + Send + 'static, T: Send + 'static;
    /// One read transaction on a pooled read-only connection (spawn_blocking).
    pub async fn read<F, T>(&self, f: F) -> Result<T>
        where F: FnOnce(ReadTx<'_>) -> Result<T> + Send + 'static, T: Send + 'static;
    /// Bumped after every commit that queued an outbox row (T88 wakes on it).
    pub fn outbox_changes(&self) -> tokio::sync::watch::Receiver<u64>;
    /// `PRAGMA data_version` of the writer connection: changes when another
    /// connection or process commits (T30 reloads on change).
    pub async fn data_version(&self) -> Result<i64>;
}
pub struct ReadTx<'a> { .. }    // Copy; repository read methods
pub struct WriteTx<'a> { .. }   // repository write methods + as_read() + now()
pub trait Clock: Send + Sync + Debug { fn now_millis(&self) -> i64; }
pub struct SystemClock;  pub struct ManualClock { .. }   // tests

pub const READER_POOL_SIZE: usize = 4;
pub const BUSY_TIMEOUT_MS: u64 = 5_000;
pub const SCHEMA_VERSION: i64;                 // = number of migrations (1 in this task)
pub const TABLES: &[&str];                     // persistent tables; none holds plaintext
pub const MAX_ENVELOPE_LEN: usize = 1_048_576 + 4_096;   // 1 MiB item + header/tag/padding slack
```

Repository methods (each exists on `ReadTx`/`WriteTx` and as an async one-shot on `Store`):

| Repo (module) | Read | Write |
|---|---|---|
| `meta` | `get_meta(key) -> Option<Vec<u8>>` | `set_meta(key, &[u8])`, `delete_meta(key)` |
| `vaults` | `list_vaults() -> Vec<VaultRow>`, `get_vault(id)` | `create_vault(id, VaultKind, org_id: Option<Id16>, key_version, wrapped_key)`, `update_wrapped_key(id, key_version, wrapped)`, `set_sync_cursor(id, i64)`, `delete_vault(id)` (cascades items, outbox, device_local and approvals of its items) |
| `items` | `get_item(id) -> Option<ItemRow>`, `list_items(vault)`, `list_all_items()`, `list_dirty(vault)`, `item_count()`, `item_markers() -> Vec<ItemMarker>` | `put_item(PutItem)`, `apply_remote(vault, &[RemoteItem], new_cursor)`, `mark_pushed(id, revision, pushed_queued_at)`, `reseal_item(id, key_version, envelope)`, `reset_sync(vault) -> u64`, `purge_item(id)` |
| `outbox` | `list_outbox(vault) -> Vec<OutboxRow>`, `pending_count()`, `pending_by_vault()` | `enqueue(id, vault, base_revision)`, `rebase(id, new_base)`, `dequeue(id)`, `bump_attempts(id) -> u32` |
| `device_local` | `get_device_local(id) -> Option<DeviceLocal>`, `list_device_local()` | `touch_connected(id, at) -> f64` (returns new frecency), `set_local_dir_override(id, Option<&str>)`, `set_tree_expanded(id, Option<bool>)`, `move_device_local(from, to)`, `delete_device_local(id)` |
| `device_blobs` | `get_device_blob(name) -> Option<Vec<u8>>` | `put_device_blob(name, &[u8])`, `delete_device_blob(name)` |
| `sync_state` | `get_sync_state() -> Option<SyncState>` | `set_sync_state(&SyncState)`, `clear_sync_state()` |
| `pins` | `get_pin(user_id)`, `list_pins()` | `observe_pin(PinObservation) -> PinState`, `set_verified(user_id, SetVerified)`, `accept_key_change(user_id)`, `delete_pin(user_id)` |
| `approvals` | `get_local_approval(id, field)`, `list_local_approvals()` | `put_local_approval(id, field, value_sha256: [u8; 32])`, `delete_local_approval(id, field) -> bool`, `delete_local_approvals_of(id) -> usize` |

```rust
pub struct ItemRow { pub id: Id16, pub vault_id: Id16, pub revision: i64, pub key_version: u32,
                     pub envelope: Vec<u8>, pub deleted: bool, pub dirty: bool, pub updated_at: i64 }
pub struct ItemMarker { pub id: Id16, pub updated_at: i64, pub revision: i64, pub deleted: bool }
pub struct PutItem<'a> { pub vault_id: Id16, pub id: Id16, pub key_version: u32,
                         pub envelope: &'a [u8], pub deleted: bool, pub mark_dirty: bool }
pub struct RemoteItem { pub id: Id16, pub revision: i64, pub key_version: u32,
                        pub envelope: Vec<u8>, pub deleted: bool, pub local_pending: bool }
pub struct OutboxRow { pub item_id: Id16, pub vault_id: Id16, pub base_revision: i64,
                       pub queued_at: i64, pub attempts: u32 }
pub enum VaultKind { Personal = 0, Shared = 1 }
pub struct VaultRow { pub id: Id16, pub kind: VaultKind, pub org_id: Option<Id16>,
                      pub key_version: u32, pub wrapped_key: Vec<u8>, pub sync_cursor: i64 }
pub struct DeviceLocal { pub item_id: Id16, pub last_connected_at: Option<i64>, pub frecency: f64,
                         pub local_dir_override: Option<String>, pub tree_expanded: Option<bool> }
pub struct SyncState { pub server_url: String, pub device_id: Id16, pub tokens_enc: Vec<u8> }
pub fn check_envelope(envelope: &[u8], key_version: u32) -> Result<()>;
pub mod meta::keys { KDF, LMK_WRAPPED_PW, LMK_WRAPPED_KEYRING, DEVICE_KEY_WRAPPED,
                     UNLOCK_FAILURES, UNLOCK_NEXT_ALLOWED_AT, DEVICE_ID, DB_ID, HLC_LAST }
pub mod device_local::{FRECENCY_HALF_LIFE_DAYS, decay, bump_frecency};
```

### Behaviour

**Opening** (sverb `db.rs::open_inner`):
1. Create the parent directory (`0700` on Unix, `create_dir_all` then `set_permissions`).
2. If the file exists and is non-empty, read `PRAGMA user_version` through a **read-only**
   connection first; if it is newer than `SCHEMA_VERSION`, return `NewerSchema` without
   touching the file (not even switching journal mode). A damaged file returns `Corrupt`.
3. Create the file with mode `0600` (Unix) if missing; tighten an existing file to `0600`.
4. Open the writer (`READ_WRITE | CREATE | NO_MUTEX`), `busy_timeout = 5000 ms`, re-check
   `user_version` (another process may have migrated meanwhile), then `PRAGMA journal_mode = WAL`
   (warn if refused), `synchronous = NORMAL`, `foreign_keys = ON`, `temp_store = MEMORY`.
5. Run migrations with `rusqlite_migration` (each in one transaction; `user_version` becomes the
   number of applied migrations). A failing migration leaves the previous version intact.
6. Tighten `-wal`, `-shm`, `-journal` siblings to `0600`.
7. Open `READER_POOL_SIZE = 4` read-only connections with the same pragmas (minus WAL).

**Transactions**: one writer connection behind a `tokio::sync::Mutex`; every `write` runs in
`spawn_blocking` inside `BEGIN IMMEDIATE` (takes the write lock up front, so two processes
serialise instead of deadlocking on lock upgrade). Readers take a semaphore permit and a pooled
connection, run a deferred read transaction, and return the connection even if the closure
panics. A panic inside a closure is resumed on the caller; a cancelled task is `StoreError::Task`.
`SQLITE_BUSY`/`SQLITE_LOCKED` after the 5 s busy timeout map to `StoreError::Busy`.

**Plaintext guard**: `put_item`, `apply_remote` and `reseal_item` call `check_envelope`: shorter
than 45 bytes → `InvalidEnvelope("too short")`; first byte `0x01` with a header whose
`key_version` differs from the declared one → `InvalidEnvelope`; longer than
`MAX_ENVELOPE_LEN` → `InvalidEnvelope("too large")`. Unknown format bytes from newer builds are
accepted (stored, not interpreted). `put_device_blob` requires first byte `0x01` and length
≥ 41 (`1 + 24 + 16`). `sync_state.tokens_enc` and `vaults.wrapped_key` must be ≥ 40 bytes
(a wrapped key). The store never decrypts anything.

**Local writes and the outbox** (sverb SPEC §5.2, §12.1): `put_item` upserts the row with
`updated_at = now`. With `mark_dirty = true` it sets `dirty = 1` and upserts the outbox row in
the **same transaction** with the item's current `revision` as `base_revision`; an existing
outbox row keeps its original `base_revision` and gets a new `queued_at` (coalescing: ten local
edits produce one push). A clean write (`mark_dirty = false`) never clears an existing dirty
flag. Outbox rows exist whether or not sync is configured, so enabling sync later pushes
everything that is dirty. T30 passes `mark_dirty = false` only for `history-entry` items while
`sync.history = false`; such items never enter the outbox and are not pushed retroactively when
the setting is turned on later (sverb ConnLog rule).

**Pull/push bookkeeping** (used by T88):
- `apply_remote(vault, page, new_cursor)`: upserts every row of a pulled page and moves
  `vaults.sync_cursor` in **one** transaction; any error rolls back the page and the cursor.
  `local_pending = false` → row becomes clean and its outbox row is deleted; `true` → row stays
  dirty and its outbox `base_revision` is rebased to the incoming `revision`.
- `mark_pushed(id, revision, pushed_queued_at)`: sets `revision`; if the outbox row's
  `queued_at` still equals `pushed_queued_at` the item becomes clean and the row is deleted,
  otherwise (edited again during the push) the row is rebased onto `revision` and stays.
- `reseal_item` replaces only `key_version` + `envelope` (key rotation, T89).
- `reset_sync(vault)`: sets `revision = 0` and `dirty = 1` on all items of the vault, enqueues
  every item with base 0, sets the cursor to 0 (full resync after `410`, T88). Returns the count.
- `purge_item(id)` deletes the item, its outbox row, its `device_local` row and its approvals.

**Device-local data**: `device_local` rows are keyed by item id but are never synced, never
in an envelope and never touch the outbox. `touch_connected(id, at)` updates
`last_connected_at` and frecency with sverb's formula
`frecency = frecency_prev · 0.5^(Δdays / 14) + 1` (Δdays clamped ≥ 0, half-life 14 days);
`DeviceLocal::score_at(now)` decays the stored value to `now` for ranking. Rows whose item no
longer exists are deleted by `purge_item` and ignored by readers.

**Device blobs**: named, LMK-protected blobs (T80 `device_blob` format, sealed by T30): `queue`
(T40) and `tabs` (T61). Max blob size 256 MiB (`InvalidInput`-style `StoreError::TooLarge`).

**Change detection across processes**: `data_version()` runs `PRAGMA data_version` on the writer
connection. Its value changes only when *another* connection commits, so T30 polls it every 2 s
while unlocked and, on change, compares `item_markers()` with its cache to reload changed rows.

**What is never stored**: decrypted item data in any table, file or temp file. All
connections use `temp_store = MEMORY` so sort spills and any TEMP table stay in RAM. Search
over decrypted labels happens in memory in T30 (no TEMP index table is created by this task).

### Data formats and configuration

Database file: `<data dir>/courier-ftp.db` (data dir from the binary's `get_data_dir()`,
overridden by `COURIER_FTP_DATA` or `COURIER_FTP_HOME`, T01). Migrations live in
`crates/courier-ftp-store/migrations/` and are embedded with `include_str!`.

`migrations/0001_init.sql` (sverb's three client migrations folded into one plus the
courier-ftp additions `device_blobs`, `device_local.local_dir_override`,
`device_local.tree_expanded`):

```sql
CREATE TABLE meta        (key TEXT PRIMARY KEY, value BLOB NOT NULL);

CREATE TABLE vaults      (id BLOB PRIMARY KEY CHECK (length(id) = 16),
                          kind INTEGER NOT NULL CHECK (kind IN (0, 1)),   -- 0 personal, 1 shared
                          org_id BLOB,
                          key_version INTEGER NOT NULL,
                          wrapped_key BLOB NOT NULL,                      -- VK wrapped under the LMK
                          sync_cursor INTEGER NOT NULL DEFAULT 0);

CREATE TABLE items       (id BLOB PRIMARY KEY CHECK (length(id) = 16),
                          vault_id BLOB NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
                          revision INTEGER NOT NULL DEFAULT 0,            -- server revision, 0 = never synced
                          key_version INTEGER NOT NULL,
                          envelope BLOB NOT NULL,                         -- encrypted ItemBody (T80)
                          deleted INTEGER NOT NULL DEFAULT 0,
                          dirty INTEGER NOT NULL DEFAULT 0,               -- pending push
                          updated_at INTEGER NOT NULL);                   -- Unix ms of the last local write

CREATE TABLE outbox      (item_id BLOB PRIMARY KEY REFERENCES items(id) ON DELETE CASCADE,
                          vault_id BLOB NOT NULL,
                          base_revision INTEGER NOT NULL,
                          queued_at INTEGER NOT NULL,
                          attempts INTEGER NOT NULL DEFAULT 0);

CREATE TABLE device_local(item_id BLOB PRIMARY KEY,                       -- no FK: rows may precede the item
                          last_connected_at INTEGER,
                          frecency REAL,
                          local_dir_override TEXT,
                          tree_expanded INTEGER);

CREATE TABLE device_blobs(name TEXT PRIMARY KEY,                          -- 'queue', 'tabs'
                          blob BLOB NOT NULL,                             -- T80 device_blob format
                          updated_at INTEGER NOT NULL);

CREATE TABLE sync_state  (id INTEGER PRIMARY KEY CHECK (id = 1),
                          server_url TEXT NOT NULL,
                          device_id BLOB NOT NULL,
                          tokens_enc BLOB NOT NULL);                      -- wrapped under the LMK (SyncTokens)

CREATE TABLE local_approvals (item_id BLOB NOT NULL, field TEXT NOT NULL,
                              value_sha256 BLOB NOT NULL CHECK (length(value_sha256) = 32),
                              approved_at INTEGER NOT NULL,
                              PRIMARY KEY (item_id, field));

CREATE TABLE pinned_keys (user_id BLOB NOT NULL PRIMARY KEY, label TEXT,
                          fingerprint BLOB NOT NULL, x25519_pub BLOB NOT NULL, ed25519_pub BLOB NOT NULL,
                          first_seen_at INTEGER NOT NULL,
                          verified INTEGER NOT NULL DEFAULT 0, verified_at INTEGER,
                          is_self INTEGER NOT NULL DEFAULT 0,
                          changed_fingerprint BLOB, changed_x25519_pub BLOB, changed_ed25519_pub BLOB,
                          changed_at INTEGER);

CREATE INDEX items_vault_id  ON items(vault_id);
CREATE INDEX items_dirty     ON items(dirty) WHERE dirty = 1;
CREATE INDEX outbox_vault_id ON outbox(vault_id);
```

`meta` keys (values are raw bytes; owners in parentheses):

| Key | Encoding | Owner |
|---|---|---|
| `kdf` | CBOR map `{alg: "argon2id", m_kib, t, p, salt: bstr(16)}` | T30 |
| `lmk_wrapped_pw` | T80 wrap, purpose `Lmk` (72 B) | T30 |
| `lmk_wrapped_keyring` | T80 wrap, purpose `Lmk`; present iff keyring unlock is on | T30 |
| `device_key_wrapped` | T80 wrap, purpose `DeviceKey` | T30 |
| `unlock_failures` | u32 BE | T30 |
| `unlock_next_allowed_at` | i64 BE, Unix ms | T30 |
| `device_id` | 16 bytes (UUIDv7) | T30 |
| `db_id` | UUIDv7 text, hyphenated | T30 |
| `hlc_last` | u64 BE | T30 |
| `vault_name_enc/<uuid>`, `vault_permission/<uuid>` | as sverb data-model §3 | T89 |
| `account/*` | defined by T87 | T87 |

Later schema changes are new files `0002_*.sql`, … (append-only; never edit a released
migration). `SCHEMA_VERSION` = number of files.

Cargo: `rusqlite = { version = "0.40.2", features = ["bundled"] }`, `rusqlite_migration = "2.6.0"`,
`tokio` (`sync`, `rt`), `parking_lot`, `thiserror`, `tracing`, `courier-ftp-crypto`;
dev: `tempfile`, `proptest`.

No settings keys.

### Errors

```rust
#[non_exhaustive]
pub enum StoreError {
    NewerSchema { found: i64, supported: i64 }, // "This database was created by a newer courier-ftp (schema N). Please update courier-ftp."
    Busy,                       // "the database is busy (another courier-ftp may be writing); try again"
    NotFound,
    Corrupt(String),            // "the database is corrupt: <reason>. Restore it from a backup (or move it away to start fresh)"
    InvalidEnvelope(&'static str), // plaintext guard
    TooLarge,
    Migration(String),
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
    Task(String),
}
```

T30 maps `Busy` to `VaultError::Busy` (UI offers *Retry*, T60), `NewerSchema` and `Corrupt`
to a startup error screen with the path, everything else to `VaultError::Storage`. The
database path appears in `Corrupt` messages (it is the user's own file, not a remote host).

### Security and logging

- Only ciphertext and non-secret bookkeeping reach disk (plaintext guard above; a canary test
  greps the `.db`, `-wal` and `-shm` files).
- File `0600`, directory `0700` on Unix. On Windows the file inherits the user profile ACL
  (`%LOCALAPPDATA%`), documented.
- Logs: `debug` only, with schema versions, counts and short ids; never envelopes, wrapped keys
  or tokens. `info`+ never carries paths of other users' data or hostnames (there are none here).
- Values read from the file are untrusted (a damaged or hostile file): ids must be 16 bytes,
  integers in range, otherwise `Corrupt` — never a panic.

## Implementation steps

1. Crate skeleton, `error.rs`, `clock.rs`, `schema.rs` with `0001_init.sql`.
2. `db.rs`: open sequence (newer-schema probe, `0600`, pragmas, migrations, reader pool),
   `write`/`read`, `data_version`, outbox watch channel.
3. `meta.rs`, `vaults.rs` (with cascade delete).
4. `items.rs` (`check_envelope`, `put_item`, `apply_remote`, `mark_pushed`, `reseal_item`,
   `reset_sync`, `purge_item`, markers) and `outbox.rs`.
5. `device_local.rs` (frecency) and `device_blobs.rs`.
6. `sync_state.rs`, `pins.rs`, `approvals.rs` (ported from sverb, ids as `Id16`).
7. Port sverb's `tests/store.rs`, `tests/pins.rs`, `tests/approvals.rs` and add the
   two-process and canary tests.

## Acceptance criteria

- [ ] AC1 A fresh file gets every table in `TABLES`, `user_version = SCHEMA_VERSION`, WAL mode,
  `foreign_keys = 1`, `temp_store = 2`, `busy_timeout = 5000` on every connection.
- [ ] AC2 A file with `user_version = SCHEMA_VERSION + 1` returns `NewerSchema` and its bytes
  (and absence of `-wal`/`-shm`) are unchanged afterwards.
- [ ] AC3 A failing extra migration leaves `user_version` and the schema at the previous version.
- [ ] AC4 `put_item(mark_dirty = true)` writes the item row and the outbox row atomically: an
  injected error after the item upsert leaves neither; 10 consecutive edits leave one outbox
  row with the first `base_revision`.
- [ ] AC5 `apply_remote` with an invalid envelope in the middle of a page leaves all rows and
  the cursor unchanged.
- [ ] AC6 Two `Store` instances on the same file (simulating two processes) each perform 500
  interleaved write transactions concurrently: all 1 000 commits are present, no `Busy` error
  surfaces with `busy_timeout = 5000`, `PRAGMA integrity_check` returns `ok`.
- [ ] AC7 After writing envelopes of bodies containing `CANARY-SITE-9d2e` and checkpointing,
  the bytes `CANARY-SITE-9d2e` occur in none of `courier-ftp.db`, `-wal`, `-shm`; handing a
  plaintext body to `put_item` returns `InvalidEnvelope`.
- [ ] AC8 On Unix the database, `-wal` and `-shm` are mode `0600` and the directory `0700`.
- [ ] AC9 A random non-SQLite file at the path returns `Corrupt` with the path in the message.
- [ ] AC10 `data_version()` changes after a commit from another `Store` instance and not after
  a commit from the same instance.
- [ ] AC11 CI gates `fmt`, `clippy`, `docs`, `test-local-only`, `test-os`, `layering`
  (`courier-ftp-store` does not depend on `courier-ftp-core`, ratatui, crossterm or clap) pass.

## Tests

### Unit tests
- `device_local::tests::{decay_halves_after_14_days, bump_adds_one, clock_backwards_clamped}`.
- `items::tests::check_envelope_rules` — too short, key-version mismatch, too large, unknown
  format byte accepted.
- `schema::tests::tables_constant_matches_sqlite_master`.

### Property / fuzz tests
- `tests/outbox_props.rs::coalescing_keeps_first_base` — random sequences of `put_item`,
  `mark_pushed`, `apply_remote` keep the invariant "dirty = 1 ⇔ outbox row exists" (except
  for clean `mark_dirty = false` writes of rows that were never dirty) (AC4).

### Snapshot tests
Not applicable.

### Integration tests
(`crates/courier-ftp-store/tests/store.rs`, ported from sverb with names kept)
- `t01_fresh_db` — tables, `user_version` (AC1).
- `t02_pragmas` — pragmas on writer and readers (AC1).
- `t03_newer_schema_untouched` — file hash before/after (AC2).
- `t04_migration_atomicity` — extra failing migration (AC3).
- `t05_outbox_coalescing` (AC4).
- `t05b_put_item_atomic_with_outbox` — closure returns an error after `put_item` (AC4).
- `t06_rebase` — `mark_pushed` with a newer `queued_at` rebases.
- `t07_apply_remote_atomic` (AC5).
- `t08_delete_vault_cascade` — items, outbox, device_local, approvals gone.
- `t09_concurrency` — two instances, 2 × 500 writes (AC6).
- `t10_data_version_cross_instance` (AC10).
- `t12_no_plaintext_on_disk` (AC7).
- `t13_corrupt_db` (AC9).
- `t14_sync_state_singleton` — second insert replaces, `CHECK (id = 1)`.
- `t15_file_modes` (Unix only) (AC8).
- `meta_and_device_local`, `device_blobs_roundtrip_and_size_limit`.
- `tests/pins.rs`, `tests/approvals.rs` — sverb's cases with `Id16`.
- `courier-ftp-e2e/tests/workspace_metadata.rs` layering rule (AC11, T76).

### End-to-end tests
Not applicable (covered through T30 and T88).

## Out of scope

- Encryption, decryption and key handling (T30).
- The server database (T85).
- A TEMP search-index table (search runs on T30's in-memory cache).

## Open questions

None.
