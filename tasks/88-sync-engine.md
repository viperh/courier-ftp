# T88 — Sync engine: pull, push and live updates

**Phase:** H Sync · **Milestone:** M7 · **Depends on:** T81, T82, T85, T87 · **Crate(s):** `courier-ftp-sync` (`engine`, `pull`, `push`, `resync`, `ws`, `status`), `courier-ftp-core` (`vault` change notifications) · **Decisions:** D4, D12 · **FEATURES.md:** §2 (sites, bookmarks and trusted keys on every device)
**Related (integrates with, not blocking):** T04, T91
**Reference:** sverb `crates/sverb-sync/src/{engine,pull,push,resync,ws,status,keys,info}.rs`, `tests/{engine,engine_mock,ws}.rs`; SPEC §12.1–§12.6.

## Goal

Keep every vault of an unlocked, signed-in courier-ftp in sync in the background,
offline-first: local edits are written locally at once and never wait for the network,
remote changes are merged field by field (T81), conflicts and outages resolve themselves,
and the UI gets a status line and short notifications. Several devices editing the same
data offline converge to identical state.

## Context

- **Before:** T81 (`ItemBody`, `merge`, HLC with `ClockSkew`), T82 (`items`, `outbox`,
  `vaults.sync_cursor`, page transactions), T85 (pull/push/WS server semantics), T87
  (`ApiClient`, `TokenManager`, `SyncError`, local account state, `VaultEngine::sync_handles`
  / `reload`).
- **After:** T89 hooks team-vault adoption, rotation pauses and key refresh into the vault
  list refresh defined here; T90 shows `SyncStatus`/`SyncEvent`s and the sync panel; T91 §8
  local-acting approvals rely on the engine never pre-approving remote values; T76 runs the
  multi-device scenarios against the Docker server.

## Technical specification

### Types and APIs

```rust
// src/engine.rs
pub const MAX_CONFLICT_ROUNDS: u32 = 5;
pub const PUSH_MAX_DELAY: Duration = Duration::from_secs(10);   // debounce cap under continuous edits
pub const WS_PULL_COALESCE: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyncPolicy { pub history: bool }                     // settings `sync.history`
impl SyncPolicy { pub const fn allows(&self, kind: ItemKind) -> bool; } // HistoryEntry only if history

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub push_debounce: Duration,        // sync.push_debounce_ms (2000)
    pub poll_interval: Duration,        // sync.poll_fallback_secs (300)
    pub policy: SyncPolicy,
    pub websocket: bool,                // true; tests may disable
    pub http_timeout: Duration,         // 30 s
    pub retry: BackoffPolicy,           // 1 s → 300 s
    pub page_limit: u32,                // ≤ 500
    #[doc(hidden)] pub crash_after_items: Option<usize>,  // test hook: panic inside a page tx
}
impl EngineConfig { pub fn from_settings(s: &courier_ftp_core::settings::Settings) -> Self; }

pub struct SyncEngine { /* Ctx */ }
impl SyncEngine {
    /// Needs an unlocked vault with sync configured (`sync_state` row + tokens).
    pub async fn new(vault: &VaultEngine, key_source: Arc<dyn VaultKeySource>, config: EngineConfig,
                     events: mpsc::UnboundedSender<SyncEvent>) -> Result<Self, SyncError>;
    /// Spawns the engine task (timers, WS client); dropping the handle stops it.
    pub fn spawn(self) -> SyncHandle;
    /// One full cycle without timers or WS (tests, "sync now" before spawn).
    pub async fn sync_once(&mut self) -> SyncStatus;
}
pub struct SyncHandle { /* cmd tx, watch rx, CancellationToken, JoinHandle */ }
impl SyncHandle {
    pub fn local_change(&self);                         // called by the vault change notifier
    pub async fn sync_now(&self) -> SyncStatus;         // full cycle, waits for its result
    pub fn status(&self) -> watch::Receiver<SyncStatus>;
    pub async fn shutdown(self);                        // cancel, await task (≤ 2 s), keys zeroized
}

/// Opens vault keys from server grants (personal self-grant here; T89 adds trust checks).
pub trait VaultKeySource: Send + Sync {
    fn open_grant(&self, view: &VaultView, key_version: u32) -> Option<Key32>;
}

// src/keys.rs
/// Vault keys by (vault, key_version), loaded from `vaults.wrapped_key` with the LMK; keeps
/// older versions after a rotation so items under them can be opened and re-sealed.
pub struct VaultKeys;
impl VaultKeys {
    pub fn load(rows: &[VaultRow], lmk: &Key32) -> (Self, Vec<(VaultId, SyncError)>);
    pub fn open(&self, vault: VaultId, id: ItemId, envelope: &[u8]) -> Result<ItemBody, SyncError>;
    pub fn seal(&self, vault: VaultId, id: ItemId, body: &ItemBody) -> Result<(u32, Vec<u8>), SyncError>; // current version
    pub fn current_version(&self, vault: VaultId) -> Option<u32>;
}

// src/status.rs
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStatus {
    Disabled,                              // no account / build without sync
    Synced,
    Syncing,
    Offline { pending: u64 },
    Error { message: String },             // human summary of held-back items etc.
    NeedsLogin(NeedsLoginReason),
}
impl SyncStatus { pub fn short(&self) -> &'static str; } // "synced" | "syncing" | "offline" | "error" | "login needed" | "local only"

#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum ToastLevel { Info, Warn, Error }
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncEvent {
    Status(SyncStatus),
    /// Remote changes committed locally: the UI reloads these items.
    Applied { vault: VaultId, items: Vec<ItemId> },
    Toast { level: ToastLevel, message: String },
    ClockSkew { device: String /*short id*/, ahead_secs: u64 },
    Resurrected { vault: VaultId, item: ItemId, label: String },
    ReadOnly { vault: VaultId, items: Vec<ItemId> },
    LocalActingChanged { item: ItemId, label: String, field: &'static str },
    AccessChanged { vault: VaultId, change: AccessChange },   // T89 fills details
    KeyRotated { vault: VaultId, key_version: u32 },          // T89
    AccountChanged { key_version: u32 },
}

// src/info.rs — read-only snapshot for the sync panel (T90)
pub struct LocalSyncInfo { pub server_url: String, pub email: String, pub last_ok_at: Option<OffsetDateTime>,
                           pub vaults: Vec<VaultPending> }
pub struct VaultPending { pub vault: VaultId, pub name: String, pub cursor: u64, pub pending: u64, pub blocked: u64 }
pub async fn local_info(store: &Store, lmk: &Key32) -> Result<Option<LocalSyncInfo>, SyncError>;

// src/ws.rs
#[derive(Debug, Clone, Copy)] pub struct BackoffPolicy { pub initial: Duration, pub max: Duration }
pub enum WsEvent { Connected, Message(ServerMsg), Disconnected { retry_in: Duration }, NeedsLogin(NeedsLoginReason) }
pub async fn run(api: ApiClient, tokens: Arc<TokenManager>, cfg: WsConfig, tx: mpsc::Sender<WsEvent>, cancel: CancellationToken);
```

Additions to `courier-ftp-core::vault` (T30's engine):

```rust
impl VaultEngine {
    /// Bumped after every committed local write (put/delete/import). The binary forwards it
    /// to SyncHandle::local_change.
    pub fn local_changes(&self) -> tokio::sync::watch::Receiver<u64>;
    /// Re-reads these items from the store into the decrypted in-memory index (after a pull).
    pub async fn apply_remote(&self, vault: VaultId, items: &[ItemId]) -> Result<(), Error>;
}
```

### Behaviour

#### Lifecycle

- The binary starts one engine after a successful unlock when `sync_state` exists and the
  `sync` feature is on; it stops the engine (`shutdown`) on lock, logout, quit, and before
  a login commit (T87). Stopping cancels in-flight HTTP requests; a SQLite page/batch
  transaction either commits or rolls back (never partial). Keys are zeroized with the
  engine (T30 live-key counter returns to its pre-start value).
- `NeedsLogin` keeps the task alive but idle (no timers, no WS) until it is shut down and
  replaced after a re-login.

#### Cycle (startup, fallback poll, sync now)

1. `GET /v1/vaults` (vault list refresh): rotation flags, new key versions (T89),
   vaults unknown to the server (excluded with one warn per vault), new team vaults (T89).
2. Pull every vault.
3. Push every vault.
4. If anything was accepted in 3, pull again (moves the cursor past our own revisions).
5. On success write `meta.sync_last_ok` (Unix ms) and set the status (below).

#### Pull (per vault)

Loop: `GET changes?since=<vaults.sync_cursor>&limit=500`. For each page, **one** SQLite
`IMMEDIATE` transaction:
1. For each item (ascending revision):
   a. open with the vault key of `item.key_version`; failure → skip, add to `undecryptable`
      (status error "N items could not be decrypted"), warn log with item id;
   b. observe every stamp in the HLC; the first `ClockSkew` per remote device per engine →
      `SyncEvent::ClockSkew` (UI: "Clock skew detected on device X");
   c. local row absent → insert clean (`revision`, `key_version`, envelope as received);
   d. local row clean → replace with the received row (clean);
   e. local row dirty → `merged = merge(local, remote)`; if `merged == remote` → replace with
      the remote row, clean, delete the outbox row; else re-seal `merged` under the current
      key, keep dirty, set `outbox.base_revision = item.revision`;
   f. if the local item was a tombstone and `merged` is live (an edit newer than the delete
      won) → `SyncEvent::Resurrected` ("<label> was restored: it was edited on another
      device"); the label comes from `name` of the decrypted body, never logged;
   g. if a local-acting field (T91 §8: `key_file` path, logon type `agent`,
      `try_agent_first`) changed value and `local_approvals` has no row for the new value
      hash → `SyncEvent::LocalActingChanged`. The engine **never** writes
      `local_approvals`.
2. Cursor: `more ? last.revision : head_revision`, written in the same transaction.
3. After commit: `vault.apply_remote(vault, ids)` and `SyncEvent::Applied`.
Repeat while `more`. `410 gone` → resync (below). `404` → the vault is excluded for this
engine and the status says "vault <name> is no longer available".

#### Full resync (`410 gone`)

1. Pull everything from `since = 0` into memory (pages of 500).
2. One transaction: apply all items as in Pull (merging into dirty copies); delete local
   **clean** items of that vault that are absent on the server; set local **dirty** items that
   are absent on the server to `outbox.base_revision = 0` (same id; the server purged the
   tombstone, so the id is free); set the cursor to the snapshot head.
3. The next push uploads the re-queued items.

#### Push (per vault)

Skipped while the vault is marked `rotating` (409 seen, until the vault list shows no
rotation; then pending items are re-sealed under the new key version, T89) or excluded.
Rounds (at most `MAX_CONFLICT_ROUNDS` per item per cycle):
1. Build a batch from `outbox` rows of the vault ordered by `queued_at`: skip blocked items;
   decrypt to check the kind against `SyncPolicy` (a `history-entry` with `sync.history =
   false` stays in the outbox and is not counted as pending); stop at 500 changes or 8 MiB;
   an envelope > 1 MiB is blocked locally (`TooLarge`) without sending.
   Change = `{id, base_revision: outbox.base_revision, key_version, envelope, deleted}`.
2. `POST changes`. Whole-request results: 403 → every pending item of the vault blocked
   `ReadOnly` + `SyncEvent::ReadOnly`; 409 `rotating` → mark vault rotating, stop; 400
   `key_version_stale` → refresh the vault list once (T89 key refresh), re-seal, retry once;
   transport error → backoff (outbox untouched, `attempts += 1`).
3. Per-item results, applied in **one** SQLite transaction:

| Result | Action |
|---|---|
| `ok{revision}` | if the row was not edited since the batch was built (same envelope): `items.revision = revision`, clean, delete outbox row; else `items.revision = revision`, keep dirty, `outbox.base_revision = revision` |
| `conflict{current: Some(c)}` | open `c`, `merged = merge(local, c)`; equal to `c` → store `c` clean, delete outbox row; else re-seal, keep dirty, `base_revision = c.revision`, `conflicts[id] += 1` |
| `conflict{current: None}` | `base_revision = 0` (re-push as new) |
| `too_large{message}` | block `TooLarge(message)`; one error toast per item ("<label> is too large to sync" / "Your sync storage is full") |
| `forbidden` | block `ReadOnly` |

4. Next round with remaining unblocked rows that changed base; an item still conflicting
   after 5 rounds is blocked `Conflict` (status error "N items kept conflicting"), retried at
   the next engine start.
The cursor is never moved by a push. Blocks live in memory for the engine's lifetime.

#### Triggers

| Trigger | Action |
|---|---|
| engine start | full cycle (with vault list) |
| `local_change` | push after `push_debounce` (2 s) since the last change, at most `PUSH_MAX_DELAY` (10 s) after the first unpushed change; then pull |
| WS `vault_changed{vault, head}` with `head > cursor` | pull that vault (coalesced 200 ms) |
| WS connected / reconnected | pull all vaults |
| WS `vault_access{…}` | vault list refresh, then pull (T89 handles adoption/removal) |
| WS `account_changed{key_version}` > `meta.account.key_version` | remember; the next 401/refresh failure becomes `NeedsLogin(PasswordChangedElsewhere)`; emit `SyncEvent::AccountChanged` |
| fallback timer `poll_interval` (300 s) | full cycle |
| `sync_now` | full cycle, returns the status |
| transport error | retry with backoff: `delay = min(1 s · 2ⁿ, 300 s)` ±20 % jitter; reset after a successful cycle |

#### Status

Computed after each cycle: `NeedsLogin` if login is needed; else `Offline{pending}` for
transport errors and 5xx (pending = outbox rows that may be pushed); else `Error{message}`
joining (in this order) "N items could not be decrypted", "N items kept conflicting", "N items
too large to sync", "N items not uploaded (read-only access)", plus T89 messages; else
`Syncing` while a cycle runs or a rotation pauses pushes with pending items; else `Synced`.
Every change is sent as `SyncEvent::Status` and on the `watch` channel.

#### WebSocket client

- URL: `wss://<host>/v1/ws` (`ws://` only for a loopback `http://` server); TLS via rustls +
  platform verifier; `Courier-Proto: 1` header on the upgrade.
- First frame `{"type":"auth","token"}` (never in the URL). `Connected` is reported when the
  server's first message (`ping`) arrives.
- Answers `ping` with `pong`; sends `ping` every 30 s; 2 unanswered → drop and reconnect.
- Reconnect backoff: attempt n waits uniform `[b/2, b]` with `b = min(1 s · 2ⁿ, 60 s)`; reset
  after a successful auth. Close 4401 → `refresh_after_401` once and reconnect immediately; a
  second 4401 without a successful auth in between backs off first; `NeedsLogin` ends the loop.
- Unknown message types are ignored.

#### What syncs

All item kinds (T81) except `history-entry` unless `sync.history = true`. Never synced
(not items): transfer queue and tab state (`device_blobs`), `device_local` (last connected,
frecency, `local_dir_override`), `local_approvals`, `pinned_keys`, `meta`, settings files.

### Data formats and configuration

| Key | Type | Default | Range | Meaning |
|---|---|---|---|---|
| `sync.history` | bool | `false` | — | also sync quickconnect history entries |
| `sync.push_debounce_ms` | u32 | `2000` | 200..=60000 | delay after the last local edit |
| `sync.poll_fallback_secs` | u32 | `300` | 30..=86400 | full cycle interval without notifications |

(Defined in T05's `sync` section; validation as T05 §3: out of range → warn + default.)
`meta.sync_last_ok`: 8-byte big-endian Unix ms.

### Errors

`SyncError` from T87. The engine never surfaces raw errors as dialogs: it turns them into
`SyncStatus` and toasts. Store errors (`SQLITE_BUSY` after `busy_timeout`) → retry next
cycle, status `Error{"local database busy"}`. A panic inside a page transaction (test hook)
rolls back and the engine task restarts the cycle after backoff.

### Security and logging

- Logs at info: cycle results with counts, vault ids, revisions; at warn: undecryptable item
  ids, clock skew device ids; never decrypted labels, hostnames, usernames or envelopes
  (T91 §4). Toast texts contain item labels but are UI-only, not logged.
- Remote items are untrusted: envelopes are opened only with the vault key for their
  `key_version` (AAD binds vault and item id, T80); merge input is the decrypted body; a
  remote item never writes `local_approvals` or `device_local`.
- Tokens stay inside `TokenManager`; WS auth frames are redacted in `Debug`.

## Implementation steps

1. `keys.rs`, `status.rs`, `info.rs`; `VaultEngine::local_changes`/`apply_remote` in core.
2. `pull.rs` (page transaction, merge, cursor) + tests with the in-process server.
3. `push.rs` (batching, results table, conflict rounds, blocks).
4. `resync.rs` (`410`).
5. `engine.rs` (cycle, triggers, debounce, backoff, status) with paused-time tests.
6. `ws.rs` client + engine wiring.
7. Binary wiring: start/stop with unlock/lock, forward `local_changes`, map `SyncEvent` to
   actions (T90 renders them).
8. Convergence property test, fault-injection tests, e2e scenarios.

## Acceptance criteria

- [ ] AC1 Two devices edit different fields of the same site while offline; after both
  reconnect both have both edits (identical decrypted bodies).
- [ ] AC2 Same field edited on both offline: the edit with the higher `(hlc, device)` wins on
  both devices.
- [ ] AC3 Delete on A, later edit on B (offline): after sync the item is live on both and A
  receives `SyncEvent::Resurrected`; delete later than the edit: deleted on both.
- [ ] AC4 Cutting the connection mid-push (request sent, response lost) loses nothing and
  creates no duplicate: after reconnect the outbox drains and server and client agree.
- [ ] AC5 After server GC raises the floor above the client's cursor, the next pull gets 410,
  resync runs, dirty local items are kept and pushed, clean items deleted on the server are
  removed locally.
- [ ] AC6 With both devices online and WS connected, a change saved on A is visible in B's
  vault within 3 s (default 2 s debounce).
- [ ] AC7 Property test: 3 devices × random sequences (≤ 30 ops of create/edit/delete/go
  offline/come online/sync) always end in identical item sets and bodies after a final sync
  round (256 cases in CI).
- [ ] AC8 A crash injected inside a pull page transaction leaves cursor and items unchanged;
  the next cycle applies the page exactly once.
- [ ] AC9 A conflict that persists for 5 rounds blocks the item and sets status `Error`
  ("1 item kept conflicting"); other items keep syncing.
- [ ] AC10 `history-entry` items are not pushed with `sync.history = false` and are pushed after
  it is switched on.
- [ ] AC11 Locking the vault stops the engine within 2 s and the live-key counter returns to
  its value before the engine started; unlock starts a new engine that resumes.
- [ ] AC12 WS: refused connections back off (1 s, 2 s, 4 s … ≤ 60 s); 4401 triggers exactly one
  refresh and an immediate reconnect; 2 missed pongs reconnect.
- [ ] AC13 No item label, hostname or username appears at info+ in logs of the engine tests
  (canary scan); CI `fmt`, `clippy`, `docs`, `test-os` pass.

## Tests

Harness from T87 (in-process server, `TestDevice`s), plus `FaultyProxy`: an in-test TCP
proxy between client and server that can refuse connections, cut a connection after the
request body has been forwarded, delay, or black-hole; time is paused where possible.

### Unit tests
- `push::tests::batch_limits_and_policy_filter` — 501 rows → 500 + 1; 8 MiB cap; history
  filtered (AC10).
- `push::tests::results_table` — each row of the per-item results table on a store fixture
  (AC9).
- `pull::tests::dirty_merge_rebases_outbox` and `merge_equal_to_remote_becomes_clean`.
- `engine::tests::debounce_and_max_delay` — edits every 1 s for 15 s → first push at 10 s.
- `engine::tests::backoff_schedule_with_jitter_bounds`.
- `status::tests::error_message_order`.
- `ws::tests::backoff_bounds_and_reset`.

### Property / fuzz tests
- `tests/convergence.rs::three_devices_converge` — proptest (256 cases in CI, 32 locally via
  `PROPTEST_CASES`), in-process server, operations as in AC7; final assertion compares
  decrypted `ItemBody`s and tombstones across devices and with the server (AC1–AC3, AC7).
- `tests/convergence.rs::pull_order_independence` — applying the same remote history in
  random page sizes yields the same local state.

### Snapshot tests
- Not applicable (T90 snapshots status rendering).

### Integration tests (`tests/engine.rs`, `tests/engine_faults.rs`, `tests/ws.rs`)
- `t01_single_device_push_after_debounce`.
- `t02_debounce_coalesces_edits`.
- `t03_two_clients_field_merge` (AC1).
- `t04_same_field_newest_wins` (AC2).
- `t05_delete_vs_edit_resurrects` (AC3).
- `t06_persistent_conflicts_block_after_five_rounds` — mock server answering conflict
  forever (AC9).
- `t07_pull_page_atomicity_on_crash` (AC8).
- `t08_gone_full_resync` (AC5).
- `t09_offline_queue_then_drain` — server down, edits queue, status `Offline{pending: n}`.
- `t10_ws_and_poll_triggered_pull` (AC6, paused time, 3 s budget).
- `t11_token_refresh_on_401_and_reuse_needs_login`.
- `t13_device_local_exclusions` (AC10).
- `t14_undecryptable_remote_item_is_skipped`.
- `t16_lock_stops_unlock_resumes` (AC11).
- `faults::cut_after_request_no_loss_no_duplicate` (AC4).
- `faults::refused_then_recovered_backoff`.
- `ws::t09_backoff_on_refused_connection`, `t09_4401_refreshes_once_then_reconnects`,
  `repeated_4401_backs_off`, `missed_pongs_reconnect` (AC12).
- `logs::no_labels_at_info` (AC13).

### End-to-end tests
- `courier-ftp-e2e/tests/sync_engine.rs` (`#[ignore]`, `COURIER_E2E=1`, Docker sync fixture,
  two `Headless` clients):
  - `offline_edits_on_both_devices_converge` — toxiproxy cuts both clients, edits, restore (AC1, AC2).
  - `live_change_arrives_within_3s` (AC6).
  - `gc_floor_forces_resync` — `admin gc` with a 0-day horizon via `docker exec` (AC5).
  - `kill_network_mid_push` (AC4).

## Out of scope

- Team vault adoption, grant verification, rotation (T89) — only the hooks.
- UI rendering (T90).
- OR-set merging of list fields (T81 keeps lists as whole LWW values).

## Open questions

None.
