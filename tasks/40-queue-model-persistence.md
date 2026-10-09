# T40 — Queue model and persistence

**Phase:** E Transfers · **Milestone:** M4 · **Depends on:** T02, T05, T30, T82 · **Crate(s):** `courier-ftp-core` (`queue` module) · **Decisions:** D4, D10 · **FEATURES.md:** §5
**Related (integrates with, not blocking):** T43
**Reference:** sverb `crates/sverb-store/src/device_local.rs` (device-local data next to synced items), `scripts/bench-gates.toml` (gate format)

## Goal

The transfer queue as a plain, synchronous data structure: items, states, priorities,
ordering, FileZilla's three lists (queued / failed / successful), statistics, an index
that lets the scheduler (T41) pick the next item in O(log n), and encrypted, device-local
persistence across restarts. It also exports and imports the queue as a secret-free JSON
file. A 100 000-item queue stays fast to edit and to render.

## Context

- Before: T02 gives `RemotePath`, `LocalPath`, `Entry`, `Timestamp`, `ServerAddress`,
  `Credentials`, `core::Error`; T03 gives `ConnectInfo` and `WriteMode`; T05 gives
  `Settings` with `queue.persist`, `transfers.*`, and the enums `ExistsAction` and
  `TransferTypeChoice`; T30 gives `VaultEngine` and the LMK; T82 gives the
  `device_blobs(name, envelope)` table; T81 gives `ItemId` (site ids are item ids).
- After: T41 runs the queue (scheduler index, state transitions, `completed` ranges);
  T41b stores segment progress in `completed`; T42 reads `on_exists`; T43 expands
  directory placeholders in place; T45 uses `QueueStats`; T56 renders rows from
  `Queue::rows`; T62 builds items (`build_transfer_items`) and calls `Queue::add_batch`.

## Technical specification

### Types and APIs

Module `courier_ftp_core::queue` (`mod.rs`, `item.rs`, `ranges.rs`, `index.rs`,
`persist.rs`, `export.rs`). Everything here is synchronous and does no I/O except
`persist.rs` and `export.rs`.

```rust
/// Unique id of a queue item for the lifetime of the queue (survives restarts).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TransferId(pub u64);
impl TransferId {
    /// Placeholder used by callers that build items; `Queue::add*` assigns the real id.
    pub const UNASSIGNED: TransferId = TransferId(0);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Direction { Download, Upload }

/// Ordered: `Lowest < … < Highest`. The scheduler starts higher priorities first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Priority { Lowest = 0, Low = 1, Normal = 2, High = 3, Highest = 4 }

/// Which server an item talks to. Shared between items via `Arc` (interned by the queue).
#[derive(Debug)]
pub enum QueueServer {
    /// A Site Manager site (T31). Resolved to a `ConnectInfo` when a connection opens.
    Site { site_id: ItemId, label: String },
    /// Quickconnect / ad-hoc server. Holds the full `ConnectInfo` including secrets
    /// (`SecretString`, never logged, never in `Debug`).
    Adhoc { info: Box<ConnectInfo>, label: String },
}
impl QueueServer {
    /// Grouping and limit key (see Behaviour §Groups).
    pub fn key(&self) -> GroupKey;
    /// Display label (`site path` or `sftp://alice@web01:22`). UI only, never logged at info+.
    pub fn label(&self) -> &str;
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum GroupKey {
    Site(ItemId),
    Adhoc { protocol: Protocol, host_lower: String, port: u16, user: String },
}

/// Opaque handle of a server group inside one `Queue` (index into a slab, not persisted).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GroupId(u32);

pub enum QueueItemKind {
    /// A single file.
    File,
    /// A directory expanded lazily by the engine (T43). Never transferred itself.
    DirPlaceholder(Box<DirExpansion>),
    /// Removes the (now empty) source directory of a Move after all of its children
    /// finished (T43, T62 `delete_source_after`). Runnable only when `pending == 0`.
    RemoveSourceDir { pending: u32 },
}

/// State carried by a directory placeholder (fields owned by T43; serialised here).
pub struct DirExpansion {
    pub filter_snapshot: Option<u32>,      // index into the queue's filter-snapshot table (T43)
    pub link_chain: Vec<LinkId>,           // symlink-loop detection (T43)
    pub depth: u16,                        // 0 = selected directory; hard limit 64 (T43)
}

pub struct QueueItem {
    pub id: TransferId,
    pub server: Arc<QueueServer>,
    pub kind: QueueItemKind,
    pub direction: Direction,
    pub local: LocalPath,
    pub remote: RemotePath,
    /// Source size when known (listing/stat at enqueue time).
    pub size: Option<u64>,
    /// Source mtime when known; used with `size` to detect a changed source on resume.
    pub source_modified: Option<Timestamp>,
    pub transfer_type: TransferTypeChoice,   // T05: Auto | Ascii | Binary
    pub priority: Priority,
    /// Per-item override of `transfers.on_exists_download|upload` (T42).
    pub on_exists: Option<ExistsAction>,
    /// Move to the other side (T62): delete the source after `Done`.
    pub delete_source_after: bool,
    /// Parent `RemoveSourceDir` item to notify when this item leaves the queued list.
    pub cleanup_parent: Option<TransferId>,
    pub state: ItemState,
    /// Failed attempts in the current run of this item (reset by "reset and requeue").
    pub attempts: u8,
    /// Last error text shown in the failed list (already user-facing, no secrets).
    pub last_error: Option<String>,
    /// Byte ranges of the destination already written and checkpointed (T41/T41b).
    pub completed: RangeSet,
    pub added_at: OffsetDateTime,
}
impl QueueItem {
    /// Builder used by T62/T43/T70; id = UNASSIGNED, state = Queued, priority = Normal.
    pub fn file(server: Arc<QueueServer>, direction: Direction, local: LocalPath, remote: RemotePath) -> Self;
    pub fn dir_placeholder(server: Arc<QueueServer>, direction: Direction, local: LocalPath, remote: RemotePath) -> Self;
    pub fn is_dir_placeholder(&self) -> bool;
}

#[derive(Clone, Debug, PartialEq)]
pub enum ItemState {
    Queued,
    /// Not runnable until `until` (retry delay, T41). Persisted as `Queued`.
    Waiting { until: Instant, reason: WaitReason },
    Active { phase: ActivePhase },
    Paused,
    Failed { at: OffsetDateTime, kind: FailureKind },
    Done { outcome: DoneOutcome, finished_at: OffsetDateTime, bytes: u64, duration: Duration },
}
pub enum WaitReason { RetryDelay, ServerBlocked }
pub enum ActivePhase { Connecting, Listing, Preparing, AwaitingUser, Transferring, Finishing }
pub enum FailureKind { Transient, Permanent, Cancelled }   // Transient = retries exhausted
pub enum DoneOutcome { Transferred, Resumed, Skipped(SkipReason), Expanded }
pub enum SkipReason { ExistsPolicy, AlreadyComplete, UserSkip, Filtered, NotEmpty }

/// Sorted, non-overlapping, non-adjacent half-open byte ranges.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeSet(Vec<(u64, u64)>);
impl RangeSet {
    pub fn insert(&mut self, start: u64, end: u64);           // merges overlaps/adjacency
    pub fn contains_range(&self, start: u64, end: u64) -> bool;
    pub fn covered(&self) -> u64;                               // total bytes
    pub fn contiguous_prefix(&self) -> u64;                     // end of [0, x) or 0
    pub fn missing(&self, total: u64) -> Vec<(u64, u64)>;       // gaps in [0, total)
    pub fn clear(&mut self);
}

/// Where to move selected items inside their server group.
pub enum MoveTo { Up, Down, Top, Bottom }

pub enum QueueTab { Queued, Failed, Successful }

/// One visible row for the queue pane (T56). Borrowed view, valid while the lock is held.
pub enum QueueRow<'a> {
    GroupHeader { group: GroupId, label: &'a str, files: u32, bytes: u64, blocked: Option<&'a str> },
    Item(&'a QueueItem),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueueStats {
    pub queued_files: u64, pub queued_dirs: u64,
    pub queued_bytes: u64, pub unknown_size_files: u64,
    pub active: u32, pub paused: u64, pub failed: u64, pub successful: u64,
}

pub struct RemoveResult { pub removed: Vec<TransferId>, pub active: Vec<TransferId> }

pub struct Queue { /* see Behaviour */ }
pub type SharedQueue = Arc<std::sync::Mutex<Queue>>;

impl Queue {
    pub fn new(max_successful: u32) -> Self;
    /// Increases on every mutation; UI re-renders and the persister saves when it changes.
    pub fn generation(&self) -> u64;

    // --- user operations (T56, T62) ---
    pub fn add_batch(&mut self, items: Vec<QueueItem>) -> Vec<TransferId>;
    pub fn insert_after(&mut self, anchor: TransferId, items: Vec<QueueItem>) -> Vec<TransferId>;
    pub fn remove(&mut self, ids: &[TransferId]) -> RemoveResult;  // active ones are not removed
    pub fn remove_all_queued(&mut self) -> RemoveResult;
    pub fn clear_failed(&mut self);
    pub fn clear_successful(&mut self);
    pub fn requeue_failed(&mut self, ids: &[TransferId]) -> usize;  // "Reset and requeue"
    pub fn move_items(&mut self, ids: &[TransferId], to: MoveTo);
    pub fn set_priority(&mut self, ids: &[TransferId], p: Priority);
    pub fn set_on_exists(&mut self, ids: &[TransferId], a: Option<ExistsAction>);
    pub fn pause(&mut self, ids: &[TransferId]) -> Vec<TransferId>; // returns active ids (engine pauses them)
    pub fn resume(&mut self, ids: &[TransferId]);

    // --- read side ---
    pub fn get(&self, id: TransferId) -> Option<&QueueItem>;
    pub fn stats(&self) -> &QueueStats;
    pub fn row_count(&self, tab: QueueTab, collapsed: &HashSet<GroupId>) -> usize;
    pub fn rows(&self, tab: QueueTab, collapsed: &HashSet<GroupId>, range: Range<usize>) -> Vec<QueueRow<'_>>;
    pub fn groups(&self) -> impl Iterator<Item = (GroupId, &QueueServer)>;

    // --- engine side (T41/T43), `pub` but documented as engine-only ---
    pub fn next_runnable(&self, allow: impl Fn(GroupId, Direction) -> bool) -> Option<TransferId>;
    pub fn set_state(&mut self, id: TransferId, state: ItemState);
    pub fn checkpoint(&mut self, id: TransferId, completed: RangeSet);
    pub fn finish(&mut self, id: TransferId, outcome: DoneOutcome, bytes: u64, duration: Duration);
    pub fn fail(&mut self, id: TransferId, kind: FailureKind, message: String);
    pub fn replace_placeholder(&mut self, id: TransferId, children: Vec<QueueItem>) -> Vec<TransferId>;
    pub fn set_group_blocked(&mut self, g: GroupId, reason: Option<String>);
    pub fn group_of(&self, id: TransferId) -> Option<GroupId>;
}
```

Persistence (`queue::persist`):

```rust
/// Device-local encrypted blob storage. Implemented by `VaultEngine` (T30) on top of
/// `device_blobs` (T82), sealed with the LMK. Returns `Error::Vault(Locked)` when locked.
#[async_trait]
pub trait DeviceBlobStore: Send + Sync {
    async fn put_blob(&self, name: &str, plaintext: Zeroizing<Vec<u8>>) -> Result<()>;
    async fn get_blob(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;
    async fn delete_blob(&self, name: &str) -> Result<()>;
}

pub const QUEUE_BLOB_NAME: &str = "transfer-queue";

pub fn encode_snapshot(q: &Queue) -> Result<Zeroizing<Vec<u8>>>;   // CBOR + zstd, see formats
pub fn decode_snapshot(bytes: &[u8], max_successful: u32) -> Result<Queue>;

pub struct PersisterHandle { /* … */ }
impl PersisterHandle {
    /// Writes now if dirty (used on quit; bounded by a 5 s timeout by the caller).
    pub async fn flush(&self) -> Result<()>;
    /// True when the in-memory queue has changes that are not stored (vault locked, error).
    pub fn has_unsaved_changes(&self) -> bool;
    pub async fn shutdown(self) -> Result<()>;
}
pub fn spawn_persister(queue: SharedQueue, store: Arc<dyn DeviceBlobStore>,
                       settings: watch::Receiver<Arc<Settings>>) -> PersisterHandle;
pub async fn load_queue(store: &dyn DeviceBlobStore, settings: &Settings) -> Result<Queue>;
```

Export / import (`queue::export`):

```rust
pub struct ExportOptions { pub include_failed: bool }          // default true
pub fn export_json(q: &Queue, sites: &dyn SiteLookup, opts: ExportOptions) -> Result<String>;
pub struct ImportReport { pub added: usize, pub rejected: Vec<(usize, String)> } // (item index, reason)
pub fn import_json(q: &mut Queue, json: &str, sites: &dyn SiteLookup) -> Result<ImportReport>;

/// Implemented by the binary on top of T31; lets core resolve sites without depending on T31.
pub trait SiteLookup {
    fn site_by_id(&self, id: ItemId) -> Option<(ItemId, String /* path "Work/web01" */)>;
    fn site_by_path(&self, path: &str) -> Option<ItemId>;
}
```

### Behaviour

**Groups.** Items are grouped by `QueueServer::key()`; the queue interns servers so all
items of a group share one `Arc<QueueServer>`. Groups are listed in order of creation;
an empty group (no queued/active items) is dropped. Per-server limits, the connection
pool and connection-limit back-off (T41) are per group. Two sites pointing at the same
host are two groups (documented limitation).

**Ordering.** Every queued item has an `OrderKey(u64)` in one global key space.
- `add_batch` appends: key = last key + `GAP` (`GAP = 1 << 20`), first key `1 << 62`.
- `insert_after(anchor, n items)` takes evenly spaced keys between the anchor and the next
  key; if fewer than `n` free keys exist, all keys are renumbered in order with `GAP`
  spacing (O(n); counted in `Queue::renumber_count()` for tests).
- `MoveTo::Top`/`Bottom` place the selection, in its current relative order, before the
  first / after the last item **of the same group**; `Up`/`Down` swap each selected item
  with the nearest unselected neighbour in the same group (FileZilla semantics; a block at
  the edge does not move). Moves never cross groups.
- Display order inside a group = ascending `OrderKey`. Scheduling order across the whole
  queue = (`Priority` descending, `OrderKey` ascending).

**Indexes** (all updated in the same call that mutates an item):
- `items: HashMap<TransferId, QueueItem>`.
- `order: BTreeMap<OrderKey, TransferId>` per group (display).
- `runnable: HashMap<(GroupId, Direction), BTreeSet<(Reverse<Priority>, OrderKey, TransferId)>>`
  containing exactly the items with `state == Queued`, not blocked, and (for
  `RemoveSourceDir`) `pending == 0`. `next_runnable(allow)` peeks the first element of
  each allowed set and returns the best: O(G · log n), G = number of groups × 2.
- `failed: VecDeque<TransferId>` (newest last, unbounded); `successful:
  VecDeque<TransferId>` capped at `queue.max_successful` (oldest dropped from memory).
- `QueueStats` counters adjusted incrementally (never recomputed by a scan).

**State transitions** (any other transition is a bug: `debug_assert!` + `tracing::warn!`,
ignored in release):

| From | To | By |
|---|---|---|
| Queued | Active | engine start (T41) |
| Queued | Paused / Queued ← Paused | `pause` / `resume` |
| Queued | Waiting → Queued | engine retry delay / timer |
| Active | Queued | engine Stop, retry without delay, connection-limit back-off |
| Active | Waiting | transient error with retries left |
| Active | Paused | engine pause of an active item |
| Active | Failed | permanent error or retries exhausted → moved to `failed` list |
| Active | Done | success or skip → moved to `successful` list |
| Active (placeholder) | Done(Expanded) | `replace_placeholder`; the placeholder disappears, not listed |
| Failed | Queued | `requeue_failed`: `attempts = 0`, `last_error = None`, `completed` kept |

`remove` never removes `Active` items; it returns them in `RemoveResult::active` so the
caller sends `Cancel { ids, remove: true }` to the engine (T41). `pause` returns active ids
for the same reason. When an item with `cleanup_parent` leaves the queued list (done,
failed or removed), the parent's `pending` is decremented; at 0 it becomes runnable.

**Placeholders** (T43): `replace_placeholder(id, children)` inserts `children` at the
placeholder's position (keys between the placeholder and its successor, in the given
order), inheriting `priority`, `on_exists`, `transfer_type`, `delete_source_after` from
the placeholder, then removes the placeholder. Returns the new ids.

**Successful list cap.** `queue.max_successful` (default 1000; 0 = keep none). Skipped
items (`DoneOutcome::Skipped`) go to the successful list too, so the user sees them.

**Statistics.** `queued_bytes` sums known sizes of `File` items that are Queued,
Waiting, Paused or Active (`size − completed.covered()` for partial ones);
`unknown_size_files` counts files without a size. The ETA shown in the status bar and
queue header is computed by T41 (`EngineStats`) from this and the engine speed.

**Persistence.**
1. Setting `queue.persist` (T05, default true). When false, the persister deletes the
   `transfer-queue` blob once and stops.
2. The persister task watches `generation()`. Debounce: write 2 s after the last change,
   but never later than 10 s after the first unsaved change (constant stream of changes
   still persists every 10 s). The snapshot is taken under the lock (`clone` of the data
   needed, ~10 ms for 100 k items) and encoded and stored in `spawn_blocking`.
3. Active items are stored as `Queued` with their last checkpointed `completed` ranges;
   `Waiting` → `Queued`. `Paused`, `Failed`, `Done` kept as is.
4. On startup (`load_queue`, after vault unlock) the queue is loaded **but not started**.
5. Vault locked or "continue without vault" (T30): `put_blob` fails with
   `Error::Vault(Locked)`; the persister keeps the dirty flag and retries every 10 s;
   `has_unsaved_changes()` is true so the UI warns on quit (T50/T60: "The transfer queue
   can't be saved while the vault is locked. Quit anyway?").
6. Quick-connect (`Adhoc`) items store their password inside the encrypted snapshot when
   `vault.store_passwords` is true; when false, `Normal { user, password }` is persisted as
   `AskForPassword { user }`.
7. A snapshot with `version` greater than this build supports is not loaded and **not
   overwritten** (persistence disabled for this process, warning logged and shown once:
   "The saved queue was written by a newer courier-ftp and was not loaded").
8. A `Site` item whose site no longer exists is kept; T41 fails it with "Site no longer
   exists" when it is scheduled.

**Export / import.**
- Export writes queued (and by default failed) items, never successful ones, never
  secrets. Sites are referenced by id **and** path; ad-hoc servers by URL without password
  plus logon kind.
- Import (untrusted input): file ≤ 64 MiB, ≤ 1 000 000 items, `format` and `version`
  checked; each item validated (`RemotePath` parses and is absolute; `local` is an absolute
  path for this OS; server reference resolves: site by id, then by path; ad-hoc URL parses
  via `ServerAddress::from_str`). Invalid items are listed in `ImportReport::rejected` and
  skipped; valid ones are added in `Queued` state with fresh ids. Ad-hoc servers with logon
  `normal` become `AskForPassword`.

**Limits.** Max 1 000 000 items in the queue (`add_batch` beyond that returns
`Error::InvalidInput("queue is full (1 000 000 items)")` and adds nothing); max path
length 4096 bytes per path (longer items rejected by T62/T43 before adding).

### Data formats and configuration

Settings (T05; this task adds `queue.max_successful`):

| Key | Type | Default | Notes |
|---|---|---|---|
| `queue.persist` | bool | `true` | T05 |
| `queue.max_successful` | u32 | `1000` | 0–100 000; validation clamps, warns |

**Snapshot blob** `device_blobs.name = "transfer-queue"`, plaintext before LMK sealing:
`zstd(level 3, cbor(QueueSnapshotV1))`; decompressed size capped at 256 MiB.

```text
QueueSnapshotV1 = {
  "v": 1,
  "next_id": u64,
  "servers": [ServerDto],             // index = server ref
  "filters": [[Filter]],              // T43 filter snapshots, referenced by index
  "items":  [ItemDto],                // queued + paused, in scheduling display order per group
  "failed": [ItemDto],
  "successful": [ItemDto]             // newest last, ≤ max_successful
}
ServerDto = { "site": bytes(16), "label": text }
          | { "adhoc": ConnectInfoDto, "label": text }   // ConnectInfoDto mirrors every
             // ConnectInfo field; secrets as text inside the encrypted blob only
ItemDto = { "id": u64, "s": uint /*server ref*/, "k": "f"|"d"|"r", "dir": 0|1 /*direction*/,
            "l": text, "r": text, "size": u64?, "mt": [i64 unix_ns, u8 precision]?,
            "tt": 0|1|2, "p": 0..4, "ox": text?, "del": bool, "cp": u64?,
            "st": "q"|"p"|"f"|"d", "att": u8, "err": text?, "done": [[u64,u64]],
            "added": i64, "fin": i64?, "bytes": u64?, "dur_ms": u64?, "out": text?,
            "dx": { "f": uint?, "lc": [LinkIdDto], "depth": u16 }? }
```

The CBOR buffer holding exposed secrets is `Zeroizing<Vec<u8>>`; the zstd output too.

**Export JSON** (`*.cftp-queue.json`, UTF-8, pretty-printed):

```json
{
  "format": "courier-ftp-queue",
  "version": 1,
  "exported_at": "2026-10-09T12:00:00Z",
  "servers": [
    { "ref": 0, "site_id": "0192a3b4-…", "site_path": "Work/web01" },
    { "ref": 1, "url": "sftp://alice@files.example.org:22", "logon": "ask_for_password" }
  ],
  "items": [
    { "server": 0, "direction": "download", "local": "/home/a/x.iso", "remote": "/pub/x.iso",
      "size": 1048576, "transfer_type": "auto", "priority": "normal", "on_exists": null,
      "directory": false, "delete_source_after": false }
  ]
}
```

### Errors

| Situation | Error | User sees |
|---|---|---|
| Queue full | `Error::InvalidInput` | status message "Queue is full (1 000 000 items)" |
| Vault locked on save | `Error::Vault(Locked)` | quit warning (above); no error popup |
| Snapshot can't be decoded / decompressed too large | `Error::InvalidInput("saved queue is corrupt")` | message dialog once; blob renamed to `transfer-queue.corrupt-<unix>` via `put_blob` + `delete_blob`; empty queue |
| Newer snapshot version | none (warning) | message once (above) |
| Import file invalid JSON / wrong format / too large | `Error::InvalidInput("not a courier-ftp queue file: …")` | error dialog |
| Import item invalid | listed in `ImportReport::rejected` | "Imported 120 items, 3 skipped" + reasons in the log |
| I/O on export/import file | `Error::Io` | error dialog with the OS message |

### Security and logging

- The snapshot contains hosts, user names, paths and ad-hoc passwords: it is only stored
  LMK-sealed in `device_blobs` and never synced (D4). Plaintext buffers are `Zeroizing`.
- `QueueServer::Adhoc` holds `ConnectInfo` with `SecretString`; `Debug` for `QueueServer`
  and `QueueItem` is hand-written and prints `label` only for the server.
- Export never contains a password, passphrase or key material (canary test, AC5). The
  file is written with mode `0600` on Unix.
- Import is untrusted input: size caps above; JSON parsed with `serde_json` into typed DTOs
  (unknown fields ignored); every path re-validated. Fuzz target `queue_import_json`
  (body also a property test) — added to T91's list.
- Tracing (`tracing` app log): `info` lines carry only counts and ids ("queue loaded:
  1203 items"); hosts and paths only at `debug` (T91 §4).

## Implementation steps

1. `TransferId`, `Direction`, `Priority`, `ItemState` and friends, `RangeSet` with unit and
   property tests.
2. `QueueServer`, `GroupKey`, interning, `QueueItem` builders, hand-written `Debug`.
3. `Queue` core: `add_batch`, `remove`, order keys with renumbering, `rows`/`row_count`,
   stats counters.
4. Scheduling index and `next_runnable`; engine-side transitions (`set_state`, `finish`,
   `fail`, `checkpoint`, `replace_placeholder`, `cleanup_parent` accounting).
5. User operations: move, priority, pause/resume, requeue, clear lists, successful cap.
6. Property test against a reference model; criterion benches + gates in
   `scripts/bench-gates.toml`.
7. Snapshot encode/decode (CBOR + zstd), `DeviceBlobStore` trait, `VaultEngine` impl (T30
   side, sealing with the LMK), `load_queue`.
8. Persister task (debounce, locked-vault retry, `flush`, `has_unsaved_changes`).
9. Export/import JSON with `SiteLookup`; fuzz target + property test.

## Acceptance criteria

- [ ] AC1 Every `Queue` operation listed in Types and APIs has a unit test (see Tests), and `cargo test -p courier-ftp-core queue::` passes.
- [ ] AC2 The scheduling order is (priority desc, order key asc) across groups; moves never cross groups (property test against the reference model, 10 000 cases).
- [ ] AC3 A persisted queue survives restart: `encode → put_blob → get_blob → decode` returns equal items; `Active`/`Waiting` items come back `Queued` with their `completed` ranges; the queue is not started.
- [ ] AC4 With 100 000 items on the reference machine: `queue/add_100k` < 50 ms, `queue/move_1k_to_top_of_100k` < 10 ms, `queue/rows_window_100k` (50 rows at offset 50 000) < 5 ms, `queue/next_runnable_100k` < 0.02 ms; gates (CI 2×) added to `scripts/bench-gates.toml` and checked by `bench.yml` (T00).
- [ ] AC5 Export output contains no canary password/passphrase planted in an ad-hoc item, and `vault.store_passwords = false` persists ad-hoc `Normal` logons as `AskForPassword`.
- [ ] AC6 A locked vault leaves `has_unsaved_changes() == true` and the write happens after unlock without user action.
- [ ] AC7 Import rejects files > 64 MiB, wrong `format`, `version > 1`, and invalid items individually; never panics (property/fuzz body).
- [ ] AC8 Memory: 100 000 typical items (60-byte paths) use ≤ 64 MiB of heap (counting allocator test).
- [ ] AC9 A newer-version snapshot is neither loaded nor overwritten.
- [ ] AC10 `cargo clippy --workspace --all-targets -- -D warnings` and the T00 `test-local-only`, `test-os`, `bench-build` jobs pass.

## Tests

### Unit tests
- `fn range_set_insert_merges_overlaps_and_adjacent` — `[0,10)+[10,20)+[5,8)` → `[0,20)` (AC1).
- `fn range_set_missing_lists_gaps` — gaps of `[0,5),[10,15)` in 20 → `[5,10),[15,20)` (AC1).
- `fn add_batch_assigns_ids_and_appends_in_order` (AC1).
- `fn insert_after_renumbers_when_keys_exhausted` — 100 inserts at the same anchor; order correct; `renumber_count() >= 1` (AC1).
- `fn move_top_bottom_up_down_stay_within_group` — table over selections at edges and blocks (AC1, AC2).
- `fn next_runnable_prefers_priority_then_order` and `fn next_runnable_respects_allow_filter` (AC2).
- `fn paused_and_blocked_items_not_runnable` (AC1).
- `fn remove_returns_active_ids_without_removing_them` (AC1).
- `fn requeue_failed_resets_attempts_keeps_completed` (AC1).
- `fn successful_list_capped_oldest_dropped` — cap 3, finish 5 (AC1).
- `fn replace_placeholder_inserts_children_in_place_and_inherits_options` (AC1).
- `fn remove_source_dir_runnable_only_after_children_leave` (AC1).
- `fn stats_track_bytes_with_partial_completion` (AC1).
- `fn debug_output_has_no_password` — ad-hoc item with canary password (AC5).

### Property / fuzz tests
- `proptest fn queue_matches_reference_model` — random sequences of add/insert/move/priority/pause/resume/remove/start/finish/fail/requeue applied to `Queue` and to a naive `Vec`-based model; after each op `rows`, `stats` and `next_runnable` agree (AC1, AC2).
- `proptest fn range_set_invariants` — sorted, disjoint, non-adjacent; `covered + Σmissing == total` (AC1).
- `proptest fn snapshot_roundtrip` — random queues encode/decode to equal values (AC3).
- `proptest fn import_never_panics` — arbitrary bytes and mutated valid exports (AC7); same body as fuzz target `queue_import_json` (T91).

### Snapshot tests
Not applicable (rendering is T56).

### Integration tests
- `async fn persister_debounces_and_caps_delay` — `start_paused`; changes every 1 s for 30 s → writes at t≈10 s, 20 s, 30 s; quiet change → write at +2 s (AC3).
- `async fn persister_retries_after_vault_unlock` — fake `DeviceBlobStore` returning `Locked` then `Ok` (AC6).
- `async fn load_restores_active_as_queued_with_ranges` — real `VaultEngine` with `Argon2Cost::TEST` and a temp store (AC3).
- `async fn newer_snapshot_not_loaded_or_overwritten` (AC9).
- `async fn store_passwords_off_persists_ask_for_password` (AC5).
- `fn export_contains_no_canary` and `fn import_rejects_invalid_items_individually` (AC5, AC7).
- `tests/queue_memory.rs` with a counting `#[global_allocator]`: 100 000 items ≤ 64 MiB (AC8).

### End-to-end tests
Covered by T41/T76 scenarios (queue survives an app restart in `PtyApp`: quit with 3 queued items, restart, unlock, items listed and not running).

### Benchmarks
`crates/courier-ftp-core/benches/queue.rs` (criterion, deterministic inputs): `queue/add_100k`,
`queue/move_1k_to_top_of_100k`, `queue/rows_window_100k`, `queue/next_runnable_100k`,
`queue/snapshot_encode_100k` (informational). Gates per AC4 (`max_ms`, `ci_max_ms` = 2×).

## Out of scope

- Rendering and key handling (T56), building items from pane selections (T62).
- Running transfers, retries, limits (T41); segment logic (T41b).
- Importing FileZilla's `queue.sqlite3` / exported queue XML (see Open questions).
- Syncing the queue between devices (D4: device-local).

## Open questions

1. Should FileZilla's exported queue XML be importable (FEATURES §5 says "import and
   export"; our export is courier-ftp JSON only)?
2. Inconsistency for T30's owner: T30 lists "LMK → device-local encrypted data (queue)"
   but defines no API; this task needs `DeviceBlobStore` (`put_blob`/`get_blob`/
   `delete_blob`, AAD `"courier-ftp-device-blob-v1" || name`) implemented by `VaultEngine`.
3. Inconsistency for T62's owner: T62 sets a field `is_dir_placeholder`; the item now has
   `kind: QueueItemKind` with builder `QueueItem::dir_placeholder(..)` and method
   `is_dir_placeholder()`. `delete_source_after` (T62 Open question 1) is added here.
