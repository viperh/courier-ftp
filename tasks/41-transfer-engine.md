# T41 — Transfer engine

**Phase:** E Transfers · **Milestone:** M4 · **Depends on:** T03, T04, T05, T40 · **Crate(s):** `courier-ftp-core` (`transfer` module) · **Decisions:** D11 · **FEATURES.md:** §5, §6
**Related (integrates with, not blocking):** T42, T44, T45

## Goal

The scheduler and workers that take items from the queue (T40) and move bytes between
the local disk and a server: they respect the global, per-direction and per-server
connection limits, reuse connections, back off when a server refuses more connections,
report progress, speed and ETA, retry transient failures from the current offset, and
cancel quickly. File-exists handling and speed limiting are injected through the
`ExistsPolicy` and `RateLimiter` traits so T42 and T44 plug in without changing the
engine.

## Context

- Before: T03 gives `Backend` (incl. `finish_transfer(TransferEnd)`), `BackendFactory`,
  `BackendContext`, `ConnectInfo` (`limit_connections`), `Capabilities`, `WriteMode`,
  `TransferOpts`, `SessionHandle` (`SessionOptions`, `lock()` → `BackendGuard`) and
  `mock::MockServer`; T06 (M1) gives `LocalBackend` and `local::path_map::{to_native,
  from_native}`, so the local side is a `Backend` too; T04 gives `EventSender` (`progress`,
  `transfer_state`, `prompt_with_cancel`, `log`), `CoreEvent` (`TransferProgress`,
  `TransferStateChanged { id }`, `QueueChanged`, `QueueFinished { stats: QueueStats }`,
  `Notice`, `Log`), `SessionId`, `SessionPurpose`, `TransferId`; T02 gives `Error` (incl.
  `ConnectionLimit`, `is_transient`, `code`), `Direction`, `TransferType`,
  `ServerIdentity`; T05 gives `SharedSettings` (`transfers.*`, `connection.*`) and
  `decide_transfer_type`; T40 gives `SharedQueue`, `QueueItem`, `ItemState`, `RangeSet`,
  `next_runnable`; T46 (M1) gives `ListingCache` with `CachePatch`.
- After: T42 implements `ExistsPolicy` and the per-file options in the worker's
  `Preparing`/`Finishing` phases; T43 adds placeholder expansion as a worker job; T44
  implements `RateLimiter`; T41b replaces the copy loop with the pipelined/segmented one
  and extends the scheduler; T45 consumes `QueueFinished` and `last_run()`; T56/T57 show
  `EngineStats`; T62 sends commands; T76's `Headless` drives the engine in e2e tests.

## Technical specification

### Types and APIs

Module `courier_ftp_core::transfer` (`engine.rs`, `sched.rs`, `pool.rs`, `worker.rs`,
`copy.rs`, `progress.rs`, `retry.rs`, `policy.rs`; mock extensions in
`backend::mock` behind `test-util`).

```rust
/// Creates a local-side backend for one slot (the binary: `LocalBackend::new(ctx)`;
/// tests: a second `MockServer` acting as the local disk).
pub type LocalFactory = Arc<dyn Fn(BackendContext) -> Box<dyn Backend> + Send + Sync>;

/// Everything the engine needs, injected by the binary (or by tests).
pub struct EngineDeps {
    pub queue: SharedQueue,
    pub factory: Arc<dyn BackendFactory>,
    pub local: LocalFactory,
    pub resolver: Arc<dyn ConnectInfoResolver>,
    pub events: EventSender,
    pub settings: SharedSettings,               // T05 watch receiver, read on every scheduling pass
    pub cache: Option<ListingCache>,            // T46: patched after uploads and remote mkdir
    pub exists_policy: Arc<dyn ExistsPolicy>,   // default: OverwritePolicy
    pub rate_limiter: Arc<dyn RateLimiter>,     // default: Unlimited
}

pub struct TransferEngine;
impl TransferEngine {
    /// Spawns the engine task. The returned `JoinHandle` completes after `Shutdown`.
    pub fn spawn(deps: EngineDeps) -> (EngineHandle, JoinHandle<()>);
}

#[derive(Clone, Debug)]
pub struct EngineHandle { /* mpsc::UnboundedSender<EngineCommand>, watch::Receiver<EngineStats>, Arc<last run> */ }
impl EngineHandle {
    pub fn send(&self, cmd: EngineCommand);                  // never blocks; ignored after shutdown
    pub fn stats(&self) -> watch::Receiver<EngineStats>;
    /// Details of the last finished run (T45 reads it on `QueueFinished`).
    pub fn last_run(&self) -> Option<QueueRunSummary>;
    pub async fn shutdown(&self);                            // Shutdown + wait for the ack
}

#[derive(Debug)]
pub enum EngineCommand {
    /// Process the queue ("Process queue"). Clears blocked server groups.
    Start,
    /// Start nothing new; cancel active transfers, which return to `Queued`
    /// (progress kept, no attempt counted). Never triggers completion actions.
    Stop,
    /// Pause every queued and active item / resume every paused item.
    PauseAll, ResumeAll,
    Pause(Vec<TransferId>), Resume(Vec<TransferId>),
    /// Cancel active items; `remove` also deletes them from the queue afterwards.
    Cancel { ids: Vec<TransferId>, remove: bool },
    /// The UI changed the queue (added, reordered, …): re-run the scheduler.
    QueueChanged,
    /// Settings were updated (T57 speed-limit toggle, T68): re-read `SharedSettings` now.
    SettingsChanged,
    /// One-shot completion action for the next finished run (T45). `None` clears it.
    SetCompletionOverride(Option<OnComplete>),
    /// Disconnect every idle pooled connection now (T45 "Disconnect" action).
    DisconnectIdle,
    /// Cancel everything, close all connections, end the task.
    Shutdown { done: oneshot::Sender<()> },
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct EngineStats {
    pub processing: bool,
    pub active_downloads: u32, pub active_uploads: u32,
    pub connections_open: u32,               // active + idle + connecting (remote side)
    pub down_bps: u64, pub up_bps: u64,      // sum of per-item EMA speeds
    pub remaining_bytes: u64,                // QueueCounts::queued_bytes (T40)
    pub eta: Option<Duration>,               // remaining / (down + up), None if unknown
}

/// Details of a finished run. `CoreEvent::QueueFinished { stats }` carries T04's
/// `QueueStats { files_ok, files_failed, bytes, duration }` filled from this; the rest is
/// read with `EngineHandle::last_run()`.
#[derive(Clone, Debug, PartialEq)]
pub struct QueueRunSummary {
    pub files_ok: u64, pub files_skipped: u64, pub files_failed: u64,
    pub blocked_items: u64,                  // items left queued in blocked server groups
    pub bytes: u64, pub duration: Duration,
    pub touched: TouchedDirs,                // for "refresh after queue" (T45)
    pub action: OnComplete,                  // resolved: one-shot override or queue.on_complete
}
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TouchedDirs {
    pub remote: Vec<(ServerIdentity, RemotePath)>, pub local: Vec<LocalPath>,
    pub overflow: bool,                      // > 1000 dirs: refresh everything
}

/// Turns a queue server into a `ConnectInfo` (secrets included). The binary implements it
/// with the vault (T31 `Site::to_connect_info`) and prompts for `AskForPassword`
/// (T04 `Prompt(Password)`), caching the answer for the process lifetime per group.
#[async_trait]
pub trait ConnectInfoResolver: Send + Sync {
    async fn resolve(&self, server: &QueueServer, cancel: &CancellationToken) -> Result<Arc<ConnectInfo>>;
}

/// File-exists decision point (T42 provides the real policy).
#[async_trait]
pub trait ExistsPolicy: Send + Sync {
    /// Decide what to do with an existing (or missing) target. May prompt the user.
    async fn resolve(&self, req: ExistsRequest<'_>, probe: &mut dyn TargetProbe,
                     cancel: &CancellationToken) -> Result<ExistsOutcome>;
    /// Called when a queue run ends (QueueFinished or Stop): drop run-scoped answers.
    fn run_finished(&self) {}
}
pub struct ExistsRequest<'a> {
    pub item: &'a QueueItem,
    pub session: SessionId,                 // for the prompt (T04)
    pub source: &'a Entry,
    pub target: Option<&'a Entry>,          // None = target missing
    pub target_path: &'a TargetPath,
    pub caps: &'a Capabilities,             // remote side capabilities
    pub transfer_type: TransferType,        // after Auto resolution
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetPath { Local(LocalPath), Remote(RemotePath) }
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExistsOutcome { Transfer { target: TargetPath, mode: WriteMode }, Skip(SkipReason) }
/// Lets the policy test candidate names for Rename on the target side.
#[async_trait]
pub trait TargetProbe: Send { async fn exists(&mut self, path: &TargetPath) -> Result<bool>; }
/// Default policy: missing → `Create`, existing → `Truncate`.
pub struct OverwritePolicy;

/// Bandwidth limiter (T44 provides the token bucket).
#[async_trait]
pub trait RateLimiter: Send + Sync {
    /// Waits until `bytes` may pass in `dir`. Cancel-safe (see T44).
    async fn acquire(&self, dir: Direction, bytes: usize);
    /// Largest chunk the copy loop should move at once (4 KiB ..= 256 KiB).
    fn max_chunk(&self, _dir: Direction) -> usize { COPY_CHUNK }
}
pub struct Unlimited;

/// Error classes used by the retry policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorClass { Transient, ConnectionLimit, ServerFatal, ItemFatal, LocalDiskFull, RemoteDiskFull, Cancelled }
pub fn classify(err: &Error, phase: ActivePhase, dir: Direction) -> ErrorClass;
pub fn is_connection_limit(err: &Error, phase: ActivePhase) -> bool;

pub const COPY_CHUNK: usize = 256 * 1024;
pub const TICK: Duration = Duration::from_millis(200);
pub const SPEED_TAU: Duration = Duration::from_secs(5);
pub const IDLE_CLOSE: Duration = Duration::from_secs(30);
pub const ABORT_TIMEOUT: Duration = Duration::from_secs(5);
pub const FINISH_TIMEOUT: Duration = Duration::from_secs(30);
pub const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(2);
pub const CHECKPOINT_EVERY: Duration = Duration::from_secs(5);
```

Extensions to T03's `mock::MockServer` (same `test-util` feature), needed for engine tests:

```rust
impl MockServer {
    /// Bandwidth for the n-th connection (0-based, in connect order); overrides set_bandwidth.
    pub fn set_connection_bandwidth(&self, n: usize, bytes_per_sec: Option<u64>);
    /// The next stream opened on `path` fails with `make()` after `after` bytes.
    pub fn fail_stream_after(&self, path: &str, after: u64, make: fn() -> Error);
    /// The next stream on `path` stops delivering bytes after `after` (stall test).
    pub fn hang_stream_after(&self, path: &str, after: u64);
    pub fn peak_streams(&self) -> usize;                 // max simultaneous open streams
    pub fn aborts(&self) -> usize;                       // finish_transfer(Abort) calls
    pub fn open_read_offsets(&self, path: &str) -> Vec<u64>;
}
```

### Behaviour

**Engine task.** One engine per process (all tabs share it). It is a tokio task running
`select!` over: the command channel, slot completions (`JoinSet`), a `DelayQueue` of
retry timers, the progress tick (`TICK`), and the pool reaper (every 5 s). Scheduler
state lives in `Arc<std::sync::Mutex<EngineShared>>`; lock order is always
`EngineShared` → `Queue`, never held across `.await` (clippy `await_holding_lock` is
denied in T00).

**Limits** (read from the current `Settings`):

| Limit | Setting | Default | Range |
|---|---|---|---|
| Active transfers (all directions, including T41b segments and T43 listings) | `transfers.max_concurrent` | 4 | 1–16 |
| Active downloads | `transfers.max_downloads` | 0 (= only the global limit) | 0–`max_concurrent` |
| Active uploads | `transfers.max_uploads` | 0 | 0–`max_concurrent` |
| Connections per server group | `ConnectInfo::limit_connections` (site setting, 1–10) | none (= global) | — |
| Learned per-group limit | back-off, see below | — | ≥ 1 |

A group's effective limit = min(`limit_connections`, learned limit, `max_concurrent`).
Active = `Connecting`, `Listing`, `Preparing`, `AwaitingUser`, `Transferring`,
`Finishing`. Idle pooled connections do not count against `max_concurrent` but do count
against the group limit (they are open connections to that server; a new item for that
group reuses one).

**Scheduling algorithm** (`sched.rs`, runs after every event that can free or add work):

```
while processing:
    if active_total >= max_concurrent: break
    allow(g, d) = !blocked(g) && active(g) < limit(g)
                  && (d == Download ? max_downloads == 0 || active_down < max_downloads
                                    : max_uploads   == 0 || active_up   < max_uploads)
    id = queue.next_runnable(allow)      // best (priority desc, order key asc) — T40 index
    if id is None: break
    mark item Active{Connecting}; active(g) += 1
    spawn a slot task for (id, g)        // slots connect in parallel (warm-up for free)
```

A slot that finishes an item asks the scheduler for the next item **inline**
(handoff, under the same lock): if the best eligible item belongs to the same group and
the direction limits allow it, the slot keeps its connections and continues immediately
(no idle gap); otherwise it returns its connection to the idle pool and ends, and the
scheduler starts the other item. Global priority order is therefore never violated by
connection reuse.

**Connection pool** (`pool.rs`), per group. Entries are T03 `SessionHandle`s created with
`SessionOptions { purpose: SessionPurpose::Transfer, reconnect: false, keepalive: false }`
(the handle emits `SessionOpened`/`SessionClosed` and owns the `SessionId`; transparent
reconnects are off because a reconnect mid-transfer would hide a lost offset — the retry
policy handles it; keep-alive is off because idle connections close after 30 s).
- `acquire`: pop the most recently released idle handle (LIFO) whose state is
  `Connected`; otherwise create one: `factory.create(info, BackendContext { session:
  SessionId::next(), events, settings })`, wrap it in a `SessionHandle`, and
  `connect(cancel)` (which already retries transient failures `connection.retries` times,
  T03). `ConnectInfo` is resolved once per group per run via `ConnectInfoResolver`.
- A slot holds the connection with `SessionHandle::lock(cancel)` (`BackendGuard`) for the
  whole item (open → copy → finish).
- `release`: healthy handle → idle list with timestamp; broken (error during the transfer,
  abort timeout) → `disconnect()` in a tracked task (`DISCONNECT_TIMEOUT`), then dropped.
- Reaper: disconnects idle handles older than `IDLE_CLOSE` (30 s); keeps total idle
  handles ≤ `max_concurrent` (oldest first).
- The local side gets one `LocalBackend` per slot from `deps.local` (always connected, not
  pooled, not counted against limits). `item.local` is converted with
  `path_map::from_native` (T06) for it.
- Transfer connections are separate from the tabs' browsing sessions (FileZilla
  behaviour), so browsing stays responsive.

**Connection-limit back-off.** `is_connection_limit(err, phase)` is true for:
1. `Error::ConnectionLimit(_)` (T02: T10 maps FTP 421/530 "too many connections" at
   greeting/login to it, T20 maps SSH disconnect reason 12 `TOO_MANY_CONNECTIONS`; the
   mock's `set_max_connections`);
2. at `Connecting` only, as a defensive fallback for servers with unusual texts:
   `Connection(message)` matching
   `(?i)too many|maximum (number of )?(connections|clients|users|sessions)|connection limit`.
   `Protocol { .. }` and `Auth` are never treated as a limit.

When it happens and the group has `n ≥ 1` other connected slots: learned limit = `n`,
the item returns to `Queued` **without** counting an attempt, a Status line is logged and
`CoreEvent::Notice { level: Warning, text }` is sent once per group: "Server refused
another connection; using at most n connection(s) to it for this session". The learned
limit lasts for the process lifetime. With `n = 0` the group is blocked like a
`ServerFatal` error.

**Worker (slot) lifecycle** for a file item (`worker.rs`):

| Phase | Steps | Timeout |
|---|---|---|
| `Connecting` | `pool.acquire(group)`; `lock()`; create the slot's local backend | `SessionHandle::connect` (T03 retries); engine backstop 120 s |
| `Preparing` | 1. Source entry: use the item's `size`/`source_modified`; `stat` the source only if the size is unknown, `completed` is non-empty, or the policy needs an mtime it lacks. 2. Target entry: `stat` on the target side (`NotFound` → missing). 3. Transfer type: T42 `resolve_transfer_type`. 4. If `completed` is non-empty, the source size/mtime equal the item's, and the target size ≥ `completed.contiguous_prefix()`: resume automatically at that prefix (binary type + `resume_download`/`resume_upload`) without asking the policy; otherwise clear `completed` and call `ExistsPolicy::resolve`. 5. Create the parent directory on the target side (`mkdir` per missing component, remembering created dirs per run). | backend inactivity timeout (`connection.timeout_secs`) |
| `AwaitingUser` | only inside `ExistsPolicy` when it prompts; the slot keeps its connection; after the answer `keepalive()` checks it, and a dead connection is replaced without counting an attempt | none (cancellable) |
| `Transferring` | `open_read(src, offset, opts)` on the source backend and `open_write(dst, mode, opts)` on the target backend, then the copy loop | stall: no byte for `connection.timeout_secs` → `Error::Timeout` |
| `Finishing` | `shutdown()` the write stream; `finish_transfer(TransferEnd::Complete)` on both backends (FTP reads 226; local syncs); checkpoint `completed = [0, size)`; T42 timestamps; `delete_source_after` (only for `Transferred`/`Resumed`; a failed delete logs an Error line, the item is still `Done`) | `FINISH_TIMEOUT` (30 s) |

Then `Queue::finish(id, outcome, bytes, duration)`, `events.transfer_state(id)`, patch
the cache after uploads (`CachePatch::Uploaded { path, size, modified }`, and `Created`
for each remote directory the slot created), log "File transfer successful, transferred
1.2 MiB in 3 seconds", and add the target's parent to `TouchedDirs` (≤ 1000, then
`overflow = true`).

**Copy loop** (`copy.rs`; T41b replaces it with the double-buffered pipeline):

```
buf = 256 KiB
loop:
  n_max = min(COPY_CHUNK, limiter.max_chunk(dir))
  n = select!(cancel => Cancelled, timeout(stall, reader.read(&mut buf[..n_max])))
  if n == 0: break                                  // EOF
  select!(cancel => Cancelled, limiter.acquire(dir, n))
  select!(cancel => Cancelled, timeout(stall, writer.write_all(&buf[..n])))
  meter.bytes.fetch_add(n)                          // AtomicU64, read by the tick
  every CHECKPOINT_EVERY: writer.flush() → queue.checkpoint(id, [0, offset))
```

At EOF, if the size is known and fewer bytes arrived than `size − start_offset`, the
result is `Error::Connection("transfer ended early")` (transient). More bytes than
expected (file grew) is accepted and logged at debug. Downloads write to the final name
directly (FileZilla behaviour); partial files stay for resume.

**Progress, speed, ETA** (`progress.rs`). Every `TICK` (200 ms) the engine reads each
active meter: `Δb` bytes in `Δt`. Speed: during the first `SPEED_TAU` (5 s) of a
transfer, `bytes_since_start / elapsed`; afterwards an exponential moving average
`speed += α · (Δb/Δt − speed)` with `α = 1 − exp(−Δt / τ)`, `τ = 5 s`. ETA =
`ceil((total − done) / speed)` seconds when the total is known, speed ≥ 1 B/s and the
transfer has run ≥ 1 s; otherwise `None`. Each tick calls `events.progress(
TransferProgress { id, bytes_done, total, speed_bps, eta })` per active item (5 Hz; T04
coalesces per id) and updates `EngineStats` (watch channel). Every state change calls
`events.transfer_state(id)`; structural queue changes made by the engine (removal,
placeholder expansion) send `CoreEvent::QueueChanged`.

**Retry policy** (`retry.rs`). `classify(err, phase, dir)`, first match wins:

| Class | Errors | Action |
|---|---|---|
| `Cancelled` | `Error::Cancelled` | slot token cancelled: the state the canceller asked for (below); otherwise (a prompt was dismissed, T42): item `Paused`, Status "Question dismissed; item paused" |
| `ConnectionLimit` | `is_connection_limit` | back-off (above) |
| `LocalDiskFull` | `Error::Io` with `ErrorKind::StorageFull`/`QuotaExceeded` or raw OS error 28 (ENOSPC), 122 (EDQUOT), 112 / 39 (Windows disk full) | item `Failed(Permanent)` "Local disk full"; engine stops like `Stop`; Error log and `Notice`: "Local disk is full — queue stopped. Free some space and start the queue again." |
| `RemoteDiskFull` | upload with `Protocol { code: Some(452 \| 552) }` | item failed; group blocked "Server disk full or quota exceeded" |
| `ServerFatal` | at `Connecting`: any error (`SessionHandle::connect` already retried transient ones), plus resolver errors (site deleted, `Error::VaultLocked` while the vault is locked — message "Unlock the vault to transfer to this site", password prompt cancelled) | group blocked with the message; its items stay queued but not runnable; `Start` unblocks |
| `ItemFatal` | `NotFound`, `PermissionDenied`, `AlreadyExists`, `InvalidInput`, `Internal`, `Unsupported`, `Protocol` 5xx, `Io` other than transient kinds | `Failed(Permanent)`, no retry |
| `Transient` | `err.is_transient()` (T02) after connect | `attempts += 1`; if `attempts ≤ connection.retries` → `Waiting { until: now + connection.retry_delay_secs }`; else `Failed(Transient)` |

Before a transient retry, the bytes written so far are checkpointed (write stream
flushed). On the retry a single-stream transfer resumes at: download — `min(local size,
completed.contiguous_prefix())` with `WriteMode::ResumeAt`; upload — the remote size from
`stat` with `ResumeAt`. This needs binary type and `resume_download` / `resume_upload`;
otherwise it restarts with `Truncate`. The last error text (`err.to_string()`) is kept in
`last_error` for the failed list. Defaults: `connection.retries` = 2 (0–10),
`retry_delay_secs` = 5 (0–600) (T05 ranges).

**Cancellation.** A root `CancellationToken` per engine; every slot gets a child token.
The copy loop checks it on every chunk (`select!`). After a cancel the slot drops both
streams and calls `finish_transfer(TransferEnd::Abort)` on both backends under
`ABORT_TIMEOUT` (5 s) — for FTP this runs `ABOR` + resync (T11 §8). On success the
connection goes back to the pool; on timeout or error it is discarded. Resulting state:
`Stop` → `Queued`; `Pause`/`PauseAll` → `Paused`; `Cancel { remove: false }` → `Paused`;
`Cancel { remove: true }` → removed from the queue. Partial local files are kept.

**Run and completion.** A run starts with `Start` and ends when processing is on, nothing
is active, nothing is `Waiting`, and `next_runnable(ignoring limits)` is `None`. If at
least one item was started during the run, the engine stores the `QueueRunSummary`
(`last_run()`), emits `CoreEvent::QueueFinished { stats }` with T04's `QueueStats`,
consumes the one-shot override (T45), calls `ExistsPolicy::run_finished()`, and sets
`processing = false`. `Stop`, disk full and `Shutdown` end a run without `QueueFinished`
(they still call `run_finished()`).

**Settings changes.** Lowered limits never cancel active transfers; they only prevent
new starts until below the limit. Raised limits trigger the scheduler at once.

**Shutdown.** Cancels all slots, waits for them (each bounded by `ABORT_TIMEOUT`),
disconnects every pooled handle in parallel (`DISCONNECT_TIMEOUT` each), drains the
`JoinSet`, then acks `done`. After the ack no engine task is alive.

### Data formats and configuration

Settings read (all from T05, via `SharedSettings`): `transfers.max_concurrent`,
`transfers.max_downloads`, `transfers.max_uploads`, `connection.retries`,
`connection.retry_delay_secs`, `connection.timeout_secs`, `queue.on_complete`. No new
keys. Validation ranges above are enforced by T05 (out of range → warning + default).

Log lines (user-facing message log, `LogKind::Status` unless noted), FileZilla wording:
"Starting download of /path", "Starting upload of /path", "File transfer successful,
transferred 1.2 MiB in 3 seconds", "Retrying in 5 seconds (attempt 2 of 3)",
`Error`: "File transfer failed: <message>", "Server refused another connection; …".

### Errors

The engine never returns errors to the UI; it records them per item (`Failed` +
`last_error`) or per group (blocked reason shown in the queue pane header, T56) and logs
them as `LogKind::Error`. `EngineHandle::send` after shutdown is a no-op. Internal
invariant violations (`debug_assert!`) only log at `warn` in release.

### Security and logging

- `ConnectInfo` secrets stay inside the resolver and backends; the engine never formats a
  `ConnectInfo` or `QueueServer` (their `Debug` impls redact, T03/T40).
- Message-log lines may contain paths (user-facing feature, T55); the tracing app log at
  `info`+ contains only `TransferId`s, group ids, counts and `Error::code()` values
  (T91 §4).
- Remote names and sizes are untrusted: sizes only used as `u64` with saturating math;
  local target paths are built with `LocalPath::join` and T42's sanitiser.
- A malicious server can't make the engine exceed limits: every connection counts,
  refused connections back off, and a server that stalls is bounded by the stall timeout.

## Implementation steps

1. `MockServer` extensions; `progress.rs` (meters, EMA, ETA) with pure tests.
2. `retry.rs`: `classify`, `is_connection_limit` with table tests.
3. `policy.rs`: `ExistsPolicy`, `OverwritePolicy`, `RateLimiter`, `Unlimited`, `TargetPath`.
4. `pool.rs`: acquire/release/reaper over `SessionHandle`, group and learned limits.
5. `sched.rs` + `engine.rs`: command loop, scheduling, handoff, run end and
   `QueueFinished`, `EngineStats`, `last_run`.
6. `worker.rs` + `copy.rs`: phases, copy loop, checkpoints, retries with resume.
7. Cancellation, Pause/Stop/Shutdown, disk-full stop, group blocking.
8. Criterion bench, property test, e2e scenarios in `courier-ftp-e2e`.

## Acceptance criteria

- [ ] AC1 With `MockServer` latency and bandwidth, `peak_streams ≤ max_concurrent`, per-direction peaks ≤ `max_downloads`/`max_uploads`, and per-group `peak_connections ≤ limit_connections` in every test, including the property test with random limits.
- [ ] AC2 With one slot, items start in (priority desc, queue order) order, including after reorders during a run.
- [ ] AC3 A transient read failure after 3 MiB of a 10 MiB download is retried after `retry_delay_secs` (paused time) and resumes at offset 3 MiB (`open_read_offsets == [0, 3 MiB]`); the result is byte-identical. A `NotFound` is not retried (`attempts == 0`, one `open_read`).
- [ ] AC4 `Cancel` of an active transfer reaches `Paused`/removed within 1 s of virtual time with 100 ms mock latency; `aborts() == 1` and the same connection serves the next item (`calls(Connect) == 1`).
- [ ] AC5 Against a mock with `set_max_connections(Some(2))` and `max_concurrent = 4`, the learned limit becomes 2, no item's `attempts` increases, and all items complete.
- [ ] AC6 After `Shutdown`, the engine's `JoinSet` is empty, `MockServer::connections() == 0`, and the `JoinHandle` has completed.
- [ ] AC7 Progress events for an active item arrive at ≤ 5 Hz; speed for a constant 1 MiB/s mock transfer is within ±2 % after 10 s; ETA within ±1 s.
- [ ] AC8 Local disk full stops the engine (no further starts), fails only that item, and emits no `QueueFinished`.
- [ ] AC9 A connect failure (`Auth`) blocks the group: no further connection attempts to that server until `Start`.
- [ ] AC10 `QueueFinished` is emitted exactly once per run that started ≥ 1 item, never after `Stop`.
- [ ] AC11 Bench `transfer_engine/mock_10k_small_files` (10 000 × 4 KiB, zero-latency mocks on both sides) < 500 ms on the reference machine; gate (CI 1000 ms) in `scripts/bench-gates.toml`.
- [ ] AC12 Docker e2e: 50 mixed-size files (0 B – 8 MiB) up and down, SHA-256 verified, against `vsftpd-plain`, `vsftpd-explicit-tls`, `proftpd-plain`, `pureftpd-plain` and sshd `password`; and back-off against `vsftpd-maxconn1` and sshd `maxconn1`.
- [ ] AC13 T00 jobs `clippy`, `test-local-only`, `test-os`, `bench-build`, `e2e` pass.

## Tests

### Unit tests
- `fn classify_table` — every `Error` variant × phase → expected `ErrorClass` (AC3, AC8, AC9).
- `fn connection_limit_detection` — `ConnectionLimit(..)` in any phase and `Connection("Maximum number of connections exceeded")` at `Connecting` → true; `Auth("Login incorrect")`, `Protocol{421}`, `Protocol{530}` → false (AC5).
- `fn speed_average_then_ema` and `fn eta_none_until_one_second_and_without_total` (AC7).
- `fn overwrite_policy_create_or_truncate` (default policy).
- `fn group_limit_is_min_of_site_learned_global`.

### Property / fuzz tests
- `proptest fn scheduler_never_exceeds_limits` — random items (1–200, random groups,
  directions, priorities, sizes), random limits, random mock latencies and queued
  failures; run to completion in paused time; asserts AC1 peaks, every item ends `Done` or
  `Failed`, attempts ≤ retries + 1, no leaked tasks (AC1, AC6). 256 cases.

### Snapshot tests
Not applicable.

### Integration tests
All `#[tokio::test(start_paused = true)]` with a remote `MockServer` and a second
`MockServer` as the local side:
- `async fn limits_respected_with_latency` (AC1).
- `async fn priority_order_single_slot` and `async fn reorder_during_run_changes_next_pick` (AC2).
- `async fn transient_error_resumes_at_offset` and `async fn permanent_error_not_retried` (AC3).
- `async fn retries_exhausted_marks_failed_with_last_error` (AC3).
- `async fn cancel_within_one_second_and_session_reused` (AC4).
- `async fn too_many_connections_lowers_limit_without_attempts` (AC5).
- `async fn shutdown_leaves_no_tasks_or_connections` (AC6).
- `async fn progress_rate_and_eta` (AC7).
- `async fn disk_full_stops_queue` — local mock `fail_stream_after(.., || Io(StorageFull))` (AC8).
- `async fn auth_error_blocks_group_until_start` (AC9).
- `async fn queue_finished_once_and_not_after_stop` (AC10).
- `async fn handoff_reuses_connection_for_same_group` — 20 small files, 1 slot → 1 connect.
- `async fn idle_connections_closed_after_30s`.
- `async fn stall_times_out_and_retries` — `hang_stream_after`; `Timeout` after 20 s.
- `async fn awaiting_user_replaces_dead_connection_without_attempt`.

### End-to-end tests
`crates/courier-ftp-e2e/tests/transfers.rs`, `#[ignore]`, `require_docker!`, through
`Headless` (T76):
The test names are the ones T76 lists for `transfers.rs`; this task implements them:
- `queue_50_mixed_files_up_and_down_<ftp|sftp>` — 50 files (0 B – 8 MiB) uploaded and
  downloaded to a new dir, SHA-256 equal; the `ftp` variant runs against `vsftpd-plain`,
  `vsftpd-explicit-tls`, `proftpd-plain` and `pureftpd-plain`, the `sftp` variant against
  sshd `password` (AC12).
- `connection_limit_backoff_<ftp|sftp>` — `vsftpd-maxconn1` / sshd `maxconn1`,
  `max_concurrent = 4`; all 20 files arrive and the limit Notice is emitted once (AC5, AC12).
- `resume_after_cut_<ftp|sftp>` — toxiproxy `LimitData { bytes: 5 MiB }` on the first
  connection of a 32 MiB download, then removed; the transfer completes, hash equal, the
  second read starts at the checkpointed offset (`REST` in the FTP server log) (AC3).
- `cancel_on_slow_profile_leaves_session_usable` — `vsftpd-slow`; cancel reaches `Paused`
  within 1 s and the next item reuses the connection (AC4).

### Benchmarks
`crates/courier-ftp-core/benches/transfer_engine.rs`: `transfer_engine/mock_10k_small_files`
(AC11). Gate `max_ms = 500`, `ci_max_ms = 1000`.

## Out of scope

- File-exists decisions, prompts, timestamps, sanitizing (T42); recursion (T43); token
  bucket (T44); segmentation, pipelining, double buffering (T41b); completion actions (T45).
- Remote → remote (FXP) transfers.
- Several SFTP channels per SSH connection (T22 decision: one SSH connection per slot).

## Open questions

1. Resolved: T10 maps FTP "too many connections" 421/530 and T20 maps SSH disconnect
   reason 12 to `Error::ConnectionLimit`.
2. Product: should a learned connection limit be remembered across restarts (per site,
   device-local)? This spec keeps it for the process lifetime only, like FileZilla.
3. Product: when connecting to a server fails (after T03's connect retries), this spec
   blocks the whole server group until the user presses Start again, instead of failing
   each item. FileZilla instead retries per item. Confirm.
