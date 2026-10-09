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

- Before: T03 gives `Backend`, `BackendFactory`, `ConnectInfo`, `Capabilities`,
  `WriteMode`, `TransferOpts`, `MockBackend`; T04 gives `EventSender`, `CoreEvent`
  (`TransferProgress`, `TransferStateChanged`, `QueueFinished`, `Log`, `Prompt`),
  `LogMessage`, `SessionId`; T05 gives `Settings` (`transfers.*`, `connection.*`); T40 gives
  `SharedQueue`, `QueueItem`, `ItemState`, `RangeSet`, `next_runnable`; T11 (done in M3)
  gives `decide_transfer_type` in core.
- After: T42 implements `ExistsPolicy` and the per-file options in the worker's prepare
  step; T43 adds placeholder expansion as a worker job; T44 implements `RateLimiter`;
  T41b replaces the copy loop with the pipelined/segmented one and extends the scheduler;
  T45 consumes `QueueFinished`; T56/T57 show `EngineStats`; T62 sends commands; T76's
  `Headless` drives the engine in e2e tests.

## Technical specification

### Types and APIs

Module `courier_ftp_core::transfer` (`engine.rs`, `sched.rs`, `pool.rs`, `worker.rs`,
`copy.rs`, `progress.rs`, `retry.rs`, `policy.rs`, `local.rs`, `mock.rs` behind
`test-util`).

```rust
/// Everything the engine needs, injected by the binary (or by tests).
pub struct EngineDeps {
    pub queue: SharedQueue,
    pub factory: Arc<dyn BackendFactory>,
    pub resolver: Arc<dyn ConnectInfoResolver>,
    pub local: Arc<dyn LocalFs>,
    pub events: EventSender,
    pub settings: Arc<Settings>,
    pub exists_policy: Arc<dyn ExistsPolicy>,   // default: OverwritePolicy
    pub rate_limiter: Arc<dyn RateLimiter>,     // default: Unlimited
}

pub struct TransferEngine;
impl TransferEngine {
    /// Spawns the engine task. The returned `JoinHandle` completes after `Shutdown`.
    pub fn spawn(deps: EngineDeps) -> (EngineHandle, JoinHandle<()>);
}

#[derive(Clone, Debug)]
pub struct EngineHandle { /* mpsc::UnboundedSender<EngineCommand>, watch::Receiver<EngineStats> */ }
impl EngineHandle {
    pub fn send(&self, cmd: EngineCommand);                  // never blocks; ignored after shutdown
    pub fn stats(&self) -> watch::Receiver<EngineStats>;
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
    SettingsChanged(Arc<Settings>),
    /// One-shot completion action for the current run (T45). `None` clears it.
    SetCompletionOverride(Option<OnComplete>),
    /// Cancel everything, close all connections, end the task.
    Shutdown { done: oneshot::Sender<()> },
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct EngineStats {
    pub processing: bool,
    pub active_downloads: u32, pub active_uploads: u32,
    pub connections_open: u32,               // active + idle + connecting
    pub down_bps: u64, pub up_bps: u64,      // sum of per-item EMA speeds
    pub remaining_bytes: u64,                // from QueueStats::queued_bytes
    pub eta: Option<Duration>,               // remaining / (down + up), None if unknown
}

/// Payload of `CoreEvent::QueueFinished { stats }` (T04).
#[derive(Clone, Debug, PartialEq)]
pub struct QueueRunSummary {
    pub files_ok: u64, pub files_skipped: u64, pub files_failed: u64,
    pub blocked_items: u64,                  // items left queued in blocked server groups
    pub bytes: u64, pub duration: Duration,
    pub touched: TouchedDirs,                // for "refresh after queue" (T45)
    pub action: OnComplete,                  // resolved: one-shot override or `queue.on_complete`
}
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TouchedDirs {
    pub remote: Vec<(GroupKey, RemotePath)>, pub local: Vec<LocalPath>,
    pub overflow: bool,                      // > 1000 dirs: refresh everything
}

/// Turns a queue server into a `ConnectInfo` (secrets included). The binary implements it
/// with the vault (T31 `Site::to_connect_info`) and prompts for `AskForPassword`
/// (T04 `Prompt(Password)`), caching the answer for the process lifetime per group.
#[async_trait]
pub trait ConnectInfoResolver: Send + Sync {
    async fn resolve(&self, server: &QueueServer, cancel: &CancellationToken) -> Result<ConnectInfo>;
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
    /// Waits until `bytes` may pass in `dir`. Cancel-safe: dropping the future gives
    /// back what it reserved if it was the last reservation.
    async fn acquire(&self, dir: Direction, bytes: usize);
    /// Largest chunk the copy loop should move at once (4 KiB ..= 256 KiB).
    fn max_chunk(&self, dir: Direction) -> usize { COPY_CHUNK }
}
pub struct Unlimited;

/// Local disk access for transfers (tokio::fs in `TokioLocalFs`, in-memory `MemLocalFs`
/// behind `test-util`). Separate from the pane's `LocalBackend` (T06) because transfers
/// need positional writes and `set_len`; `TokioLocalFs` reuses T06 helpers.
#[async_trait]
pub trait LocalFs: Send + Sync {
    async fn stat(&self, p: &LocalPath) -> Result<Option<Entry>>;     // follows symlinks; None = missing
    async fn open_read(&self, p: &LocalPath, offset: u64) -> Result<Box<dyn AsyncRead + Send + Unpin>>;
    async fn open_write(&self, p: &LocalPath, mode: WriteMode) -> Result<Box<dyn LocalWriter>>;
    async fn create_dir_all(&self, p: &LocalPath) -> Result<()>;
    async fn read_dir(&self, p: &LocalPath) -> Result<Vec<Entry>>;     // T43
    async fn set_mtime(&self, p: &LocalPath, t: OffsetDateTime) -> Result<()>;
    async fn remove_file(&self, p: &LocalPath) -> Result<()>;
    async fn remove_dir(&self, p: &LocalPath) -> Result<()>;
}
#[async_trait]
pub trait LocalWriter: Send {
    async fn write_all(&mut self, buf: &[u8]) -> Result<()>;            // buffered (1 MiB)
    async fn set_len(&mut self, len: u64) -> Result<()>;
    async fn sync_data(&mut self) -> Result<()>;
    async fn finish(self: Box<Self>) -> Result<()>;                      // flush + close
}

/// Error classes used by the retry policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorClass { Transient, ConnectionLimit, ServerFatal, ItemFatal, LocalDiskFull, RemoteDiskFull, Cancelled }
pub fn classify(err: &Error, phase: ActivePhase, dir: Direction) -> ErrorClass;
pub fn is_connection_limit(err: &Error) -> bool;

pub const COPY_CHUNK: usize = 256 * 1024;
pub const TICK: Duration = Duration::from_millis(200);
pub const SPEED_TAU: Duration = Duration::from_secs(5);
pub const IDLE_CLOSE: Duration = Duration::from_secs(30);
pub const ABORT_TIMEOUT: Duration = Duration::from_secs(5);
pub const FINISH_TIMEOUT: Duration = Duration::from_secs(30);
pub const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(2);
pub const CHECKPOINT_EVERY: Duration = Duration::from_secs(5);
```

`MockBackend` extensions (T03's mock, `test-util` feature), shared server state:

```rust
pub struct MockServer { /* Arc'd tree + config + stats */ }
pub struct MockServerConfig {
    pub max_connections: Option<u32>,          // beyond it: connect fails with
    pub refuse_with: Error,                    //   Protocol{code: Some(421), "Too many connections"}
    pub connect_latency: Duration,             // default 0
    pub rtt: Duration,                         // added to every request
    pub bandwidth_bps: Option<u64>,            // per connection; `per_conn_bandwidth` overrides by index
    pub per_conn_bandwidth: HashMap<u32, u64>,
    pub faults: Vec<FaultRule>,                // FailConnect{times, err}, FailRead{path, after, err, times},
                                               // FailWrite{..}, FailOpen{path, err}, HangRead{path, after}
}
pub struct MockServerStats { pub peak_connections: u32, pub peak_transfers: u32,
    pub peak_per_direction: [u32; 2], pub connects: u32, pub aborts: u32, pub open_now: u32 }
```

### Behaviour

**Engine task.** One engine per process (all tabs share it). It is a tokio task running
`select!` over: the command channel, worker completions (`JoinSet`), a `DelayQueue` of
retry timers, the progress tick (`TICK`), and the pool reaper (every 5 s). Scheduler
state lives in `Arc<std::sync::Mutex<EngineShared>>`; lock order is always
`EngineShared` → `Queue`, never held across `.await` (clippy `await_holding_lock` is
denied in T00).

**Limits** (read from the current `Settings`):

| Limit | Setting | Default | Range |
|---|---|---|---|
| Active transfers (all directions, including T41b segments and T43 listings) | `transfers.max_concurrent` | 4 | 1–16 |
| Active downloads | `transfers.max_downloads` | 0 (= only the global limit) | 0–16 |
| Active uploads | `transfers.max_uploads` | 0 | 0–16 |
| Connections per server group | `ConnectInfo` connection limit (site `limit_connections`, 1–10) | none (= global) | — |
| Learned per-group limit | back-off, see below | — | ≥ 1 |

A group's effective limit = min(site limit, learned limit, `max_concurrent`). Active =
`Connecting`, `Listing`, `Preparing`, `AwaitingUser`, `Transferring`, `Finishing`. Idle
pooled connections do not count against `max_concurrent` but do count against the group
limit (they are open connections to that server; a new item for that group reuses one).

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
    spawn slot task for (id, g)          // connects in parallel (warm-up for free)
```

A slot task that finishes an item asks the scheduler for the next item **inline**
(handoff, under the same lock): if the best eligible item belongs to the same group and
direction limits allow it, the slot keeps its connection and continues immediately
(no idle gap); otherwise it returns the connection to the idle pool and ends, and the
scheduler starts the other item. Global priority order is therefore never violated by
connection reuse.

**Connection pool** (`pool.rs`), per group:
- `acquire`: pop the most recently released idle connection (LIFO) whose
  `is_connected()` is true; otherwise create one with `BackendFactory::create(&info,
  events)` and `connect(cancel)` (backend timeouts from T10/T20; engine backstop 60 s).
  `ConnectInfo` is resolved once per group per run via `ConnectInfoResolver` and cached.
- `release`: healthy connection → idle list with timestamp; broken (error during the
  transfer, abort timeout) → disconnected in a tracked background task (2 s timeout).
- Reaper: closes idle connections older than `IDLE_CLOSE` (30 s); keeps total idle
  connections ≤ `max_concurrent` (closes the oldest first).
- Transfer connections are separate from the tabs' browsing sessions (FileZilla
  behaviour), so browsing stays responsive. The pool holds `Box<dyn Backend>` directly
  rather than `SessionHandle`: a slot needs exclusive `&mut` access for the whole
  transfer, idle connections close after 30 s (no keep-alive needed), and reconnects are
  the retry policy's job (a transparent reconnect mid-transfer would hide a lost offset).
- Each pooled connection gets its own `SessionId` (T04) for its log lines.

**Connection-limit back-off.** `is_connection_limit(err)` is true for:
1. `Protocol { code: Some(421), .. }` returned by `connect` (greeting or login);
2. `Protocol { code: Some(530), message }` or `Auth(message)` / `Connection(message)` where
   `message` matches `(?i)too many|maximum (number of )?(connections|clients|users|sessions)|connection limit|limit reached|max(imum)?[ _-]?(connections|clients)`;
3. SSH disconnect with reason code 12 (`SSH_DISCONNECT_TOO_MANY_CONNECTIONS`), which T20
   maps to `Error::Connection` with the text "too many connections".

When it happens at connect and the group has `n ≥ 1` other connected slots: learned
limit = `n`, the item returns to `Queued` **without** counting an attempt, and a Status
line is logged: "Server refused another connection; using at most n connection(s) to it
for this session". The learned limit lasts for the process lifetime. With `n = 0` the
error is treated as `Transient` (attempt counted).

**Worker (slot) lifecycle** for a file item (`worker.rs`):

| Phase | Steps | Timeout |
|---|---|---|
| `Connecting` | `pool.acquire(group)` | backend connect timeout; backstop 60 s |
| `Preparing` | 1. source entry: use the item's `size`/`source_modified`; `stat` the source only if size is unknown, `completed` is non-empty, or the policy needs an mtime it lacks. 2. target entry: `stat` (download: `LocalFs::stat`; upload: `Backend::stat`, `NotFound` → missing). 3. Auto transfer type → `decide_transfer_type` (T11). 4. If `completed` is non-empty, the source size/mtime equal the item's, and the target size ≥ `completed.contiguous_prefix()`: resume automatically at that prefix (binary + `resume_*` capability) without asking the policy; otherwise clear `completed` and call `ExistsPolicy::resolve`. 5. Create the parent directory (download: `create_dir_all`; upload: `mkdir` each missing component, remembering created dirs per run). | per backend call: `connection.timeout_secs` (backend) |
| `AwaitingUser` | only inside `ExistsPolicy` when it prompts; the slot keeps its connection; after the answer, `keepalive()` checks it, and a dead connection is replaced without counting an attempt | none (cancellable) |
| `Transferring` | open reader at the start offset (`Backend::open_read` / `LocalFs::open_read`) and writer (`LocalFs::open_write` / `Backend::open_write` with the `WriteMode`), run the copy loop | stall: no byte for `connection.timeout_secs` → `Error::Timeout` |
| `Finishing` | `writer.finish()` (local) or close the remote writer; `finish_transfer()` (FTP 226); checkpoint `completed = [0, size)`; `delete_source_after` (only for `Transferred`/`Resumed`; failure to delete logs an Error line, item still Done) | `FINISH_TIMEOUT` (30 s) |

Then `Queue::finish(id, outcome, bytes, duration)`, emit `TransferStateChanged`, log
"File transfer successful, transferred 1.2 MiB in 3 seconds", add the target's parent to
`TouchedDirs` (≤ 1000, then `overflow = true`).

**Copy loop** (`copy.rs`; T41b replaces it with the double-buffered pipeline):

```
buf = 256 KiB
loop:
  n_max = min(COPY_CHUNK, limiter.max_chunk(dir))
  n = select!(cancel => Cancelled, timeout(stall, reader.read(&mut buf[..n_max])))
  if n == 0: break                                  // EOF
  select!(cancel => Cancelled, limiter.acquire(dir, n))
  select!(cancel => Cancelled, timeout(stall, writer.write_all(&buf[..n])))
  meter.bytes.fetch_add(n)                           // AtomicU64, read by the tick
  every CHECKPOINT_EVERY: writer flushed → queue.checkpoint(id, [0, offset))
```

At EOF, if the size is known and fewer bytes arrived than `size − start_offset`, the
result is `Error::Connection("transfer ended early")` (transient). More bytes than
expected (file grew) is accepted and logged at debug. Downloads write to the final name
directly (FileZilla behaviour); partial files stay for resume.

**Progress, speed, ETA** (`progress.rs`). Every `TICK` (200 ms) the engine reads each
active meter: `Δb` bytes in `Δt`. Speed: for the first `SPEED_TAU` (5 s) of a transfer,
`bytes_since_start / elapsed`; afterwards an exponential moving average
`speed += α · (Δb/Δt − speed)` with `α = 1 − exp(−Δt / τ)`, `τ = 5 s`. ETA =
`ceil((total − done) / speed)` seconds when the total is known and speed ≥ 1 B/s, and
the transfer has run ≥ 1 s; otherwise `None`. Each tick emits one
`TransferProgress { id, bytes_done, total, speed_bps, eta }` per active item (5 Hz,
below T04's 10 Hz cap; T04 coalesces further) and updates `EngineStats` (watch channel).

**Retry policy** (`retry.rs`). `classify(err, phase, dir)`:

| Class | Errors | Action |
|---|---|---|
| `Cancelled` | `Error::Cancelled` | if the slot's token was cancelled: the state the canceller asked for (below); otherwise (a prompt was dismissed, T42): item `Paused`, Status line "Question dismissed; item paused" |
| `ConnectionLimit` | `is_connection_limit` at connect | back-off (above) |
| `LocalDiskFull` | `Error::Io` with `ErrorKind::StorageFull`/`QuotaExceeded` or raw OS error 28 (ENOSPC), 122 (EDQUOT), 112/39 (Windows disk full) | item `Failed(Permanent)` "Local disk full"; engine stops like `Stop`; Error log "Local disk is full — queue stopped. Free some space and start the queue again." |
| `RemoteDiskFull` | upload with `Protocol { code: Some(452 \| 552) }` | item failed; group blocked "Server disk full or quota exceeded" |
| `ServerFatal` | at `Connecting`: `Auth`, `HostKey`, `Tls`, `Unsupported`, `Vault`, resolver errors (site deleted, password prompt cancelled) | group blocked with the message; its items stay queued but not runnable; `Start` unblocks |
| `ItemFatal` | `NotFound`, `PermissionDenied`, `AlreadyExists`, `InvalidInput`, `Unsupported` after connect, `Protocol` 5xx, `Io` other than transient kinds | `Failed(Permanent)`, no retry |
| `Transient` | `err.is_transient()` (T02: timeouts, 4xx, resets) plus `Io` kinds `ConnectionReset`, `ConnectionAborted`, `BrokenPipe`, `UnexpectedEof`, `TimedOut` | `attempts += 1`; if `attempts ≤ connection.retries` → `Waiting { until: now + connection.retry_delay_secs }`; else `Failed(Transient)` |

Before a transient retry, the bytes written so far are checkpointed (local writer
flushed). On the retry, a single-stream transfer resumes at: download — `min(local
size, completed.contiguous_prefix())`; upload — the remote size from `stat`. This needs
binary type and `resume_download` / `resume_upload`; otherwise it restarts with
`Truncate`. The last error text is kept in `last_error` for the failed list. Defaults:
`connection.retries` = 2 (0–99), `retry_delay_secs` = 5 (0–3600).

**Cancellation.** A root `CancellationToken` per engine; every slot gets a child token.
The copy loop checks it on every chunk (`select!`). After a cancel, the slot drops the
reader/writer and calls `finish_transfer()` with `ABORT_TIMEOUT` (5 s) — for FTP this
sends `ABOR` (T11 contract: dropping the stream before EOF and calling `finish_transfer`
aborts and leaves the control connection usable). On success the connection goes back
to the pool; on timeout or error it is discarded. Resulting state: `Stop` → `Queued`;
`Pause`/`PauseAll` → `Paused`; `Cancel { remove: false }` → `Paused`; `Cancel { remove:
true }` → removed from the queue. Partial local files are kept.

**Run and completion.** A run starts with `Start` and ends when processing is on, nothing
is active, nothing is `Waiting`, and `next_runnable(ignoring limits)` is `None`. If at
least one item was started during the run, the engine emits
`CoreEvent::QueueFinished { stats: QueueRunSummary }`, consumes the one-shot override
(T45), calls `ExistsPolicy::run_finished()`, and sets `processing = false`. `Stop`, disk
full and `Shutdown` end a run without `QueueFinished`.

**Settings changes.** Lowered limits never cancel active transfers; they only prevent
new starts until below the limit. Raised limits trigger the scheduler at once.

**Shutdown.** Cancels all slots, waits for them (each bounded by `ABORT_TIMEOUT`),
disconnects every pooled connection in parallel (`DISCONNECT_TIMEOUT` each), drains the
`JoinSet`, then acks `done`. After the ack no engine task is alive.

### Data formats and configuration

Settings read (all from T05): `transfers.max_concurrent`, `transfers.max_downloads`,
`transfers.max_uploads`, `connection.retries`, `connection.retry_delay_secs`,
`connection.timeout_secs`, `queue.on_complete`. No new keys. Validation ranges above are
enforced by T05's validation (out of range → warning + default).

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

- `ConnectInfo` secrets stay inside the resolver/backends; the engine never formats a
  `ConnectInfo` or `QueueServer` with secrets (`Debug` impls redact, T02/T40).
- Message-log lines may contain paths (user-facing feature, T55); the tracing app log
  at `info`+ contains only `TransferId`s, group ids, counts and error classes (T91 §4).
- Remote names and sizes are untrusted: sizes only used as `u64` with saturating math;
  local target paths are built by T42's sanitizer (never joined from raw remote names).
- A malicious server can't exceed the limits: every connection counts, refused
  connections back off, and a server that floods bytes is bounded by the stall timeout
  and the rate limiter.

## Implementation steps

1. `LocalFs` + `TokioLocalFs` + `MemLocalFs`; `MockServer` extensions for `MockBackend`.
2. `progress.rs` (meters, EMA, ETA) with pure tests.
3. `retry.rs`: `classify`, `is_connection_limit` with table tests.
4. `policy.rs`: `ExistsPolicy`, `OverwritePolicy`, `RateLimiter`, `Unlimited`, `TargetPath`.
5. `pool.rs`: acquire/release/reaper, group limits, learned limits.
6. `sched.rs` + `engine.rs`: command loop, scheduling, handoff, run end and
   `QueueFinished`, `EngineStats`.
7. `worker.rs` + `copy.rs`: phases, copy loop, checkpoints, retries with resume.
8. Cancellation, Pause/Stop/Shutdown, disk-full stop, group blocking.
9. Criterion bench, property test, e2e scenarios in `courier-ftp-e2e`.

## Acceptance criteria

- [ ] AC1 With `MockServer` latency and bandwidth, `peak_transfers ≤ max_concurrent`, per-direction peaks ≤ `max_downloads`/`max_uploads`, and per-group `peak_connections ≤` site limit in every test, including the property test with random limits.
- [ ] AC2 With one slot, items start in (priority desc, queue order) order, including after reorders during a run.
- [ ] AC3 A transient read failure after 3 MiB of a 10 MiB download is retried after `retry_delay_secs` (paused time) and resumes at offset 3 MiB (mock records `open_read(offset = 3 MiB)`); the result is byte-identical. A `NotFound` is not retried (`attempts == 0`, one `open_read`).
- [ ] AC4 `Cancel` of an active transfer reaches `Paused`/removed within 1 s of virtual time with a 100 ms mock RTT; the mock records an abort and the same connection is used for the next item.
- [ ] AC5 Against a mock with `max_connections = 2` and `max_concurrent = 4`, the learned limit becomes 2, no item's `attempts` increases, and all items complete.
- [ ] AC6 After `Shutdown`, the engine's `JoinSet` is empty, `MockServerStats::open_now == 0`, and the `JoinHandle` has completed.
- [ ] AC7 Progress events for an active item arrive at ≤ 5 Hz; speed for a constant 1 MiB/s mock transfer is within ±2 % after 10 s; ETA within ±1 s.
- [ ] AC8 Local disk full stops the engine (no further starts), fails only that item, and emits no `QueueFinished`.
- [ ] AC9 An `Auth` error blocks the group: no further connection attempts to that server until `Start`.
- [ ] AC10 `QueueFinished` is emitted exactly once per run that started ≥ 1 item, never after `Stop`.
- [ ] AC11 Bench `transfer_engine/mock_10k_small_files` (10 000 × 4 KiB, zero-latency mock, `MemLocalFs`) < 500 ms on the reference machine; gate (CI 1000 ms) in `scripts/bench-gates.toml`.
- [ ] AC12 Docker e2e: 50 mixed-size files (0 B – 64 MiB) up and down, SHA-256 verified, against vsftpd `plain` and `explicit-tls`, proftpd, pure-ftpd and sshd `password`; and back-off against `max-1-connection`.
- [ ] AC13 T00 jobs `clippy`, `test-local-only`, `test-os`, `bench-build`, `e2e` pass.

## Tests

### Unit tests
- `fn classify_table` — every `Error` variant × phase → expected `ErrorClass` (AC3, AC8, AC9).
- `fn connection_limit_patterns` — "421 Too many connections (8) from this IP", "530 Sorry, the maximum number of clients (5) for this user are already connected.", "Maximum login limit has been reached." → true; "530 Login incorrect." → false (AC5).
- `fn speed_average_then_ema` and `fn eta_none_until_one_second_and_without_total` (AC7).
- `fn overwrite_policy_create_or_truncate` (default policy).
- `fn group_limit_is_min_of_site_learned_global`.

### Property / fuzz tests
- `proptest fn scheduler_never_exceeds_limits` — random items (1–200, random groups,
  directions, priorities, sizes), random limits, random mock latencies and fault rules;
  run to completion in paused time; asserts AC1 peaks, every item ends `Done` or
  `Failed`, attempts ≤ retries + 1, no leaked tasks (AC1, AC6). 256 cases.

### Snapshot tests
Not applicable.

### Integration tests
All `#[tokio::test(start_paused = true)]` with `MockBackend` + `MockServer` + `MemLocalFs`:
- `async fn limits_respected_with_latency` (AC1).
- `async fn priority_order_single_slot` and `async fn reorder_during_run_changes_next_pick` (AC2).
- `async fn transient_error_resumes_at_offset` and `async fn permanent_error_not_retried` (AC3).
- `async fn retries_exhausted_marks_failed_with_last_error` (AC3).
- `async fn cancel_within_one_second_and_session_reused` (AC4).
- `async fn too_many_connections_lowers_limit_without_attempts` (AC5).
- `async fn shutdown_leaves_no_tasks_or_connections` (AC6).
- `async fn progress_rate_and_eta` (AC7).
- `async fn disk_full_stops_queue` — `MemLocalFs` with a 1 MiB quota (AC8).
- `async fn auth_error_blocks_group_until_start` (AC9).
- `async fn queue_finished_once_and_not_after_stop` (AC10).
- `async fn handoff_reuses_connection_for_same_group` — 20 small files, 1 slot → 1 connect.
- `async fn idle_connections_closed_after_30s`.
- `async fn awaiting_user_replaces_dead_connection_without_attempt`.

### End-to-end tests
`crates/courier-ftp-e2e/tests/transfers.rs`, `#[ignore]`, `require_docker!`, through
`Headless` (T76):
- `fn queue_50_files_roundtrip_<profile>` for vsftpd `plain`, `explicit-tls`, proftpd,
  pure-ftpd, sshd `password` — upload 50 files, download them to a new dir, SHA-256
  equal (AC12).
- `fn backoff_on_max_one_connection` — vsftpd `max-1-connection`, `max_concurrent = 4`;
  all 20 files arrive, Status line about the limit logged (AC12, AC5).
- `fn resume_after_connection_cut` — toxiproxy `reset_peer` after 5 MiB of a 32 MiB
  download; transfer completes, hash equal, second `RETR` preceded by `REST` (AC3).
- `fn cancel_on_slow_profile_within_one_second` — vsftpd `slow` (AC4).

### Benchmarks
`crates/courier-ftp-core/benches/transfer_engine.rs`: `transfer_engine/mock_10k_small_files`
(AC11). Gate `max_ms = 500`, `ci_max_ms = 1000`.

## Out of scope

- File-exists decisions, prompts, timestamps, sanitizing (T42); recursion (T43); token
  bucket (T44); segmentation, pipelining, double buffering (T41b); completion actions (T45).
- Remote → remote (FXP) transfers.
- Several SFTP channels per SSH connection (T22 decision: one SSH connection per slot).

## Open questions

1. Inconsistency for T03/T11 owners: the abort contract ("dropping the stream returned by
   `open_read`/`open_write` before EOF, then `finish_transfer()`, aborts the transfer,
   returns `Ok(())` and leaves the session usable") must be stated in T03 and implemented
   by T11 (FTP) and T22 (SFTP: close handle).
2. Inconsistency for T03's owner: the old T41 text said the pool reuses `SessionHandle`s;
   this spec pools `Box<dyn Backend>` (reasons above). T03 needs no change, but T03's
   `SessionHandle` docs should not promise it is used for transfers.
3. Inconsistency for T20's owner: SSH disconnect reason 12 must be mapped to
   `Error::Connection("too many connections …")` so the back-off can detect it.
4. Inconsistency for T76's owner: the sshd `MaxSessions 1` profile limits channels per SSH
   connection; with one SSH connection per slot it never refuses a second connection. A
   per-user limit needs `MaxStartups 1:100:1` (pre-auth) or PAM `maxlogins 1`.
5. Product: should a learned connection limit be remembered across restarts (per site,
   device-local)? This spec keeps it for the process lifetime only, like FileZilla.
