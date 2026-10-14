# T40 — Queue model and persistence

**Phase:** E Transfers · **Depends on:** T02, T05, T30, T82 · **Crate:** `courier-ftp-core` (`queue` module) · **FEATURES.md:** §5
**Related (integrates with, not blocking):** T43

## Goal

The transfer queue data structure: items, states, priorities, ordering, the
three lists (queued / failed / successful) and persistence across restarts.

## Scope

1. **`QueueItem`**
   ```rust
   pub struct QueueItem {
       pub id: TransferId,
       pub server: QueueServer,          // SiteId or inline quickconnect ServerAddress (+ password, kept encrypted)
       pub direction: Direction,         // Download | Upload
       pub local: LocalPath,
       pub remote: RemotePath,
       pub size: Option<u64>,
       pub transfer_type: TransferTypeChoice, // Auto | Ascii | Binary
       pub priority: Priority,           // Lowest, Low, Normal, High, Highest
       pub on_exists: Option<ExistsAction>,   // per-item override, set by "apply to all"
       pub state: ItemState,             // Queued, Active{progress}, Paused, Failed{error, attempts}, Done{finished_at, bytes, duration}
       pub attempts: u8,
       pub added_at: OffsetDateTime,
       pub is_dir_placeholder: bool,     // a dir to be expanded lazily (T43)
   }
   ```
2. **Lists**: `queued: Vec<TransferId>` (ordered), `failed`, `successful`. Successful list capped (setting, default 1000) to bound memory.
3. **Operations**
   - Add (single/batch), remove (selected/all), clear failed, clear successful.
   - Reorder: move up/down/top/bottom; set priority (selected). Scheduler picks highest priority first, then queue order.
   - "Reset and requeue" failed items (resets attempts, moves back to queued — FileZilla's "Reset and requeue selected files").
   - Pause/resume individual items (excluded from scheduling while paused).
   - Group-by-server view helper (FileZilla groups queue rows under a server header).
4. **Persistence** (setting `queue.persist`):
   - Written to the `device_blobs` table (T82) as a blob encrypted with the LMK (T30) — it contains hosts and paths. The queue is device-local and never syncs.
   - Debounced writes (≤ 2 s) on change; final write on quit.
   - On startup, load the queue but **don't start** it automatically; items that were `Active` become `Queued` (resume will use REST/offset).
   - Vault locked → queue not persisted; UI warns on quit if items would be lost.
5. **Export/import queue**: plain JSON file of items without secrets (FileZilla has "Export queue"). Importing resolves `SiteId`s; quickconnect items with missing secrets become ask-for-password.
6. **Statistics**: total bytes queued, item count, estimated time (from recent average speed) — for the status bar and queue pane header.

## Acceptance criteria

- [x] All operations are unit tested.
- [x] Persisted queue survives restart; active items come back as queued.
- [x] 100 000 items: add, reorder and render-model generation each < 50 ms (benchmark test, `#[ignore]` in CI).
- [x] Export contains no secrets.

**Status:** core model, persistence and export done (`courier_ftp_core::queue`;
`DeviceBlobVault` implemented by `VaultEngine`). The 100k gate is a release-only
`#[ignore]` test run by `bench.yml`. Wiring is left to the UI tasks: creating the
`QueuePersister` at startup, `restore()` after unlock, `changed()` after mutations
and the quit warning dialog from `quit_check()` go with T56 (queue pane); the
Export/Import queue menu entries with T56/T73.

## Tests

- Unit tests per operation, ordering with priorities.
- Round-trip persistence with a test vault key.
