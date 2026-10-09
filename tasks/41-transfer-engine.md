# T41 — Transfer engine

**Phase:** E Transfers · **Depends on:** T03, T04, T40 · **Crate:** `courier-ftp-core` (`transfer` module) · **FEATURES.md:** §5, §6

## Goal

The scheduler and workers that take items from the queue and move bytes,
respecting connection limits, reporting progress and retrying failures.

## Scope

1. **Engine** (`TransferEngine`) runs as a tokio task, controlled through a command channel: `Start`, `Stop` (finish nothing new, cancel active), `PauseAll`, `ResumeAll`, `Cancel(id)`, `SettingsChanged`.
2. **Scheduling**
   - Global `max_concurrent`, plus `max_downloads` / `max_uploads`, plus per-site `limit_connections`.
   - Pick next eligible item by priority then order; skip items whose server is at its limit.
   - **Connection pool** per server: reuse idle sessions (`SessionHandle`, T03) for consecutive transfers; open new ones up to the limit; close idle ones after 30 s. Transfer sessions are separate from the browsing session of the tab (like FileZilla), so browsing stays responsive.
   - Servers that only allow one connection (detected by `421 Too many connections` / `530 ... maximum`): reduce that server's limit for the session and requeue the item without counting an attempt; log it.
3. **Worker** per active transfer:
   - Resolve existence/size of target (T42 decides action).
   - Open source reader + destination writer via backends (local ↔ remote; remote ↔ remote is out of scope).
   - Copy loop with a 64–256 KiB buffer, through the speed limiter (T44), updating progress.
   - On completion: `finish_transfer`, apply `preserve_timestamps` (T42), mark Done, emit events.
   - Downloads write to the final name directly (FileZilla behaviour) — keep it simple; partial files are resumable.
4. **Progress**: bytes done, total, instantaneous speed (exponential moving average over ~5 s), ETA. Emitted via coalesced progress events (T04), max 10 Hz per item.
5. **Retries**: on `is_transient()` errors, retry up to `connection.retries` with `retry_delay_secs`, resuming from the current offset where possible. Permanent errors → Failed immediately. Record the last error message for the failed list.
6. **Cancellation**: per-item `CancellationToken`; cancelling an FTP transfer issues `ABOR` (T11), SFTP just closes the handle.
7. **Events**: state changes, progress, `QueueFinished { stats }` when nothing is queued or active (T45).
8. **Disk full / local permission errors**: permanent failure with a clear message; disk full also pauses the whole queue (prevents every item failing in a row).

## Acceptance criteria

- [ ] With `MockBackend` (T03) supporting artificial latency, limits are never exceeded (assert in tests).
- [ ] Priority ordering respected.
- [ ] Transient failure retried and resumes at offset; permanent failure not retried.
- [ ] Cancel stops within 1 s and leaves the session reusable.
- [ ] "Too many connections" lowers the limit and doesn't burn attempts.
- [ ] No task leaks after `Stop` (track with a JoinSet and assert empty).

## Tests

- Deterministic tests with `tokio::time::pause` and the mock backend.
- Integration (T76): 50 files up/down against each server type, verify checksums.
