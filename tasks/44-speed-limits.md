# T44 — Speed limits

**Phase:** E Transfers · **Depends on:** T05, T41 · **Crate:** `courier-ftp-core` (`transfer::ratelimit`) · **FEATURES.md:** §6 (speed limits, burst tolerance, status bar toggle)
**Related (integrates with, not blocking):** T57

## Goal

Global download and upload bandwidth limits shared by all active transfers,
toggleable at runtime.

## Scope

1. **Token bucket** per direction: rate = limit (KiB/s), capacity = rate × burst factor (`Normal` = 1 s, `High` = 2 s, `VeryHigh` = 5 s — document mapping).
2. Shared across all workers (and across tabs) via `Arc`; each worker `acquire(n_bytes).await` before writing a chunk. Fair-ish: waiters served FIFO so one transfer doesn't starve others.
3. **Runtime changes**: enable/disable and new limits apply immediately without restarting transfers (`SettingsChanged` command, T41). Disabled = `acquire` returns instantly.
4. Limits of 0 mean unlimited for that direction.
5. Expose current effective limit for the status bar indicator (T57).
6. Chunk sizes adapted to rate (don't request a 256 KiB chunk when the limit is 10 KiB/s; cap chunk to ~rate/10).

## Acceptance criteria

- [ ] With a 100 KiB/s limit, measured throughput over 10 s (paused time) is within ±5 %.
- [ ] Two concurrent transfers share the limit roughly equally (±20 %).
- [ ] Toggling off mid-transfer removes throttling within one chunk.

## Tests

- `tokio::time::pause` based deterministic tests with mock writer.
