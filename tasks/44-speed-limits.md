# T44 — Speed limits

**Phase:** E Transfers · **Milestone:** M4 · **Depends on:** T05, T41 · **Crate(s):** `courier-ftp-core` (`transfer::ratelimit`) · **Decisions:** none · **FEATURES.md:** §6 (speed limits, burst tolerance, status bar toggle)
**Related (integrates with, not blocking):** T57

## Goal

Global download and upload bandwidth limits shared by every active transfer, segment and
tab, with FileZilla's burst tolerance, switchable on and off at runtime (status-bar
toggle) without restarting transfers. The limiter is a token bucket implementing T41's
`RateLimiter` trait; it is exact over time, fair between transfers, and deterministic
under tokio's paused clock.

## Context

- Before: T41 defines `RateLimiter { acquire(dir, bytes), max_chunk(dir) }`, calls
  `acquire` for every chunk in the copy loop (inside `select!` with the slot's cancel
  token) and sizes chunks with `max_chunk`; T05 defines `transfers.speed_limit_enabled`,
  `download_limit_kib`, `upload_limit_kib`, `burst_tolerance` (`BurstTolerance`),
  `SharedSettings` and `SettingsStore::set_transient`; T02 gives `Direction`.
- After: the `Ctrl-x k` `ToggleSpeedLimit` action (T51 keymap; T44/T57) flips `transfers.speed_limit_enabled` through
  `SettingsStore::set_transient` and shows `SpeedLimitIndicator` built from
  `EffectiveLimits`; T68 edits and persists the values; T41b's segments share the same
  limiter (the limit applies to the sum of all connections and segments).

## Technical specification

### Types and APIs

Module `courier_ftp_core::transfer::ratelimit`:

```rust
/// One limiter for the whole process (both directions), injected into the engine.
#[derive(Debug)]
pub struct TokenBucketLimiter { /* settings: SharedSettings, state: [Mutex<Bucket>; 2] */ }

impl TokenBucketLimiter {
    pub fn new(settings: SharedSettings) -> Self;
    /// Limits currently in force (None = unlimited), for the status bar (T57).
    pub fn effective(&self) -> EffectiveLimits;
}
impl RateLimiter for TokenBucketLimiter { /* acquire, max_chunk */ }

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EffectiveLimits { pub enabled: bool, pub down_kib: Option<u32>, pub up_kib: Option<u32> }

/// Burst window in seconds for a tolerance level.
pub fn burst_secs(t: BurstTolerance) -> u32;          // Normal 1, High 2, VeryHigh 5

/// Chunk size for a rate: rate/10 rounded down to a multiple of 4 KiB, clamped to
/// 4 KiB ..= 256 KiB; 256 KiB when unlimited.
pub fn chunk_for_rate(bytes_per_sec: Option<u64>) -> usize;

/// Internal per-direction state (GCRA form of a token bucket).
struct Bucket {
    config: Option<BucketConfig>,   // None = unlimited
    generation: u64,                // bumps on every config change
    tat: Instant,                   // theoretical arrival time of the next byte
}
struct BucketConfig { rate: u64 /* bytes/s */, burst: Duration }
```

### Behaviour

**Configuration.** For direction `d`, the limiter is active iff
`transfers.speed_limit_enabled` and the direction's `*_limit_kib > 0`. Rate =
`limit_kib × 1024` bytes/s. Burst window = `burst_secs(transfers.burst_tolerance)`;
bucket capacity = rate × burst window (FileZilla mapping: Normal = 1 s, High = 2 s,
Very high = 5 s of traffic).

**Algorithm (GCRA, equivalent to a token bucket).** Per direction, under a
`std::sync::Mutex` held only for the arithmetic (never across `.await`):

```
acquire(d, n):
  loop:
    cfg = current config (see "Runtime changes"); if unlimited → return
    lock bucket
      if bucket.generation != my_generation: drop my reservation; my_generation = it
      if no reservation yet:
          now = Instant::now()
          tat = max(bucket.tat, now − burst)        // idle time earns up to `burst` credit
          bucket.tat = tat + n / rate               // reserve (FIFO: call order = slot order)
          my_end = bucket.tat; my_wait_until = tat  // wait until our first byte's slot
    unlock
    if my_wait_until ≤ now → return
    sleep_until(min(my_wait_until, now + 100 ms))  // short slices to see config changes
```

- Time math in integer nanoseconds (`n × 1e9 / rate`, `u128` intermediate, saturating).
- The bucket starts **empty**: on creation and on every config change `tat = now`, so a
  measurement starting at the first byte sees exactly the configured rate (burst credit
  only accumulates while idle).
- **Fairness**: reservations are taken in call order, so concurrent transfers that ask for
  equal chunk sizes get equal shares; no transfer can take more than one chunk ahead of
  another.
- **Cancel safety**: a dropped `acquire` future gives its reservation back when it is the
  latest one (`bucket.tat == my_end` → `bucket.tat -= n / rate`); otherwise the reserved
  time is lost, which under-uses the link by at most one chunk.

**Chunk sizing** (`max_chunk(d)`): `chunk_for_rate(rate)` — e.g. 10 KiB/s → 4 KiB,
100 KiB/s → 8 KiB, 1 MiB/s → 100 KiB, ≥ 2.5 MiB/s → 256 KiB. So waits are ~100 ms and
toggling takes effect within one chunk.

**Runtime changes.** Every `acquire` and every 100 ms sleep slice reads the current
`Arc<Settings>` from `SharedSettings` (`borrow().clone()`, an `Arc` clone). If it is not
the same `Arc` as the one last applied (`Arc::ptr_eq`), the bucket config is recomputed;
when the effective values differ, `generation += 1` and `tat = now`. Waiters notice within
one slice (≤ 100 ms): disabled → return immediately; new rate → re-reserve under the new
rate. Transfers are never restarted. T57's toggle and T68's edits therefore apply
immediately; the engine's `SettingsChanged` command is not needed by the limiter.

**Scope.** One `TokenBucketLimiter` per process, shared by every slot and segment (T41,
T41b) and so by every tab. Limits apply to payload bytes counted by the copy loop.
Known overshoot, documented: at the start of a stream the network may run ahead by the
protocol's read-ahead (SFTP pipeline window, ≤ 8 MiB per stream, T22; TCP socket buffers
for FTP); the long-run average is exact.

### Data formats and configuration

| Key (T05) | Type | Default | Range | Use |
|---|---|---|---|---|
| `transfers.speed_limit_enabled` | bool | false | — | master toggle (`Ctrl-x k` ToggleSpeedLimit, status bar indicator; T57) |
| `transfers.download_limit_kib` | u32 | 0 | 0–1 048 576 | KiB/s, 0 = unlimited |
| `transfers.upload_limit_kib` | u32 | 0 | 0–1 048 576 | KiB/s, 0 = unlimited |
| `transfers.burst_tolerance` | BurstTolerance | normal | normal / high / very-high | 1 s / 2 s / 5 s |

No new keys. The toggle from the status bar is applied with `set_transient` (T05) and
persisted when the user saves settings (T68).

### Errors

None: `acquire` cannot fail. Invalid settings never reach the limiter (T05 validation
clamps them).

### Security and logging

Not security-relevant. Config changes are logged at `Debug(Verbose)` in the message log
("Speed limits: download 500 KiB/s, upload off, burst 1 s"); nothing at `info`+ in the
tracing log beyond "speed limits changed".

## Implementation steps

1. `burst_secs`, `chunk_for_rate`, `BucketConfig` from `Settings` + unit tests.
2. GCRA bucket with reservation, cancel-safe guard and integer time math.
3. `TokenBucketLimiter` with `SharedSettings` reconfiguration and sleep slices.
4. Wire it into the engine in the binary (replacing `Unlimited`); `effective()` for T57.
5. Paused-time tests (limiter alone and through the engine with `MockServer`), property
   test, bench.

## Acceptance criteria

- [ ] AC1 With a 100 KiB/s download limit, bytes granted over 10 s of virtual time measured from the first byte are within ±5 % of 1 000 KiB (limiter alone and through the engine with a mock transfer).
- [ ] AC2 Two concurrent transfers under a 200 KiB/s limit each get 100 KiB/s ±20 % over 10 s; three get 66.7 KiB/s ±20 %.
- [ ] AC3 Toggling `speed_limit_enabled` off mid-transfer: the next chunk is granted within 100 ms of virtual time and throughput then equals the mock's unthrottled bandwidth.
- [ ] AC4 Changing the rate from 100 to 200 KiB/s mid-transfer: the next 5 s average is 200 KiB/s ±5 %.
- [ ] AC5 Burst: after 10 s idle with `very-high` at 100 KiB/s, 500 KiB are granted without waiting, then the rate is 100 KiB/s ±5 %.
- [ ] AC6 Upload and download limits are independent (a saturated download limit does not slow uploads).
- [ ] AC7 A cancelled `acquire` returns its reservation (a following acquire is not delayed by it).
- [ ] AC8 `max_chunk` follows `chunk_for_rate` (table test).
- [ ] AC9 Bench `rate_limit/acquire_unlimited_1m` (1 000 000 acquires with limits off) < 50 ms; gate `ci_max_ms = 100` in `scripts/bench-gates.toml`.
- [ ] AC10 T00 `test-local-only`, `test-os`, `bench-build` pass.

## Tests

### Unit tests
- `fn burst_secs_mapping` — 1 / 2 / 5 (AC5).
- `fn chunk_for_rate_table` — None → 256 KiB; 1 KiB/s → 4 KiB; 10 KiB/s → 4 KiB; 100 KiB/s → 8 KiB; 1 MiB/s → 100 KiB; 10 MiB/s → 256 KiB (AC8).
- `fn config_inactive_when_toggle_off_or_zero` (AC3).

### Property / fuzz tests
- `proptest fn never_exceeds_rate_plus_burst` — random rates, burst levels, chunk sizes and arrival times; for every window `[t1, t2]`, granted bytes ≤ `rate × (t2 − t1) + capacity + max_chunk` (AC1, AC5). Paused time.

### Snapshot tests
Not applicable.

### Integration tests
All `#[tokio::test(start_paused = true)]`:
- `async fn limiter_100k_over_10s` (AC1) and `async fn engine_download_100k_over_10s` (T41 engine + `MockServer`, AC1).
- `async fn two_and_three_transfers_share_fairly` (AC2).
- `async fn toggle_off_within_100ms` (AC3) — `SettingsStore::set_transient` mid-transfer.
- `async fn rate_change_applies_without_restart` (AC4) — asserts `open_read` was called once.
- `async fn burst_after_idle` (AC5).
- `async fn directions_independent` (AC6).
- `async fn cancelled_acquire_refunds` (AC7).

### End-to-end tests
T76's `transfers.rs::speed_limit_within_10_percent` (`#[ignore]`, `require_docker!`,
`Headless`), implemented by this task: a 20 MiB download at 1 024 KiB/s from sshd
`password` takes 20 s ±10 % wall time (AC1 on a real server; generous for CI noise).

### Benchmarks
`crates/courier-ftp-core/benches/ratelimit.rs`: `rate_limit/acquire_unlimited_1m` (AC9,
gate `max_ms = 50`, `ci_max_ms = 100`); `rate_limit/acquire_limited_contended`
(informational, 8 tasks).

## Out of scope

- Per-site or per-transfer limits (FileZilla has only global limits).
- Scheduled limits (time-of-day).
- Limiting at the socket level (the limit applies to payload bytes in the copy loop).

## Open questions

1. With a low limit, the SFTP pipeline (T22: up to 8 MiB in flight per stream) lets the
   network run ahead of the limit at the start of each transfer. Should T22 reduce its
   in-flight window when a limit is active (e.g. to 0.5 s worth of the limit), as
   FileZilla's fzsftp effectively does? Current spec: documented overshoot only.
