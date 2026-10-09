# T41b — Fast transfers: parallelism, segmented files, pipelining

**Phase:** E Transfers · **Milestone:** M4 · **Depends on:** T11, T22, T40, T41, T42, T43, T44, T76 · **Crate(s):** `courier-ftp-core` (`transfer`), `courier-ftp-proto-ftp`, `courier-ftp-proto-sftp` · **Decisions:** D11 · **FEATURES.md:** §5, §6 (goes beyond FileZilla, D11)
**Related (integrates with, not blocking):** T12, T31, T68

## Goal

Transfers saturate the link both for many small files and for a few huge ones.
FileZilla only parallelises across files (2 at once by default). courier-ftp adds, in
order of impact: (1) many files at once over several connections, (2) one large file
split into byte ranges fetched over several connections with work stealing, (3) SFTP
request pipelining so one connection is not bound by round-trip time, and (4) no
per-file overhead (connection reuse, parallel directory listing, fewer round trips per
small file, double-buffered streaming). Targets are measured and gated.

## Context

- Before: T41 (scheduler, slots, pool with handoff, copy loop, checkpoints every 5 s,
  retry policy, `MockServer` per-connection bandwidth), T40 (`completed: RangeSet`,
  persisted), T42 (exists decision → `WriteMode`, preallocate hint), T43 (placeholder
  expansion = parallel listing), T44 (shared limiter), T03 (`TransferOpts.range_len`,
  `WriteMode::WriteAt`, `Capabilities::positional_writes`/`resume_download`,
  `TransferEnd::Abort`), T11 (`DataConnOpts.socket_buffer`, ABOR resync), T12 (TLS session
  reuse for data connections), T20 (16 MiB SSH window, 65 535 max packet, AEAD-first cipher
  order), T22 (pipelined `SftpReader`/`SftpWriter` on `RawSftpSession`, `limits@openssh.com`,
  8 MiB in-flight cap), T76 (Docker fixtures, toxiproxy, `Headless`), T00 (bench gates).
- After: T68 shows the settings below; T56 shows segment count per active row
  (`EngineStats`/progress); `docs/performance.md` records the measurements.

## Technical specification

### Types and APIs

`courier_ftp_core::transfer::segment` (new) and changes in `sched.rs`, `copy.rs`:

```rust
/// Splitting and work stealing for one file. Pure data structure (unit/property tested);
/// shared by the item's segment slots behind a std Mutex (no await while locked).
pub struct SegmentPlan {
    size: u64,
    /// Ranges nobody owns yet (from a fresh split, resume gaps, or a failed segment).
    free: Vec<(u64, u64)>,
    /// One entry per running segment: owned range [pos, end), reserved_to ≤ end.
    owned: Vec<SegmentState>,
    done: RangeSet,                     // written and flushed windows
}
pub struct SegmentState { pub id: SegmentId, pub pos: u64, pub reserved_to: u64, pub end: u64 }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SegmentId(pub u32);

impl SegmentPlan {
    /// Fresh file: `n` equal ranges aligned to 1 MiB (the last takes the remainder).
    pub fn split(size: u64, n: u32) -> Self;
    /// Resume: free ranges = `done.missing(size)`, largest first.
    pub fn resume(size: u64, done: RangeSet) -> Self;
    /// A segment claims a range: a free range, else half of the largest unreserved
    /// remainder of another segment if it is ≥ `2 × min_split`. None = nothing left.
    pub fn claim(&mut self, min_split: u64) -> Option<(SegmentId, u64, u64)>;
    /// Next window to read for `seg`: [reserved_to, min(reserved_to + WINDOW, end)).
    pub fn reserve(&mut self, seg: SegmentId) -> Option<(u64, u64)>;
    /// The window was written (and flushed for checkpoints).
    pub fn written(&mut self, seg: SegmentId, start: u64, end: u64);
    /// Segment failed or was cancelled: its unwritten part returns to `free`.
    pub fn release(&mut self, seg: SegmentId);
    /// Largest unreserved remainder over all owned + free ranges (scheduler growth).
    pub fn largest_unreserved(&self) -> u64;
    pub fn done(&self) -> &RangeSet;
    pub fn is_complete(&self) -> bool;
}

pub const WINDOW: u64 = 1024 * 1024;        // reservation granularity
pub const STEAL_MIN: u64 = 1024 * 1024;     // an existing segment steals only if ≥ 2 MiB remain
pub const SPLIT_ALIGN: u64 = 64 * 1024;     // split points are 64 KiB aligned

/// Initial segment count (pure; see Behaviour).
pub fn initial_segments(size: u64, s: &SegmentedSettings, spare_slots: u32) -> u32;
/// Eligibility (pure; see Behaviour).
pub fn can_segment(item: &QueueItem, size: Option<u64>, ty: TransferType,
                   remote: &Capabilities, local: &Capabilities, s: &SegmentedSettings) -> bool;

/// Per-run index of target directory listings used for uploads (fewer round trips).
pub struct TargetIndex { /* LRU: (GroupId, RemotePath) → HashMap<String, Entry>; 256 dirs, 1 000 000 entries */ }
```

`copy.rs` gains the double-buffered pipeline (`copy_pipelined(reader, writer, …)`); the
protocol crates get the tuning values below. No new public `Backend` methods.

### Behaviour

#### 1. Many files in parallel (extends T41)

- Defaults (T05): `transfers.max_concurrent = 4` (FileZilla 2), range 1–16. Per-site
  `limit_connections` and the T41 back-off still apply.
- **Warm-up**: the scheduler starts up to `max_concurrent` slots at once; each slot
  connects in its own task, so N connections are opened in parallel (T41).
- **No idle gap**: a finishing slot takes the next item of the same group inline (T41
  handoff) and keeps its connection, FTP `cwd`, `TYPE` and TLS session.
- **Parallel listing**: recursive transfers expand directory placeholders as normal slot
  work (T43), so up to `max_concurrent` listings run in parallel with file transfers and
  the queue fills continuously instead of listing the whole tree first.
- **Fewer round trips per small file**:
  - The source is not `stat`ed when the queue item has a size (T41 `Preparing` step 1).
  - Uploads into a directory created or listed during this run use `TargetIndex` for the
    existence check instead of a `stat` per file: T43's expansion stores the target
    directory's listing (empty when it just created it); otherwise the first file whose
    target directory has ≥ 8 more queued siblings lists it once. The index is updated
    after every upload and dropped at the end of the run (≤ 256 dirs, LRU).
  - Downloads check the local target with a local `stat` (no network round trip).
  - FTP: `CWD`/`TYPE` only when they change (T14 tracks both); TLS data connections resume
    the control session (T12), so each data connection costs no full handshake.

Round trips per small file with defaults (RTT = r):

| Case | Commands | ≈ RTTs |
|---|---|---|
| SFTP upload (TargetIndex hit) | OPEN, WRITE (pipelined with) CLOSE | 3 |
| SFTP download | OPEN, FSTAT, READ, CLOSE | 4 |
| FTP download (passive, plain) | EPSV, data connect, RETR→150, data + 226 | 4 |
| FTP upload (passive, plain) | EPSV, data connect, STOR→150, data + 226 | 4 |
| FTPS (+ resumed TLS on data) | as FTP | +1 |

#### 2. Segmented single-file transfers

**Eligibility** (`can_segment`): `transfers.segmented.enabled`; size known and ≥
`segmented.min_file_size_mib`; transfer type Binary; `max_segments ≥ 2`; group limit ≥ 2;
and for a download: remote `resume_download` (FTP `REST STREAM`, SFTP) and local
`positional_writes`; for an upload: remote `positional_writes` (SFTP only — FTP `REST` +
`STOR` at arbitrary offsets from several connections is not reliably supported, so FTP
uploads always use one stream) and local `resume_download`.

**Initial split.** In the item's first slot, after the T41 `Preparing` phase (exists
decision, auto-resume):
- `spare` = free slots for this group and direction (global, direction and group limits)
  minus the number of other runnable items that could use them now — **new files are
  preferred over splitting** one file.
- `initial_segments = max(1, min(max_segments, size / min_segment_size, 1 + spare))`.
- Fresh transfer: the coordinator first creates the target — download: local
  `open_write(Create | Truncate, preallocate_hint)` then `finish_transfer(Complete)`
  (zero-length file, space reserved by T06); upload: remote `open_write(Create |
  Truncate)` + close — then `SegmentPlan::split(size, n)`. Resume (`completed`
  non-empty, T41 auto-resume conditions hold): `SegmentPlan::resume(size, completed)`,
  no truncation.
- The first slot becomes segment 0; the scheduler starts `n − 1` segment slots for the
  item (each counts against all limits like a file slot).

**Segment worker loop** (each with its own pooled remote connection and its own local
backend):

```
(seg, start, end) = plan.claim(STEAL_MIN)          // None → segment ends
download: r = remote.open_read(path, start, TransferOpts { range_len: Some(end − start), .. })
          w = local.open_write(path, WriteAt(start), ..)
upload:   r = local.open_read(path, start, range_len) ; w = remote.open_write(path, WriteAt(start))
loop:
  (a, b) = plan.reserve(seg)  else break           // end may have shrunk (stolen)
  copy exactly b − a bytes from r to w (pipelined copy, limiter per chunk)
  plan.written(seg, a, b)
end of range:
  if b == size and the reader returned EOF: finish_transfer(Complete) on both
  else: drop streams, remote finish_transfer(Abort) (FTP ABOR + resync, SFTP close),
        local finish_transfer(Complete) after shutdown()
  loop back to claim (work stealing reuses this connection)
```

- **Work stealing**: `claim` first takes a free range; otherwise it picks the owned range
  with the largest unreserved remainder `end − reserved_to`; if that is ≥ `2 × STEAL_MIN`
  (2 MiB), the split point `mid = reserved_to + ceil_to(SPLIT_ALIGN, (end − reserved_to)
  / 2)`; the victim's `end = mid`, the thief gets `[mid, old_end)`. Because a segment only
  reads inside reserved windows and reservation happens under the plan lock, no byte is
  read or written by two segments.
- **Growth with new connections**: on every scheduling pass, after all startable files
  were started, a free slot goes to the active segmented transfer (same group,
  direction limits permitting) with the largest unreserved remainder, if that remainder is
  ≥ `2 × min_segment_size` and it has fewer than `max_segments` segments.
- **Read-ahead**: SFTP stops requesting at `range_len` (T22); bytes requested beyond a
  stolen end (≤ T22's 8 MiB pipeline window) are discarded. FTP: the remainder of the
  stream is aborted with ABOR.
- **Checkpoints**: every `CHECKPOINT_EVERY` (5 s) the coordinator flushes the segment
  writers and stores `plan.done()` into the queue item's `completed` (persisted by T40),
  so a crash resumes only the missing ranges.
- **Failures**: a segment error is classified by T41. Transient: `plan.release(seg)`
  (its unwritten part becomes free and is picked up by the other segments at once), the
  item's `attempts += 1`, and a replacement segment slot may start after
  `retry_delay_secs`; more than `connection.retries` segment failures → all segments
  aborted, item `Failed(Transient)` with `completed` kept. Any other class fails the item
  (segments aborted). `Stop`/cancel abort all segments and keep `completed`.
- **Completion**: when `plan.is_complete()`: the coordinator `stat`s the source again
  (download: remote; upload: local) and requires the same size and mtime as at the start
  (else "Source changed during transfer": `completed` cleared, transient retry from
  scratch); it then `stat`s the target and requires `length == size`; T42 timestamps;
  `Done(Transferred)`.
- **Speed limits** (T44) apply per chunk in every segment, so the limit covers the sum of
  all connections and segments.
- **Progress**: the item's meter is the sum of its segments; `TransferProgress` is per
  item; the queue pane may show the segment count from the item's active slot count.

#### 3. SFTP pipelining (tuning of T22)

| Parameter | Value | Why |
|---|---|---|
| Read/write request size | `limits@openssh.com` `max-read-len`/`max-write-len` capped at 261 120 B (255 KiB); else `sftp.request_size` (32 768) | OpenSSH accepts 255 KiB |
| Requests in flight per file | `min(sftp.max_outstanding_requests (64), 8 MiB / request size)`, 1–256 | 8 MiB in flight per stream |
| SSH channel window | 16 MiB (T20) | ≥ in-flight bytes, so the window never throttles |
| Max SSH packet | 65 535 (T20) | fewer packets |
| Cipher order | `aes128-gcm@openssh.com`, `aes256-gcm@openssh.com`, `chacha20-poly1305@openssh.com`, then CTR (T20) | AEAD, AES-NI |

Single-stream throughput bound ≈ min(link, in-flight / RTT): with OpenSSH, 8 MiB / 50 ms
≈ 168 MB/s (> 1 Gbit/s); with a server without `limits@openssh.com`, 64 × 32 KiB = 2 MiB
/ 50 ms ≈ 42 MB/s — segmentation (4 connections) closes that gap.

#### 4. FTP data path (tuning of T11/T12)

- `DataConnOpts.socket_buffer` = 4 MiB (`SO_RCVBUF`/`SO_SNDBUF`, the OS may cap it; T11's
  default is 256 KiB). Single-stream bound ≈ 4 MiB / RTT (≈ 84 MB/s at 50 ms), so large
  files rely on segmentation to fill 1 Gbit/s.
- TLS 1.3 with AES-GCM preferred, session resumption on data connections (T12).

#### 5. Copy pipeline and local disk

- **Double buffering** (`copy_pipelined`): a reader task and a writer task joined by a
  bounded `tokio::sync::mpsc` channel of 4 × 256 KiB `Bytes` chunks (≤ 1 MiB in flight);
  the limiter's `acquire` runs in the writer before each write; both tasks `select!` on
  the slot's cancel token. Chunk size = `limiter.max_chunk(dir)` (T44). Used for every
  transfer (single-stream and segments).
- Local writes go through a 1 MiB `BufWriter` around T06's stream; positional segment
  writes use `WriteAt` (one local backend per segment).
- Uploads read ahead the same way (reader task fills the channel).
- Runtime: tokio multi-threaded runtime; each connection is its own task, so TLS/SSH
  crypto spreads over worker threads; no `spawn_blocking` besides what `tokio::fs` does.

### Data formats and configuration

Settings (already defined in T05 with this task as owner; editable in T68):

| Key | Type | Default | Range | Notes |
|---|---|---|---|---|
| `transfers.segmented.enabled` | bool | true | — | |
| `transfers.segmented.min_file_size_mib` | u32 | 32 | 1–1 048 576 | files below are never split |
| `transfers.segmented.max_segments` | u8 | 4 | 1–16 | 1 = off |
| `transfers.segmented.min_segment_size_mib` | u32 | 8 | 1–1024 | initial split and growth granularity |
| `sftp.max_outstanding_requests` | u32 | 64 | 1–256 | per open file (T22) |
| `sftp.request_size` | u32 | 32 768 | 4 096–261 120 | used without `limits@openssh.com` (T22) |

Constants (not settings): `WINDOW` 1 MiB, `STEAL_MIN` 1 MiB, `SPLIT_ALIGN` 64 KiB, copy
channel 4 × 256 KiB, local `BufWriter` 1 MiB, FTP socket buffer 4 MiB, `TargetIndex` 256
dirs / 1 000 000 entries.

Benchmark results are recorded in `docs/performance.md` ("Transfers" table, same format as
sverb's) with machine, kernel, server versions, link settings, date.

### Errors

No new error variants. Segment errors use T41's classes (above). A segmented transfer
whose source changed fails transiently with `Error::Protocol { code: None, message:
"source changed during transfer" }`. A final length mismatch is
`Error::Protocol { code: None, message: "size mismatch after transfer (expected N, got M)" }`
(transient, `completed` cleared).

### Security and logging

- More connections per server can trip server-side abuse limits: segments count against
  the per-site `limit_connections` and T41's back-off, and `max_concurrent` caps the total.
- No byte range is written twice; positional writes stay inside `[0, size)` of the target
  chosen by T42 (no new path handling).
- Log: Status "Downloading with 4 connections" when a transfer is segmented; segment
  steals and growth at `Debug(Verbose)`; tracing at `info`+ only ids and counts.

## Implementation steps

1. `SegmentPlan` (`split`, `resume`, `claim`, `reserve`, `written`, `release`) with unit
   and property tests; `initial_segments`, `can_segment`.
2. `copy_pipelined` (double buffering) replacing T41's loop; bench.
3. Segment coordinator + segment slots in the scheduler (counting, growth, handoff
   exclusions), checkpoints of `plan.done()`.
4. Segmented download (FTP, SFTP) and upload (SFTP) with resume; completion checks.
5. `TargetIndex` for uploads; T43 expansion feeds it.
6. Protocol tuning: FTP socket buffer 4 MiB (T11 option), SFTP parameters (T22 settings).
7. Benchmarks: criterion gates; `scripts/bench-transfer.sh` + netem sidecar; record
   results in `docs/performance.md`.

## Acceptance criteria

- [ ] AC1 Segmented downloads (FTP and SFTP) and segmented SFTP uploads produce byte-identical files (SHA-256), including runs where segments fail and are retried (mock and Docker e2e).
- [ ] AC2 Work stealing: mock, 256 MiB file, 4 segments, connection bandwidths 10/10/10/1 MiB/s, `min_segment_size_mib = 8`: completion ≤ 1.25 × 256/31 s + 1.5 s ≈ 11.8 s of virtual time; with stealing disabled (test hook) ≥ 60 s.
- [ ] AC3 Resume after a crash: with `completed = {[0, 8 MiB), [16, 24 MiB)}` of 32 MiB, only `[8, 16)` and `[24, 32)` MiB are requested (`open_read_offsets`), and the result is byte-identical.
- [ ] AC4 New files are preferred over splitting: with 10 queued 64 MiB files and `max_concurrent = 4`, no file uses more than 1 segment until fewer than 4 files remain.
- [ ] AC5 Segments never exceed limits: property test (random sizes, limits, failures) shows `peak_streams ≤ max_concurrent` and per-group peaks ≤ `limit_connections`.
- [ ] AC6 SFTP pipelining with one connection reaches ≥ 80 % of a 1 Gbit/s link at 50 ms RTT against OpenSSH (`bench-transfer.sh`, segmentation off), recorded in `docs/performance.md`.
- [ ] AC7 Network benchmarks meet the targets below and are recorded in `docs/performance.md`.
- [ ] AC8 Criterion gates in `scripts/bench-gates.toml` (CI = 2×): `transfer_schedule/plan_10k_files` < 20 ms (planned in T00), `segment_plan/claim_reserve_100k` < 10 ms, `transfer_engine/mock_single_stream_1gib` ≥ 1000 MB/s, `transfer_engine/mock_segmented_4x_1gib` ≥ 1000 MB/s.
- [ ] AC9 Uploading 200 files into one new remote directory issues no per-file `stat` (mock `calls(Stat) == 0` after the expansion).
- [ ] AC10 All six settings above appear in T05's generated settings docs and are editable in T68.
- [ ] AC11 T00 jobs `test-local-only`, `test-os`, `bench-build`, `e2e` pass; nightly `bench.yml` passes the gates.

## Tests

### Unit tests
- `fn split_aligns_and_covers` — sizes 1 B … 1 TiB, n 1–16 (AC1).
- `fn claim_takes_free_then_steals_half` and `fn no_steal_below_two_steal_min` (AC2).
- `fn reserve_respects_shrunk_end` (AC1, AC2).
- `fn release_returns_unwritten_part` (AC1).
- `fn resume_free_ranges_largest_first` (AC3).
- `fn initial_segments_prefers_files` — spare 0 → 1 segment; spare 3, size 64 MiB, min 8 → 4 (AC4).
- `fn can_segment_matrix` — FTP upload never; ASCII never; below threshold never; caps (AC1).

### Property / fuzz tests
- `proptest fn plan_never_overlaps_and_completes` — random sizes, segment counts, interleavings of claim/reserve/written/release (failures); invariants: owned and free ranges disjoint, `done` grows monotonically, every byte written exactly once, terminates with `done == [0, size)` (AC1, AC2).
- `proptest fn segmented_engine_respects_limits` — T41's scheduler property extended with segmented items (AC5).

### Snapshot tests
Not applicable.

### Integration tests
`#[tokio::test(start_paused = true)]`, remote and local `MockServer`s:
- `async fn segmented_download_identical_with_failures` — 64 MiB pattern file, `fail_stream_after` on two segments (AC1).
- `async fn segmented_sftp_like_upload_identical` — mock with `positional_writes = true` (AC1).
- `async fn work_stealing_shortens_tail` and `async fn no_stealing_baseline` (AC2).
- `async fn resume_only_missing_ranges` (AC3).
- `async fn files_preferred_over_segments` (AC4).
- `async fn source_changed_restarts` — mock mtime changed before completion.
- `async fn target_index_avoids_stats` (AC9).
- `async fn copy_pipeline_cancel_within_one_chunk`.

### End-to-end tests
T76's `transfers.rs` entries implemented here (`#[ignore]`, `require_docker!`, `Headless`):
- `segmented_download_2gib_sparse_<ftp|sftp>` — 2 GiB sparse file on `vsftpd-plain` /
  sshd `password`, 4 segments, SHA-256 equal (AC1).
- `work_stealing_with_throttled_connection` — `vsftpd-plain` behind toxiproxy
  (`front_ftpd`), `Bandwidth { kbytes_per_s: 512 }` on PASV ports 30000–30004 only; a
  256 MiB download finishes in ≤ 1.5 × (size / unthrottled rate) + 10 s and the log shows
  at least one steal (AC2 on real servers).
- `segmented_resume_after_cut_sftp` — `LimitData` cuts one segment's connection; the
  transfer completes and the hash matches (AC1, AC3).

### Benchmarks
Criterion (`crates/courier-ftp-core/benches/transfer_fast.rs`, gates per AC8):
`transfer_schedule/plan_10k_files` (10 000 queued files in 3 groups, 16 slots, instant
completions, no I/O), `segment_plan/claim_reserve_100k`, `transfer_engine/mock_single_stream_1gib`,
`transfer_engine/mock_segmented_4x_1gib`.

Network benchmarks (`scripts/bench-transfer.sh`, manual and before each release; not a
CI gate because shared runners are noisy): T76 fixture containers with a sidecar sharing
the server's network namespace and `NET_ADMIN` that runs `tc qdisc add dev eth0 root
netem delay 50ms rate 1gbit` (server egress: 50 ms RTT, 1 Gbit/s downloads). Each case
runs 3 times; the median is recorded.

| Scenario | Target |
|---|---|
| 1 × 2 GiB SFTP download (OpenSSH), defaults | ≥ 90 % of link (≥ 112 MB/s); also record 1 segment |
| 1 × 2 GiB SFTP download, segmentation off | ≥ 80 % of link (AC6) |
| 1 × 2 GiB FTPS download (`vsftpd-explicit-tls`), defaults | ≥ 90 % of link |
| 1 × 2 GiB SFTP upload, defaults | ≥ 80 % of the download speed measured in the same setup |
| 2 000 × 4 KiB SFTP upload into a new dir, defaults | ≤ 85 s (3 RTT/file over 4 connections + 10 %) |
| 2 000 × 4 KiB FTP download (`vsftpd-plain`), defaults | ≤ 110 s (4 RTT/file over 4 connections + 10 %) |
| CPU during the 1 Gbit/s SFTP download with 4 segments | per-core usage recorded; no core > 90 % averaged |
| FileZilla 3.x with defaults, same two small-file cases (manual, once) | informational; expected ≥ 2.5× slower |

## Out of scope

- Several files in flight on one SFTP session (SFTP allows it, but `Backend` is one
  operation at a time per instance, T03); revisit after v1.
- Segmented FTP uploads; FTP `MODE Z` compression.
- End-to-end hash verification (FTP `HASH`, SFTP `check-file`) — see Open questions.
- Remote → remote (FXP).

## Open questions

1. Hash verification after segmented transfers: T10 parses FTP `HASH` support and T22
   detects SFTP `check-file`, but `Backend` has no checksum method. Add
   `Backend::checksum(path, range) -> Option<Digest>` (T03) and verify when available, or
   rely on size + unchanged-source checks only (this spec, v1)?
2. Inconsistency for T05's owner: T05 lists `sftp.max_outstanding_requests` as 1–1024 and
   `sftp.request_size` as 1024–262 144; T22 (and this task) use 1–256 and 4 096–261 120.
   T05 should adopt T22's ranges.
3. Inconsistency for T22's owner: T22's capability table does not list
   `positional_writes`; segmented SFTP uploads need it `true` (T03 `WriteMode::WriteAt`).
4. Inconsistency for T11's owner: T03's `TransferOpts.range_len` is not mentioned in T11;
   this task only relies on `finish_transfer(Abort)` for early stops, but T11 should honour
   `range_len` (return EOF after N bytes) to avoid reading past a segment.
5. Inconsistency for T06's owner: T06 calls `sync_all` when every local write stream is
   shut down. That costs 1–10 ms per file on SSDs (seconds for 10 000 small files) and
   FileZilla never fsyncs. Proposal: `sync_all` only for files ≥ 32 MiB (or never).
