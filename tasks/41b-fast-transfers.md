# T41b — Fast transfers: parallelism, segmented files, pipelining

**Phase:** E Transfers · **Depends on:** T11, T22, T40, T41, T42, T43, T44, T76 · **Crates:** `courier-ftp-core` (`transfer`), both protocol crates · **Decisions:** D11
**Related (integrates with, not blocking):** T12, T31, T68

## Goal

Transfers must be fast: saturate the link for both many small files and a few
huge ones. FileZilla only parallelises across files (default 2 at once). We go
further, with these techniques in this order of impact:

1. Many files transferred at the same time over several connections.
2. One large file split into byte ranges, each fetched on its own connection
   (segmented / multi-connection transfer).
3. Pipelined SFTP requests, so one connection isn't limited by round-trip time.
4. No per-file overhead: connections reused, directory listings done in parallel,
   uploads and downloads streamed with large buffers.

All of it runs on the tokio multi-threaded runtime. CPU-heavy work (TLS and SSH
encryption, ASCII conversion) is spread across worker threads automatically
because each connection is its own task. No `spawn_blocking` is needed except
for local file I/O on platforms where tokio's fs uses a blocking pool anyway.

## Scope

### 1. Parallel files (extends T41)

- Defaults change: `transfers.max_concurrent` = **4** (FileZilla: 2), max 16.
- Per-server connection limit still applies (T31), and the "too many connections"
  back-off from T41 protects servers that refuse more.
- **Small-file batching**: when many files are under 64 KiB, keep connections warm
  and start the next file on a connection the moment the previous one finishes
  (no idle gap waiting for the scheduler tick). For FTP, avoid redundant `CWD`/`TYPE`
  commands between files in the same dir.
- **Connection warm-up**: when the queue starts, open all allowed connections
  in parallel instead of one after another.

### 2. Segmented (multi-connection) single-file transfers

- Setting `transfers.segmented`: `enabled` (default true), `min_file_size_mib`
  (default 32), `max_segments` (default 4, max 16), `min_segment_size_mib` (default 8).
- **Download**: when a file is ≥ the threshold, the server supports ranged reads
  (FTP `REST STREAM`, SFTP always) and the transfer type is binary:
  1. Preallocate the local file to full size (sparse file is fine).
  2. Split into N ranges. Each segment opens its own session from the pool and does
     `open_read(offset)`; it stops after its range length (FTP: read the range then
     `ABOR` the rest, as servers have no "end offset").
  3. Each segment writes with positional writes (`pwrite`/`seek_write`) at its offset.
  4. **Work stealing**: when a segment finishes early, split the largest remaining
     range in half and give the second half to the idle connection, so slow
     segments don't hold up the end of the file.
- **Upload**: SFTP supports writes at offsets, so segmented upload works the same
  way (open the remote file once with `CREATE`, then each segment opens with
  `WRITE` and writes at its offset). FTP upload **cannot** be segmented reliably
  (`REST`+`STOR` at arbitrary offsets is not widely supported), so it stays one
  stream. Document this.
- **Resume**: segment progress (completed ranges) is saved in the queue item
  (T40) so a restart resumes each unfinished range, not from the smallest offset.
- **Integrity**: after a segmented transfer, compare the final size; optionally
  compute a hash if the server offers one (FTP `HASH`/`XSHA256` / SFTP
  `check-file` extension) — use it when available, skip otherwise.
- Segments count against the same connection limits as whole-file transfers. The
  scheduler balances: when many files are queued, prefer starting new files over
  splitting one file.

### 3. SFTP pipelining (extends T22)

- Keep up to `sftp.max_outstanding_requests` (default 64) read or write requests of
  `sftp.request_size` (default 32 KiB; 255 KiB with OpenSSH servers that advertise
  `limits@openssh.com` — read the advertised max and use it) in flight per file.
- If `russh-sftp`'s file API is request-at-a-time, implement our own pipelined
  reader and writer on its raw request API.
- SSH channel window: set a large initial window (e.g. 16 MiB) and max packet size
  in `russh::client::Config`, so the window doesn't throttle a fast link.
- Pick fast ciphers by default where the server allows: `aes128-gcm@openssh.com`
  or `chacha20-poly1305@openssh.com` (AES-GCM is faster on CPUs with AES-NI).

### 4. FTP data path (extends T11)

- Data socket buffers: set `SO_RCVBUF`/`SO_SNDBUF` to 4 MiB (let the OS cap it).
- Read and write in 256 KiB chunks; double-buffer (read next chunk while writing
  the previous) using two tasks joined by a bounded channel.
- TLS: rustls with TLS 1.3 and AES-GCM; reuse the TLS session (already required
  by T12) so each data connection skips the full handshake.

### 5. Local disk side

- Buffered writes with 1 MiB `BufWriter`; `fsync` only at the end of a file.
- Preallocation on by default for segmented downloads (needed for positional writes).
- Read ahead on uploads (same double-buffer pattern).

### 6. Recursive transfers (extends T43)

- List directories in parallel (up to `max_concurrent` listing sessions) while
  transfers of already-found files have started. The walker feeds the queue
  continuously instead of listing the whole tree first.

### 7. Speed limits (T44) still apply to the sum of all connections and segments.

## Benchmarks (must be measured and recorded in this file)

Use a `scripts/bench-transfer.sh` that runs against the Docker servers from T76 with
`tc netem` adding 50 ms latency and a 1 Gbit/s limit:

| Scenario | Target |
|---|---|
| 1 × 2 GiB file, SFTP download | ≥ 90 % of link speed with segmentation; record speed-up over 1 segment |
| 1 × 2 GiB file, FTPS download | ≥ 90 % of link speed with segmentation |
| 10 000 × 4 KiB files, SFTP upload | ≥ 3× faster than FileZilla with default settings (measure FileZilla manually once) |
| 10 000 × 4 KiB files, FTP download | same |
| CPU use during 1 Gbit/s SFTP | report per-core usage; no single core pegged at 100 % when ≥ 4 connections |

### Results (2026-10-11)

Measured with `scripts/bench-transfer.sh` (no Docker locally: an unprivileged
network namespace whose loopback has MTU 1500, `tc netem` 25 ms each way =
50 ms RTT, 1 Gbit/s, TCP buffers up to 32 MiB; OpenSSH 10 `sshd`, pyftpdlib
for FTP/FTPS). Laptop, 12 threads; other agents were compiling in parallel
for most runs, so treat the numbers as ±30 %. netem costs CPU per packet,
so the emulated link never delivers 1 Gbit/s: the raw TCP baseline is what
"link speed" means below.

| Measurement | Result |
|---|---|
| Raw TCP baseline, 1 / 4 connections | 63–86 / 69–77 MiB/s |
| SFTP download 512 MiB (tmpfs), 1 segment, 3 runs | 58, 67, 56 MiB/s |
| SFTP download 512 MiB (tmpfs), 4 segments, 3 runs | 55, 68, 59 MiB/s (at the link's limit already with 1) |
| SFTP upload 512 MiB (tmpfs), 1 → 4 segments, 3 runs | 34 → 58, 35 → 53, 34 → 46 MiB/s (**1.4–1.7×**) |
| SFTP 2 GiB on disk, loaded machine: down 1 / 4, up 1 / 4 | 29.8 / 24.0, 30.4 / 18.4 MiB/s (disk-bound, CPU idle) |
| FTPS download 2 GiB, 1 → 4 segments (pyftpdlib) | 25.5 → 40.2 MiB/s (**1.6×**) |
| OpenSSH `sftp` CLI, same link, 1 connection | 27–29 MiB/s (256 MiB), 10 MiB/s for 2 GiB on the loaded machine |
| 2 000 × 4 KiB SFTP upload, 4 (default) vs 2 connections | 13 vs 7 files/s (`sftp` CLI: 5 files/s) |
| 2 000 × 4 KiB FTP download, 4 (default) vs 2 connections | 18 vs 9 files/s (lftp `mirror --parallel=1/2/4`: 3 / 12 / 25 files/s) |
| Client CPU during transfers | ≤ 18 % of one core in total, no thread above 5 % |

- **Segmentation** pays off where one connection can't fill the link: SFTP
  uploads (OpenSSH grants only a 2 MiB channel window, so one upload
  connection tops out near 40 MiB/s at 50 ms) and FTPS. SFTP downloads with
  our 16 MiB window and 64 × 255 KiB requests in flight already reach the
  emulated link's TCP rate with one connection (≈ 80–90 % of the raw TCP
  baseline, ~2× the `sftp` CLI).
- **Small files**: default settings are ~2× FileZilla's default concurrency
  (FileZilla itself wasn't measured: no GUI here; its 2 connections stand
  in for it). Each file still costs ~6 round trips per connection (SFTP:
  `STAT`, `OPEN`, `WRITE`, `CLOSE`, `SETSTAT`…); reaching 3× needs fewer
  round trips per file, not more connections.
- Found while measuring: on loopback's default 64 KiB MTU, Linux's receive
  buffer autotuning sometimes never grows on one of several connections
  (`rcv_space` stuck at 64 KiB, `rwnd_limited` 90 %), so that segment crawls
  at ~1.5 MiB/s; the benchmark therefore sets MTU 1500. Before this, a
  segment's SFTP reader also requested past the end of its range (up to
  16 MiB wasted per range); `TransferOpts::read_limit` fixes that.

**Not met / deferred:** ≥ 90 % of 1 Gbit/s and the 10 000-file runs (2 000
files were run; the rate is the result) need a real 1 Gbit/s link — T76's
Docker setup in CI or a manual run; the toxiproxy throttling test is T76's
(the mock-backend test `work_stealing_shortens_the_tail_of_a_throttled_connection`
covers the logic); ≥ 80 % of link speed with one SFTP connection holds for
downloads against the emulated link but not for uploads (server window).
FTP data socket buffers are left to the OS (setting `SO_RCVBUF` disables
Linux autotuning, which grows past 4 MiB on its own); no double-buffered
FTP data path and no `HASH`/`check-file` verification yet (size check only).

## Acceptance criteria

- [x] Segmented download produces byte-identical files (hash check) for FTP and SFTP, including when segments fail and are retried.
- [ ] Work stealing measurably shortens the tail when one connection is throttled (test with toxiproxy on one connection).
- [x] Resume of a segmented transfer after a crash continues only the missing ranges.
- [ ] SFTP pipelining reaches ≥ 80 % of link speed on a 50 ms RTT link with one connection.
- [x] Benchmarks recorded above.
- [x] Every new setting documented and editable in Settings (T68).

## Tests

- Unit: range splitting and work-stealing logic (pure functions).
- Mock backend with per-connection artificial latency and bandwidth to test scheduling.
- Integration (T76): hash-verified segmented transfers against vsftpd and OpenSSH.

**Status:** done in `courier_ftp_core::transfer` (`segmented`, `segments`,
engine grants and warm-up), the SFTP backend (pipelining settings, cipher
order, `read_limit`) and the FTP backend (`write_at: false`). Tests: unit
tests in `transfer/segments.rs`, mock-backend tests in
`transfer/tests/segmented.rs` (failures, throttled connection, resume,
connection limits, speed limit across segments, warm-up), in-process FTP
and SFTP segmented tests, and Docker e2e tests in
`crates/courier-ftp-e2e/tests/segmented.rs` (vsftpd and OpenSSH, byte
compared; written, run in CI only). Deferred: see "Not met / deferred"
above (toxiproxy test and full-speed runs to T76).
