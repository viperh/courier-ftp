# T41b — Fast transfers: parallelism, segmented files, pipelining

**Phase:** E Transfers · **Depends on:** T41, T11, T22, T44 · **Crates:** `courier-ftp-core` (`transfer`), both protocol crates · **Decisions:** D11

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

## Acceptance criteria

- [ ] Segmented download produces byte-identical files (hash check) for FTP and SFTP, including when segments fail and are retried.
- [ ] Work stealing measurably shortens the tail when one connection is throttled (test with toxiproxy on one connection).
- [ ] Resume of a segmented transfer after a crash continues only the missing ranges.
- [ ] SFTP pipelining reaches ≥ 80 % of link speed on a 50 ms RTT link with one connection.
- [ ] Benchmarks recorded above.
- [ ] Every new setting documented and editable in Settings (T68).

## Tests

- Unit: range splitting and work-stealing logic (pure functions).
- Mock backend with per-connection artificial latency and bandwidth to test scheduling.
- Integration (T76): hash-verified segmented transfers against vsftpd and OpenSSH.
