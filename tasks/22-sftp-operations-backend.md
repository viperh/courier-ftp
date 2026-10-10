# T22 — SFTP operations and Backend impl

**Phase:** C SFTP · **Milestone:** M2 · **Depends on:** T03, T06, T13, T20, T21, T76 · **Crate(s):** `courier-ftp-proto-sftp` (`backend`, `io`, `convert`, `testing` modules) · **Decisions:** D2, D5, D11 · **FEATURES.md:** §4 (file operations), §1 (SFTP)
**Related (integrates with, not blocking):** T41, T41b

## Goal

`SftpBackend` implements the core `Backend` trait (T03) over SFTP protocol version 3
using `russh-sftp` on the authenticated connection from T20, so the panes, transfer
engine, search and comparison work on SFTP servers exactly as on the local filesystem.
Reads and writes are pipelined (many requests in flight) so a single connection is not
limited by round-trip time (D11, T41b §3).

## Context

- **Before:** T03 defines `Backend`, `Capabilities`, `Listing`, `WriteMode`,
  `TransferOpts` (incl. `range_len`), `ConnectInfo`, `BackendContext`, `BackendFactory`,
  `SessionHandle`, `SessionSecurityInfo`, `MockBackend` and the reusable conformance suite
  (`courier_ftp_core::backend::conformance`, `backend_conformance_tests!`, feature
  `test-util`); T06 is the local reference backend. T13 provides the Unix `ls -l`
  parser in `courier_ftp_core::listing::unix` (used for SFTP `longname`). T20 provides
  `SshConnection::connect`/`open_subsystem`, `SshConnectParams::from_connect_info`
  and the in-process russh test server; T21 provides `TrustVerifier`. T76 provides the
  `sshd` Docker fixture (profiles `password`, `key`, `chroot-sftp`, `windows-like`).
- **After:** T58 wires `SftpBackend` into the binary's `BackendFactory`. T41 opens one
  `SftpBackend` per transfer slot; T41b uses positional `open_read`/`open_write` for
  segmented transfers and tunes `sftp.*` settings; T42 relies on the `WriteMode`
  semantics and `AlreadyExists` mapping below; T71 shows `Listing.raw` (SFTP longnames).

## Technical specification

### Types and APIs

```rust
// courier_ftp_proto_sftp::backend
pub struct SftpBackend { /* Arc<ConnectInfo>, BackendContext, SftpTuning,
                             Arc<dyn HostKeyVerifier>, Option<Arc<dyn AgentConnector>>,
                             Option<Live>, Arc<Mutex<Option<Error>>> deferred_error */ }

impl SftpBackend {
    /// No I/O; `connect` does the work. `info` is shared with the other sessions to the
    /// same server (T03); `ctx` carries the SessionId, EventSender and SharedSettings
    /// (tuning read from `ctx.settings` at construction).
    pub fn new(
        info: Arc<ConnectInfo>,
        ctx: BackendContext,
        verifier: Arc<dyn HostKeyVerifier>,
        agent: Option<Arc<dyn AgentConnector>>,
    ) -> Self;
    /// Negotiated SSH algorithms and SFTP extensions (also summarised in security_info()).
    pub fn server_info(&self) -> Option<SftpServerInfo>;
}

#[async_trait]
impl Backend for SftpBackend {
    /* every method, see Behaviour. `security_info()` → SessionSecurityInfo { encrypted: true,
       summary: "SSH", peer_addr, server_software: SshSessionInfo.server_version,
       tls: None, host_key: Some(HostKeyInfo { key_type, bits, fingerprint_sha256 }),
       details: [("Key exchange", kex), ("Cipher", cipher), ("MAC", mac),
                 ("Compression", compression), ("Authentication", auth_method),
                 ("SFTP version", "3"), ("Extensions", names)] } */
}

/// Values taken from Settings at construction.
#[derive(Debug, Clone, Copy)]
pub struct SftpTuning {
    pub request_timeout: Duration,      // connection.timeout_secs (20 s)
    pub max_outstanding_requests: u32,  // sftp.max_outstanding_requests (64; 1..=256)
    pub request_size: u32,              // sftp.request_size (32 KiB; 4 KiB..=255 KiB)
    pub max_inflight_bytes: u32,        // constant 8 MiB per open file
}

/// What the server advertised in SSH_FXP_VERSION.
#[derive(Debug, Clone, Default)]
pub struct ServerExtensions {
    pub posix_rename: bool,     // "posix-rename@openssh.com" = "1"
    pub statvfs: bool,          // "statvfs@openssh.com" = "2"
    pub fsync: bool,            // "fsync@openssh.com" = "1"
    pub hardlink: bool,         // "hardlink@openssh.com" = "1"
    pub limits: Option<ServerLimits>, // "limits@openssh.com" = "1", then queried
    pub check_file: bool,       // "check-file-name" / "check-file-handle" (T41b integrity)
    pub other: Vec<String>,     // names only, for the info dialog
}
#[derive(Debug, Clone, Copy)]
pub struct ServerLimits { pub max_packet_len: u64, pub max_read_len: u64, pub max_write_len: u64, pub max_open_handles: u64 }

#[derive(Debug, Clone)]
pub struct SftpServerInfo { pub ssh: SshSessionInfo /* T20 */, pub sftp_version: u32, pub extensions: ServerExtensions, pub read_chunk: u32, pub write_chunk: u32, pub outstanding: u32 }

// courier_ftp_proto_sftp::io — pipelined streams returned by open_read / open_write
pub struct SftpReader { /* Arc<RawSftpSession>, handle, offsets, VecDeque<pending READ>, buffer */ }
impl AsyncRead for SftpReader {}
pub struct SftpWriter { /* Arc<RawSftpSession>, handle, offset, FuturesOrdered<pending WRITE> */ }
impl AsyncWrite for SftpWriter {}

// courier_ftp_proto_sftp::convert — pure, unit-tested
/// One SSH_FXP_NAME element → Entry. `None` for ".", "..", and names that are empty,
/// contain '/' or NUL, or are longer than 4096 bytes.
pub fn entry_from_name(filename: &str, longname: &str, attrs: &FileAttributes) -> Option<Entry>;
pub fn kind_from_mode(mode: Option<u32>, longname: &str) -> EntryKind;
pub fn map_status(err: russh_sftp::client::error::Error, op: SftpOp, path: &RemotePath) -> Error;
pub enum SftpOp { Connect, List, Stat, Mkdir, Rmdir, Remove, Rename, SetStat, Open, Read, Write, Close, RealPath, ReadLink }

// courier_ftp_proto_sftp::testing (feature "test-util") — in-process servers
/// russh server + russh-sftp server handler over a temp directory, with fault injection.
pub struct SftpTestServer { /* addr, root: TempDir, knobs */ }
pub struct SftpTestKnobs {
    pub per_request_latency: Duration,     // default 0
    pub max_read_len: Option<u32>,         // short reads above this size
    pub advertise_posix_rename: bool,      // default true
    pub advertise_limits: Option<ServerLimits>,
    pub fail_next: Option<(SftpOp, StatusCode)>,
    pub record_requests: bool,             // counts, max in-flight, sizes
}
/// SFTP server handler over a duplex stream (no SSH) for paused-time pipelining tests.
pub fn duplex_sftp_pair(knobs: SftpTestKnobs, root: &Path) -> (RawSftpSession, ServerStats);
```

Decision: the backend uses `russh_sftp::client::RawSftpSession` directly (behind an
`Arc`) instead of the high-level `SftpSession`/`File`, because it needs the
`SSH_FXP_VERSION` extension list (posix-rename, check-file), the `limits@openssh.com`
values, positional reads bounded by a byte budget, and the raw status codes for error
mapping. `RawSftpSession` methods take `&self`, so many requests can be in flight on one
channel; that is the pipelining mechanism.

### Behaviour

**Connect** (`connect(cancel)`):

1. `SshConnectParams::from_connect_info(&info, &settings, can_save)` (T20: host, port
   default 22, `address.user`, `LogonType` incl. `KeyFile { key, passphrase }`,
   `try_agent_first`, `NetOpts` incl. bypass-proxy) with `can_save` for prompts =
   `info.site_id.is_some()` ∧ `vault.store_passwords` (T69 also disables saving while
   the vault is locked).
2. `SshConnection::connect` (T20) with the `TrustVerifier` (T21).
3. `open_subsystem("sftp")`; `RawSftpSession::new_with_config(stream, Config {
   request_timeout_secs: connection.timeout_secs, max_packet_len: 270_336 /* 264 KiB */,
   ..Default })`; `init()` → `SSH_FXP_VERSION`. Version ≠ 3 → we still speak v3 (servers
   must accept a lower client version); log `Status: SFTP protocol version <n>`.
4. Parse extensions into `ServerExtensions`; if `limits@openssh.com` → `limits()` and
   `set_limits`. Compute I/O sizes:
   - `read_chunk = limits.map_or(request_size, |l| min(l.max_read_len, 261_120))`;
     `write_chunk` likewise with `max_write_len`; values of 0 mean "not limited" and fall
     back to `request_size`; all clamped to 4 096..=261 120 (255 KiB, so a DATA packet
     stays below 256 KiB).
   - `outstanding = clamp(min(max_outstanding_requests, 8 MiB / chunk), 1, 256)` per
     direction (64 × 32 KiB = 2 MiB; with OpenSSH limits 32 × 255 KiB ≈ 8 MiB).
   - Log `Debug(3): SFTP extensions: …; read 255 KiB × 32, write 255 KiB × 32`.
5. `realpath(".")` → `home` (`RemotePath::parse`; a non-absolute or unparsable answer →
   `/` with a `Status` warning).
6. Charset: SFTP v3 names are bytes; `russh-sftp` decodes them as UTF-8 (lossy).
   `Charset::Custom` on an SFTP site → `Status` warning once: "Custom character sets are
   not supported for SFTP; using UTF-8".
7. Log `Status: Connected to <host>` (session log). The `Connected` event is emitted by
   `SessionHandle` (T03), not by the backend.

SFTP has no working directory: the caller picks the initial directory (site
`default_remote_dir` if set, else `home_dir()`; T58/T59).

**Operations** (one at a time per backend, T03 rule; each SFTP request is bounded by
`request_timeout`; `list` and `connect` also race their `CancellationToken`):

| Backend method | SFTP v3 requests | Rules |
|---|---|---|
| `home_dir` | none (cached from connect) | |
| `list(dir)` | `OPENDIR dir` → `READDIR` until `STATUS EOF` → `CLOSE` | see Listing below |
| `stat(path)` | `LSTAT path`; if symlink: `STAT path` (target kind) + `READLINK path` | never follows a final symlink: a symlink returns `EntryKind::Symlink { target, target_kind }` with the link's own attributes (T03); `NotFound(path)` if `NO_SUCH_FILE` |
| `mkdir(path)` | `MKDIR path` (empty attrs: server applies umask) | `FAILURE` and `LSTAT path` is a dir → `AlreadyExists` |
| `rmdir(path)` | `RMDIR path` | non-empty dir → `Protocol { code: Some(4), message: <server text> }` |
| `remove_file(path)` | `REMOVE path` | |
| `rename(from, to, replace)` | `replace = false`: `LSTAT to` (exists → `AlreadyExists`, nothing renamed) then `RENAME`. `replace = true`: `posix-rename@openssh.com` (`EXTENDED`) if advertised, else `RENAME` | posix-rename replaces an existing target atomically. Plain `RENAME` onto an existing target fails → `LSTAT to` exists → `AlreadyExists` (overwrite not supported by this server; caller decides to delete first, T42/T62). T14 uses the same contract |
| `chmod(path, mode)` | `SETSTAT path {permissions: mode & 0o7777}` | only the permissions flag set |
| `set_mtime(path, t)` | `SETSTAT path {atime: t, mtime: t}` | `t` outside `0..=u32::MAX` seconds → `InvalidInput("SFTP v3 cannot store dates before 1970 or after 2106")` |
| `open_read(path, offset, opts)` | `OPEN path READ` → `FSTAT handle` (size) → pipelined `READ`s from `offset` | returns `SftpReader`; with `opts.range_len = Some(n)` no READ is issued at or beyond `offset + n` and the reader returns EOF after `n` bytes |
| `open_write(path, mode, opts)` | `OPEN path <flags>` (+ `FSTAT` for Append/ResumeAt) → pipelined `WRITE`s | returns `SftpWriter`; flags below |
| `finish_transfer` | none | returns (and clears) the deferred error of the last reader/writer `CLOSE`; `Ok(())` otherwise |
| `raw_command` | — | `Err(Unsupported("Custom commands are not available over SFTP"))` |
| `keepalive` | `REALPATH "."` | also keeps SFTP-level idle timers on some servers busy |
| `disconnect` | channel EOF (`close_session`) then T20 `disconnect` | bounded by 2 s total |
| `is_connected` | — | `live.is_some() && ssh.is_open()` |

`open_write` flags (SSH_FXF_*):

| `WriteMode` | Flags | Start offset | Notes |
|---|---|---|---|
| `Create` | `WRITE \| CREAT \| EXCL` | 0 | target exists → `FAILURE` → `LSTAT` → `AlreadyExists` |
| `Truncate` | `WRITE \| CREAT \| TRUNC` | 0 | |
| `Append` | `WRITE \| CREAT` | `FSTAT` size | explicit offsets instead of `APPEND` (servers differ in APPEND handling) |
| `ResumeAt(n)` | `WRITE` | `n` | `FSTAT` size < n → `InvalidInput("Remote file is shorter than the resume offset")`; size > n → `SETSTAT size = n` first (T03: truncate to n, then write) |
| `WriteAt(n)` | `WRITE \| CREAT` | `n` | no truncation, existing bytes outside the written range kept (segmented uploads, T41b) |

`TransferOpts.transfer_type = Ascii` is ignored (`Capabilities.ascii_mode = false`; SFTP v3
has no text mode); logged once per session at `Debug(2)`.

**Listing** (`list(dir)`):

1. `OPENDIR`; loop `READDIR` (each reply holds a server-chosen batch, ~100 on OpenSSH)
   until `STATUS EOF`, checking `cancel` between batches; `CLOSE` the handle in every
   exit path (on cancel: spawned, best effort, 2 s bound).
2. Each element → `convert::entry_from_name`:
   - skip `.`/`..`, and (hostile server, T91) names that are empty, contain `/` or NUL, or
     exceed 4 096 bytes — each skip logged at `debug` with a count summary
     `Status: Skipped N entries with invalid names` (no names).
   - `kind`: `S_IFMT` of `attrs.permissions` (`0o040000` Dir, `0o100000` File,
     `0o120000` Symlink, other types Other); without permissions: first char of
     `longname` (`d`, `l`, `-`), else File.
   - `size`: `attrs.size` for files and symlinks, `None` for dirs.
   - `modified`: `attrs.mtime` (UTC seconds) → `Timestamp { precision: Second }`.
   - `permissions`: `Permissions::from_mode(perm & 0o7777)`.
   - `owner`/`group`: from `longname` via `courier_ftp_core::listing::unix` (T13) when
     it parses; else `attrs.uid`/`gid` as decimal strings; else `None`.
   - `hidden`: name starts with `.`. (No per-entry raw text; longnames go to
     `Listing.raw` only.)
3. **Symlinks**: for the first 1 000 symlinks of a listing, issue `STAT` (follows) and
   `READLINK` with at most 16 requests in flight; fill
   `EntryKind::Symlink { target: readlink text, target_kind: kind of STAT result }`;
   a failing `STAT` (broken link) leaves `target_kind: None`. Beyond 1 000 symlinks,
   `target_kind` stays `None` and the UI resolves on demand with `stat`.
4. Caps: more than 1 000 000 entries → abort with `Protocol { code: None, message:
   "Directory has more than 1 000 000 entries" }`. `Listing.raw` = longnames joined by
   `\n` while ≤ 16 MiB, else `None`.
5. Result `Listing { dir, entries, fetched_at: Instant::now(), raw }` (entries in server
   order; sorting is the UI's job).

**Pipelined reader** (`SftpReader`, AsyncRead):

- Keeps up to `outstanding` `READ(handle, offset, read_chunk)` requests in flight at
  consecutive offsets, as `'static` futures over `Arc<RawSftpSession>` in a `VecDeque`;
  never requests at offsets ≥ `fstat_size + read_chunk` when the size is known (avoids
  wasted requests past EOF).
- Delivers data strictly in offset order (front of the queue).
- `DATA` shorter than requested (server cap or file end): deliver it, drop all other
  pending requests, set `read_chunk = len` if `len ≥ 4 096`, and continue from the new
  offset. `STATUS EOF` or empty `DATA` → end of stream.
- Error → `io::Error` carrying the mapped core error (`map_status`), also stored as the
  deferred error. Drop/EOF → `CLOSE` the handle (spawned on drop, best effort).

**Pipelined writer** (`SftpWriter`, AsyncWrite):

- `poll_write(buf)`: if a previous ack failed → return that error. If `outstanding`
  requests or `max_inflight_bytes` are in flight → poll acks in order until one
  completes. Then send `WRITE(handle, offset, buf[..min(len, write_chunk)])`, advance
  `offset`, return the count.
- Acks (`STATUS OK`) are consumed in request order; the first error is stored and
  returned by the next `poll_write`/`poll_flush`/`poll_shutdown`.
- `poll_flush`: wait for all acks. `poll_shutdown`: flush, then `CLOSE`; a `CLOSE`
  failure (e.g. disk full on close) is returned and stored as the deferred error.
- Dropped without shutdown (cancelled transfer): pending acks are abandoned and `CLOSE`
  is spawned (best effort); nothing is reported.

**Segmented transfers** (T41b): each segment uses its own `SftpBackend` (own SSH
connection). Download segments call `open_read(path, segment_start, TransferOpts {
range_len: Some(segment_len), .. })`; the reader never requests past the segment end.
Upload segments open the remote file with `WriteAt(segment_start)`
(`Capabilities.positional_writes = true`).

**Capabilities** (constant for SFTP):

| Field | Value |
|---|---|
| `chmod`, `set_mtime`, `resume_download`, `resume_upload`, `append`, `symlinks` | true |
| `server_side_rename_across_dirs`, `parallel_connections_allowed`, `positional_writes` | true |
| `raw_commands`, `ascii_mode`, `case_insensitive_names` | false |
| `path_style` | `Unix` |

**Connection loss**: any operation when `!ssh.is_open()` returns
`Error::Connection(<T20 end cause>)` without sending a request; `SessionHandle` (T03)
reconnects once. One SSH connection per `SftpBackend`; the engine (T41) creates more
backends for parallel transfers (FileZilla model; no channel multiplexing in v1).

### Data formats and configuration

Settings read (defaults from T05/T41b; T22 consumes them, T41b owns tuning/docs):

| Key | Type | Default | Range | Use |
|---|---|---|---|---|
| `connection.timeout_secs` | u32 | 20 | 1–600 | per-request timeout, SSH (T20) |
| `sftp.max_outstanding_requests` | u16 | 64 | 1–256 | pipelining depth per open file |
| `sftp.request_size` | u32 (bytes) | 32 768 | 4 096–261 120 | chunk size when the server has no `limits@openssh.com` |

Constants: in-flight budget 8 MiB per open file; symlink resolution 1 000 per listing,
16 in flight; listing cap 1 000 000 entries; raw listing cap 16 MiB; name length cap
4 096 bytes; `max_packet_len` given to russh-sftp 270 336 bytes.

SFTP v3 wire subset used (draft-ietf-secsh-filexfer-02): `INIT/VERSION`, `OPEN`,
`CLOSE`, `READ`, `WRITE`, `LSTAT`, `FSTAT`, `SETSTAT`, `OPENDIR`, `READDIR`, `REMOVE`,
`MKDIR`, `RMDIR`, `REALPATH`, `STAT`, `RENAME`, `READLINK`, `EXTENDED`
(`posix-rename@openssh.com`, `limits@openssh.com`). Paths are sent as UTF-8 strings of
`RemotePath` (always absolute, `/`-separated; OpenSSH for Windows paths look like
`/C:/Users/x` and pass through unchanged).

Benchmark script `scripts/bench-sftp.sh` (manual, not CI): starts the T76 `sshd`
`password` profile, creates a 1 GiB random file, downloads and uploads it 3 times each
with `courier-ftp-e2e`'s `Headless` and with OpenSSH `sftp -B 261120 -R 64`, prints the
median MiB/s of each and the ratio.

### Errors

`map_status(err, op, path)`:

| russh-sftp error / status | `courier_ftp_core::Error` | Notes |
|---|---|---|
| `Status(NO_SUCH_FILE = 2)` | `NotFound(path)` | |
| `Status(PERMISSION_DENIED = 3)` | `PermissionDenied` | |
| `Status(FAILURE = 4)` on `Mkdir`/`Open(EXCL)`/`Rename` when `LSTAT` of the target succeeds | `AlreadyExists` | one extra `LSTAT` request |
| `Status(FAILURE = 4)` otherwise | `Protocol { code: Some(4), message: <sanitized server message or "Failure"> }` | permanent |
| `Status(BAD_MESSAGE = 5)` | `Protocol { code: Some(5), .. }` | |
| `Status(NO_CONNECTION = 6 / CONNECTION_LOST = 7)` | `Connection(msg)` | transient |
| `Status(OP_UNSUPPORTED = 8)` | `Unsupported("The server does not support this operation")` | |
| `Status(EOF = 1)` outside READ/READDIR | `Protocol { code: Some(1), .. }` | |
| `Error::Timeout` | `Timeout` | transient |
| `Error::IO(_)`, `UnexpectedBehavior("session closed")` | `Connection(msg)` | transient |
| `Error::Limited(_)`, `UnexpectedPacket`, other `UnexpectedBehavior` | `Protocol { code: None, message }` | a bug or hostile server |
| connect errors from T20 (`Auth`, `HostKey`, `Proxy`, `ConnectionLimit` for SSH disconnect reason 12, …) | passed through unchanged | |
| local `set_mtime` range | `InvalidInput` | |

Server messages are passed through `sanitize_server_text` (T20) and capped at 512 chars.
The user sees `Error: <op> <path>: <message>` in the session log (e.g. `Error: Could not
create directory /var/www/new: Permission denied`).

### Security and logging

- Hostile servers (T91): invalid names (`/`, NUL, `.`/`..`, oversize) never reach
  `Entry`; names with control characters are kept verbatim in `Entry.name` and are
  sanitized at render time (T53/T55). Listing size, raw text, symlink resolution and
  in-flight memory are capped (above). Sizes are `u64`; a server-reported size is never
  used to preallocate memory.
- No secrets pass through this module except via T20's prompt flow.
- `tracing` at info: `SessionId`, operation name and result kind only; paths at `debug`.
  The session log (user-facing) shows paths, as FileZilla does.

## Implementation steps

1. Add `russh-sftp = "3.0.1"` (workspace dep) and the `convert` module: `entry_from_name`,
   `kind_from_mode`, `map_status` with table tests.
2. `testing::duplex_sftp_pair` and `SftpTestServer` (russh-sftp server handler over a
   temp dir, knobs, request stats).
3. `SftpBackend::connect`/`disconnect`/`home_dir`/`keepalive`, extension and limits
   parsing, I/O size computation, `server_info`, `security_info`.
4. Metadata operations: `stat`, `mkdir`, `rmdir`, `remove_file`, `rename`, `chmod`,
   `set_mtime` with the `AlreadyExists` probes.
5. `list` with symlink resolution, caps, cancellation.
6. `SftpReader` (pipelined, short-read handling) + paused-time tests over the duplex pair.
7. `SftpWriter` (pipelined, ordered acks, deferred close error) + tests;
   `open_read`/`open_write`/`finish_transfer`.
8. Run `backend_conformance_tests!` (T03) against `SftpTestServer`; e2e conformance
   against the Docker profiles; `scripts/bench-sftp.sh`; record numbers here.

## Acceptance criteria

- [ ] AC1 `backend_conformance_tests!` passes against `SftpTestServer` in the normal `cargo test` run and, in the e2e job, against the `password`, `chroot-sftp` and `windows-like` sshd profiles.
- [x] AC2 A symlink to a directory lists as `Symlink { target: Some(..), target_kind: Some(Dir) }`, and `list(symlink path)` returns the target's entries; a broken symlink has `target_kind: None`.
- [x] AC3 Resumed download (`open_read` at offset) and resumed upload (`ResumeAt(n)`) produce byte-identical files (SHA-256), including at an offset above 4 GiB on a sparse test file.
- [x] AC4 Every row of the error mapping table is produced by the test server's fault injection and maps as specified.
- [x] AC5 `rename(.., replace = true)` sends `posix-rename@openssh.com` when advertised and replaces an existing target; without it, renaming onto an existing file returns `AlreadyExists` and leaves both files unchanged; `rename(.., replace = false)` onto an existing file returns `AlreadyExists` without sending `RENAME`.
- [x] AC6 `mkdir` of an existing directory and `open_write(Create)` of an existing file return `AlreadyExists`.
- [x] AC7 Pipelining (paused time, duplex pair, 50 ms per-request latency, 64 MiB file): the server sees 64 READ requests in flight and the download takes ≤ 1.7 s of virtual time with defaults, versus ≥ 100 s with `max_outstanding_requests = 1`; the same for WRITE.
- [x] AC8 With short reads (server caps reads at 10 000 bytes) downloads are byte-identical and no byte range is requested twice after the chunk adapts.
- [ ] AC9 With `limits@openssh.com` advertising `max_read_len = 16 384`, no READ or WRITE larger than 16 384 bytes is sent; with OpenSSH (e2e) the read chunk is 261 120 bytes.
- [x] AC10 In-flight data per open file never exceeds 8 MiB (server-side counter over a 256 MiB transfer).
- [x] AC11 Entries named `a/b`, with NUL, `.`/`..`, or 5 000 bytes long are not returned; a name with an ESC sequence is returned verbatim; the skip count is logged.
- [x] AC12 Listing a directory of 100 000 files returns 100 000 entries with owner/group names parsed from longnames; a fake server streaming more than 1 000 000 names gets a `Protocol` error and the handle is closed.
- [x] AC13 Cancelling `list` returns `Error::Cancelled` within 100 ms and a `CLOSE` for the directory handle is sent.
- [x] AC14 Killing the server mid-download yields `Error::Connection` from the reader and `is_connected() == false`; `SessionHandle` (T03) reconnects once on the next call.
- [x] AC15 `raw_command` returns `Unsupported`; `capabilities()` equals the table (incl. `positional_writes = true`); `set_mtime` with a 1960 date returns `InvalidInput`; `chmod` sends only the permissions attribute; `security_info()` reports `encrypted`, "SSH", the host key and negotiated algorithms.
- [ ] AC16 Throughput: `scripts/bench-sftp.sh` on localhost shows ≥ 80 % of OpenSSH `sftp` CLI throughput for a 1 GiB download and upload; numbers recorded in the table below.
- [ ] AC17 T00 gates pass (`fmt`, `clippy -D warnings`, `docs`, `test`, `deny`); no `unwrap`/`expect` outside tests.
- [x] AC18 `stat` of a symlink returns `Symlink` (not the target's kind) with `target_kind` filled; `open_read` with `range_len = Some(n)` returns exactly `n` bytes and the server sees no READ at or past `offset + n`; `WriteAt(n)` keeps bytes before `n` and after the written range.

Benchmark results (fill in when done):

| Date | Machine | Download MiB/s (ours / OpenSSH) | Upload MiB/s (ours / OpenSSH) |
|---|---|---|---|
| — | — | — | — |

## Tests

### Unit tests
- `convert::tests::kind_from_mode_all_types_and_longname_fallback`.
- `convert::tests::entry_from_name_fields` (size, mtime precision Second, permissions, hidden) — AC12.
- `convert::tests::owner_group_from_longname_else_uid_gid` — AC12.
- `convert::tests::invalid_names_skipped` — AC11.
- `convert::tests::map_status_table` — AC4.
- `backend::tests::io_sizes_from_limits_and_settings` (clamping, 0 = unlimited, 8 MiB budget) — AC9, AC10.
- `backend::tests::write_mode_flags` — AC6, open_write table.
- `backend::tests::set_mtime_range_check` and `chmod_sets_only_permissions` — AC15.
- `backend::tests::capabilities_constant`, `security_info_fields` — AC15.

### Property / fuzz tests
- `io::props::reader_reassembles_any_short_read_pattern` (proptest: random per-request caps and EOF positions on the duplex server; output equals the file) — AC8.
- `io::props::writer_any_write_sizes_byte_identical` (random `poll_write` sizes) — AC3.
- `convert::props::entry_from_name_never_panics` (arbitrary filename/longname/attrs).

### Snapshot tests
Not applicable (no UI).

### Integration tests
`crates/courier-ftp-proto-sftp/tests/`:
- `conformance_against_test_server` (`backend_conformance_tests!` from T03) — AC1.
- `stat_symlink_not_followed`, `range_len_stops_requests_at_segment_end`, `write_at_keeps_other_bytes` — AC18.
- `symlink_to_dir_enterable_and_broken_link` — AC2.
- `resume_download_and_upload_sha256`, `resume_above_4gib_sparse` — AC3.
- `fault_injection_error_mapping` — AC4.
- `rename_posix_and_plain` — AC5.
- `already_exists_probes` — AC6.
- `pipelining_depth_and_virtual_time_read`, `pipelining_depth_and_virtual_time_write` (paused time, duplex pair) — AC7.
- `limits_extension_respected` — AC9.
- `inflight_budget_respected` — AC10.
- `hostile_names_filtered` — AC11.
- `large_directory_and_entry_cap` — AC12.
- `cancel_list_closes_handle` — AC13.
- `server_killed_mid_download` — AC14.

### End-to-end tests
`crates/courier-ftp-e2e/tests/sftp_backend.rs`, `#[ignore]`, `require_docker!` (T76):
- `e2e_conformance_password_profile`, `e2e_conformance_chroot_sftp`, `e2e_conformance_windows_like` — AC1.
- `e2e_openssh_limits_chunk_is_255k` — AC9.
- `e2e_resume_after_toxiproxy_cut` (once T76 M4 toxiproxy exists) — AC3.
Manual: `scripts/bench-sftp.sh` — AC16.

## Out of scope

- SFTP versions 4–6 features (text mode, ACLs, `check-file` hashing — T41b decides whether to use `check-file` when present).
- Custom commands over `exec` channels; remote-to-remote copy; `copy-data` extension.
- Non-UTF-8 file names (see Open questions).
- Segment scheduling, work stealing and speed limits (T41/T41b/T44).

## Open questions

1. **Non-UTF-8 names:** `russh-sftp` 3.0.1 decodes names with `String::from_utf8_lossy`,
   so names in legacy encodings show `U+FFFD` and cannot be opened, and a site's custom
   charset cannot be applied to SFTP. Accept this for v1 (FileZilla also assumes UTF-8 for
   SFTP), or budget a fork/upstream patch exposing raw name bytes?
Resolved: T03 `TransferOpts.range_len` (read limit), T03 `rename(from, to, replace)`
semantics (shared with T14), and the top-level `sftp.*` settings section with this task's
ranges (T05).

## Implementation notes

- **Layout.** `convert.rs` (+ `convert/{tests,props}.rs`), `io.rs` (`SftpReader`,
  `SftpWriter`, `IoParams`, `TransferState`, `write_flags`; + `io/props.rs`),
  `backend.rs` (+ `backend/tests.rs`), `testing/{mod,server}.rs` (feature `test-util`,
  which now also enables `tempfile` and core's `test-util`). Integration tests:
  `tests/conformance_against_test_server.rs`, `tests/operations.rs` (AC2–AC6, AC11–AC15,
  AC18), `tests/pipelining.rs` (AC7–AC10). E2e: `crates/courier-ftp-e2e/tests/
  {backend_conformance,sftp_backend,proxies}.rs`; `scripts/bench-sftp.sh`.
- **Public API for dependants (T41/T41b/T58/T71):** `SftpBackend::{new, server_info,
  tuning}` (+ `attach` under `test-util`), `backend::{SftpTuning, ServerLimits,
  ServerExtensions, SftpServerInfo, IoSizes, io_sizes, SFTP_CAPABILITIES, mtime_attrs,
  chmod_attrs, MAX_INFLIGHT_BYTES, MAX_CHUNK, …}`, `io::{SftpReader, SftpWriter, IoParams,
  TransferState, write_flags}`, `convert::{entry_from_name, entry_from_attrs,
  kind_from_mode, map_status, SftpOp, io_error, core_error, from_io, clone_error}`,
  `testing::{SftpTestServer, SftpTestKnobs, ServerStats, duplex_sftp_pair,
  duplex_session, duplex_backend, test_context_with}`. T20 additions:
  `SshConnection::{host_key, peer_addr}`, `ssh::testing::{SubsystemHook,
  TestServer::{spawn, abort_connections}}`, `TestServerConfig::sftp`.
- **Own test server, not russh-sftp's.** russh-sftp's server handler answers one
  request at a time, which hides pipelining. `testing::server` decodes/encodes with
  russh-sftp's `protocol` types but handles each request on arrival and sends the reply
  `per_request_latency` later (a link-latency model), so in-flight depth and bytes are
  measurable. Extra knobs beyond the spec: `read_caps` (per-READ caps for the property
  test), `bogus_reply_next` (wrong reply type → `UnexpectedPacket`), `inject_names`,
  `synthetic_dirs`, `readdir_batch`, `owner`/`group`. Paths are chroot-like (`/` = the
  temp dir, `/scratch` exists). On non-Unix hosts permissions are kept in a map and
  symlinks are unsupported (the symlink tests are `cfg(unix)`).
- **Pipelining mechanism.** Request futures own an `Arc<RawSftpSession>` and sit in a
  `FuturesOrdered`; a pushed future is polled once by the next `poll_next`, which sends
  the request. Results come back in push order. The reader's depth is
  `min(outstanding, budget / chunk)` and it also tracks bytes in flight.
- **Deviations.**
  - A broken symlink is `target_kind: Some(SymlinkTarget::Broken)` (core's model and the
    local backend, T06, use `Broken`; `None` means "not resolved"), not `None` as AC2
    says. A `STAT` failing for another reason (permission) leaves `None`.
  - The chunk is clamped to 4 KiB..=255 KiB **and** never above a non-zero server limit
    (a server limit below 4 KiB would otherwise make every READ fail with russh-sftp's
    `Limited`).
  - A short read at the known end of the file (FSTAT size) does not adapt the chunk.
  - `mkdir` returns `AlreadyExists` when the probing `LSTAT` finds anything (file or
    dir) at the path — the T03 contract "AlreadyExists if present".
  - `rename` failures other than `AlreadyExists` name the source (`NotFound(from)`).
  - `PermissionDenied` carries the path; the session log reads
    `Error: <op text> <path>: Permission denied`. `stat` → `NotFound` and `Cancelled`
    are not logged as errors.
  - Reader/writer errors are `io::Error`s whose inner error is the core error
    (`convert::core_error` recovers it; kinds map `Connection` → `ConnectionReset`,
    `Timeout` → `TimedOut`, so `Error::from(io)` stays connection-lost). The same error
    is the deferred error returned by `finish_transfer(Complete)`.
  - `finish_transfer` while the stream is still alive → `Internal`. A dropped stream is
    aborted implicitly by the next operation (T03 rule 4).
  - Connection loss without SSH (`attach`, duplex tests) is detected from the first
    connection-level error (`broken` flag); with SSH also from `SshConnection::is_open`.
  - `TestServer` (T20) now keeps clones of the accepted sockets: russh runs each server
    session on its own task, so aborting the accept-loop's task did not close the
    connection. `abort_connections()`/drop shut the sockets down.
  - AC7 measures the data phase (open stream → EOF / all WRITEs acknowledged); with
    `OPEN`+`FSTAT` / `CLOSE` the whole transfer adds 2 × 50 ms resp. 50 ms of virtual
    time. Measured: read ≈ 1.65 s, write ≈ 1.6 s; with one request in flight ≥ 102 s.
  - AC1 e2e: the per-profile conformance runs are `crates/courier-ftp-e2e/tests/
    backend_conformance.rs` (T76 AC13: `backend_conformance_tests!(ignored, …)` with
    backends from `E2eBackendFactory`; modules `sftp_password`, `sftp_key`,
    `sftp_chroot_sftp`, `sftp_windows_like`) instead of `e2e_conformance_*` functions in
    `sftp_backend.rs`, so CI runs the suite once per profile. Each profile's container
    runs on its own thread/runtime (the env fn is synchronous) and is shared by the
    running cases; without Docker every case reports itself skipped.
  - `E2eBackendFactory` builds `SftpBackend` with a process-wide `TrustVerifier` over a
    `MemoryHostKeyStore` (no OpenSSH known_hosts), so `Headless` answers host-key
    prompts. `proxies.rs` has the SFTP part (`sftp_via_socks5`,
    `sftp_via_http_connect_auth`: a 7-case conformance subset); the FTP part is T14's.
  - `scripts/bench-sftp.sh` runs the ignored e2e test `bench_sftp_vs_openssh`
    (`COURIER_BENCH=1`): the OpenSSH `sftp -B 261120 -R 64` side runs inside the sshd
    container over loopback via `sshpass` (no OpenSSH client is assumed on the host).
- **Not done here:** Docker is not available locally, so the e2e tests
  (`backend_conformance.rs` SFTP modules, `sftp_backend.rs`, `proxies.rs`) compile and
  skip but were never run: AC1 (e2e part), AC9 (OpenSSH 255 KiB part) and AC16 (benchmark,
  table above still empty) stay unticked until CI's e2e job / a manual run passes.
  Open question 1 (non-UTF-8 names) kept at the default: accepted for v1.

