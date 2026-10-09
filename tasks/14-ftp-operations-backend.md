# T14 — FTP operations and Backend impl

**Phase:** B FTP · **Milestone:** M3 · **Depends on:** T03, T06, T10, T11, T12, T13, T15, T76 · **Crate(s):** `courier-ftp-proto-ftp` (`backend`, `paths`, `errors`, `testing::MemFtpServer`), `courier-ftp` (FTP arm of the `BackendFactory`) · **Decisions:** D1, D5 · **FEATURES.md:** §1 (FTP/FTPS, server type, charset, time zone), §3 (hidden files), §4 (file operations, custom command)
**Related (integrates with, not blocking):** T31, T41
**Reference:** sverb `crates/sverb-e2e/src/{lib,sshd}.rs` and `tests/openssh_*.rs` (Docker fixture + per-profile e2e pattern), `crates/sverb-conn/src/mock.rs` (in-process fake used by fast tests).

## Goal

`FtpBackend`, the implementation of the core `Backend` trait for FTP and FTPS, built on
the control connection (T10), data connections (T11), TLS (T12), listing parsers (T13)
and FTP proxies (T15). It maps every `Backend` method to an exact RFC command sequence,
learns what each server supports during the session, translates paths for VMS/MVS/DOS
servers, maps reply codes to `courier_ftp_core::Error` variants, and is wired into the
binary's `BackendFactory`. It passes the shared backend conformance suite (T06) against an
in-process FTP server in `cargo test` and against vsftpd, ProFTPD and pure-ftpd in Docker.

## Context

**Exists before this task:** T03 `Backend`, `Capabilities`, `Listing`, `WriteMode`,
`TransferOpts`, `ConnectInfo`, `BackendFactory`, `SessionHandle` (reconnect-once,
keep-alive), `MockBackend`; T06 `backend_conformance_tests!`; T10 `ControlConnection`,
`LoginScript`, `FakeServer`; T11 `FtpData`, `DataStream`, `DataConfig/DataState`; T12
`TlsSession`, `TlsTrustGate`, `TlsReuseRequired`; T13 `parse_mlsd`, `parse_list`,
`parse_mlst_line`, `ListFormat`, `TextDecoder`; T15 `LoginPlan` (proxy target + login
script); T58 `BackendFactory` implementation in the binary with the SFTP arm; T76 Docker
FTP fixture images and profiles.

**Why T15 was added to Depends on:** the FTP proxy settings only take effect if the
backend's `connect` uses T15's `LoginPlan`; T15 cannot wire itself in (it doesn't depend
on T14), so T14 must. T15 is already ordered before T14 in milestone M3, so no cycle or
milestone change results.

**Later tasks need from this one:** T41/T41b (transfers through `open_read`/`open_write`/
`finish_transfer`, connection-limit errors, resume), T42 (`set_mtime`, `stat`, resume
modes), T43 (recursive list/delete), T46 (cache patching after operations), T53/T62
(capabilities greying out actions), T57 (`tls_info`), T63 (download/upload of edited
files), T72 (connect + data probes), T76 (conformance in Docker).

## Technical specification

### Types and APIs

```rust
// courier_ftp_proto_ftp::backend ---------------------------------------------------------
/// Shared, process-wide dependencies handed out by the factory.
#[derive(Clone)]
pub struct FtpDeps {
    pub settings: Arc<Settings>,          // snapshot at creation; new connections pick up changes
    pub tls_gate: Arc<TlsTrustGate>,      // T12: trust store, "once" set, TLS 1.2 hints
    pub roots: RootSourceKind,            // Platform in production, Custom(test CA) in tests
    pub clock: Arc<dyn Fn() -> OffsetDateTime + Send + Sync>, // `now` for T13 year inference
}

pub struct FtpBackend {
    info: ConnectInfo,
    deps: FtpDeps,
    events: EventSender,
    session: SessionId,
    ctrl: Option<ControlConnection>,
    tls: Option<TlsSession>,
    data_cfg: DataConfig,
    data_state: DataState,
    learned: Learned,                     // per-session feature knowledge (below)
    caps: Capabilities,
    style: PathStyle,                     // T02: Unix | Dos | Vms | Mvs
    list_hint: Option<ListFormat>,
    cwd: Option<RemotePath>,              // None = unknown → next op sends CWD
    home: Option<RemotePath>,
    transfer: TransferSlot,               // None | Open(Arc<TransferFlag>)
    asked_password: Option<SecretString>, // AskForPassword answer, kept for reconnects
    cancel: CancellationToken,            // session token; child tokens per operation
}

#[derive(Debug, Default)]
struct Learned {
    mlsd_failed: bool, mlst_failed: bool, list_a_failed: bool,
    mfmt_failed: bool, mdtm_set_failed: bool, site_utime_failed: bool,
    size_failed: bool, mdtm_failed: bool,
    mvs_pds: HashSet<RemotePath>,         // MVS partitioned datasets seen in listings
}

impl FtpBackend {
    pub fn new(info: ConnectInfo, events: EventSender, deps: FtpDeps) -> Self;
    /// TLS details for the status bar / server-info dialog (T57) until T03 offers a trait
    /// method (see T12 open question).
    pub fn tls_info(&self) -> Option<&TlsSessionInfo>;
    pub fn server_software(&self) -> Option<String>;   // greeting first line + SYST
}

#[async_trait]
impl Backend for FtpBackend { /* all methods from T03, behaviour below */ }

// courier_ftp_proto_ftp::paths ------------------------------------------------------------
/// RemotePath (always Unix-style, T02) ↔ server syntax.
pub fn to_server(path: &RemotePath, style: PathStyle, kind: PathKind,
                 mvs_pds: &HashSet<RemotePath>) -> Result<String>;
pub fn from_server(text: &str, style: PathStyle) -> Result<RemotePath>;
pub enum PathKind { Dir, File }
/// Auto-detection from SYST and the first PWD reply.
pub fn detect_style(syst: Option<&str>, pwd: &str) -> (PathStyle, Option<ListFormat>);

// courier_ftp_proto_ftp::errors -----------------------------------------------------------
pub enum Op { Cwd, List, Stat, Mkd, Rmd, Dele, Rename, Chmod, SetMtime, Retr, Stor, Appe, Raw }
pub fn map_reply(op: Op, path: Option<&RemotePath>, reply: &Reply) -> Error;

// courier_ftp_proto_ftp::testing (feature `test-util`) -------------------------------------
/// Stateful in-process FTP server over loopback TCP backed by an in-memory tree (reuses
/// T03's `MockBackend` tree). Supports USER PASS PWD CWD CDUP SYST FEAT OPTS TYPE PASV EPSV
/// PORT EPRT LIST MLSD MLST SIZE MDTM MFMT MKD RMD DELE RNFR RNTO RETR STOR APPE REST ABOR
/// NOOP QUIT SITE CHMOD, optional AUTH TLS (rcgen cert). Knobs: disable MLSD, reject
/// SITE CHMOD, max connections, LIST format (unix/dos), latency per reply.
pub struct MemFtpServer { /* … */ }
impl MemFtpServer {
    pub async fn start(cfg: MemFtpConfig) -> (Self, SocketAddr);
    pub fn tree(&self) -> &MemTree;
}

// courier-ftp (binary) --------------------------------------------------------------------
// In the T58 factory: Protocol::Ftp | FtpsExplicit | FtpsImplicit →
//   Box::new(FtpBackend::new(info.clone(), events, self.ftp_deps.clone()))
// `ftp_deps.tls_gate` is created once per process; T30 calls `tls_gate.set_store(..)` with
// the vault-backed `CertTrustStore` after unlock.
```

### Behaviour

**1. `connect(cancel)`** (on error every partial state is dropped; `is_connected()` false).
1. `LoginPlan` from T15 (`ftp_proxy::login_plan(&info, &settings)`): target host/port
   (the FTP proxy or the server), TLS server name, `LoginScript` (proxy script or
   `LoginScript::for_credentials`). `AskForPassword`: prompt answer cached in
   `asked_password` for later reconnects of this instance.
2. `NetOpts` from settings + `ConnectInfo` proxy choice (generic proxy unless bypass, T07).
3. `RequireImplicit` → `TlsSession` + `StreamUpgrade` hook; `ControlConnection::connect`.
4. Explicit TLS per T12 mode table → login (T10 state machine) → `negotiate` (SYST, FEAT,
   OPTS) → `PBSZ 0`/`PROT P` (T12).
5. `PWD` → path style: `ConnectInfo` server type override if not `Auto`, else
   `detect_style`; `home = from_server(pwd)`; `cwd = home`.
6. Capabilities computed (table §6). Status "Connected"/"Logged in"; the `Connected` event
   is emitted by `SessionHandle` (T03).
7. Trust prompt answered after the server closed the connection, or `TlsReuseRequired` →
   one transparent reconnect (step 1 again).

**2. Method → command mapping.** Paths go through `to_server` (absolute server paths;
only `LIST`/`MLSD` run relative to a `CWD`). "Learned" flags make later calls skip
known-failing commands.

| Backend method | Command sequence | Success | Notes |
|---|---|---|---|
| `home_dir` | – (cached `PWD` result) | – | re-`PWD` only if `home` unknown |
| `list(dir)` | `CWD dir` (skipped if `cwd == dir`) → `MLSD` or `LIST [-a]` | `250`; `150/125`→`226/250` | §3 |
| `stat(path)` | `MLST path` → else `TYPE I`, `SIZE path`, `MDTM path` → else `CWD path` → else list parent | `250` / `213` / `250` | §4 |
| `mkdir(path)` | `MKD path` | `257`, `250` | `521` → `AlreadyExists`; `550` → `CWD path` succeeds → `AlreadyExists` |
| `rmdir(path)` | `RMD path` | `250`, `200` | `cwd` reset if inside `path` |
| `remove_file(path)` | `DELE path` | `250`, `200` | |
| `rename(from, to)` | `RNFR from` → `RNTO to` | `350` → `250` | existing target: server decides (most overwrite); T42 checks first |
| `chmod(path, mode)` | `SITE CHMOD <octal> path` | `200`, `250` | `500/502/504` → `caps.chmod = false`, `Unsupported` |
| `set_mtime(path, t)` | `MFMT YYYYMMDDHHMMSS path` → `MDTM YYYYMMDDHHMMSS path` → `SITE UTIME path t t t UTC` | `213` / `213`,`253`,`250` / `200`,`250` | §5 |
| `open_read(path, off, opts)` | `TYPE`, [`EPSV`/`PASV`/`PORT`…], [`REST off`], `RETR path` | `350`, `150` | T11; ASCII + `off>0` → `Unsupported` |
| `open_write(path, mode, opts)` | `Create`/`Truncate` → `STOR`; `Append` → `APPE`; `ResumeAt(n)` → `REST n`+`STOR`, or `APPE` (§5) | `150` | FTP has no exclusive create; `Create` = `STOR` |
| `finish_transfer` | read final reply, or `ABOR` + resync if the stream was dropped early | `226`, `250` | dropped early → `Error::Cancelled` after abort |
| `raw_command(cmd)` | T10 `raw_command` | any reply | returns reply lines joined with `\n` |
| `keepalive` | T10 `keepalive` | any | no-op during a transfer |
| `disconnect` | `QUIT` (T10) | `221` | never fails |

Only one operation runs at a time (`&mut self`); any call except `finish_transfer` while a
transfer is open → `Error::InvalidInput("a transfer is in progress")`.

**3. Listing strategy** (moved here from T13).
1. `CWD dir` unless `cwd == Some(dir)`. `550` → mapped error (`NotFound(dir)` /
   `PermissionDenied`). The listing's `dir` is the requested path (no extra `PWD`).
2. If `features.mlsd && settings.ftp.use_mlsd && !mlsd_failed` → `MLSD`; reply
   `500/501/502` → `mlsd_failed = true`, continue with `LIST`.
3. `LIST -a` if `settings.interface.force_show_hidden_remote && !list_a_failed`, else
   `LIST`. `LIST -a` answered with `500/501`, or `550` whose text names `-a` → plain `LIST`,
   `list_a_failed = true`.
4. `450`/`550` with text matching `/no files|not found|empty|no such file/i` **after a
   successful CWD** → empty listing (servers that refuse to list empty directories).
5. Bytes from T11 `read_listing` (TLS when `PROT P`), parsed with T13 using
   `ParseOptions { ctx: { now: clock(), tz_offset_minutes: info.timezone_offset }, decoder,
   hint: list_hint }`. MLSD is parsed with `parse_mlsd`, LIST with `parse_list`.
6. `used_fallback_encoding` → T10 session encoding switches to windows-1252 (Status line).
7. `logging.show_raw_listing` → every raw line as `LogKind::ListingRaw`; skipped lines →
   Status "Could not parse N lines of the directory listing" + `Debug(3)` per line.
8. MVS: entries of kind `Dir` from dataset listings are added to `learned.mvs_pds`.
9. Returns `Listing { dir, entries, fetched_at: Instant::now(), raw: Some(parsed.raw) }`.
   Symlinks keep `target_kind: None` (resolved when entered: a successful `CWD`).

**4. `stat(path)`** — first applicable step wins:
1. `features.mlst && !mlst_failed`: `MLST path` → `250-` reply whose fact line starts with
   one space → `parse_mlst_line`. `550` → mapped error. `500/502` → `mlst_failed`, step 2.
2. `TYPE I` (vsftpd refuses `SIZE` in ASCII mode), `SIZE path` → `213 <u64>` → kind `File`;
   then `MDTM path` → `213 YYYYMMDDHHMMSS[.sss]` (UTC, `Precision::Second`) unless
   `mdtm_failed`. `SIZE` → `550`: step 3. `500/502` → `size_failed`, step 3.
3. `CWD path` → `250` → `Entry { kind: Dir, .. }` (`cwd` updated). `550` → step 4.
4. `list(parent)` and find the exact name; not found → `Error::NotFound(path)`.

**5. Upload resume and timestamps.**
- `WriteMode::ResumeAt(0)` → `STOR`. `ResumeAt(n)`: if `rest_supported != Some(false)`:
  `REST n` + `STOR`; `REST` refused (T11 `Unsupported`) → `TYPE I`, `SIZE path`; size == n
  → `APPE`; otherwise `Error::Unsupported("server cannot resume this upload")`.
- `set_mtime(path, t)`: `t` converted to UTC, formatted `YYYYMMDDHHMMSS`.
  1. `MFMT` if `features.mfmt && !mfmt_failed` (draft-somers-ftp-mfxx) → `213`.
  2. `MDTM <time> <path>` (vsftpd and others set the time with this form) if
     `!mdtm_set_failed` → `213`, `253` or `250`.
  3. `SITE UTIME <path> <t> <t> <t> UTC` if `features.site` contains `UTIME` and
     `!site_utime_failed` → `200`/`250`.
  Each step answered with `500/501/502/504` sets its flag; `550` returns the mapped error
  without trying the next step. All flags set → `caps.set_mtime = false`,
  `Error::Unsupported("server cannot set modification times")`.

**6. Capabilities** (recomputed after connect and whenever a learned flag changes;
`Backend::capabilities()` returns the current value).

| Capability | Value |
|---|---|
| `chmod` | `true` until `SITE CHMOD` is refused with 500/502/504 |
| `set_mtime` | `features.mfmt` or `true` until all three methods failed |
| `resume_download` | `features.rest_stream` or `rest_supported != Some(false)` |
| `resume_upload` | `true` (REST+STOR or APPE fallback) |
| `append` | `true` (`APPE`) |
| `raw_commands` | `true` |
| `symlinks` | `false` (FTP cannot create symlinks) |
| `server_side_rename_across_dirs` | `true` |
| `ascii_mode` | `true` |
| `parallel_connections_allowed` | `true` (T41 opens extra instances, honouring the site limit) |

**7. Path styles.**

| Style | Detected when | `RemotePath` | Server form |
|---|---|---|---|
| `Unix` | default; SYST `UNIX…`, `Windows_NT` (IIS accepts `/`), `OS/400` (IFS) | `/home/alice/www` | same |
| `Dos` | PWD like `C:\…` or `C:/…` | `/C:/Users/alice` | `C:\Users\alice` |
| `Vms` | SYST starts `VMS` or PWD like `DEV:[DIR]` | `/DISK$USER/ALICE/WWW` (dir), `/DISK$USER/ALICE/LOGIN.COM` (file) | `DISK$USER:[ALICE.WWW]`, `DISK$USER:[ALICE]LOGIN.COM`; device root `DISK$USER:[000000]` |
| `Mvs` | SYST contains `MVS` or `z/OS`, or PWD `'HLQ.'` | `/ALICE/DATA.TXT`, `/ALICE/SOURCE` (PDS), `/ALICE/SOURCE/MEMBER1` | `'ALICE.DATA.TXT'`, `'ALICE.SOURCE'`, `'ALICE.SOURCE(MEMBER1)'` (member form when the parent is in `mvs_pds`) |

List hints: SYST `Windows_NT` → `Dos`; `VMS` → `Vms`; MVS → `MvsDataset`; `OS/400` →
`IbmI`; otherwise none. Server type override (`ConnectInfo`, T31 `ServerTypeOverride`):
`Unix`/`Dos`/`Vms`/`Mvs` force style + hint; any other value → `Unix` style with a Status
warning "Server type X is not supported, using Unix". MVS and VMS support is best effort:
connecting logs Status "Warning: limited support for <style> servers".

**8. Reconnect and transfer bookkeeping.**
- `Error::Connection`/`Timeout` from an operation → `ctrl = None`, `is_connected() = false`;
  `SessionHandle` (T03) reconnects once and re-lists `cwd`.
- `TlsReuseRequired` (T12) inside `list`/`open_read`/`open_write` → this backend
  reconnects with TLS 1.2 itself and retries the operation once.
- `open_read`/`open_write` return the T11 `DataStream` boxed as
  `Box<dyn AsyncRead/AsyncWrite + Send + Unpin>`; a shared `TransferFlag` records
  `Eof`/`ShutDown`/`Dropped` so `finish_transfer` knows whether to read `226` or abort.
- Cancellation (T41): the engine drops the stream and calls `finish_transfer()` → ABOR +
  resync (T11 §8) → `Error::Cancelled`; the session is reusable.

### Data formats and configuration

| Setting / field | Used for |
|---|---|
| `ftp.use_mlsd` (true) | MLSD vs LIST |
| `interface.force_show_hidden_remote` (false) | `LIST -a` |
| `logging.show_raw_listing` (false) | `ListingRaw` lines |
| `ftp.*` transfer settings | `DataConfig` (T11) |
| `connection.timeout_secs` (20) | all timeouts |
| `ConnectInfo`: address, credentials, encryption, charset, server type override, timezone offset, transfer mode, proxy choice | connect, parsing, path style |

Time format on the wire: `YYYYMMDDHHMMSS` UTC (RFC 3659 `time-val`), e.g. `MFMT
20240131120000 /www/index.html` → `213 Modify=20240131120000; /www/index.html`.

### Errors

`map_reply(op, path, reply)`; text patterns are case-insensitive.

| Code | Text contains | Error |
|---|---|---|
| 421 | – | `Connection(text)` |
| 425, 426, 450, 451, 452 | – | `Protocol { code, message }` (transient → T41 retries) |
| 500, 502, 504 | – | `Unsupported(<op name>)` and the learned flag for that command |
| 501, 503 | – | `Protocol { code, message }` |
| 521 | – | `AlreadyExists` (MKD) |
| 530 | – | `Connection("not logged in")` (session expired; `SessionHandle` reconnects once) |
| 532 | – | `PermissionDenied` |
| 550 | `no such file`, `not found`, `does not exist`, `doesn't exist`, `cannot find`, `can't find`, `no such directory` | `NotFound(path)` |
| 550 | `permission denied`, `access denied`, `access is denied`, `not permitted`, `forbidden`, `insufficient privilege` | `PermissionDenied` |
| 550 | `exists`, `already` (MKD only) | `AlreadyExists` |
| 550 | anything else | `Protocol { code: Some(550), message }` (permanent) |
| 551, 552, 553 | – | `Protocol { code, message }` (552: "storage quota exceeded" hint in the message) |

The message shown is `"<code> <server text>"` with control characters already replaced (T10).

### Security and logging

- Server-supplied names are never turned into local paths here (T42/T06 sanitize); hostile
  names were dropped by T13. Paths sent to the server pass T10's CR/LF/NUL check.
- Credentials (incl. the `AskForPassword` answer) stay in `SecretString`; `FtpBackend`
  implements `Debug` by hand without `info.credentials`.
- `tracing` `info`: session id + operation kind + outcome ("ftp list ok", "ftp connect
  failed: auth"); paths, host names and reply text only at `debug` (T91 §4). The session
  message log carries commands/replies (masked) as in FileZilla.
- `MemFtpServer` doubles as the base of T76's hostile-server fixture (configurable
  malicious listings and replies).

## Implementation steps

1. `errors::map_reply` with the table tests.
2. `paths` (`to_server`, `from_server`, `detect_style`) with table tests per style.
3. `MemFtpServer` (testing module) on loopback TCP, using T10/T11 fake-server parts.
4. `FtpBackend::new`, `connect` (T15 `LoginPlan`, T12 modes, PWD, style), `disconnect`,
   `is_connected`, `capabilities`, `home_dir`.
5. `list` (strategy, parse, encoding switch, raw log, MVS PDS tracking).
6. `stat`, `mkdir`, `rmdir`, `remove_file`, `rename`, `chmod`, `set_mtime`.
7. `open_read`, `open_write`, `finish_transfer` (TransferFlag, abort path), resume rules.
8. `raw_command`, `keepalive`, TLS-reuse reconnect, prompt-closed reconnect.
9. Factory arm in the binary (T58 factory), `FtpDeps` with the process-wide `TlsTrustGate`.
10. Conformance suite against `MemFtpServer` (plain + TLS) in `cargo test`.
11. Docker e2e: conformance × server profiles, error mapping, MLSD/LIST toggle.

## Acceptance criteria

- [ ] AC1 `FtpBackend` passes `backend_conformance_tests!` (T06) against `MemFtpServer`
  (plain and explicit TLS, MLSD on and off) in the normal `cargo test` run.
- [ ] AC2 Docker e2e: conformance suite passes against vsftpd (`plain`, `explicit-tls`),
  proftpd (plain and mod_tls) and pure-ftpd (plain and TLS) — T76 profiles.
- [ ] AC3 Error mapping: missing file → `NotFound`, permission denied → `PermissionDenied`,
  existing directory on `mkdir` → `AlreadyExists`, verified on the fake server table and on
  each Docker server.
- [ ] AC4 `SITE CHMOD` refused with `502` sets `capabilities().chmod = false` and later
  `chmod` calls return `Unsupported` without sending a command.
- [ ] AC5 Both listing paths exercised: with `use_mlsd = true` proftpd/pure-ftpd are listed
  via `MLSD`; with `false` via `LIST`; vsftpd always via `LIST`; entries match the prepared
  tree (names, kinds, sizes).
- [ ] AC6 `stat` works via each strategy (MLST, SIZE+MDTM, CWD, parent listing) on the fake
  server.
- [ ] AC7 `set_mtime` falls through MFMT → MDTM → SITE UTIME and learns failures; with
  `preserve_timestamps` an uploaded file's mtime on proftpd (MFMT) and vsftpd (MDTM) equals
  the local mtime (±1 s).
- [ ] AC8 Upload resume: `REST`+`STOR` where supported, `APPE` fallback when `REST` is
  refused and sizes match; byte-identical result.
- [ ] AC9 Dropping a read stream mid-transfer and calling `finish_transfer` returns
  `Error::Cancelled` and the next `list` succeeds.
- [ ] AC10 Path translation tables for Dos, VMS and MVS round-trip (`from_server(to_server(p)) == p`).
- [ ] AC11 The binary's factory creates `FtpBackend` for `ftp://`, `ftpes://` and `ftps://`
  quickconnect URLs (unit test on the factory).
- [ ] AC12 `max-1-connection` profile: a second concurrent connect fails with
  `Error::Protocol { code: Some(421 | 530) }` (what T41 back-off detects).
- [ ] AC13 CI gates (T00) pass, incl. `e2e` and `layering`.

## Tests

### Unit tests
- `map_reply_table` — every row of the error table, incl. text variants. AC3.
- `paths_dos_roundtrip`, `paths_vms_dir_and_file_forms`, `paths_vms_device_root`,
  `paths_mvs_dataset_pds_member`, `detect_style_from_syst_and_pwd`. AC10.
- `capabilities_from_features_table`. AC4.
- `factory_creates_ftp_backend_for_ftp_schemes`. AC11.

### Property / fuzz tests
- `prop_paths_roundtrip_unix_dos` — random `RemotePath`s (no `\`, `:` only in the drive
  component for Dos) round-trip. AC10.
- `prop_map_reply_never_panics` — random code 100–599 + random text.

### Snapshot tests
Not applicable (no UI). Listing results are snapshotted in T13.

### Integration tests (`FakeServer` scripts for exact sequences; `MemFtpServer` for state)
- `list_cwd_then_mlsd`, `list_skips_redundant_cwd`, `list_mlsd_500_falls_back_to_list`,
  `list_a_refused_retries_without_and_remembers`, `list_550_no_files_after_cwd_is_empty`,
  `list_invalid_utf8_switches_encoding`, `list_raw_lines_logged_when_enabled`. AC5.
- `stat_via_mlst`, `stat_via_size_and_mdtm_sets_type_i`, `stat_dir_via_cwd`,
  `stat_via_parent_listing`, `stat_missing_is_not_found`. AC6.
- `mkdir_257`, `mkdir_521_already_exists`, `mkdir_550_then_cwd_ok_is_already_exists`,
  `rmdir_resets_cwd_inside`, `rename_rnfr_rnto`, `rename_rnfr_550_not_found`. AC3.
- `chmod_502_disables_capability`. AC4.
- `set_mtime_mfmt`, `set_mtime_falls_back_to_mdtm`, `set_mtime_site_utime_only_if_advertised`,
  `set_mtime_all_refused_is_unsupported`. AC7.
- `open_read_with_offset_sends_rest`, `open_read_ascii_offset_unsupported`,
  `open_write_resume_rest_stor`, `open_write_resume_appe_fallback`,
  `open_write_resume_size_mismatch_unsupported`. AC8.
- `dropped_stream_finish_aborts_and_session_reusable`,
  `operation_during_open_transfer_rejected`. AC9.
- `raw_command_returns_all_lines`.
- `tls_reuse_required_reconnects_with_tls12_and_retries` (T12 fake TLS server).
- `ask_password_prompted_once_per_instance_across_reconnect`.
- `conformance_mem_ftp_plain`, `conformance_mem_ftp_explicit_tls`,
  `conformance_mem_ftp_without_mlsd` — `backend_conformance_tests!`. AC1.

### End-to-end tests (`courier-ftp-e2e`, `#[ignore]` + `COURIER_E2E=1`, T76)
- `ftp_conformance_vsftpd_plain`, `ftp_conformance_vsftpd_explicit_tls`,
  `ftp_conformance_proftpd_plain`, `ftp_conformance_proftpd_tls`,
  `ftp_conformance_pureftpd_plain`, `ftp_conformance_pureftpd_tls`. AC2.
- `ftp_error_mapping_on_each_server` — missing file, read-only directory, existing dir. AC3.
- `ftp_listing_matches_server_tree_mlsd_and_list` (proftpd, pure-ftpd with `use_mlsd`
  on/off; vsftpd LIST). AC5.
- `ftp_preserve_timestamps_proftpd_mfmt`, `ftp_preserve_timestamps_vsftpd_mdtm`. AC7.
- `ftp_max_one_connection_second_connect_refused`. AC12.

## Out of scope

- Connection pooling, parallel and segmented transfers (T41, T41b), file-exists decisions
  (T42), recursive operations (T43), listing cache (T46).
- Creating symlinks, `SITE` commands other than `CHMOD`/`UTIME`, FXP, `HASH` verification
  (T41b uses `features.hash` later).
- Full MVS/VMS feature parity (best effort only, warned).

## Open questions

- T31 `ServerTypeOverride` lists "Auto/Unix/Dos/Vms/Mvs/…". FileZilla also has VxWorks,
  z/VM, HP NonStop, Cygwin and "DOS with forward slashes". This task maps any value beyond
  Unix/Dos/Vms/Mvs to Unix with a warning; T31 should either restrict the enum to those
  five or say which extra types it keeps.
- T03's `ConnectInfo` field names (server type override, timezone offset, proxy choice)
  are used here by meaning; adjust to T03's final names.
