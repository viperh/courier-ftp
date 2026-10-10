# T71 — Log to file, debug levels, raw listing

**Phase:** G App-level · **Milestone:** M9 · **Depends on:** T04, T05, T55 · **Crate(s):** `courier-ftp` (`logging/`, `panic.rs`, log pane actions), `courier-ftp-core` (`session_log` module) · **Decisions:** D3 · **FEATURES.md:** §9 (debug level, log to file with size limit and rotation, raw directory listing)
**Related (integrates with, not blocking):** T91
**Reference:** sverb `crates/sverb-core/src/logging/{mod,ring}.rs`, `crates/sverb-core/tests/logging.rs`, `crates/sverb/src/{logging,panic}.rs`, `docs/logging.md`

## Goal

Two separate logs with clear rules. The **application log** (`tracing`, for developers)
goes to daily-rotated files with the sverb logging policy, and crashes leave a private
crash report. The **session log** (FileZilla's message log, for users diagnosing
connections) can be written to a size-rotated file. Users can change the debug level
0–4 at runtime, see the raw directory listing, and copy or save the message log.

## Context

- The template `logging.rs` truncates `<data dir>/courier-ftp.log` on every start and
  honours `RUST_LOG`; `errors.rs` uses human-panic/better-panic and `process::exit(1)`.
- T04 defines `LogMessage { time, session: SessionId, kind: LogKind, text }`,
  `LogKind { Status, Command, Response, Error, ListingRaw, Debug(u8) }` (there is no
  warning kind: warnings are `Status` lines whose text starts with `"Warning: "`),
  `mask_command`, and drops messages above the configured level at the source.
- T05 defines `logging.level` (`DebugLevel`, 0–4, default 2), `logging.log_to_file`
  (false), `logging.log_file` (absolute path, `null` = `<data dir>/session.log`),
  `logging.log_file_max_mib` (1–1024, 10), `logging.log_file_keep` (1–50, 3),
  `logging.show_raw_listing` (false), `logging.pane_max_lines` (T55).
- T55 shows the per-tab message log (ring of `logging.pane_max_lines` lines, default
  5 000, prefixes `Status:`, `Command:`, `Response:`, `Error:`, `Trace:`, `Listing:`) and
  owns `crate::ui::clipboard` (OSC 52 + platform tools, 100 KiB cap, no `arboard`).
- T03/T13/T22 fill `Listing.raw` (FTP LIST/MLSD text, SFTP longnames; there is no
  per-entry raw field).
- T01 provides `AppPaths { config_dir, data_dir, cache_dir }`; T70 passes `--debug`,
  `--debug-level`, `--log-file` in `RunOptions` and adds `AppPaths::log_dir()` /
  `crash_dir()`.
- T91 §4–§5 depends on this task for the logging policy, crash reports and the
  canary scan of log files.

## Technical specification

### Types and APIs

**Application log** — `crates/courier-ftp/src/logging/{mod.rs,ring.rs}` (port of sverb
`sverb_core::logging`; it stays in the binary because only the binary installs a global
subscriber):

```rust
/// The only environment variable that controls the application log filter. `RUST_LOG` is ignored.
pub const LOG_ENV: &str = "COURIER_FTP_LOG_LEVEL";
pub const LOG_FILE_PREFIX: &str = "courier-ftp";   // courier-ftp.YYYY-MM-DD.log
pub const LOG_FILE_SUFFIX: &str = "log";
pub const MAX_LOG_FILES: usize = 7;                 // days kept
pub const CRASH_RING_CAPACITY: usize = 200;         // info+ lines, always on
pub const DEBUG_RING_CAPACITY: usize = 5_000;       // only with --debug
pub const DEBUG_WARNING: &str = "Debug logging is on: log files may contain hostnames and usernames.";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LogOptions { pub debug: bool }

#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    #[error("cannot create the log directory {path}: {source}")] LogDir { path: String, source: std::io::Error },
    #[error("cannot open the log file: {0}")] Appender(#[from] tracing_appender::rolling::InitError),
    #[error("logging is already initialized")] AlreadyInitialized,
}

/// Flushes the file writer when dropped. Held in `main` until exit.
#[derive(Debug)]
pub struct LoggingGuard { /* options, crash ring, debug ring */ }

pub fn init(paths: &AppPaths, opts: LogOptions) -> Result<LoggingGuard, LoggingError>;
pub fn init_with_filter(paths: &AppPaths, opts: LogOptions, filter: Option<&str>) -> Result<LoggingGuard, LoggingError>;
/// Flush and stop the writer; idempotent; waits ≤ 100 ms for the lock (panic-hook safe).
pub fn shutdown();
pub fn crash_ring() -> Option<LogRing>;
pub fn debug_ring() -> Option<LogRing>;

/// Bounded in-memory ring of formatted lines (`ring.rs`, from sverb).
#[derive(Debug, Clone)] pub struct LogRing { /* Arc<Mutex<VecDeque<LogLine>>> */ }
#[derive(Debug, Clone)] pub struct LogLine { pub time: OffsetDateTime, pub level: tracing::Level, pub target: String, pub message: String }
pub struct RingLayer { /* tracing_subscriber::Layer writing into a LogRing */ }
```

**Crash reports** — `crates/courier-ftp/src/panic.rs` (replaces `errors.rs`, port of sverb `panic.rs`):

```rust
pub(crate) fn install() -> color_eyre::Result<()>;      // first line of main
pub(crate) fn set_crash_dir(paths: &AppPaths);           // after paths resolve
pub(crate) const RING_LINES: usize = 200;
pub(crate) const MAX_CRASH_REPORTS: usize = 20;
fn write_crash_report(dir: &Path, now: SystemTime, pid: u32, text: &str) -> io::Result<PathBuf>;
```

**Session log file** — `courier_ftp_core::session_log` (core: no UI deps, testable):

```rust
/// What the writer needs from `Settings.logging` (+ T70 overrides).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLogConfig {
    pub enabled: bool,
    pub path: PathBuf,
    pub max_bytes: u64,  // log_file_max_mib * 1 MiB, minimum 1 MiB
    pub keep: u8,        // rotated files kept, 1..=50 (T05 logging.log_file_keep)
}

/// Handle to the background writer task. Cheap to clone.
#[derive(Debug, Clone)]
pub struct SessionLogWriter { /* mpsc::Sender<Cmd>, Arc<AtomicU64> dropped */ }

impl SessionLogWriter {
    /// Spawns the writer task on the current tokio runtime.
    /// `offset` is the local UTC offset read in `main`; `clock` is injectable for tests.
    pub fn spawn(config: SessionLogConfig, offset: UtcOffset, clock: Arc<dyn Clock>) -> (Self, JoinHandle<()>);
    /// Non-blocking. Drops (and counts) the message when the channel is full.
    pub fn log(&self, msg: &LogMessage);
    /// Apply new settings (open/close/rotate as needed). Non-blocking.
    pub fn reconfigure(&self, config: SessionLogConfig);
    /// Flush and close; waits at most 2 s.
    pub async fn shutdown(self);
    pub fn dropped(&self) -> u64;
}

/// Time source for the writer's own lines (header, dropped count). `SystemClock` in production.
pub trait Clock: Send + Sync + std::fmt::Debug { fn now(&self) -> OffsetDateTime; }

/// Formats one line exactly as it is written to the file and to "Save log as…".
pub fn format_line(msg: &LogMessage, offset: UtcOffset) -> String;
/// Replaces C0/C1 control characters (except TAB) with caret/escape notation (`ESC` → `^[`).
pub fn escape_controls(s: &str) -> Cow<'_, str>;
```

**Debug level at runtime** — T04's source filter reads a shared level:

```rust
// courier_ftp_core::events (T04), added/confirmed here:
#[derive(Debug, Clone)] pub struct LogLevelHandle(Arc<AtomicU8>);
impl LogLevelHandle { pub fn get(&self) -> u8; pub fn set(&self, level: u8); }  // clamps to 0..=4
impl EventSender { pub fn log_level(&self) -> &LogLevelHandle; }   // shared by all clones
```

**UI actions** (added to `Action`, T51 keymap):

| Action | Default key | Where |
|---|---|---|
| `ShowRawListing` | `Ctrl-x v` | file list (remote or local pane) |
| `CopyLog` | `Y` | message log pane |
| `SaveLogAs` | `Ctrl-x w` | message log pane |
| `ShowAppLog` | `Ctrl-x D` | global, only when started with `--debug` |
| `SetDebugLevel(u8)` | — (Settings → Logging, T68) | |

### Behaviour

**Application log**
- File: `<data dir>/logs/courier-ftp.YYYY-MM-DD.log` (`AppPaths::log_dir()`, dir created
  `0700` on Unix), one file per UTC day via `tracing_appender::rolling::Builder`
  (`Rotation::DAILY`, `max_log_files(7)`), appended to, never truncated. The template's
  single `courier-ftp.log` is no longer written (a leftover file is left alone).
- Written through `tracing_appender::non_blocking` (thread `courier-ftp-log`, default
  buffer 128 000 lines, lossy) so the UI never waits on disk.
- Format: RFC 3339 UTC timestamp, level, target, `file:line`, message and fields, no
  ANSI; `log_internal_errors(false)` so a failing writer never prints to stderr.
- Filter: `COURIER_FTP_LOG_LEVEL` only (`EnvFilter` directives). Default `info`, `debug`
  with `--debug`. Directives that name only targets keep the default for everything else
  (sverb rule). Invalid value → default used, warning logged as the first line.
- Nothing is ever written to stdout/stderr by `tracing`.
- Crash ring: last 200 `info`+ lines, always on. Debug ring: last 5 000 lines passing the
  file filter, only with `--debug`; `ShowAppLog` opens it in a read-only scrollable dialog
  (T52) — the TUI equivalent of sverb's log pane. With `--debug`, `DEBUG_WARNING` is shown
  once as a status-bar message (T57) after startup (T70 prints it to stderr too).

**Crash reports** (`panic.rs`, sverb behaviour):
1. Restore the terminal (leave alternate screen, disable raw mode, show cursor; never
   panics, no tokio).
2. Build color-eyre's panic report with the section `This is a bug. Please report it at
   https://github.com/viperh/courier-ftp/issues`.
3. Write `<data dir>/crash/crash-<UTC yyyymmddThhmmssZ>-<pid>.txt` (dir `0700`, file
   `0600`, `create_new`; a numeric suffix on name collision, give up after 100) containing:
   version + git describe, OS/arch, `TERM`, `TERM_PROGRAM`, thread, location, message,
   report, backtrace, and the last 200 crash-ring lines (filtered again to `info`+).
   Afterwards delete the oldest reports so that at most 20 remain.
4. stderr: `courier-ftp crashed: <message>` and `A crash report was written to <path>`
   (full color-eyre report only in debug builds or when `COURIER_FTP_LOG_LEVEL` is
   `debug`/`trace`).
5. `logging::shutdown()` to flush the file, then return so the panic unwinds; a panicked
   main task ends the process with exit code **101** (T70 lists it).
6. A panic inside the hook prints one line and aborts. `human-panic` and `better-panic`
   are removed from the dependencies.

**Debug levels** (FileZilla semantics; `logging.level`, default 2):

| Level | Name | What appears in the message log |
|---|---|---|
| any | — | `Status`, `Command`, `Response`, `Error` are always shown |
| ≥ 1 | warning | `Debug(1)`: recoverable problems (`Skipping unparsable listing line 12`, `Server sent invalid MDTM reply`) |
| ≥ 2 | info | `Debug(2)`: decisions (`Using EPSV`, `MLSD not supported, using LIST`, `Falling back to active mode`) |
| ≥ 3 | verbose | `Debug(3)`: TLS handshake (version, cipher suite, ALPN, session reuse, certificate chain subjects and SHA-256), SSH negotiation (kex, host key algorithm, ciphers, MACs, compression), data connection addresses; raw listing lines as `ListingRaw` |
| 4 | debug | `Debug(4)`: data connection open/close with byte counts, keep-alive commands, reconnect attempts, transfer state transitions, SFTP request ids |

- `ListingRaw` lines are emitted when `logging.show_raw_listing` is true **or** the level
  is ≥ 3; each raw line becomes one `Listing:` message (max 10 000 lines per listing; then
  one `Listing: … N more lines not shown` message).
- The level changes at runtime: Settings (T68) calls `LogLevelHandle::set`, which every
  backend and the transfer engine see on their next message (no reconnect). `--debug-level`
  sets the initial value without saving it (T70).
- Producers must check the level **before** formatting expensive debug text
  (`if events.log_level().get() >= 3 { … }`).

**Session log file** (`logging.log_to_file`):
- The app's main loop forwards every `CoreEvent::Log(LogMessage)` it receives (all tabs
  and transfer workers) to `SessionLogWriter::log`. Messages already filtered at the
  source are never written; the file shows exactly what the message log could show.
- Line format (same as T55 plus date and session). Times are local time using the UTC
  offset read once in `main` before the tokio runtime starts (`time` cannot read the
  local offset safely from a multi-threaded process on Unix); it is passed to the writer:
  ```
  2026-10-09 12:00:00.123 [s3] Status:   Connecting to 203.0.113.5:21...
  2026-10-09 12:00:00.456 [s3] Command:  PASS ****
  2026-10-09 12:00:01.002 [s3] Response: 230 Login successful.
  ```
  `[s<N>]` is the `SessionId` display (T04). Prefix column padded to 10 chars. Text passes
  through `escape_controls` and is cut at 8 KiB per line (` … [truncated]`). Multi-line
  texts are written as one line per text line, each with the same prefix.
- When a file is opened, the first line is
  `--- courier-ftp <version> session log opened <RFC 3339 local time> ---`.
- Channel: `tokio::sync::mpsc` with capacity **4 096** messages. `try_send` failure
  increments `dropped`; when the writer next drains, it writes
  `<time> [--] Status:   <N> log messages were dropped because the disk was too slow`
  and resets the counter.
- Writer: `BufWriter` (64 KiB), flushed every 1 s when dirty, on rotation and on shutdown.
- Rotation by size: before a write that would make the file exceed `max_bytes`, close it,
  delete `<path>.<keep>`, rename `<path>.<i>` → `<path>.<i+1>` for `i = keep-1 … 1`,
  rename `<path>` → `<path>.1`, open a fresh `<path>`. (`keep` is at least 1, T05.) A
  single line larger than `max_bytes` is written to a fresh file
  anyway. On startup an existing file is appended to (rotated first if already over the limit).
- File created with mode `0600` (Unix); parent directory must exist (default parent is
  the data dir, which exists).
- Errors (open, write, rename): the writer logs one `Error:` line to the UI log of the
  active tab (`Cannot write the session log file: <io error>`), sets a status message,
  and disables itself until the next `reconfigure`. It never retries in a loop.
- `reconfigure` with `enabled = false` flushes and closes; with a new path, closes the old
  file and opens the new one; changed limits apply on the next write.
- On quit the app awaits `shutdown()` (≤ 2 s) after the UI is torn down.

**Raw directory listing**
- `ShowRawListing` on the focused pane opens a scrollable read-only dialog (T52):
  title `Raw listing: <dir> (<source>, <N> lines)`, where source is `MLSD`, `LIST`,
  `SFTP readdir` or `local`. Content: `Listing.raw` if present (for SFTP it holds the
  `longname` lines, T22); else the message `The server did not send a raw listing for
  this directory.` (local pane: always this message).
- Backends keep `Listing.raw` up to **16 MiB**; beyond that it is cut and the dialog shows
  `… listing truncated at 16 MiB`. The listing cache (T46) keeps `raw` with the listing.
- Dialog keys: `j/k`, `PageUp/PageDown`, `g/G`, `/` search, `y` copy all (T55
  `ui::clipboard`), `w` save as (same flow as `SaveLogAs`), `Esc` close. Lines are
  `escape_controls`-ed and wrap off with horizontal scroll (`h/l`).

**Copy and save the message log** (T55 pane):
- `CopyLog` copies the current tab's visible log buffer (respecting the pane's quick level
  filter) in `format_line` format via T55's `crate::ui::clipboard` (OSC 52 + platform
  tools, no `arboard`). The clipboard cap is **100 KiB** (102 400 bytes) of text: when
  the buffer is larger, only the newest whole lines that fit are copied (selected here,
  before calling the clipboard, so no line is cut) and the status bar says
  `Copied the last <N> lines (clipboard limit)`; otherwise `Copied <N> lines`.
- `SaveLogAs` opens a `PathInput` (T52) prefilled with
  `~/courier-ftp-log-<YYYYMMDD-HHMMSS>.txt`; writes atomically (temp file + rename),
  mode `0600`, asks before overwriting an existing file
  (`ConfirmOpts::danger("Overwrite")`, T52); status message on success,
  error dialog on failure.

### Data formats and configuration

| Key | Type | Default | Notes |
|---|---|---|---|
| `logging.level` | `DebugLevel` (integer 0–4) | 2 | runtime-changeable; `--debug-level` overrides per run |
| `logging.log_to_file` | bool | false | `--log-file` turns it on per run |
| `logging.log_file` | `Option<PathBuf>` | `null` = `<data dir>/session.log` | must be absolute (T05 validation; a relative value → warning + default) |
| `logging.log_file_max_mib` | u32 | 10 | 1–1024; out of range → warning + default (T05 validation) |
| `logging.log_file_keep` | u8 | 3 | 1–50 |
| `logging.show_raw_listing` | bool | false | |
| `logging.pane_max_lines` | u32 | 5000 | 500–100 000; message log pane size (T55; also bounds `CopyLog`) |
| env `COURIER_FTP_LOG_LEVEL` | EnvFilter | `info` | application log only |

Files: `<data>/logs/courier-ftp.YYYY-MM-DD.log` (7 kept), `<data>/crash/crash-*.txt`
(20 kept), session log at `logging.log_file` plus `.1`…`.<keep>`.

### Errors

- `LoggingError` at startup: `main` prints `warning: logging disabled: <error>` to stderr and
  continues **without** a file layer (the app must still start, e.g. on a read-only data
  dir). The crash ring still works.
- Session log I/O errors: `courier_ftp_core::Error::Io` inside the writer, surfaced as
  described above; never fatal.
- `SaveLogAs` errors: error dialog with the I/O error text (`Error::Io`).
- Crash report write failure: stderr `The crash report could not be written: <error>`.

### Security and logging

- Policy (from sverb `docs/logging.md`, copied into `docs/logging.md` and
  `CONTRIBUTING.md`): at `info`, `warn`, `error` never log hostnames, IP addresses, ports
  tied to a host, usernames, remote or local paths, file names, site names, commands or
  server replies — use `SessionId`, `TransferId`, `ItemId`. `debug`/`trace` may contain
  hostnames and usernames. **Secrets are never logged at any level.**
- The **session log is a user feature** and contains hostnames, usernames, paths and
  masked commands by design (T91 §4). Its Settings help text says so; it is written
  `0600`. Commands are masked by T04's `mask_command` before they become `LogMessage`s, so
  `PASS`, `ACCT` and proxy credentials appear as `****` in the file.
- Crash reports contain only `info`+ ring lines (no hostnames by policy) and are `0600`.
- Control characters from servers (ESC sequences in replies, filenames in raw listings)
  are escaped before they reach a file, the clipboard or the screen.
- Audit: every `tracing` call in client crates is reviewed against the policy (checklist
  in `docs/logging.md`); a test asserts no fixture hostname appears in `info`+ lines.

## Implementation steps

1. `logging/ring.rs` + `logging/mod.rs`: port sverb's subscriber (daily file, filter
   from `COURIER_FTP_LOG_LEVEL`, crash and debug rings, `ErrorLayer`), using T01's
   `AppPaths` (with T70's `log_dir()`). Add `tracing-appender` and `parking_lot`
   workspace deps. Unit tests.
2. `panic.rs`: port sverb's hook and crash report writer; remove `errors.rs`,
   `human-panic`, `better-panic`; keep `trace_dbg!` in `logging`. Tests.
3. `LogLevelHandle` shared by `EventSender` clones; Settings → Logging and `--debug-level`
   set it. Audit producers for level checks and the level table above.
4. `courier_ftp_core::session_log`: `format_line`, `escape_controls`, rotation, the writer
   task with drop counting. Unit tests with a temp dir and a fake clock.
5. Wire the writer into the app loop (forward `CoreEvent::Log`), `reconfigure` on settings
   change and `--log-file`, `shutdown` on quit.
6. Raw listing dialog and `ShowRawListing` action; enforce the 16 MiB `raw` cap in the
   FTP and SFTP backends; `ListingRaw` emission rule.
7. `CopyLog`, `SaveLogAs`, `ShowAppLog` actions with key bindings and help entries.
8. Leak tests (canary password, hostname at `info`+) and `docs/logging.md`.

## Acceptance criteria

- [ ] AC1 The application log is written to `<data>/logs/courier-ftp.<date>.log`, appended
  across restarts, rotated daily, and at most 7 files remain (test with `MAX_LOG_FILES`
  files pre-created).
- [ ] AC2 `COURIER_FTP_LOG_LEVEL` controls the filter, `RUST_LOG` is ignored, an invalid
  value logs a warning and uses the default, `--debug` sets `debug`.
- [ ] AC3 A panic restores the terminal, writes a `0600` crash report with ≤ 200 `info`+
  lines and no `debug` lines, prints its path to stderr, exits 101, and at most 20 reports remain.
- [ ] AC4 With `logging.log_to_file` on, every message-log line of every session is written
  in the specified format; `PASS`/`ACCT` appear as `****`.
- [ ] AC5 The session log rotates at `log_file_max_mib` and keeps exactly `log_file_keep`
  (1–50) rotated files.
- [ ] AC6 With the writer blocked, 10 000 messages never block the sender, memory stays
  bounded by the 4 096-message channel, and a "N log messages were dropped" line appears
  once the writer resumes.
- [ ] AC7 Changing the debug level in Settings changes which `Debug(n)` messages appear
  without reconnecting; level ≥ 3 shows TLS/SSH negotiation details and raw listing lines.
- [ ] AC8 The raw listing dialog shows the server text for FTP `LIST`, FTP `MLSD` and SFTP
  (`longname` lines), and the "no raw listing" message for the local pane.
- [ ] AC9 Copy log goes through T55's `ui::clipboard` and respects its 100 KiB cap with whole lines; Save log as writes a `0600` file
  identical to the buffer in `format_line` format.
- [ ] AC10 Canary test: after the integration suite runs at `COURIER_FTP_LOG_LEVEL=trace`,
  no canary password appears in application logs, session logs or crash reports, and no
  fixture hostname appears in any `info`+ application-log line.
- [ ] AC11 ESC sequences in server replies and raw listings appear escaped (`^[`) in the
  session log file, the raw listing dialog and copied text.
- [ ] AC12 T00 gates pass (`fmt`, `clippy`, `docs`, `test-local-only`, `test-os`, `canary`).

## Tests

### Unit tests
- `filter_defaults_to_info_and_debug_with_flag`, `filter_target_only_directive_keeps_default`, `filter_invalid_value_warns_and_uses_default`, `rust_log_is_ignored` — port of sverb `logging/tests.rs` (AC2).
- `appender_appends_across_inits`, `appender_keeps_seven_files` (AC1).
- `crash_ring_keeps_200_info_lines_only`, `debug_ring_only_with_debug_flag` (AC3).
- `crash_report_text_has_no_debug_lines`, `crash_report_file_is_0600_unix`, `crash_reports_pruned_to_20`, `crash_report_name_collision_gets_suffix`, `nested_panic_takes_the_abort_path` (AC3).
- `format_line_matches_spec` — exact string for each `LogKind` (AC4).
- `format_line_masks_pass_and_acct` — `LogMessage` built through `mask_command` (AC4).
- `escape_controls_escapes_esc_and_c1_keeps_tab` (AC11).
- `rotation_shifts_files_and_keeps_n` (keep 1 and 50), `oversized_line_written_to_fresh_file`, `startup_rotates_when_already_over_limit` (AC5).
- `writer_drops_and_counts_when_full`, `writer_reports_dropped_count_on_resume` — paused time, blocked writer via a fake file sink (AC6).
- `writer_disables_itself_after_io_error_until_reconfigure` (AC4).
- `listing_raw_emitted_with_setting_or_level_3`, `listing_raw_capped_at_10000_lines` (AC7).
- `log_level_handle_shared_across_clones_and_clamped` (AC7).
- `copy_log_caps_at_100_kib_whole_lines` (AC9).
- `raw_listing_source_listing_raw_else_message` — `Listing.raw` shown; `None` → the message (AC8).
- `warning_status_lines_keep_prefix_in_file` — a `Status` message `"Warning: …"` is written as `Status:   Warning: …` (AC4).

### Property / fuzz tests
- `prop_escape_controls_output_has_no_control_chars` — proptest over arbitrary strings: output contains no C0/C1 chars except TAB (AC11).
- `prop_rotation_never_exceeds_keep` — random write sizes and limits (AC5).

### Snapshot tests
- `raw_listing_dialog_80x24`, `raw_listing_dialog_160x48` — FTP LIST fixture, ESC in a file name (AC8, AC11).
- `raw_listing_dialog_none_80x24` (AC8).
- `save_log_as_dialog_80x24`, `save_log_as_dialog_160x48` (AC9).
- `app_log_dialog_debug_80x24` (AC2).

### Integration tests
- `session_log_end_to_end_mock_backend` — app loop with a mock backend emitting all kinds across two sessions; file content compared to expected lines (AC4).
- `debug_level_change_applies_to_running_session` — scripted fake FTP server (T10 harness); level 2 → 3 at runtime; `Debug(3)` lines appear afterwards only (AC7).
- `raw_listing_ftp_list_and_mlsd` — fake FTP server serving fixed LIST/MLSD bodies; dialog content equals the bodies (AC8).
- `raw_listing_sftp_longname` — in-process russh SFTP server (T76 harness) (AC8).
- `bin_panic_writes_crash_report` — test-only hook (`COURIER_FTP_TEST_PANIC=1`, compiled only with `cfg(debug_assertions)`) makes the binary panic after logging init; asserts exit 101, report exists, mode `0600`, stderr names it (AC3).
- `log_leak_canary` — runs the vault, quickconnect and transfer integration flows with `init_with_filter(Some("trace"))`, a canary password and a canary hostname; greps every file under the temp home: no canary password anywhere, no canary hostname in lines at `INFO`/`WARN`/`ERROR` (AC10). The CI `canary` job (T00/T91) repeats this over the whole suite.

### End-to-end tests
- `e2e_session_log_file_against_vsftpd` (`#[ignore]`, `COURIER_E2E=1`): `Headless` session against the `vsftpd-plain` FTP profile (T76) with `log_to_file` on; file contains `Command:  PASS ****`, `Response: 230`, and no password (AC4, AC10).
- `e2e_raw_listing_proftpd_mlsd` — `proftpd-plain` profile (vsftpd has no MLSD): raw listing equals the server's MLSD text (AC8).

## Out of scope

- Shipping logs to remote services or telemetry.
- A log viewer for rotated session log files inside the TUI (open them with an editor, T63).
- Per-session separate log files.
- Translating the application log (T75 keeps it English; the session log is written in
  the UI language because it renders the same messages as the log pane).

## Open questions

None.
