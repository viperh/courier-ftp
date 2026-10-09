# T45 — Queue completion actions

**Phase:** E Transfers · **Milestone:** M4 · **Depends on:** T41, T46, T52, T56 · **Crate(s):** `courier-ftp-core` (`transfer::completion`), `courier-ftp` (`completion.rs`) · **Decisions:** D8 (no sound/sleep/shutdown), D10 · **FEATURES.md:** §5 (actions after the queue finishes, automatic refresh of the remote listing)

## Goal

When a queue run finishes, courier-ftp does what the user chose: nothing, show a summary
(with an optional terminal bell or desktop notification), run a command, disconnect all
tabs, or close the app — either every time (`queue.on_complete`) or once for the
current run (FileZilla's "Action after queue completion" menu). Panes showing
directories the queue changed are refreshed. Sound, sleep and shutdown are dropped (D8).

## Context

- Before: T41 emits `CoreEvent::QueueFinished { stats }` exactly once per run that started
  ≥ 1 item and ended on its own (never after `Stop`), stores `QueueRunSummary` (files
  ok/skipped/failed, bytes, duration, `touched` dirs, resolved `action`) for
  `EngineHandle::last_run()`, and has `EngineCommand::SetCompletionOverride` (consumed when
  a run finishes) and `DisconnectIdle`; T46 gives `ListingCache::invalidate`; T52 gives
  `message`, `confirm`, `prompt_text` and the modal stack; T56 sends
  `QueueRequest::SetCompletionAction { action, always }`; T05 gives `OnComplete`,
  `NotifyMethod`, `queue.on_complete`, `queue.on_complete_command`, `queue.notify`,
  `queue.refresh_remote_after`, `SettingsStore::update`; T50 gives `Action::Quit`, quit
  blockers and the background task runner; T61 gives per-tab sessions (Disconnect).
- After: T68 edits the settings; T57 shows the queue summary (unchanged by this task).

## Technical specification

### Types and APIs

Core, `courier_ftp_core::transfer::completion` (pure helpers, no I/O):

```rust
/// One line for the summary dialog, log and notifications. Counts and sizes only
/// (no paths or hosts). Example: "12 files transferred (30.2 MiB) in 00:02:14, 1 failed, 2 skipped".
pub fn summary_text(s: &QueueRunSummary, size_format: SizeFormat) -> String;

/// Environment for `RunCommand` (sorted, deterministic).
pub fn completion_env(s: &QueueRunSummary) -> Vec<(&'static str, String)>;

/// Bytes to write to the terminal for a notification. Empty for `NotifyMethod::None`.
/// `in_tmux` wraps OSC sequences in tmux DCS passthrough.
pub fn notification_bytes(method: NotifyMethod, title: &str, body: &str, in_tmux: bool) -> Vec<u8>;
```

Binary, `crates/courier-ftp/src/completion.rs`:

```rust
/// Reacts to QueueFinished and to the queue pane's completion menu.
pub struct CompletionHandler { /* settings store, engine handle, cancel token */ }
impl CompletionHandler {
    /// T56 menu: always = false → one-shot override; true → persist queue.on_complete.
    pub fn set_action(&mut self, action: OnComplete, always: bool) -> Vec<Action>;
    /// Called by App on CoreEvent::QueueFinished; returns the actions to dispatch.
    pub fn on_queue_finished(&mut self, summary: QueueRunSummary) -> Vec<Action>;
}

// New App actions (T50's Action enum):
//   Action::TerminalNotify(Vec<u8>)        — written to the terminal between frames
//   Action::DisconnectAllTabs              — T61 disconnects every tab's sessions
//   Action::RefreshTouched(TouchedDirs)    — re-list panes showing touched dirs
//   Action::CloseAppCountdown              — opens the 10 s countdown modal
```

### Behaviour

**Choosing the action** (T56 context menu "Action after queue completion ▸"):
- `always = false`: `EngineCommand::SetCompletionOverride(Some(action))`. The engine uses
  it for the next run that finishes and then clears it (one-shot, FileZilla behaviour).
  `Stop` does not clear it. Choosing the same entry with `always = true` later clears the
  override (`SetCompletionOverride(None)`).
- `always = true`: `SettingsStore::update(|s| s.queue.on_complete = action)` (persisted,
  T05) and `SetCompletionOverride(None)`.
- "Run command…": opens `prompt_text("Command to run after the queue finished",
  queue.on_complete_command)`; OK stores the text in `queue.on_complete_command`
  (≤ 1024 chars, T05) and then applies the action as above. The command text is always
  the setting value; there is no separate one-shot command.

**Trigger.** Only `CoreEvent::QueueFinished` triggers anything. It is not emitted at
startup with an empty queue, after `Stop`, after a disk-full stop, or at shutdown
(T41). The handler reads `engine.last_run()`; `summary.action` is already resolved
(override or setting).

**Actions** (always preceded by one Status log line "Queue finished: <summary_text>"):

| `OnComplete` | Behaviour |
|---|---|
| `None` | nothing more |
| `ShowMessage` | `message("Queue finished", summary_text)` on top of the modal stack; if `files_failed > 0` the text adds "See the Failed tab for details." Then the notification (below). |
| `RunCommand` | spawn the command (below) |
| `Disconnect` | `Action::DisconnectAllTabs` (every tab's browsing session `disconnect()`, tabs stay open, T61) and `EngineCommand::DisconnectIdle` |
| `CloseApp` | `Action::CloseAppCountdown`: modal "courier-ftp will close in 10 s" with a countdown and buttons *Close now* / *Cancel* (default *Cancel*, `Esc` cancels). At 0 s or *Close now* → `Action::Quit` (T50's normal path: quit blockers still apply, persistence of queue and settings, terminal restored). |

**Notification** (with `ShowMessage` only), from `queue.notify` (default `bell`):
- `none`: nothing.
- `bell`: the BEL byte `0x07`.
- `osc`: `ESC ] 9 ; <title>: <body> ESC \` (iTerm2, Windows Terminal, ConEmu) followed by
  `ESC ] 777 ; notify ; <title> ; <body> ESC \` (rxvt-unicode, foot, Ghostty, WezTerm).
  Title "courier-ftp", body = `summary_text`. Text is sanitised: control characters
  removed, `;` replaced by `,`, at most 200 characters. The body never starts with a
  digit (ConEmu treats `9;<digit>` as a different command), guaranteed by the title prefix.
- In tmux (`$TMUX` set) the OSC sequences are wrapped: `ESC P tmux; <sequence with each
  ESC doubled> ESC \` (needs tmux `allow-passthrough on`; otherwise tmux drops them).
- Written via `Action::TerminalNotify(bytes)`; the App writes them to the terminal backend
  outside `draw` and flushes.

**RunCommand:**
- Empty `queue.on_complete_command` → Error log "No command configured for the action
  after queue completion" and nothing else.
- Unix: `sh -c <command>`; Windows: `cmd /C <command>` (passed with `raw_arg`, no extra
  quoting). Working directory: the user's home directory. stdin, stdout and stderr are
  null (the TUI owns the terminal). Unix: `process_group(0)`; Windows:
  `CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW`. `kill_on_drop(false)`: the command keeps
  running when courier-ftp exits.
- Environment: inherited, plus `COURIER_FTP_FILES_OK`, `COURIER_FTP_FILES_FAILED`,
  `COURIER_FTP_FILES_SKIPPED`, `COURIER_FTP_BYTES`, `COURIER_FTP_DURATION_SECS` (decimal
  integers). No paths, hosts or secrets are passed.
- A background task (T50 runner) waits for the exit and logs Status "Command after queue
  completion exited with code N" (code ≠ 0 → Error line); a spawn failure logs Error with
  the OS message. No timeout; on app quit the waiting task is dropped, the process is not
  killed.

**Refresh after the queue** (`queue.refresh_remote_after`, default true), independent
of the chosen action:
- For each `(server, dir)` in `summary.touched.remote`: `ListingCache::invalidate(server,
  dir)`; every tab whose remote pane shows `dir` on a session with that `ServerIdentity`
  re-lists it (same path as F5 refresh, T53).
- For each local dir in `summary.touched.local`: local panes showing it re-list.
- `touched.overflow` → every pane of every connected tab re-lists.
- With the setting off, panes keep what T41's cache patches already updated.

### Data formats and configuration

Settings (all defined in T05):

| Key | Type | Default | Notes |
|---|---|---|---|
| `queue.on_complete` | OnComplete | `none` | `none`, `show_message`, `run_command`, `disconnect`, `close_app` |
| `queue.on_complete_command` | String | "" | ≤ 1024 chars; run by `sh -c` / `cmd /C` |
| `queue.notify` | NotifyMethod | `bell` | `none`, `bell`, `osc` |
| `queue.refresh_remote_after` | bool | true | |

The one-shot override lives only in the engine (memory), never persisted. Settings
import (T73) only imports `queue.on_complete_command` when `allow_commands` is set.

### Errors

| Situation | User sees |
|---|---|
| Command empty | Error log line (above) |
| Spawn fails (`sh` missing, permission) | Error log "Could not run the command after queue completion: <OS message>" |
| Command exits non-zero | Error log with the code |
| Settings save fails when choosing "always" | error dialog from `SettingsStore::update`; the override is still set for this run |

No core `Error` crosses into the UI from this task besides `SettingsStore::update`'s.

### Security and logging

- The command comes only from the local settings file (D10, never synced); imports
  require explicit `allow_commands` (T73). It runs with the user's privileges, without
  courier-ftp secrets in its environment.
- Notification text contains only counts, sizes and durations — no paths or hosts —
  because terminal notifications may be forwarded to the OS notification centre.
- The summary log line is a Status line in the message log; the tracing log at `info`
  records "queue finished: ok=12 failed=1 skipped=2 action=show_message".
- Notification bytes are built from sanitised text, so no control sequence from a server
  (file names never appear) can reach the terminal through this path.

## Implementation steps

1. Core helpers `summary_text`, `completion_env`, `notification_bytes` + unit/snapshot tests.
2. `CompletionHandler::set_action` wired to T56's `SetCompletionAction`; "Run command…" prompt.
3. `on_queue_finished` with the action table; new App actions; terminal write path.
4. RunCommand spawning with env and exit logging (Unix + Windows).
5. Disconnect (T61 hook + `DisconnectIdle`), CloseApp countdown modal.
6. Refresh of touched directories (cache invalidation + pane re-list).
7. AppHarness tests and snapshots.

## Acceptance criteria

- [ ] AC1 Each `OnComplete` value produces its behaviour after a mock queue run (AppHarness): none → only the log line; show_message → modal with the summary; run_command → process started; disconnect → every tab disconnected, idle engine connections closed; close_app → countdown, then quit.
- [ ] AC2 A one-shot override applies to the next finished run only; the run after it uses `queue.on_complete`; `Stop` keeps the override; "always" persists `queue.on_complete`.
- [ ] AC3 The command receives `COURIER_FTP_FILES_OK`, `_FAILED`, `_SKIPPED`, `_BYTES`, `_DURATION_SECS` with the run's values (test script writes its env to a temp file; Unix `sh`, Windows `cmd`).
- [ ] AC4 Stopping the queue manually, a disk-full stop, and app start with an empty queue trigger no action and no notification.
- [ ] AC5 After a run that uploaded into `/var/www`, a tab showing `/var/www` re-lists it (mock `calls(List)` +1) and a tab showing another dir does not; overflow re-lists all.
- [ ] AC6 `notification_bytes` output matches the snapshots for bell, osc, osc-in-tmux; sanitising removes control characters and `;`.
- [ ] AC7 The countdown modal defaults to Cancel: `Enter` keeps the app running; with a quit blocker present, reaching 0 s shows T50's quit confirmation instead of exiting.
- [ ] AC8 Snapshot tests of the summary modal and the countdown modal at 80×24 and 160×48.
- [ ] AC9 T00 `test-local-only` and `test-os` (Windows `cmd /C` path) pass.

## Tests

### Unit tests
- `fn summary_text_variants` — no failures, failures, skipped only, zero bytes, IEC/SI sizes (AC1).
- `fn completion_env_values_and_order` (AC3).
- `fn notification_bytes_none_bell_osc_tmux` — insta snapshots of escaped bytes (AC6).
- `fn notification_sanitises_text` — ESC, BEL, `;`, 300 chars (AC6).
- `fn set_action_once_vs_always` — commands sent / settings updated (AC2).

### Property / fuzz tests
- `proptest fn notification_never_contains_raw_control_chars` — random body text; the only ESC/BEL bytes are the ones the format adds (AC6).

### Snapshot tests
- `snap_queue_finished_message_80x24`, `snap_queue_finished_message_160x48` — summary with 1 failure (AC8).
- `snap_close_countdown_80x24`, `snap_close_countdown_160x48` (AC8).

### Integration tests
AppHarness (T50) with the engine on `MockServer`s, paused time:
- `async fn action_none_logs_only`, `async fn action_show_message_modal_and_bell`,
  `async fn action_disconnect_all_tabs`, `async fn action_close_app_after_countdown`,
  `async fn countdown_cancel_keeps_running`, `async fn countdown_with_blocker_shows_quit_confirm` (AC1, AC7).
- `async fn run_command_receives_env` — `#[cfg(unix)]` `env > $T/out`, `#[cfg(windows)]` `set > %T%\out` (AC3).
- `async fn oneshot_used_once_then_setting` and `async fn stop_keeps_oneshot` (AC2).
- `async fn no_action_after_stop_or_disk_full_or_empty_start` (AC4).
- `async fn refresh_touched_dirs_only` and `async fn refresh_overflow_all` (AC5).

### End-to-end tests
`PtyApp` (T76), `#[ignore]` + `COURIER_E2E=1`: `queue_finished_show_message` — upload two
files to sshd `password` with `queue.on_complete = show_message`; the screen shows
"Queue finished: 2 files transferred" (AC1 on the real binary).

## Out of scope

- Sound, system sleep and shutdown after the queue (D8).
- Per-site or per-item completion commands (would be synced local-acting values, T91).
- OS-native notification APIs (only terminal BEL/OSC).

## Open questions

1. `queue.notify` is used only together with `ShowMessage` in this spec (default
   `on_complete = none`, so no bell by default). Should the notification fire after every
   finished run regardless of the action (e.g. for runs longer than 10 s)?
