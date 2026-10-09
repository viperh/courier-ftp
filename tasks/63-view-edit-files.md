# T63 — View / edit files externally

**Phase:** F TUI · **Milestone:** M6 · **Depends on:** T05, T41, T62 · **Crate(s):** `courier-ftp` (+ pure helpers in `courier-ftp-core::edit`) · **Decisions:** D6, D7 · **FEATURES.md:** §4 (view/edit with watched temp copy, file associations)
**Reference:** sverb `crates/sverb-tui/src/runtime/terminal.rs` (suspend/restore of terminal modes), `crates/sverb-tui/src/runtime/signals.rs`, `crates/sverb-core/src/config/watch.rs` (notify watcher on the parent directory with debounce)

## Goal

Open a remote file in a viewer or editor, notice when it is saved, and offer to
upload it back — FileZilla's View/Edit, adapted to a terminal. Terminal programs
(vim, nano, less) take over the terminal while courier-ftp is suspended; GUI
programs run detached while a file watcher reports saves. A "Files being edited"
list shows every open edit, and temporary copies are cleaned up reliably.

## Context

Before this task:
- T62 gives `OpSource`, `PaneSide`, `PanePath` and the new-file dialog; T53 gives the
  pane cursor; T50 gives the app loop, `Tui` (`enter`/`exit`, the event-loop task,
  modal stack) and `tabs::TabId(u32)`; T52 gives dialogs (`confirm` with
  `ConfirmOpts`; destructive confirmations here use `ConfirmOpts::danger(..)`).
- T01 gives `AppPaths` (`cache_dir` holds the edit temp tree).
- T03 gives `SessionHandle`, `BackendFactory::create(Arc<ConnectInfo>, BackendContext)`,
  `ConnectInfo`, `WriteMode`, `TransferOpts`; T05 provides
  `settings::decide_transfer_type` (used by T11 too); T44 provides the shared rate
  limiter used by T41; T46 provides the cache upload patch.
- T05 has the `editing` section (`editor: EditorChoice`, `associations:
  Vec<Association>`, `watch_and_prompt_upload`, `max_size_mib`) and creates the data
  types `EditorChoice` and `Association` in `courier_ftp_core::edit` (fields and serde
  as shown below) so the settings model compiles. This task adds the logic to that
  module and does not redefine the types.

Later tasks use from this task: T65 (open search results), T68 (editing settings
section), T76 (PtyApp edit round-trip with a fake editor), T91 (edit temp dirs are
canary-scanned; temp files are an asset in the threat model).

## Technical specification

### Types and APIs

Pure helpers in `courier-ftp-core/src/edit.rs` (no process spawning, no UI). The two
data types are created there by T05 and only referenced here (shown for the meaning
of their fields); serde uses `rename_all = "snake_case"` like every settings enum:

```rust
// ---- created by T05 (data only) ----
/// One entry of `editing.associations`. First match wins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Association {
    /// Glob (`globset` syntax). Without `/` it matches the file name only,
    /// with `/` it matches the full remote path. Always case-insensitive.
    pub pattern: String,
    /// Program and arguments, split with POSIX shell-word rules (`shell-words`).
    /// `%f` is replaced by the file path; without `%f` the path is appended.
    pub command: String,
    /// true: runs in this terminal (courier-ftp suspends); false: GUI, detached.
    pub terminal: bool,
}

/// `editing.editor`. JSON `"auto"` or `{"command":{"command":"vim","terminal":true}}`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EditorChoice {
    /// $VISUAL, then $EDITOR, then the platform default.
    #[default] Auto,
    Command { command: String, terminal: bool },
}

// ---- added by this task ----

pub fn match_association<'a>(assocs: &'a [Association], file_name: &str,
                             remote_path: &str) -> Option<(usize, &'a Association)>;

/// Splits `command` and inserts `file` (as one argument) at `%f` or at the end.
pub fn build_argv(command: &str, file: &std::path::Path) -> Result<Vec<OsString>, EditError>;

/// GUI editors detected by program basename when they come from $VISUAL/$EDITOR.
pub const KNOWN_GUI_EDITORS: &[&str] = &[
    "code", "code-insiders", "codium", "subl", "sublime_text", "gedit", "gnome-text-editor",
    "kate", "kwrite", "mousepad", "pluma", "xed", "zed", "atom", "mate", "bbedit",
    "notepad", "notepad.exe", "notepad++", "notepad++.exe", "gvim", "mvim",
];

/// Length + mtime + SHA-256 of a file. Equality of `sha256` decides "changed".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint { pub len: u64, pub mtime: Option<std::time::SystemTime>, pub sha256: [u8; 32] }
pub fn fingerprint(path: &std::path::Path) -> std::io::Result<Fingerprint>;

/// Text heuristic for View: first 8 KiB has no NUL and is valid UTF-8
/// (a cut multi-byte sequence at the end is allowed).
pub fn looks_like_text(head: &[u8]) -> bool;

#[derive(Debug, thiserror::Error)]
pub enum EditError {
    #[error("no program configured for this file")] NoProgram,
    #[error("invalid command line: {0}")] BadCommand(String),
    #[error("could not start {program}: {source}")] Spawn { program: String, source: std::io::Error },
    #[error("temporary directory unavailable: {0}")] TempDir(std::io::Error),
}
```

Binary crate, module `crates/courier-ftp/src/edit/` (`mod.rs`, `resolve.rs`,
`temp.rs`, `foreground.rs`, `watcher.rs`, `registry.rs`, `transfer.rs`,
`dialogs.rs`):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)] pub struct EditId(pub u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum EditMode { View, Edit }

#[derive(Debug, Clone)]
pub struct ResolvedProgram { pub argv: Vec<OsString>, pub terminal: bool, pub source: ProgramSource }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramSource { Association(usize), Setting, Visual, Editor, Pager, PlatformDefault }

/// Resolution order in "Program resolution" below. `env` is injectable for tests.
pub fn resolve_program(mode: EditMode, file_name: &str, remote_path: &str, is_text: bool,
                       settings: &EditingSettings, env: &dyn Fn(&str) -> Option<OsString>,
                       which: &dyn Fn(&str) -> bool) -> Result<ResolvedProgram, EditError>;

/// What is known about the remote file when it was downloaded / last uploaded.
#[derive(Debug, Clone)]
pub struct RemoteSnapshot { pub size: Option<u64>, pub modified: Option<Timestamp> }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditState {
    Downloading { done: u64, total: Option<u64> },
    InForeground,            // terminal program running
    Watching,                // GUI program, no unsaved change
    Modified,                // changed, not uploaded (prompt pending or declined)
    Uploading { done: u64, total: u64 },
    UploadFailed(String),
    Conflict,                // remote changed since download; waiting for the user
}

pub struct EditSession {
    pub id: EditId,
    pub mode: EditMode,
    pub origin_tab: Option<TabId>,
    pub connect: Option<Arc<ConnectInfo>>, // None for local files (no temp copy)
    pub remote_path: RemotePath,
    pub temp_file: PathBuf,
    pub program: ResolvedProgram,
    pub remote_at_sync: RemoteSnapshot,
    pub synced: Fingerprint,     // temp file content that matches the server
    pub state: EditState,
    pub auto_upload: bool,       // "Always upload this file"
}

/// All open edits; owned by `App`.
pub struct EditRegistry { /* BTreeMap<EditId, EditSession>, TempLayout, EditWatcher */ }

/// Per-process temp tree (see "Temporary directory layout").
pub struct TempLayout { pub root: PathBuf, pub instance: PathBuf, lock: std::fs::File }
impl TempLayout {
    pub fn create(cache_dir: &Path) -> std::io::Result<Self>;
    pub fn edit_dir(&self, id: EditId) -> PathBuf;
    pub fn file_path(&self, id: EditId, remote_name: &str) -> PathBuf; // sanitised name
    pub fn remove_edit(&self, id: EditId) -> std::io::Result<()>;
    pub fn stale_instances(root: &Path) -> Vec<StaleInstance>; // dirs whose lock is free
    pub fn cleanup_instance(self) -> std::io::Result<()>;
}

/// Leaves the TUI, runs a terminal program in the foreground, restores the TUI.
pub trait ForegroundRunner {
    fn run(&mut self, tui: &mut Tui, argv: &[OsString]) -> std::io::Result<std::process::ExitStatus>;
}
pub struct RealForegroundRunner;

/// notify-based watcher with debounce; falls back to polling.
pub struct EditWatcher { /* RecommendedWatcher | PollWatcher, debounce thread */ }
impl EditWatcher {
    pub fn new(tx: UnboundedSender<Action>) -> Self;   // sends Action::EditFileChanged(EditId)
    pub fn watch(&mut self, id: EditId, dir: &Path) -> Result<(), WatchError>;
    pub fn unwatch(&mut self, id: EditId);
}
pub const WATCH_DEBOUNCE: Duration = Duration::from_millis(500);
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);
```

New `Action` variants: `View`, `Edit`, `EditedFilesList`, `EditFileChanged(EditId)`,
`EditProgramExited { id, status }`, `EditTransferFinished { id, result }`.

### Behaviour

#### Entry points

| Key (T51) | Action | Remote pane | Local pane |
|---|---|---|---|
| `F3`, `o` | View | download to temp, open viewer, no upload | open the file directly with the viewer |
| `F4`, `e` | Edit | download to temp, open editor, watch, offer upload | open the file directly with the editor; no watch, no upload |
| `Ctrl-x e` | EditedFilesList | "Files being edited" dialog | — |

(`Ctrl-x e` is in T51's `Ctrl-x` prefix table, owner T63.) Only the cursor entry is opened (marked
entries are ignored; status message says so when more are marked). Directories →
status "Can't open a directory"; symlinks are resolved with `stat` first; `Other`
entries refused.

#### Edit flow (remote file)

1. **Already open**: the same `(connection identity, remote path)` is in the
   registry → dialog "index.html is already open for editing. [Reopen] [Download
   again] [Cancel]". *Reopen* starts the program on the existing temp file;
   *Download again* asks for confirmation (`ConfirmOpts::danger("Download again")`)
   if the edit is `Modified`, then replaces the temp copy.
2. **Size check**: if `editing.max_size_mib > 0` and `entry.size > editing.max_size_mib
   × 1 MiB` (default 50; 0 = never ask) →
   `confirm("Large file", "index.log is 312 MiB. Download it to open it?",
   ConfirmOpts { default_yes: false, ..ConfirmOpts::new() })`.
   Unknown size → no check.
3. **Resolve program** (below). Failure → error dialog "No editor configured. Set
   one in Settings → Editing or set $EDITOR." and stop.
4. **Download** to `TempLayout::file_path(id, name)` with a direct transfer
   (`edit::transfer`), not through the queue, so it works while the queue is
   stopped: a dedicated `SessionHandle` from `BackendFactory::create(info, ctx)` with
   the tab's `Arc<ConnectInfo>` (when the site's `limit_connections == Some(1)`, the browsing
   session is used instead). Transfer type from `decide_transfer_type` (T05) unless
   `file_types.default_type` forces one; bytes go through the shared rate limiter
   (T44). A `ProgressDialog` "Downloading index.html… 45 %" with Cancel appears after
   300 ms. Session timeout `connection.timeout_secs`; one retry on a transient error
   (T02 `is_transient`). The fingerprint and `RemoteSnapshot` (size and mtime from
   the listing entry, refreshed by `stat` after the download when available) are
   recorded. On failure the temp file is removed and an error dialog shows.
5. **Launch**:
   - terminal program → foreground run (below); afterwards compare fingerprints.
   - GUI program → spawn detached, register the watcher, state `Watching`.
6. **Change detected** (after a foreground run, or a debounced watcher event):
   new fingerprint's `sha256` differs from `synced.sha256` → state `Modified`, and
   (if `editing.watch_and_prompt_upload` is true) the upload prompt is queued.
   Same hash → nothing (a save without changes, or an editor touching mtime only).
7. **Upload prompt** (queued like T69 prompts: one at a time; a second change of the
   same file while its prompt is open does not add another prompt):
   ```
   ┌ File changed ─────────────────────────────────────────────────┐
   │ index.html has been changed.                                  │
   │ Upload it back to the server?                                 │
   │                                                               │
   │ Server: sftp://alice@web01.example.com                        │
   │ Path:   /var/www/index.html                                   │
   │                                                               │
   │ [ Upload ]  [ Always upload this file ]  [ Not now ]          │
   │                     [ Stop editing ]                          │
   └───────────────────────────────────────────────────────────────┘
   ```
   - *Upload* → upload flow. *Always upload this file* → `auto_upload = true`, upload
     now and later changes upload without a prompt (state still visible in the
     list). *Not now* → stays `Modified`, upload later from the list. *Stop editing*
     → if unsaved changes would be lost, confirm (`ConfirmOpts::danger("Stop
     editing")`); then stop watching and delete the temp file. `Esc` = *Not now*.
8. **Upload flow**:
   - Conflict check: `stat(remote_path)`. If size differs from
     `remote_at_sync.size`, or mtime differs (compared at the coarser precision,
     T02) → state `Conflict` and dialog "index.html was changed on the server since
     you opened it (12 034 → 12 410 bytes, modified 10:02 → 10:17). [Overwrite]
     [Cancel]" (`ConfirmOpts::danger("Overwrite")`, default Cancel). `NotFound` →
     "index.html no longer exists on the
     server. [Upload anyway] [Cancel]". `stat` unsupported or no mtime/size known →
     skip the check (log `Status:` "Can't check for changes on the server").
   - Upload with `WriteMode::Truncate` on a dedicated session from the stored
     `ConnectInfo` (works after the origin tab was closed or disconnected). Progress
     shown in the list and the status bar.
   - Success → `synced = fingerprint(temp)`, `remote_at_sync` from a fresh `stat`,
     cache upload patch (T46), log `Status: Uploaded edited file /var/www/index.html`,
     state `Watching` (GUI) or removed (terminal program already exited, see below).
   - Failure → `UploadFailed(reason)`, error dialog with *Retry* / *Later*.
9. **End of an edit**:
   - Terminal program: after it exits and the change (if any) was uploaded,
     declined with *Not now* (kept as `Modified`) or nothing changed, an unmodified
     edit is removed and its temp dir deleted immediately; a `Modified` one stays
     in the list until uploaded or discarded.
   - GUI program: watched until the user picks *Stop editing* / *Discard* in the
     list, or the app exits. The GUI process's own exit is not tracked (many
     editors hand off to an existing instance and exit at once).

#### View flow

Same as Edit steps 1–5 but: the temp file is made read-only (`0400` on Unix,
read-only attribute on Windows), no watcher, no prompt, no upload. A terminal
viewer's temp copy is deleted when it exits; a GUI viewer's copy is deleted when
the app exits (the viewer may still be reading it). View sessions appear in the
list with state "Viewing" only while a GUI viewer may be using them.

#### Program resolution

Edit (`EditMode::Edit`), first hit wins:
1. `match_association(editing.associations, name, remote_path)` → its command and
   `terminal` flag.
2. `editing.editor = Command { command, terminal }`.
3. `$VISUAL`, then `$EDITOR` (non-empty). `terminal = true` unless the program's
   basename (without `.exe`) is in `KNOWN_GUI_EDITORS`.
4. Platform default: Linux/BSD — `nano`, then `vi` (first in `PATH`, terminal);
   macOS — `open -W -t %f` is **not** used (it blocks on all TextEdit windows):
   `open -t %f` (GUI); Windows — `notepad.exe %f` (GUI).
5. Nothing found → `EditError::NoProgram`.

View (`EditMode::View`):
1. Association (same list; a match means "open with that program").
2. Text file (`looks_like_text` on the first 8 KiB): `$PAGER` (terminal), then
   `less` (Unix, in `PATH`, terminal), then `more.com` (Windows, terminal).
3. Otherwise the platform opener (GUI): `xdg-open %f` (Linux/BSD), `open %f`
   (macOS), `cmd /C start "" %f` (Windows — the only case that goes through a
   shell; the path is passed as a separate argument after the empty title, and
   temp paths contain no shell metacharacters because names are sanitised).

Commands are never run through a shell except the Windows `start` case above.
`build_argv` substitutes `%f` as one argument; the absolute temp path is used, so
a file name starting with `-` can't be read as an option.

#### Foreground run of a terminal program (`RealForegroundRunner`)

Unix (Linux, macOS, BSD):
1. Set the app-wide flag `foreground_child = true`. While set, the signal task
   (T50) ignores `SIGINT`, `SIGQUIT` and `SIGCONT`-redraw requests (Ctrl-C inside
   vim reaches our process group too).
2. `tui.exit()`: cancel the event-loop task and **wait until it has finished**
   (join the `JoinHandle`, up to 500 ms, then abort) so crossterm's `EventStream`
   is dropped and its reader stops reading stdin; disable bracketed paste, leave the
   alternate screen, show the cursor, disable raw mode. Flush stdout.
3. Spawn the program with inherited stdin/stdout/stderr in our process group
   (`std::process::Command`, no `process_group` change, so the terminal's
   job control works: Ctrl-Z stops both the editor and courier-ftp; `fg` resumes
   both), and wait for it in `tokio::task::spawn_blocking`.
4. When it exits: `tui.enter()` (raw mode, alternate screen, hide cursor, bracketed
   paste, restart the event loop), `terminal.clear()` to force a full redraw, read
   `crossterm::terminal::size()` and dispatch `Action::Resize` (the window may have
   changed), set `foreground_child = false`.
5. If re-entering fails, the app quits with the error (terminal restored by the
   panic/exit path) rather than running on a cooked terminal.

Windows (Windows Terminal, conhost):
1. Save the console input and output modes with `crossterm_winapi::ConsoleMode`
   (safe API; no `unsafe` in this crate, T91 §2).
2. Same `tui.exit()` sequence as Unix (crossterm restores the cooked input mode).
3. Spawn with inherited handles and wait in `spawn_blocking`. While the child runs,
   `Ctrl-C` console events received by courier-ftp are ignored (`foreground_child`).
4. Restore the saved console modes (an editor may leave
   `ENABLE_VIRTUAL_TERMINAL_PROCESSING` off), then `tui.enter()`, clear, resize as
   on Unix.

Both: the app loop stops polling its own events while the child runs; core events
(T04) queue up (progress is coalesced) and are processed after resume. Keep-alive
tasks of `SessionHandle`s keep running. Auto-lock (T30) keeps counting; if the
vault locked meanwhile, the unlock overlay appears after resume and pending upload
prompts are shown after unlock (they live in the registry, not on the modal stack).

#### GUI program spawn

`Command` with stdin/stdout/stderr set to null; Unix: `process_group(0)` so
terminal signals don't reach it; Windows: `creation_flags(DETACHED_PROCESS |
CREATE_NEW_PROCESS_GROUP)`. The `Child` is reaped by a background thread
(`child.wait()`), so no zombies remain. Spawn errors (`NotFound`) → error dialog
"Could not start 'code': program not found".

#### File watcher (`notify` crate)

- One `notify::RecommendedWatcher` for the whole app (inotify, FSEvents,
  ReadDirectoryChangesW). Each edit's **directory** (`<instance>/<edit id>/`) is
  watched non-recursively, because editors save by writing a temp file and renaming
  it over the original (sverb `config/watch.rs`).
- Events for other file names in that dir (editor swap/backup files) are ignored.
- Debounce: a change is reported once the file has been quiet for 500 ms
  (`WATCH_DEBOUNCE`), on a dedicated thread, as `Action::EditFileChanged(id)`; the
  handler then computes the fingerprint (in `spawn_blocking`).
- If the native watcher can't be created or a `watch` call fails (e.g. inotify
  watch limit), fall back to `notify::PollWatcher` with a 2 s interval and log
  `Status:` "File change detection uses polling".
- Our own writes (download, "Download again") are done before `watch` is called or
  while the edit is unwatched, so they never trigger a prompt.
- The file being deleted by the editor and recreated is handled: the dir is watched,
  and the fingerprint is read on the next quiet period; if the file is missing,
  nothing is reported.

#### "Files being edited" dialog (`Ctrl-x e`)

```
┌ Files being edited ─────────────────────────────────────────────────────┐
│ File          Server                          Status                    │
│ index.html    sftp://alice@web01.example.com  Modified, not uploaded    │
│ app.conf      ftp://deploy@ftp.example.org    Watching                  │
│ big.log       sftp://alice@web01.example.com  Uploading 45 %            │
│ notes.txt     sftp://alice@web01.example.com  Upload failed: timeout    │
│                                                                         │
│ [u] Upload now  [r] Reopen  [s] Stop editing  [d] Discard changes  [Esc]│
└─────────────────────────────────────────────────────────────────────────┘
```
At 80 columns the Server column is dropped and shown under the selected row.
- `u` upload now (conflict check applies); `r` reopen in the program; `s` stop
  editing (confirm with `ConfirmOpts::danger("Stop editing")` when `Modified`); `d`
  discard changes: confirm with `ConfirmOpts::danger("Discard")`, then delete the
  temp file and remove the entry.
- Empty list → "No files are being edited."

#### Quit with edits

On quit (T50) with any edit in `Modified`, `Uploading`, `UploadFailed` or `Conflict`:
```
┌ Edited files not uploaded ────────────────────────────────────┐
│ 2 edited files have changes that were not uploaded.           │
│ [ Upload all and quit ]  [ Quit and keep the files ]  [ Cancel ] │
└───────────────────────────────────────────────────────────────┘
```
*Quit and keep the files* leaves those temp dirs (and only those) in place and
releases the instance lock; all other edit dirs are deleted. *Upload all and quit*
uploads sequentially (conflicts still ask) and quits when all succeeded; on any
failure the dialog returns with the remaining count.

#### Temporary directory layout and cleanup

```
<cache dir>/edit/                              0700
  <pid>-<8 hex random>/                        0700  one per running process ("instance")
    .lock                                      0600  exclusive lock held while running (fs2)
    <edit id, 16 hex>/                         0700  one per edit
      <sanitised remote file name>             0600  (View: 0400)
```
- `<cache dir>` = `AppPaths.cache_dir` (T01): `$COURIER_FTP_HOME/cache` when
  `COURIER_FTP_HOME` is set (tests, T76), else `directories::ProjectDirs::cache_dir()`
  (Linux `~/.cache/courier-ftp`, macOS `~/Library/Caches/<project>`, Windows
  `%LOCALAPPDATA%\<project>\cache`).
  On Windows the directories inherit the per-user ACL of `%LOCALAPPDATA%`.
- The remote name is sanitised with `sanitize_local_name` (T06) using
  `transfers.invalid_char_replacement`, and capped at 200 bytes (stem cut,
  extension kept, so associations still match). The edit id directory keeps two
  files with the same name apart.
- Unix: directories are created with mode `0700` (`DirBuilderExt::mode`) and
  re-checked with `symlink_metadata` (must be a real directory owned by the current
  uid, not a symlink) before use; files are created with `O_EXCL` and mode `0600`.
- **Cleanup**: stop editing / discard / unmodified terminal edit ends → remove its
  `<edit id>` dir; normal exit → remove the whole instance dir except edits the user
  chose to keep; startup → `stale_instances(root)` finds instance dirs whose `.lock`
  can be taken (owner process gone): empty ones are removed silently; non-empty ones
  produce one dialog "Files from an earlier session were left in
  <path>: 2 files. [Delete them] [Keep]" (keep = ask again next start). Removal
  errors are logged (`Error:` line) and never block startup or exit.
- No secure erase is attempted (documented residual risk in T91).

### Data formats and configuration

| Key | Type | Default | Meaning |
|---|---|---|---|
| `editing.editor` | `EditorChoice` | `"auto"` | default editor when no association matches |
| `editing.associations` | `Vec<Association>` | `[]` | first match wins; ≤ 256 entries (T05) |
| `editing.watch_and_prompt_upload` | bool | `true` | prompt to upload on change; false = only mark `Modified` in the list |
| `editing.max_size_mib` | u32 | `50` | 0–10240 (T05); ask before downloading larger files; `0` = never ask |
| `file_types.default_type` | `TransferTypeChoice` | `Auto` | transfer type for edit downloads/uploads |
| `transfers.invalid_char_replacement` | char | `'_'` | temp file name sanitising |
| `connection.timeout_secs` | u32 | `20` | edit transfer timeout |

Example (`config.json`):
```json
"editing": {
  "editor": { "command": { "command": "nvim", "terminal": true } },
  "associations": [
    { "pattern": "*.{png,jpg,jpeg,gif}", "command": "xdg-open %f", "terminal": false },
    { "pattern": "*.md", "command": "code --wait %f", "terminal": false }
  ],
  "watch_and_prompt_upload": true,
  "max_size_mib": 50
}
```
Validation (T05 rules): empty `pattern` or `command`, invalid glob, or a command
that `shell-words` can't split → warning, entry dropped (not the whole list).

### Errors

| Situation | Error | User sees |
|---|---|---|
| No program found | `EditError::NoProgram` | error dialog pointing to Settings → Editing / `$EDITOR` |
| Program can't start | `EditError::Spawn` | error dialog with the program name |
| Temp dir can't be created / wrong owner / symlink | `EditError::TempDir` | error dialog with the path; nothing downloaded |
| Download / upload failure | `courier_ftp_core::Error` (`Timeout`, `Connection`, `PermissionDenied`, `NotFound`, `Protocol`) | error dialog; list status `Upload failed: <reason>` |
| Remote changed / deleted | — (conflict check) | conflict dialog, default Cancel |
| Watcher unavailable | `notify::Error` | polling fallback + `Status:` log line |
| TUI re-enter failed after a foreground program | `io::Error` | app exits with the error; terminal restored |

### Security and logging

- Temp files contain the user's remote data: `0700`/`0600`, unique per process and
  edit, symlink checks, removed when no longer needed; the canary scan (T91 §5)
  includes `<cache dir>/edit`.
- Commands are executed without a shell (except Windows `start`), with the file
  path as a single argument; association commands come from the user's own config
  (not synced), so no T91 §8 approval is needed.
- `ConnectInfo` kept for re-upload holds secrets only in `SecretString`; it is
  dropped when the edit ends.
- `tracing` at `debug`: edit ids, program source (`Association(2)`, `Visual`), exit
  codes, watcher backend; never paths, hostnames or file names at `info`+. The
  session log shows `Status:` lines with remote paths (user-facing, T55).
- Environment passed to programs unchanged; no secret is ever put in the environment
  or on a command line.

## Implementation steps

1. Core `edit` module (types from T05): `match_association`, `build_argv`,
   `Fingerprint`, `looks_like_text`, `KNOWN_GUI_EDITORS`; unit tests.
2. `resolve_program` with injectable env/`which`; unit tests per platform branch.
3. `TempLayout`: creation with permissions and lock, sanitised names, removal,
   stale-instance detection; startup dialog.
4. `ForegroundRunner` + `RealForegroundRunner` (Unix and Windows paths), the
   `foreground_child` flag in the signal task; local-file Edit/View using it.
5. Edit transfer helper (download/upload over a dedicated `SessionHandle` with
   progress, rate limiter, retry) and the remote Edit flow for terminal programs.
6. `EditWatcher` (notify + debounce + PollWatcher fallback) and GUI spawn.
7. Upload prompt, conflict check, auto-upload, registry state machine.
8. "Files being edited" dialog and quit guard; View flow; T62 new-file checkbox
   "Open in editor after creating".
9. Snapshot tests, UI-flow tests with a mock runner, e2e PtyApp round-trip, manual
   checklist.

## Acceptance criteria

- [ ] AC1 Terminal editor round-trip on Linux and macOS: after the program exits the TUI is fully restored (alternate screen, raw mode, no stray characters, correct size) and a changed file triggers the upload prompt (e2e PtyApp test + manual check on macOS Terminal/iTerm2).
- [ ] AC2 Terminal editor round-trip on Windows (Windows Terminal and conhost): console modes restored, TUI redrawn, prompt shown (manual checklist in `docs/manual-checks.md`; `test-os` runs the unit/integration parts).
- [ ] AC3 While a terminal program runs, courier-ftp reads no keys from stdin and Ctrl-C inside the program doesn't quit courier-ftp (e2e test sends Ctrl-C to a fake editor).
- [ ] AC4 A save by a GUI program (simulated by writing the watched file, including write-to-temp-and-rename) produces exactly one prompt within 3 s; writes with identical content produce none.
- [ ] AC5 Associations: first match wins, globs are case-insensitive, `%f` substitution and appending work (unit tests).
- [ ] AC6 Resolution order association → `editing.editor` → `$VISUAL` → `$EDITOR` → platform default for Edit, and association → `$PAGER`/`less` → platform opener for View, with GUI detection for known editors (unit tests).
- [ ] AC7 Conflict check blocks a silent overwrite when the remote size or mtime changed since download.
- [ ] AC8 Temp layout: dirs `0700`, files `0600` (View `0400`) on Unix; a pre-planted symlink at the edit dir is refused; temp dirs are removed on stop editing, on normal exit, and stale instances are found at startup.
- [ ] AC9 Quit with unuploaded edits shows the guard dialog; "keep" leaves exactly those files.
- [ ] AC10 Files above `editing.max_size_mib` ask before downloading; `0` never asks.
- [ ] AC11 Snapshot tests for every dialog in this task at 80×24 and 160×48.
- [ ] AC12 Canary scan (T91) finds no canary in edit temp dirs after the test suite; no paths/hostnames at `info`+ in logs.
- [ ] AC13 CI gates pass: `fmt`, `clippy -D warnings`, `docs`, `test-local-only`, `test-os`, `e2e`, `canary`.

## Tests

### Unit tests

- `fn association_first_match_wins` / `fn association_glob_case_insensitive` / `fn association_with_slash_matches_full_path` (AC5).
- `fn build_argv_substitutes_percent_f_as_one_arg` — path with spaces and quotes stays one argument (AC5).
- `fn build_argv_appends_path_without_placeholder`; `fn build_argv_rejects_unbalanced_quotes` (AC5).
- `fn resolve_edit_order_association_setting_visual_editor_default` — table with injected env and `which` (AC6).
- `fn resolve_known_gui_editor_from_env_is_not_terminal` — `EDITOR="code --wait"` → GUI (AC6).
- `fn resolve_view_text_uses_pager_then_less`, `fn resolve_view_binary_uses_platform_opener` (AC6).
- `fn editor_choice_json_is_snake_case` — `"auto"` and `{"command":{"command":"nvim","terminal":true}}` deserialise (AC6).
- `fn looks_like_text_cases` — UTF-8, NUL byte, cut multi-byte at 8 KiB boundary.
- `fn fingerprint_detects_same_length_same_mtime_change` — content differs, len and mtime forced equal (AC4).
- `fn temp_file_name_sanitised_and_capped_keeps_extension` (AC8).
- `#[cfg(unix)] fn temp_layout_permissions_and_symlink_refused` (AC8).
- `fn stale_instance_detected_when_lock_free` (AC8).
- `fn registry_state_machine` — Downloading → Watching → Modified → Uploading → Watching; Conflict; UploadFailed → retry.
- `fn debounce_coalesces_burst_into_one_event` — feeds synthetic notify events with paused time (AC4).

### Property / fuzz tests

- `proptest fn build_argv_never_splits_the_file_path` — any path string ends up as exactly one argv element equal to the path (AC5).

### Snapshot tests

Each at 80×24 and 160×48 (AC11): `snapshot_upload_prompt`, `snapshot_conflict_dialog`,
`snapshot_remote_deleted_dialog`, `snapshot_already_open_dialog`,
`snapshot_large_file_confirm`, `snapshot_edited_files_list`,
`snapshot_edited_files_list_empty`, `snapshot_quit_guard`,
`snapshot_stale_temp_files_dialog`, `snapshot_download_progress`.

### Integration tests

Using `MockBackend`, a mock `ForegroundRunner` that records `exit`/`run`/`enter`
calls and edits the file, and a real `notify` watcher on a temp dir:
- `fn terminal_edit_calls_exit_run_enter_in_order_and_prompts_on_change` (AC1).
- `fn terminal_edit_without_change_cleans_temp_dir` (AC8).
- `fn gui_edit_save_via_rename_prompts_once` — writes `x.tmp` then renames over the file (AC4).
- `fn gui_edit_identical_rewrite_no_prompt` (AC4).
- `fn poll_watcher_fallback_detects_change` — forced fallback, paused time not usable with real FS, so a 10 s `timeout()` poll (AC4).
- `fn upload_conflict_when_remote_size_changed` / `fn upload_when_remote_deleted_asks` (AC7).
- `fn auto_upload_skips_prompt_on_second_change`.
- `fn large_file_confirm_threshold` — 51 MiB asks at 50, `max_size_mib = 0` never asks (AC10).
- `fn quit_guard_keep_files_leaves_only_modified` (AC9).
- `fn edit_of_closed_tab_reuploads_with_stored_connect_info`.
- `fn local_file_edit_opens_directly_without_temp_copy`.

### End-to-end tests

`courier-ftp-e2e` (`#[ignore]`, `COURIER_E2E=1`), `PtyApp` with `EDITOR` set to a
fake editor script (`tests/fixtures/fake-editor.sh`: appends a line to `$1`, or
waits for a signal file):
- `fn e2e_edit_terminal_round_trip_sftp` — F4 on a remote file, fake editor appends,
  prompt appears, Upload, verify the content on the `sshd` `password` profile, screen
  shows the panes again (AC1).
- `fn e2e_ctrl_c_in_editor_does_not_quit` — fake editor waits; harness sends Ctrl-C;
  app still running after the editor exits (AC3).
- `fn e2e_edit_temp_dir_removed_after_exit` (AC8) and canary scan over the home (AC12).

Manual checks (`docs/manual-checks.md`): vim, nano and less on Linux (xterm, tmux),
macOS (Terminal, iTerm2), Windows (Windows Terminal, conhost with `notepad.exe`,
`nvim.exe`): redraw, resize while editing, Ctrl-Z inside vim then `fg` (Unix) (AC1, AC2).

## Out of scope

- Built-in viewer or editor inside the TUI.
- Diff/merge of conflicting versions (the conflict dialog only offers overwrite or cancel).
- Tracking the lifetime of GUI editor processes.
- OS file-type associations (`mimeapps.list`, Windows registry) beyond the platform opener.
- Secure erase of temp files.

## Open questions

1. Should FileZilla-style default associations ship (e.g. images → platform opener),
   or stay empty as specified?

Resolved (reconciliation): `Ctrl-x e` = `EditedFilesList` is in T51's table; T05
creates `EditorChoice` and `Association` in `courier_ftp_core::edit` for
`editing.editor` / `editing.associations` (snake_case JSON); `editing.max_size_mib` is
0–10240 with 0 = never ask.
