# T62 — File operations UI

**Phase:** F TUI · **Milestone:** M4 · **Depends on:** T03, T40, T41, T43, T46, T52, T53 · **Crate(s):** `courier-ftp` · **Decisions:** D6, D7 · **FEATURES.md:** §4

## Goal

The dialogs and flows behind every file operation started from a file list pane:
transfer (F5), queue only (Shift-F5), move (F6), rename (F2), make directory (F7 /
Shift-F7), new empty file, delete (F8), change permissions, copy URL, custom
command, manual transfer and refresh. Each operation works the same on the local
and the remote pane, greys out what the backend can't do, keeps both panes current
through listing-cache patches, and reports success or failure in the message log
and the status bar.

## Context

Before this task:
- T03 gives `Backend`, `Capabilities`, `SessionHandle`, `ConnectInfo`, `WriteMode`,
  `TransferOpts`; T06 gives `LocalBackend` (the local pane holds a `SessionHandle`
  over it, without keep-alive).
- T40 gives `Queue`, `QueueItem`, `QueueServer`, `Direction`, `Priority`,
  `TransferTypeChoice`; T41 gives `TransferEngine` and its command channel
  (`Start`, `Stop`, …); T43 gives the walker plus recursive delete and chmod; T46
  gives `ListingCache` with patch operations and `CoreEvent::ListingUpdated`.
- T52 gives the modal stack, widgets (`TextInput`, `PathInput`, `TriStateCheckbox`,
  `RadioGroup`, `Select`, `ProgressDialog`) and standard dialogs (`confirm` with
  `ConfirmOpts`, `message`, `error`, `prompt_text`, `choose`). Every destructive
  confirmation in this task uses `ConfirmOpts::danger(..)` (default and initial focus on
  the safe button).
- T43 gives `delete_recursive`, `chmod_recursive`, `ChmodSpec`, `ChmodScope` and
  `compute_mode` (the chmod rule); T40 gives `QueueItemKind` (`File`,
  `DirPlaceholder`, `RemoveSourceDir`) and `QueueItem.delete_source_after`.
- T50 gives `tabs::TabId(u32)`; T55 owns `crate::ui::clipboard` (OSC 52 + platform
  clipboard tools, sverb approach, 100 KiB cap, no `arboard`), which this task uses.
- T53 gives the file list pane (cursor, marked selection, `Entry` rows, address bar,
  quick filter) and emits operation actions; T51 provides the key bindings.

Later tasks use from this task:
- T63 adds "open in editor after creating" to the new-file dialog and reuses
  `FileOpsController::source()`.
- T65 and T66 reuse the transfer
  builder (`build_transfer_items`) and the delete flow. T45 relies on cache
  invalidation done here for its "refresh after queue".

## Technical specification

### Types and APIs

Module `crates/courier-ftp/src/file_ops/` (`mod.rs`, `source.rs`, `transfer.rs`,
`rename.rs`, `mkdir.rs`, `delete.rs`, `chmod.rs`, `url.rs`, `command.rs`,
`manual.rs`, `dialogs/*.rs`).

```rust
/// Which pane of a tab an operation starts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaneSide { Local, Remote }

/// A directory or file path on one side. The UI never mixes the two (T02).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PanePath { Local(LocalPath), Remote(RemotePath) }

/// Snapshot of what an operation acts on, taken when the key is pressed.
/// Later changes to the pane (navigation, refresh) don't affect a running operation.
#[derive(Debug, Clone)]
pub struct OpSource {
    pub tab: TabId,             // T50 `tabs::TabId(u32)`
    pub side: PaneSide,
    pub dir: PanePath,          // pane's current directory
    pub entries: Vec<Entry>,    // marked entries, or the cursor entry; never ".."
}

/// Every file operation this task implements (one `Action` variant each, T51).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FileOp {
    Transfer, QueueOnly, Move, Rename, Mkdir, MkdirEnter, NewFile, Delete,
    Chmod, CopyUrl, CopyUrlOptions, CustomCommand, ManualTransfer, Refresh,
}

/// Result reported to the log and status bar.
#[derive(Debug)]
pub enum OpOutcome {
    Done { summary: String },
    Partial { ok: usize, failed: Vec<(String, courier_ftp_core::Error)> },
    Cancelled { done: usize },
    Failed(courier_ftp_core::Error),
}

/// Why an operation is not available (shown instead of running it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unavailable {
    NotConnected,
    NothingSelected,
    Capability(&'static str),   // name of the missing `Capabilities` flag
    LocalPlatform(&'static str),// e.g. chmod on Windows
    VaultLocked,                // only for actions that need the vault
    Busy,                       // another blocking operation runs on this tab
}

/// Pure check used by the pane (to grey out menu entries) and before running.
pub fn availability(op: FileOp, side: PaneSide, caps: &Capabilities,
                    connected: bool, src: &OpSource) -> Result<(), Unavailable>;

/// Builds queue items for a transfer from `src` to `dest_dir` on the other side.
/// Files become `QueueItemKind::File` items; directories become
/// `QueueItemKind::DirPlaceholder` items with depth 0 (T40; T43 expands them lazily).
pub fn build_transfer_items(src: &OpSource, dest_dir: &PanePath, server: &QueueServer,
                            transfer_type: TransferTypeChoice,
                            delete_source_after: bool) -> Vec<QueueItem>;

// The new mode per entry is computed by T43 `compute_mode(old, ChmodSpec { value, mask })`
// (`(old & !mask) | (value & mask)`; unknown old mode → Some only for a full mask).
// This task does not duplicate it.

/// Parses the numeric chmod field: 3 or 4 characters, each `0-7` or `x`
/// (`x` = leave unchanged). Returns a T43 `ChmodSpec` (value and mask over 12 bits).
pub fn parse_mode_field(s: &str) -> Result<ChmodSpec, ModeFieldError>;
pub fn format_mode_field(spec: ChmodSpec, four_digits: bool) -> String;

/// Validates a single path component typed by the user for `side`.
pub fn validate_name(name: &str, side: PaneSide) -> Result<(), NameError>;

/// Builds the URL for a remote entry (see "Copy URL") with T02
/// `ServerAddress::to_url(&UrlOptions { password, path, force_port })`.
/// `PortChoice::Always` → `force_port = true`; `Never` → formats a copy of the address
/// with `port = None`; `PathChoice::ServerOnly` → `path = None`.
pub fn entry_url(addr: &ServerAddress, path: &RemotePath, opts: CopyUrlChoice,
                 password: Option<&SecretString>) -> SecretString;
/// Dialog choices (named `CopyUrlChoice` so it clashes neither with T02 `UrlOptions` nor
/// with the `CopyUrlOptions` action).
#[derive(Debug, Clone, Copy, Default)]
pub struct CopyUrlChoice { pub with_password: bool, pub with_port: PortChoice, pub path: PathChoice }
#[derive(Debug, Clone, Copy, Default)] pub enum PortChoice { #[default] IfNotDefault, Always, Never }
#[derive(Debug, Clone, Copy, Default)] pub enum PathChoice { #[default] Full, ServerOnly }

/// Commands rejected in the custom-command line (they would break the session state).
pub const BLOCKED_RAW_COMMANDS: &[&str] = &[
    "PASV", "EPSV", "PORT", "EPRT", "LIST", "NLST", "MLSD", "RETR", "STOR", "STOU",
    "APPE", "REST", "ABOR", "CWD", "CDUP", "XCWD", "XCUP", "QUIT", "REIN", "USER",
    "PASS", "AUTH", "PROT", "PBSZ", "CCC", "TYPE", "MODE", "STRU",
];

/// Owns per-tab operation state (custom-command history, busy flag) and runs flows.
pub struct FileOpsController { /* … */ }
impl FileOpsController {
    pub fn source(&self, pane: &FileListPane) -> Option<OpSource>;
    pub fn start(&mut self, op: FileOp, ctx: &mut OpContext) -> Vec<Action>;
}
```

`OpContext` gives the controller the tab's two `SessionHandle`s, `Capabilities`,
`ConnectInfo` (for URLs and queue servers), `Arc<ListingCache>`, the
`TransferEngine` command sender, `Arc<Mutex<Queue>>`, the `EventSender`, the
`Settings` snapshot and the T55 clipboard handle. Network work runs in spawned tasks that send
`Action::FileOpFinished { tab, op, outcome }` back (T50 §7); `update`/`draw` never await.

### Behaviour

#### Operation source

1. Marked entries of the focused pane if any; otherwise the entry under the cursor.
2. The `..` row is never part of a source. Cursor on `..` with nothing marked →
   status message "No files selected" (no dialog).
3. Quick-filtered-out entries are never part of the source even if marked earlier.
4. The source is copied into `OpSource` when the key is pressed.

#### Availability (checked before any dialog opens)

| Operation | Local pane | Remote pane |
|---|---|---|
| Transfer / QueueOnly | remote must be connected | — |
| Move (to other side) | remote connected | — |
| Move (same side, other dir) | always | `server_side_rename_across_dirs` |
| Rename (same dir) | always | always |
| Mkdir / MkdirEnter / NewFile / Delete / Refresh | always | connected |
| Chmod | Unix only (`LocalPlatform("chmod")` on Windows) | `chmod` |
| CopyUrl / CopyUrlOptions | always (copies native path) | connected |
| CustomCommand | not available (`LocalPlatform`) | `raw_commands` |
| ManualTransfer | always (opens dialog) | always |

An unavailable operation shows a `message` dialog with the reason, e.g.
"This server does not support changing permissions (SFTP server without
SETSTAT, or FTP server without SITE CHMOD)." and logs nothing. It never fails silently.

While a blocking operation (delete, chmod, mkdir chain, new file) runs on a tab's
browsing session, other operations on that tab return `Unavailable::Busy`
("Wait for the current operation to finish or press Esc to cancel it").
Navigation in the pane is still possible from the cache; uncached listings wait
on the session mutex and show the spinner.

#### 1. Transfer (F5) and queue only (Shift-F5)

Direction follows the focused pane: local → remote is an upload, remote → local
a download. Destination = the other pane's current directory.

Flow:
1. Availability check (remote connected).
2. If `interface.confirm_transfer` (bool, default `false`) is on, or the transfer
   type must be chosen (action invoked from the menu with "Transfer…"), show the
   transfer dialog:
   ```
   ┌ Upload ──────────────────────────────────────────────────────┐
   │ Upload 3 files and 1 directory (12.4 MiB, plus directory     │
   │ contents counted when the queue reaches them)                │
   │                                                              │
   │ From: ~/projects/site                                        │
   │ To:   sftp://alice@web01.example.com/var/www                 │
   │                                                              │
   │ Transfer type:  (•) Auto   ( ) ASCII   ( ) Binary            │
   │ [ ] Add to queue only (don't start processing)               │
   │                                                              │
   │                   [ Upload ]    [ Cancel ]                   │
   └──────────────────────────────────────────────────────────────┘
   ```
   Title is "Download" for downloads. Shift-F5 pre-ticks "Add to queue only".
   On SFTP the transfer-type row is disabled with "(SFTP always transfers binary)"
   (`Capabilities::ascii_mode == false`).
3. `build_transfer_items` creates one `QueueItem` per entry:
   `priority = Normal`, `on_exists = None` (engine defaults from
   `transfers.on_exists_*`, T42), `transfer_type` from the dialog or
   `file_types.default_type`, `size = entry.size`, `state = Queued`,
   `kind = QueueItemKind::DirPlaceholder(..)` (depth 0) when `entry.kind == Dir`,
   otherwise `QueueItemKind::File` (symlinks to dirs follow
   `transfers.follow_symlinks`; when false a symlinked dir is skipped with a log line).
   `QueueServer` = the tab's site id, or the inline quickconnect address.
4. `Queue::add_batch(items)`; unless queue-only, send `Start` to the engine.
5. Status message: "Queued 4 items (12.4 MiB)"; log `Status:` line with the same text.
6. Both panes stay as they are; when items finish the engine's cache patches
   (T46) update the destination pane via `ListingUpdated`.

Hostile names: an entry whose name contains `/`, NUL, a control character, or is
`.`/`..` is skipped with an `Error:` log line ("Skipped entry with an invalid
name") — T91 hostile-server rule. Local names on download go through
`sanitize_local_name` in the engine (T42), not here.

There is no remote → remote or local → local transfer: the other pane of a tab is
always the other side.

#### 2. Move (F6)

```
┌ Move 2 files ─────────────────────────────────────────────────┐
│ Destination:                                                  │
│  (•) Other side: /var/www  (transfer, then delete the source) │
│  ( ) This side:  [~/projects/site/old________________]        │
│                                                               │
│ The source files are deleted only after their transfer        │
│ finished successfully.                                        │
│                     [ Move ]    [ Cancel ]                    │
└───────────────────────────────────────────────────────────────┘
```
- **Other side**: like Transfer with `delete_source_after = true` on each item
  (T40 `QueueItem.delete_source_after`); the engine deletes the source after state
  `Done` (T41). Directory placeholders propagate the flag to expanded children; T43
  appends a `QueueItemKind::RemoveSourceDir` item that removes (`rmdir`) the source
  directory only when it is empty after its children were moved. Failed items keep
  their source.
- **This side**: a `PathInput` (local completion, or remote completion via the
  pane's cached listings) prefilled with the current directory. Each entry is
  renamed to `<dest>/<name>` with `rename`. The destination directory must exist
  (`stat` first → `NotFound` → error "Destination directory does not exist").
  On remote, requires `server_side_rename_across_dirs`; else the option is
  disabled with a reason line.
- A destination equal to the current directory is rejected inline ("Source and
  destination are the same").

#### 3. Rename (F2)

Dialog (inline list editing is out of scope):
```
┌ Rename ──────────────────────────────────────────────┐
│ New name: [index.html_______________________]        │
│                                                      │
│               [ Rename ]    [ Cancel ]               │
└──────────────────────────────────────────────────────┘
```
- Acts on the cursor entry only (marked entries are ignored, status message says so
  when more than one is marked).
- Initial selection covers the stem (`index` of `index.html`); dotfiles and
  directories select the whole name.
- Input containing `/` is a relative or absolute path: the target is
  `dir.resolve(input)` (T02 `RemotePath::resolve`); the parent of the target must exist; on
  remote a different parent requires `server_side_rename_across_dirs`.
- Unchanged name → dialog closes with no action.
- Target exists (checked in the current cached listing, and `rename(from, to,
  replace = false)` failing with `AlreadyExists`) → `confirm("Overwrite?", "\"x\"
  already exists. Replace it?", ConfirmOpts::danger("Overwrite"))`; on Yes call
  `rename(from, to, replace = true)` (T03); if the backend cannot replace (T14/T22:
  `AlreadyExists` again), remove the target file and retry with `replace = false`.
  Never a directory: renaming onto an existing directory is an error "A directory
  with that name exists".
- Case-only rename on a case-insensitive local filesystem (Windows, macOS default):
  rename via a temporary name `<name>.courier-tmp-<4 random hex>` then to the final
  name.
- Cache: `rename` patch (T46) on success; cursor moves to the new name.

#### 4. Make directory (F7) and make directory and enter it (Shift-F7)

```
┌ Create directory ────────────────────────────────────┐
│ Please enter the name of the directory which should  │
│ be created:                                          │
│ [/var/www/New directory_____________________]        │
│                                                      │
│               [ Create ]    [ Cancel ]               │
└──────────────────────────────────────────────────────┘
```
- Prefilled with `<current dir>/New directory` (FileZilla), with `New directory`
  selected so typing replaces it.
- Relative input is resolved against the current directory; absolute input is used
  as is. Normalised by `RemotePath` / `LocalPath` rules.
- **mkdir -p semantics**: for each missing component from the deepest existing
  ancestor down: `mkdir`. The deepest existing ancestor is found from the cache
  first, then by `stat` from the target upwards (at most 32 components; deeper
  paths are rejected with `InvalidInput`). `AlreadyExists` on an intermediate
  component is not an error.
- Local: `create_dir_all` semantics through the same backend calls.
- Success: cache `mkdir` patch per created component, cursor on the new directory;
  Shift-F7 then navigates into it.
- Target already exists as a directory → status "Directory already exists" (Shift-F7
  still enters it). Exists as a file → error.

#### 5. Create new empty file (`Ctrl-x n`)

```
┌ Create empty file ───────────────────────────────────┐
│ File name: [new file.txt____________________]        │
│                                                      │
│               [ Create ]    [ Cancel ]               │
└──────────────────────────────────────────────────────┘
```
- Name validated with `validate_name`; existing name (cache or `stat` OK) → inline
  error "A file with that name already exists".
- Remote: `open_write(path, WriteMode::Create, &TransferOpts::default())` (Binary),
  shut down the writer without data, `finish_transfer()`. Local: same through
  `LocalBackend`. Cache insert patch with size 0. Cursor on the new file.
- T63 adds a checkbox "Open in editor after creating".

#### 6. Delete (F8 / Delete)

```
┌ Delete ──────────────────────────────────────────────────────┐
│ Really delete 3 files and 2 directories from the server?     │
│ Directories are deleted with all their contents.             │
│                                                              │
│   assets/                                                    │
│   build/                                                     │
│   index.html                                                 │
│   style.css                                                  │
│   main.js                                                    │
│   … and 0 more                                               │
│                                                              │
│                  [ Delete ]    [ Cancel ]                    │
└──────────────────────────────────────────────────────────────┘
```
- Local wording: "Really delete … permanently from this computer?" (no trash, see
  Open questions). The dialog is `confirm(.., ConfirmOpts::danger("Delete"))` (T52):
  the default button is **Cancel**; `Enter` on the opened dialog cancels, `d` /
  `Alt-d` or moving to *Delete* confirms.
- Up to 5 names listed (sanitised for display, T53 control-char rule), then
  "… and N more" (line omitted when N = 0).
- `interface.confirm_delete = false` skips the dialog.
- Files only: `remove_file` each, sequentially on the browsing session.
- Any directory: T43 `delete_recursive(session, targets, RecursiveCtx { .. })`
  (post-order; filters from T47 applied when `filters.apply_to_transfers` is on —
  filtered entries and their parents stay; result `DeleteReport`).
  A `ProgressDialog` appears if the operation is still running after 300 ms:
  ```
  ┌ Deleting ────────────────────────────────────────────┐
  │ Deleting /var/www/build/assets/img/logo.png          │
  │ 1 204 files and 37 directories deleted               │
  │ ███████████████░░░░░░░░░░░░░░  (unknown total)       │
  │                     [ Cancel ]                       │
  └──────────────────────────────────────────────────────┘
  ```
  The bar is indeterminate (the walker doesn't know the total). Cancel / Esc trips
  the operation's `CancellationToken`; the current backend call finishes, nothing
  further is deleted; outcome `Cancelled { done }`.
- Partial failure → error dialog "Deleted 1 241 entries, 3 could not be deleted:"
  with up to 10 paths and reasons, full list in the log.
- Cache: `remove` patch per deleted file, dropped subtree for deleted directories
  (T46); the pane re-renders from `ListingUpdated`.

#### 7. Change permissions (`c`)

```
┌ Change file attributes ───────────────────────────────────────┐
│ Please select the new attributes for the 2 selected entries.  │
│                                                               │
│ Owner permissions:   [x] Read   [x] Write   [ ] Execute       │
│ Group permissions:   [x] Read   [-] Write   [ ] Execute       │
│ Public permissions:  [x] Read   [ ] Write   [ ] Execute       │
│                                                               │
│ Numeric value: [6x4_]   (x = keep the current value)          │
│                                                               │
│ [x] Recurse into subdirectories                               │
│     (•) Apply to all files and directories                    │
│     ( ) Apply to files only                                   │
│     ( ) Apply to directories only                             │
│                                                               │
│                  [ OK ]    [ Cancel ]                         │
└───────────────────────────────────────────────────────────────┘
```
- 9 `TriStateCheckbox`es (`[x]` on, `[ ]` off, `[-]` unchanged). `Space` cycles
  on → off → unchanged → on; the unchanged state is offered only when the dialog
  opened with mixed values for that bit or the user typed `x`.
- Initial state per bit: on if set on every entry with known permissions, off if
  clear on all, unchanged if mixed. Entries with `permissions: None` don't
  contribute; if no entry has known permissions every bit starts unchanged and the
  numeric field shows `xxx`.
- **Numeric field** (`parse_mode_field`): 3 characters (`rwx` triples) or 4 (leading
  digit = setuid 4 / setgid 2 / sticky 1). Each character `0`–`7` or `x`. With 3
  characters, the special bits are unchanged (mask excludes `0o7000`). Editing the
  checkboxes rewrites the field and vice versa on every keystroke; invalid input
  shows an inline error and disables OK.
- The recursion block appears only if the source contains a directory; the radio
  group is enabled only when "Recurse" is ticked.
- Apply: for each target entry T43 `compute_mode(old, spec)`; `None` (unknown old
  mode with partial mask) → entry skipped and counted, log `Error:` "Permissions of
  X are unknown; set all bits or none to change them". If the computed mode equals
  the old mode, no call is made.
- Non-recursive: `chmod` each selected entry. Recursive: T43 `chmod_recursive(session,
  targets, spec, scope, recurse = true, ctx)` with the chosen `ChmodScope` (`All`,
  `FilesOnly`, `DirsOnly`; selected directories themselves are included unless
  `FilesOnly`).
- Cache: `chmod` patch per entry.

#### 8. Copy URL (`y u`) and copy URL with options (`y U`)

- Remote pane, default (`y u`): one URL per source entry, newline-separated:
  `scheme://user@host[:port]/path`, port included only if not the protocol default,
  user and path percent-encoded (T02 `ServerAddress` `Display` rules), directories
  end with `/`. Anonymous FTP omits the user. IPv6 literals in brackets.
- `y U` opens:
  ```
  ┌ Copy URL ───────────────────────────────────────────┐
  │ (•) Full URL         ( ) Server only (no path)      │
  │ Port:  (•) If not default  ( ) Always  ( ) Never    │
  │ [ ] Include password                                │
  │               [ Copy ]    [ Cancel ]                │
  └─────────────────────────────────────────────────────┘
  ```
  "Include password" is disabled when the connection has no password in memory.
  Ticking it shows a second `confirm` ("The clipboard will contain your password.
  Other programs can read it.", `ConfirmOpts::danger("Include")`).
- Local pane: copies native absolute paths (one per line), no URL.
- Clipboard: the text goes through T55's `crate::ui::clipboard` (OSC 52 over SSH,
  otherwise the platform tool with OSC 52 fallback; 100 KiB cap; tool on a background
  thread). This task does not implement a clipboard. When T55 reports that the text
  was truncated, the status message says "Clipboard text truncated"; a clipboard
  error becomes the status message `Could not copy: <reason>`.
- Status message "Copied 3 URLs to the clipboard" (3 s, T57). The copied text is
  never logged.

#### 9. Custom command (`:`)

```
│ Remote: /var/www ─────────────────────────────────────────── │
│ ...                                                          │
│:SITE CHMOD 755 deploy.sh█                                    │
```
- A single-line `TextInput` replaces the status bar (mode `Input`, T50). Up/Down
  walk the per-tab history (last 50 commands, in memory only, never persisted —
  commands may contain secrets), `Esc` cancels, `Enter` sends.
- The first word (case-insensitive) in `BLOCKED_RAW_COMMANDS` → status error
  "PASV can't be sent manually: it would break the connection state" and the line
  stays open for editing. Empty input closes the line.
- Sent with `SessionHandle::raw_command` on the browsing session (timeout
  `connection.timeout_secs`). The backend logs `Command:` (masked by T04
  `mask_command`) and `Response:` lines; the first line of the returned reply is
  also shown as a 3 s status message.
- After every accepted command the remote pane's current directory is invalidated in
  the cache and re-listed (a `SITE CHMOD`, `DELE` or `MKD` may have changed it).

#### 10. Manual transfer (`Ctrl-x m`)

```
┌ Manual transfer ──────────────────────────────────────────────┐
│ Direction:   (•) Download   ( ) Upload                        │
│ Local file:  [~/Downloads/backup.tar.gz___________________]   │
│ Remote file: [/var/backups/backup.tar.gz__________________]   │
│                                                               │
│ Server:      (•) Current connection (sftp://alice@web01)      │
│              ( ) Site: [Work/Production/db01          ▾]      │
│ Transfer type: (•) Auto  ( ) ASCII  ( ) Binary                │
│ [x] Start transfer now                                        │
│                                                               │
│                  [ OK ]    [ Cancel ]                         │
└───────────────────────────────────────────────────────────────┘
```
- Prefill: remote file = remote pane dir + cursor entry name (if a remote file is
  under the cursor), local file = local pane dir + same name.
- "Current connection" is disabled when the tab is not connected. "Site" needs the
  vault unlocked (T30); when locked the option shows "(unlock the vault to choose a
  site)" and an `[ Unlock vault ]` button next to it calls `App::request_unlock()`
  (T60). (`Ctrl-u` is not used: in text fields it deletes to the start of the line.)
- Validation: upload → local file exists and is a regular file; download → local
  parent directory exists and the local path is not an existing directory; remote
  path non-empty, relative paths resolved against the remote pane's directory.
- Creates one `QueueItem` with `size = None` (or the local size for uploads); with
  "Start transfer now" sends `Start`.

#### 11. Refresh (`Ctrl-r`)

Invalidate the cache entries of both panes' current directories and list both
again (bypass cache, T46). The cursor stays on the same name if it still exists,
otherwise on the nearest row index.

#### 12. Reporting

Every finished operation writes one `LogMessage` with `LogKind::Status` (success)
or `LogKind::Error` (failure) to the tab's session log (T04/T55), e.g.
`Status: Created directory /var/www/new`, and a transient status-bar message (T57,
3 s). Paths appear in the session log (user-facing) but never in `tracing` output
at `info`+.

### Data formats and configuration

| Key | Type | Default | Used for |
|---|---|---|---|
| `interface.confirm_transfer` | bool | `false` | show the transfer dialog on F5 |
| `interface.confirm_delete` | bool | `true` | show the delete confirmation |
| `file_types.default_type` | `TransferTypeChoice` | `Auto` | transfer type in built items |
| `transfers.follow_symlinks` | bool | `false` | symlinked dirs in transfer sources |
| `filters.apply_to_transfers` | bool | `true` | recursive delete/chmod skip filtered entries (T67) |
| `connection.timeout_secs` | u32 | `20` | custom command timeout |

New `Action` variants (serialised names for the keymap, T51): `Transfer`,
`QueueOnly`, `Move`, `Rename`, `Mkdir`, `MkdirEnter`, `NewFile`, `Delete`,
`Chmod`, `CopyUrl`, `CopyUrlOptions`, `CustomCommand`, `ManualTransfer`,
`Refresh`, plus internal `FileOpFinished { tab, op, outcome }`.

Default bindings (T51 table; the two marked * are added there by this task):

| Key | Action | Mode |
|---|---|---|
| `F5` | Transfer | FileList |
| `Shift-F5` | QueueOnly | FileList |
| `F6` | Move | FileList |
| `F2` | Rename | FileList |
| `F7` / `Shift-F7` | Mkdir / MkdirEnter | FileList |
| `Ctrl-x n` * | NewFile | FileList |
| `F8` / `Delete` | Delete | FileList |
| `c` | Chmod | FileList |
| `y u` / `y U` | CopyUrl / CopyUrlOptions | FileList |
| `:` | CustomCommand | FileList |
| `Ctrl-x m` * | ManualTransfer | Normal |
| `Ctrl-r` | Refresh | Normal |

### Errors

| Situation | Core error | What the user sees |
|---|---|---|
| Name invalid (empty, `/`, NUL, control chars, `.`/`..`, > 255 bytes; on Windows also `\ : * ? " < > \|` and reserved names) | `NameError` (UI) | inline error under the field; OK disabled |
| Target exists | `Error::AlreadyExists` | inline error or overwrite confirm (rename) |
| Path missing | `Error::NotFound(path)` | error dialog "… does not exist"; pane refreshed |
| Permission denied | `Error::PermissionDenied` | error dialog "Permission denied: …" |
| Server reply error | `Error::Protocol { code, message }` | error dialog with code and server text (control chars stripped) |
| Capability missing at call time | `Error::Unsupported(_)` | message dialog (same text as the pre-check) |
| Timeout / connection lost | `Error::Timeout`, `Error::Connection` | `SessionHandle` reconnects once (T03); if it still fails: error dialog, tab shows disconnected |
| User cancelled | `Error::Cancelled` | status "Cancelled after N entries" |
| Vault locked (manual transfer to a site) | `Error::VaultLocked` | the Site option shows the unlock button; no queue item |
| Clipboard tool failed | — | T55 falls back to OSC 52; debug log only |

### Security and logging

- `tracing` events from this module: operation kind, counts, durations and error
  kinds at `debug`; never paths, hostnames or user names at `info`+ (T91 §4).
- The session log (T55) shows paths as FileZilla does; command lines go through
  `mask_command` (T04).
- Copy URL with password: password exists only in a `SecretString` until it is handed
  to T55's clipboard (which keeps its payload buffer in `Zeroizing<Vec<u8>>`); the text
  is never logged.
- Server-provided names are displayed only after control-character stripping
  (T53); names that can't be valid path components are never used to build paths.
- Custom command history stays in memory and is dropped with the tab.

## Implementation steps

1. `file_ops` module skeleton: `PaneSide`, `PanePath`, `OpSource`, `FileOp`,
   `OpOutcome`, `Unavailable`, `availability()`, `validate_name()`; new `Action`
   variants and default bindings; unit tests.
2. `FileOpsController` with the async task pattern and `FileOpFinished` reporting
   (log + status message); Refresh as the first operation.
3. Transfer and queue-only: `build_transfer_items`, transfer dialog,
   `interface.confirm_transfer`, engine `Start`.
4. Mkdir / MkdirEnter with mkdir -p and cache patches; new empty file.
5. Rename dialog (stem selection, path targets, overwrite confirm, case-only rename).
6. Delete: confirmation, file deletes, recursive delete with delayed
   `ProgressDialog`, cancel, partial-failure report.
7. Chmod: `parse_mode_field`, `format_mode_field` (over T43 `ChmodSpec`), tri-state
   dialog, `compute_mode` / `chmod_recursive` from T43, recursive scope.
8. Move: other side (`delete_source_after`) and this side (rename into dir).
9. Copy URL (default and options) through T55's `ui::clipboard`.
10. Custom command line with history and blocked commands.
11. Manual transfer dialog.
12. Snapshot tests for every dialog at both sizes; UI-flow tests; e2e scenario.

## Acceptance criteria

- [ ] AC1 Every operation in §1–§11 works on the local pane (temp dir) and the remote pane (`MockBackend`) and both panes show the result without a manual refresh (cache patches + `ListingUpdated`).
- [ ] AC2 Each operation whose capability is missing (table above) shows the explanatory message and makes no backend call (mock call counter = 0).
- [ ] AC3 F5 on 3 files + 1 directory adds exactly 3 file items and 1 placeholder item with correct local/remote paths and direction; Shift-F5 adds them without sending `Start`.
- [ ] AC4 Mkdir of `a/b/c` where only `a` exists issues exactly 2 `mkdir` calls in order `a/b`, `a/b/c`.
- [ ] AC5 Delete confirmation defaults to Cancel; `interface.confirm_delete = false` skips it; recursive delete can be cancelled within 1 s and reports how many entries were deleted.
- [ ] AC6 `parse_mode_field` matches the table tests (including `x` digits and 4-digit special bits); the dialog builds the `ChmodSpec` passed to T43 `compute_mode`/`chmod_recursive` (entries with unknown mode and a partial mask are skipped); the dialog's checkboxes and numeric field stay in sync.
- [ ] AC7 Rename onto an existing file asks before overwriting; rename onto an existing directory is refused; case-only rename works on a case-insensitive filesystem (macOS/Windows CI job `test-os`).
- [ ] AC8 Copy URL produces the exact strings in the URL table test; the password is included only after the extra confirm; copied text never appears in logs (canary test).
- [ ] AC9 Copy URL hands its text to T55's `ui::clipboard` (no other clipboard code in `file_ops`, checked by `grep -r "osc52\|wl-copy\|pbcopy" crates/courier-ftp/src/file_ops` → empty) and shows "Clipboard text truncated" when T55 reports truncation. Manual check: in tmux 3.x with `set-clipboard on`, `y u` puts the URL into the outer terminal's clipboard.
- [ ] AC10 Blocked raw commands are refused without a backend call; an accepted command's reply appears in the log and the remote pane is re-listed.
- [ ] AC11 Manual transfer validates its fields and queues one item with the chosen transfer type.
- [ ] AC12 Hostile entry names (`../x`, `a/b`, ESC sequences) in a source are skipped and never reach a backend call or the terminal unescaped.
- [ ] AC13 Snapshot tests exist for every dialog in this task at 80×24 and 160×48.
- [ ] AC14 CI gates pass: `fmt`, `clippy -D warnings`, `docs`, `test-local-only`, `test-os`.

## Tests

### Unit tests

- `fn availability_table_matches_capabilities` — every `FileOp` × side × capability flag combination against the table (AC2).
- `fn source_uses_marked_entries_else_cursor_and_never_dotdot` (AC1).
- `fn validate_name_rejects_slash_nul_control_dot_dotdot_and_long_names`; `#[cfg(windows)] fn validate_name_rejects_windows_reserved_names_case_insensitive` (AC12).
- `fn build_transfer_items_files_and_dir_placeholder` — 3 files + 1 dir → 4 items, paths joined correctly, 3 × `QueueItemKind::File` and 1 × `QueueItemKind::DirPlaceholder` with depth 0 (AC3).
- `fn build_transfer_items_skips_hostile_names` (AC12).
- `fn build_transfer_items_sets_delete_source_after_for_move`.
- `fn parse_mode_field_table` — `"644"`, `"6x4"`, `"0755"`, `"4755"`, `"xxx"`, `"x7"` (error), `"8"` (error), `"77777"` (error) (AC6).
- `fn chmod_dialog_builds_spec_and_skips_unknown_partial` — tri-state bits → `ChmodSpec`; with T43 `compute_mode`, an entry with `permissions: None` and a partial mask is skipped and counted (AC6).
- `fn initial_tristate_from_mixed_entries` (AC6).
- `fn entry_url_table` — SFTP default port omitted, FTP port 2121 kept, anonymous FTP, IPv6 literal, user with `@`, path with spaces and `#`, directory trailing slash, server-only, with password (AC8).
- `fn copy_url_goes_through_ui_clipboard_and_reports_truncation` — fake clipboard handle records the text; a truncated report produces the status message (AC9).
- `fn blocked_raw_commands_case_insensitive` (AC10).
- `fn mkdir_plan_creates_missing_components_only` — pure planner over a fake "exists" oracle (AC4).
- `fn rename_target_parsing_relative_absolute_and_parent_dir`.

### Property / fuzz tests

- `proptest fn mode_field_roundtrip` — for any `ChmodSpec { value, mask }` over 12 bits, `parse_mode_field(&format_mode_field(spec, true)) == ChmodSpec { value: value & mask, mask }` (AC6).
  (`compute_mode` properties are tested in T43.)

### Snapshot tests

All with ratatui `TestBackend` + `insta`, each at 80×24 and 160×48 (AC13):
`snapshot_transfer_dialog_upload`, `snapshot_transfer_dialog_download_sftp_type_disabled`,
`snapshot_move_dialog`, `snapshot_rename_dialog`, `snapshot_mkdir_dialog`,
`snapshot_new_file_dialog`, `snapshot_delete_confirm_remote_many`,
`snapshot_delete_confirm_local`, `snapshot_delete_progress`,
`snapshot_delete_partial_failure`, `snapshot_chmod_single`, `snapshot_chmod_mixed_tristate_recursive`,
`snapshot_copy_url_options`, `snapshot_custom_command_line`,
`snapshot_manual_transfer_vault_locked`, `snapshot_unsupported_chmod_message`.

### Integration tests

UI-flow tests drive the app with scripted key events against `MockBackend` (with
call counters and optional latency) and a `LocalBackend` in a `tempfile::TempDir`:
- `fn f5_queues_and_starts_engine` / `fn shift_f5_queues_without_start` (AC3).
- `fn mkdir_nested_creates_two_dirs_and_patches_cache` (AC4, AC1).
- `fn shift_f7_enters_created_dir`.
- `fn delete_enter_on_dialog_cancels` / `fn delete_confirmed_removes_and_updates_pane` / `fn delete_without_confirm_setting` (AC5, AC1).
- `fn recursive_delete_cancel_within_1s` — mock with 50 ms latency per call, `tokio::time::pause`, cancel after 200 ms, assert `Cancelled { done }` and no calls after cancel (AC5).
- `fn recursive_delete_partial_failure_lists_remaining` (AC5).
- `fn chmod_dialog_keys_update_numeric_field` and `fn chmod_recursive_files_only_calls` (AC6).
- `fn rename_overwrite_prompt_and_dir_refused` (AC7); `#[cfg(any(windows, target_os = "macos"))] fn rename_case_only_local` (AC7).
- `fn move_other_side_sets_flag_and_this_side_renames` (AC1).
- `fn unsupported_chmod_on_mock_without_capability_makes_no_call` (AC2).
- `fn custom_command_blocked_and_accepted` (AC10).
- `fn manual_transfer_validation_and_queue` (AC11).
- `fn copy_url_with_password_requires_confirm` + canary log scan (AC8).
- `fn hostile_names_from_mock_listing_skipped` (AC12).

### End-to-end tests

In `courier-ftp-e2e` (`#[ignore]`, `COURIER_E2E=1`, T76), `PtyApp` against the
`proftpd` profile (MLSD + `SITE CHMOD`) and the `sshd` `password` profile:
- `fn e2e_file_ops_round_trip` — F7 create dir, F5 upload a file into it, `c` set
  `600`, F2 rename, F8 delete the dir recursively; verify each step on the server
  through `Headless` listing (AC1).

Manual check (AC9): tmux clipboard with `set-clipboard on`, documented in
`docs/manual-checks.md`.

## Out of scope

- Remote → remote transfers (between two servers) and server-side copy.
- Inline rename inside the list (dialog only in v1).
- Drag and drop (D7: keyboard only; OS drag and drop dropped by D8).
- Moving local files to the OS trash/recycle bin (see Open questions).
- Persisting the custom-command history.

## Open questions

1. **Local delete to trash**: FileZilla on Windows uses the recycle bin. Should
   local deletes go to the OS trash (`trash` crate) instead of deleting
   permanently? Current spec: permanent delete with explicit wording.

Resolved (reconciliation): `QueueItem.delete_source_after` and
`QueueItemKind::RemoveSourceDir` exist in T40/T43; recursive delete/chmod use T43's
`delete_recursive`/`chmod_recursive`/`compute_mode`; `filters.apply_to_transfers` is a T05
key; the clipboard is T55's `ui::clipboard`.
