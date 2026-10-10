# T56 — Queue pane

**Phase:** F TUI · **Milestone:** M4 · **Depends on:** T40, T41, T50, T51, T52 · **Crate(s):** `courier-ftp` (`components/queue/`) · **Decisions:** D6, D7, D8, D11 · **FEATURES.md:** §5 (queue tabs, process/pause/stop, reorder, priority, reset and requeue, progress, file-exists action, action after completion)
**Related (integrates with, not blocking):** T45, T57

## Goal

Show and control the transfer queue with FileZilla's three tabs — queued, failed and
successful transfers — grouped by server, with live progress for active transfers.
Every queue and engine control is reachable from the keyboard and from a context
menu, and the pane stays responsive with 100 000 queued items.

## Context

**Before this task:** T40 provides `QueueItem` (`id: TransferId`, `server:
QueueServer`, `direction: Direction`, `local: LocalPath`, `remote: RemotePath`,
`size`, `transfer_type`, `priority: Priority`, `on_exists: Option<ExistsAction>`,
`state: ItemState`, `attempts`, `added_at`, `kind: QueueItemKind` — directory
placeholders are `QueueItemKind::DirPlaceholder`, there is no `is_dir_placeholder`
field), the three lists, all queue operations, the read-only `QueueView` trait and the
`QueueServerKey` grouping key (both defined in T40), statistics and import/export.
T41 provides `TransferEngine` with the `EngineCommand`s `Start`, `Stop`, `PauseAll`,
`ResumeAll`, `Pause(ids)`, `Resume(ids)`, `Cancel { ids, remove }`, `SettingsChanged`, and `CoreEvent::TransferProgress` /
`TransferStateChanged` / `QueueFinished` (coalesced by T04). T50 provides focus
(`FocusQueue`, `g q`, `ctrl-x 7`), layout and the queue toggle (`ToggleQueuePane`,
`ctrl-x j`), `ui::text::sanitize`, `ui::symbols::Symbols` and `Action::StatusMessage`;
T51 the `Queue` keymap mode; T52 the `ListView` popup menu, `confirm`, `prompt_text`
and `RadioGroup`.

**Later tasks need from it:** T45 (one-shot/always completion action chosen in the
context menu), T62 (F5/Shift-F5 add items and show them here), T57 (shares the
queue summary).

## Technical specification

### Types and APIs

Module `crates/courier-ftp/src/components/queue/` (`mod.rs`, `state.rs`, `rows.rs`,
`render.rs`, `menu.rs`).

```rust
/// The three FileZilla tabs, the read-only view and the grouping key come from T40.
pub use courier_ftp_core::queue::{QueueTab, QueueView, QueueServerKey};
/// Server grouping key (`QueueServer` → stable key: site item id or the server identity).
pub type GroupKey = QueueServerKey;

/// One display row. Item details are looked up by id at draw time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueRow {
    Group { group: u32 },            // index into `QueueRows::groups`
    Item { id: TransferId },
    Progress { id: TransferId },     // second line of an active item
}

/// Row model for one tab; rebuilt only on structural changes.
#[derive(Debug, Default)]
pub struct QueueRows {
    pub tab: QueueTab,
    pub rows: Vec<QueueRow>,
    pub groups: Vec<GroupHeader>,
    pub version: u64,                // the queue version it was built from
}
#[derive(Debug, Clone)]
pub struct GroupHeader { pub key: GroupKey, pub label: String /* sanitised URL without password */,
                         pub files: u64, pub bytes: u64, pub collapsed: bool }

/// Latest progress per active item (from coalesced `TransferProgress`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ProgressInfo { pub bytes_done: u64, pub total: Option<u64>, pub speed_bps: u64,
                          pub eta: Option<Duration>, pub started: Instant }

/// Pure pane state.
#[derive(Debug, Default)]
pub struct QueuePaneState {
    pub tab: QueueTab,
    pub rows: Arc<QueueRows>,
    pub cursor: usize,
    pub offset: usize,
    pub marks: HashSet<TransferId>,
    pub visual_anchor: Option<usize>,
    pub collapsed: HashSet<GroupKey>,
    pub progress: HashMap<TransferId, ProgressInfo>,  // ≤ active transfers
    pub menu: Option<QueueMenu>,
    pub totals: QueueTotals,
}
#[derive(Debug, Clone, Copy, Default)]
pub struct QueueTotals { pub queued: u64, pub failed: u64, pub successful: u64,
                         pub bytes: u64, pub down_bps: u64, pub up_bps: u64, pub eta: Option<Duration> }

/// What the pane asks the app to perform (mapped 1:1 in the table below).
#[derive(Debug, Clone)]
pub enum QueueRequest {
    Queue(QueueOp),                    // T40 operation on the shared queue
    Engine(EngineCommand),             // T41 command
    SetCompletionAction { action: OnComplete, always: bool }, // T45
    Export, Import,                    // T40 §5 (file dialogs via T52 PathInput)
}
#[derive(Debug, Clone)]
pub enum QueueOp {
    PauseToggle(Vec<TransferId>),
    SetPriority(Vec<TransferId>, Priority),
    RaisePriority(Vec<TransferId>), LowerPriority(Vec<TransferId>),
    MoveUp(Vec<TransferId>), MoveDown(Vec<TransferId>), MoveTop(Vec<TransferId>), MoveBottom(Vec<TransferId>),
    Remove(Vec<TransferId>),
    ResetAndRequeue(Vec<TransferId>),
    ClearFailed, ClearSuccessful, ClearSuccessfulSelected(Vec<TransferId>),
    SetExistsAction(Vec<TransferId>, Option<ExistsAction>),  // None = use default
}

impl QueuePaneState {
    pub fn reduce(&mut self, input: QueueInput, view: &dyn QueueView) -> Vec<QueueRequest>;
    /// The ids the next command applies to: marked items, else the cursor item, else
    /// (cursor on a group header) every item of that group in the current tab.
    pub fn target_ids(&self, view: &dyn QueueView) -> Vec<TransferId>;
}

// `QueueView` (T40) is the pane's only read access to the queue: a structural
// version counter, the rows of one tab with collapsed groups, item lookup by id and
// statistics. This task does not define it.
```

`QueueInput` = keymap commands (table below) plus `Progress(TransferId, ProgressInfo)`,
`StateChanged(TransferId, ItemState)`, `QueueChanged { version }`, `Resize`.
Requests travel as `Action::Queue(QueueRequest)` (`#[serde(skip)]`); `App` applies
`QueueOp`s to T40's queue under its lock and sends `EngineCommand`s on T41's channel.

### Behaviour

#### Layout

| Row | Content |
|---|---|
| border top | ` Queue ` (+ spinner while the engine is running) |
| 1 | tab bar: active tab in brackets and style `queue.tab_active`; totals right-aligned |
| 2 | column header for the active tab |
| 3 … | rows (virtualised): group header, item, progress line under active items |
| border bottom | — |

Tab labels: inner width ≥ 100: `Queued files (N)`, `Failed transfers (N)`,
`Successful transfers (N)`; 60–99: `Queued (N)`, `Failed (N)`, `Done (N)`; < 60: `1:N 2:N 3:N`.
Totals (Queued tab): ≥ 100: `Queue: 12 files, 30.2 MiB, ↓8.40 MiB/s ↑1.20 MiB/s, ~00:02:14`;
60–99: `30.2 MiB ~00:02:14`; < 60: hidden. Failed/Successful tabs show `N files, X`.
Group header: `▾`/`▸` (ASCII `-`/`+`) + server URL (`sftp://user@host`, port only when
not default, never a password) + ` — N files, X`. `Enter`/`o` on a header collapses or
expands it.

#### Columns per tab and width

Queued tab:

| Inner width | Columns |
|---|---|
| ≥ 100 | Local file (½ flex), direction, Remote file (½ flex), Size 9, Priority 7, Status 12 |
| 60–99 | Name (45 % flex), direction, Destination directory (55 %), Size 9, Status 12 |
| 40–59 | Name, direction, Size 9, Status 12 |
| < 40 | Name, Status 12 |

Failed tab: ≥ 100: Local file, direction, Remote file, Size, Time 8, Attempts 3, Reason
(rest); 60–99: Name (30 %), direction, Destination (25 %), Time, Reason (rest); < 60: Name,
Reason. Successful tab: ≥ 100: Local file, direction, Remote file, Time, Size, Duration 8,
Avg speed 11; 60–99: Name (50 %), direction, Destination (rest), Time, Size, Duration,
Avg speed; < 60: Name, Size, Avg speed.

Direction: `→` upload (local → remote), `←` download (ASCII `->`, `<-`). Paths are
shortened **from the left** with `…` so the file name stays visible; destination is the
remote dir for uploads and the local dir for downloads (`~` for home).

Status texts: `Queued`, `Queued (dir)` (`QueueItemKind::DirPlaceholder`, T43), `Transferring`,
`‖ Paused` (ASCII `|| Paused`), `Waiting` (connection limit), `Retrying 2/3`,
`Ask: file exists` (waiting on a T42 prompt).

Progress line (active items only), indented 6:
- ≥ 100: bar 20 cells + `  62%  2.54 KiB / 4.10 KiB  1.20 MiB/s  elapsed 00:00:02  left 00:00:01`
- 60–99: bar 10 + percent + bytes + speed + time left
- 40–59: bar 10 + percent + speed; < 40: percent + speed
- Unknown total: bar replaced by `…` and no percent; speed 0 for > 5 s shows `stalled`.

#### Mock-up: standalone at 80×24 (Queued tab, narrow columns)

```
┌ Queue ───────────────────────────────────────────────────────────────────────┐
│ [Queued (12)]│ Failed (1) │ Done (14)                     30.2 MiB ~00:02:14 │
│  Name                     Destination                      Size Status       │
│ ▾ sftp://deploy@web01.example.com — 5 files, 1.27 GiB                        │
│  index.html             → /var/www/html/               4.10 KiB Transferring │
│      ██████░░░░  62%  2.54 KiB / 4.10 KiB  1.20 MiB/s  00:00:01              │
│  backup-2026-10-01.tar… ← ~/Downloads/                 1.21 GiB Transferring │
│      ████░░░░░░  37%  458 MiB / 1.21 GiB  8.40 MiB/s  00:01:32               │
│  style.min.css          → /var/www/html/css/           48.7 KiB Queued       │
│  hero.jpg               → /var/www/html/img/           2.31 MiB ‖ Paused     │
│  assets/                → /var/www/html/                        Queued (dir) │
│ ▸ ftpes://alice@ftp.example.com — 7 files, 28.9 MiB                          │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

Failed and Successful tabs at 80 columns (cut to the first rows):

```
┌ Queue ───────────────────────────────────────────────────────────────────────┐
│  Queued (12) │[Failed (1)]│ Done (14)                       1 file, 3.20 KiB │
│  Name                 Destination     Time     Reason                        │
│ ▾ sftp://deploy@web01.example.com — 1 file                                   │
│  secret.conf        ← ~/Downloads/    12:03:40 Permission denied: /etc/secr… │
└──────────────────────────────────────────────────────────────────────────────┘
```
```
┌ Queue ───────────────────────────────────────────────────────────────────────┐
│  Queued (12) │ Failed (1) │[Done (14)]                    14 files, 1.02 MiB │
│  Name               Destination      Time          Size Duration   Avg speed │
│ ▾ sftp://deploy@web01.example.com — 14 files                                 │
│  index.html       → /var/www/html/   12:03:11  4.10 KiB 00:00:01  4.10 KiB/s │
│  style.min.css    → …r/www/html/css/ 12:03:12  48.7 KiB 00:00:01  48.7 KiB/s │
└──────────────────────────────────────────────────────────────────────────────┘
```

#### Mock-up: standalone at 160×48 (Queued tab, wide columns)

```
┌ Queue ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ [Queued files (12)]│ Failed transfers (1) │ Successful transfers (14)                          Queue: 12 files, 30.2 MiB, ↓8.40 MiB/s ↑1.20 MiB/s, ~00:02:14 │
│  Local file                                                      Remote file                                                       Size Prio    Status       │
│ ▾ sftp://deploy@web01.example.com — 5 files, 1.27 GiB                                                                                                        │
│  /home/alice/site/index.html                                   → /var/www/html/index.html                                      4.10 KiB Normal  Transferring │
│      ████████████░░░░░░░░  62%  2.54 KiB / 4.10 KiB  1.20 MiB/s  elapsed 00:00:02  left 00:00:01                                                             │
│  /home/alice/Downloads/backup-2026-10-01.tar.gz                ← /var/www/html/backup-2026-10-01.tar.gz                        1.21 GiB High    Transferring │
│      ███████░░░░░░░░░░░░░  37%  458 MiB / 1.21 GiB  8.40 MiB/s  elapsed 00:00:54  left 00:01:32                                                              │
│  /home/alice/site/css/style.min.css                            → /var/www/html/css/style.min.css                               48.7 KiB Normal  Queued       │
│  /home/alice/site/img/hero.jpg                                 → /var/www/html/img/hero.jpg                                    2.31 MiB Low     ‖ Paused     │
│  /home/alice/site/assets/                                      → /var/www/html/assets/                                                  Normal  Queued (dir) │
│ ▸ ftpes://alice@ftp.example.com — 7 files, 28.9 MiB                                                                                                          │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

In the Classic layout at 80×24 (T50) the queue gets 5 inner rows; the same rules apply.

#### Keybindings (mode `Queue`, from T51) and the operation each one performs

| Key | Command | Request | T40/T41 operation |
|---|---|---|---|
| `1` `2` `3` | `QueueTabQueued` / `QueueTabFailed` / `QueueTabSuccessful` | — | — |
| `j` `k` `↓` `↑`, `ctrl-d` `ctrl-u`, `PageDown` `PageUp`, `g g` `Home` `G` `End` | `CursorDown` … `Bottom` (move) | — | — |
| `Insert` | `ToggleMark` (cursor down) | — | — |
| `v` / `ctrl-a` | `VisualMode` / `MarkAll` (in tab) | — | — |
| `Enter` `o` | `QueueToggleGroup` | — | — |
| `Space` | `QueuePauseResume` | `Queue(PauseToggle)` | pause/resume items (active: engine `Cancel { ids, remove: false }`, item `Paused`, resumable from offset) |
| `+` / `-` | `QueuePriorityUp` / `QueuePriorityDown` | `Queue(RaisePriority/LowerPriority)` | set priority (Lowest…Highest, clamped) |
| `K` / `J` | `QueueMoveUp` / `QueueMoveDown` | `Queue(MoveUp/MoveDown)` | reorder |
| `t` / `b` | `QueueMoveTop` / `QueueMoveBottom` | `Queue(MoveTop/MoveBottom)` | reorder |
| `x` `Delete` | `QueueRemove` (Queued: confirm if any is active; Successful: clear selected) | `Queue(Remove)` + `Engine(Cancel { ids, remove: true })` for active | remove |
| `X` | `QueueClearList` (Failed/Successful tab, confirm) | `Queue(ClearFailed/ClearSuccessful)` | clear |
| `r` | `QueueResetRequeue` (Failed tab) | `Queue(ResetAndRequeue)` | reset attempts, move to queued |
| `e` | `QueueSetExistsAction` — opens the "File exists action" sub-menu for the targets | `Queue(SetExistsAction)` | `set_on_exists` |
| `a` | `QueueCompletionAction` — opens the "Action after queue completion" sub-menu | `SetCompletionAction` | T45 |
| `m` | `QueueMenu` (context menu) | — | — |
| `ctrl-p` (global) | `ProcessQueue` (start / stop) | `Engine(Start)` / `Engine(Stop)` | start/stop |
| `Esc` | `Escape` (cancel visual / close menu) | — | — |

Commands apply to `target_ids()`. Commands that do not apply to the current tab
(e.g. `r` on Queued) show Info `Not available in this tab` instead of doing nothing.
After reordering, the cursor follows the moved item.

#### Context menu (`m`)

A T52 `ListView` popup (width 40, under the cursor row or centred) listing the actions
valid for the targets and tab, each with its key: Process queue / Stop processing,
Pause / Resume, Priority ▸ (Highest, High, Normal, Low, Lowest), Move to top / up / down /
bottom, File exists action ▸ (Use default, Ask, Overwrite, Overwrite if newer, Overwrite
if size differs, Overwrite if newer or size differs, Resume, Rename, Skip), Action after
queue completion ▸ (None, Show message, Run command…, Disconnect, Close app; then
`Once` / `Always` choice — T45 one-shot vs `queue.on_complete`), Reset and requeue,
Remove selected, Clear list, Collapse all / Expand all, Export queue…, Import queue….
Sub-menus open with `l`/`→`/`Enter`, close with `h`/`←`/`Esc`. Type-to-jump works.

#### Updates and performance

- **Structural change** (`QueueChanged { version }`): rebuild `QueueRows` for the shown
  tab. ≤ 10 000 items inline; above, on `spawn_blocking` with the version as generation
  (stale results dropped); the old rows stay visible meanwhile. Cursor kept on the same
  `TransferId` (or nearest index).
- **Progress** (`TransferProgress`, ≤ 10 Hz per item from T41, coalesced per frame by
  T04): only `progress` map updated; no rebuild. Entries removed when the item leaves
  `Active`. Active items get their `Progress` row inserted by the row builder.
- Drawing formats only the visible rows; item fields are fetched by id from `QueueView`.

| Measure | Target |
|---|---|
| Draw at 160×48 with 100 000 items | ≤ 2 ms median (bench `queue_render_100k`) |
| Row model rebuild, 100 000 items, grouped | ≤ 50 ms (T40 AC; bench `queue_rows_100k`) |
| Progress event → visible update | next frame (≤ 1 frame at T50's frame rate) |
| Memory besides the queue | rows: 16 bytes × rows; progress: ≤ `transfers.max_concurrent` entries |

### Data formats and configuration

| Key | Type | Default | Notes |
|---|---|---|---|
| `interface.show_queue` | bool | `true` | T05; toggled by `ctrl-x j` (`ToggleQueuePane`, T50/T51) |
| `queue.on_complete` | enum (`none`, `show_message`, `run_command`, `disconnect`, `close_app`) | `none` | T05/T45; "Always" in the completion sub-menu writes it |
| `transfers.max_concurrent` | u8 | 4 | T05/T41b; bounds the progress map |

Style keys: `queue.tab_active`, `queue.tab`, `queue.header`, `queue.group`,
`queue.item`, `queue.item_active`, `queue.item_paused` (dim), `queue.item_failed` (red),
`queue.reason` (red), `queue.progress_bar`, `queue.progress_empty`, `queue.cursor`
(reverse), `queue.marked` (bold + `*` marker in column 0). `NO_COLOR`: failed/paused
are distinguished by the status/reason text; cursor reverse; marks `*` + bold.

### Errors

| Situation | What the user sees |
|---|---|
| Queue operation rejected by T40 (e.g. move on a placeholder being expanded) | Warning message from the returned error text |
| Engine channel closed (engine crashed) | Error `Transfer engine stopped; restart courier-ftp` and the pane shows `Engine not running` in the title |
| Import file invalid | T52 `error` dialog with the T40 parse error |
| Removing active items | confirm `Cancel N active transfers and remove them?` (default No) |

Failure reasons in the Failed tab are T41's last error message (`Error` display text),
sanitised and cut to the column.

### Security and logging

- Group labels and paths come from the queue (user and server data): sanitised before
  drawing. Group labels never include passwords (`QueueServer` secrets stay encrypted in
  T40); quickconnect items show `user@host` only.
- Export goes through T40's export (no secrets); this pane adds nothing to it.
- No `tracing` at `info`+ with paths or hosts; `debug` may log
  `queue_pane rows=<n> rebuild_ms=<n>`.

## Implementation steps

1. `QueueView` implementation on T40's `Queue`; `QueueRows` builder with groups/collapse; tests.
2. `QueuePaneState` with cursor/marks/visual/targets and the reducer for movement and tabs.
3. Rendering per tab with the width rules; progress line; snapshot tests.
4. Requests → T40 operations and T41 commands in `App`; confirmations.
5. Progress/state event handling; off-thread rebuild with versions.
6. Context menu with sub-menus; completion action (T45 hook: `SetCompletionAction`).
7. Benchmarks and gates.

## Acceptance criteria

- [ ] AC1 Snapshot tests at 80×24 and 160×48 for each tab with sample data, including two active transfers with progress, a paused item, a placeholder dir item, a collapsed group and a failed item with reason; plus widths 50 and 35.
- [ ] AC2 Each key in the keybinding table produces exactly the request listed, for cursor-only, marked and group-header targets (table-driven test).
- [ ] AC3 Applying the requests to a real T40 `Queue` and a T41 engine with `MockBackend` gives the expected queue state (order, priorities, paused flags, failed→queued).
- [ ] AC4 Removing an active item asks for confirmation first, then sends `Cancel { ids, remove: true }` and the item is gone within 1 s (T41 AC); pausing an active item sends `Cancel { ids, remove: false }`.
- [ ] AC5 Rendering with 100 000 items: draw ≤ 2 ms median, rebuild ≤ 50 ms (bench gates); progress events do not trigger a rebuild (counter test).
- [ ] AC6 The completion sub-menu sets the one-shot action (`always = false`) or `queue.on_complete` (`always = true`).
- [ ] AC7 `NO_COLOR` + ASCII snapshots: all cells ASCII, paused/failed/active distinguishable by text.
- [ ] AC8 CI gates `fmt`, `clippy`, `test-local-only`, `test-os`, `bench-build` pass.

## Tests

### Unit tests
- `rows_group_by_server_and_collapse` — group counts/bytes, collapsed hides items.
- `rows_insert_progress_line_for_active_items`.
- `target_ids_marked_cursor_and_group` (AC2).
- `keys_map_to_requests_table` — every row of the keybinding table × three target kinds (AC2).
- `command_not_available_in_tab_shows_message`.
- `cursor_follows_moved_item`.
- `progress_updates_do_not_rebuild_rows` (AC5).
- `stale_rebuild_result_dropped`.
- `remove_active_asks_confirmation` — then `EngineCommand::Cancel { ids, remove: true }` (AC4).
- `pause_active_sends_cancel_without_remove` (AC4).
- `queue_default_keys` — `AppHarness` with the default keymap and the queue focused: `t`/`b` → `QueueMoveTop`/`QueueMoveBottom`, `e` → `QueueSetExistsAction`, `a` → `QueueCompletionAction`; `ctrl-x j` hides the pane; `ctrl-j` does nothing (AC2).
- `completion_menu_once_vs_always` (AC6).
- `column_rules_per_width_and_tab` — widths 35, 39, 40, 59, 60, 99, 100.

### Property / fuzz tests
- `prop_rows_contain_each_visible_item_once` — random queues and collapse sets.
- `prop_render_never_panics_any_size`.

### Snapshot tests
`queue_queued_{80x24,160x48}`, `queue_failed_{80x24,160x48}`, `queue_successful_{80x24,160x48}`,
`queue_collapsed_group_80x24`, `queue_width_50`, `queue_width_35`, `queue_menu_open_80x24`,
`queue_empty_80x24`, each also `*_mono_ascii` (AC1, AC7).

### Integration tests
- `pane_controls_drive_real_queue_and_engine` — T40 `Queue` + T41 engine + `MockBackend` with latency; pause, reprioritise, move, remove active, reset failed (AC3, AC4).
- Benches `queue_render_100k`, `queue_rows_100k` (AC5).

### End-to-end tests
- T76 scenario `queue_50_files_up_and_down` asserts via PtyApp that the Successful tab shows 50 entries and the Failed tab is empty.

## Out of scope

- Mouse drag to reorder (D7). Sound, sleep and shutdown completion actions (D8).
- Queue persistence and import/export formats (T40); the completion actions themselves (T45).

## Open questions

None. (Resolved by the coordinator: `QueueView` and `QueueServerKey` are defined in T40;
the engine command is `Cancel { ids, remove }`; the queue toggle is `ctrl-x j`.)
