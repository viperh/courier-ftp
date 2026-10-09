# T53 — File list pane

**Phase:** F TUI · **Milestone:** M1 · **Depends on:** T02, T06, T46, T47, T50, T51, T52 · **Crate(s):** `courier-ftp` (`components/file_list/`) · **Decisions:** D6, D7 · **FEATURES.md:** §3 (local/remote pane, address bars, columns, sorting, size/date formats, hidden files, listing cache)
**Related (integrates with, not blocking):** T13, T62

## Goal

The central widget of courier-ftp: a fast, sortable, multi-select file list with an
editable address bar, used for both the local and the remote side. It handles
100 000-entry directories without lag, never lets untrusted file names reach the
terminal unescaped, and turns key presses into navigation and file-operation
requests that other tasks (T62, T63, T66) carry out.

## Context

**Before this task:** T02 defines `Entry`, `EntryKind`, `Timestamp`/`Precision`,
`Permissions`, `RemotePath`, `LocalPath`. T03/T06 provide `Backend`, `Listing`,
`SessionHandle` and `LocalBackend`. T46 provides `ListingCache`; T04 defines the
`CoreEvent::ListingUpdated { server: Option<ServerIdentity>, dir: RemotePath }` event
that T46 emits (`server: None` = local filesystem, sent by T62). T05 provides the
settings types `Column`, `ColumnSpec`, `SortSpec`, `PaneColumns`, `PaneSort`,
`SizeFormat`, `EnterOnFile` (`courier_ftp_core::settings`); this task uses them and
defines none of its own. T47 provides `FilterEngine` and
the quick-filter matchers (`StringOp::Contains`, glob). T50 provides the
`MainScreen`, focus handling, the `Theme` (from the `styles` config, monochrome
under `NO_COLOR`), the async-operation runner, `Mode`, `crate::tabs::TabId`,
`crate::ui::text::sanitize` and `crate::ui::symbols::Symbols` (Unicode/ASCII glyph
sets). T51 provides the `Action` names and keymap modes (this task uses mode
`FileList` and `Filter`). T52 provides `PathInput`, `prompt_text` and `confirm`.

**Later tasks need from it:** T54 (tree follows the list's directory), T58/T59/T61
(remote pane connects/disconnects), T62 (file operations take the `Selection` this
pane builds and patch it via the cache), T63 (view/edit), T64 (bookmarks navigate
panes), T66 (comparison colouring and lockstep cursor through `RowDecoration`),
T67 (filter changes re-filter panes), T57 (filter indicator reads `is_filtered()`).

## Technical specification

### Types and APIs

Module `crates/courier-ftp/src/components/file_list/` with files `mod.rs` (component),
`state.rs` (pure state + reducer), `view.rs` (filter/sort pipeline), `columns.rs`,
`format.rs` (size/date/type formatting), `render.rs`, `natural.rs`.

```rust
/// Which side of a tab a pane shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Side { Local, Remote }

/// Identifies one pane. `TabId` (`crate::tabs::TabId(u32)`) is owned by T50;
/// before T61 the only tab is `TabId(0)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PaneId { pub tab: TabId, pub side: Side }

/// The directory a pane shows. The UI never mixes the two path kinds; the
/// conversion to the backend's path type is T06's adapter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PaneDir { Local(LocalPath), Remote(RemotePath) }

/// Columns, column config and sort order are the core types from T05
/// (`Column { Name, Size, Type, Modified, Permissions, OwnerGroup }`,
/// `ColumnSpec { column, visible }`, `SortSpec { column, descending }`), persisted as
/// `interface.columns.{local,remote}` and `interface.sort.{local,remote}`.
pub use courier_ftp_core::settings::{Column, ColumnSpec, SortSpec};

/// What the pane is doing.
#[derive(Debug, Clone, PartialEq)]
pub enum PaneStatus {
    /// Showing `listing`.
    Ready,
    /// A listing request is in flight; the previous listing (if any) stays visible.
    Loading { request: RequestId, since: Instant },
    /// Remote pane without a session.
    NotConnected,
    /// The last request failed. `listing` still holds the previous directory.
    Error { message: String, at: Instant },
}

/// The quick filter (`/`), separate from T47 filter sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickFilter { pub text: String, pub editing: bool }

/// Pure pane state. No I/O, no async; every change goes through `reduce`.
#[derive(Debug)]
pub struct FileListState {
    pub id: PaneId,
    pub dir: Option<PaneDir>,
    pub listing: Option<Arc<Listing>>,
    pub status: PaneStatus,
    /// Indices into `listing.entries` after hidden/filters/quick filter, sorted.
    view: Vec<u32>,
    /// Bumped on every `view` rebuild; stale async sort results are dropped.
    view_generation: u64,
    /// Row index (row 0 is `..` when `has_parent_row()`).
    pub cursor: usize,
    /// First visible row.
    pub offset: usize,
    /// Marked entries, bit per index in `listing.entries` (`fixedbitset::FixedBitSet`).
    marks: FixedBitSet,
    /// Visual-mode anchor row.
    visual_anchor: Option<usize>,
    pub sort: SortSpec,
    pub columns: Vec<ColumnSpec>,
    pub quick_filter: Option<QuickFilter>,
    pub show_hidden: bool,
    /// Back/forward stacks, 50 entries each.
    history: NavHistory,
    /// Last cursor entry name per directory, LRU of 256 directories.
    cursor_memory: LruCache<PaneDir, String>,
    /// Address bar editor while `a` is active.
    pub address_edit: Option<PathInput>,
    /// Per-row decoration provided by T66 (comparison); `None` here.
    pub decoration: Option<Arc<dyn RowDecoration>>,
}

/// T66 hook: colour and alignment of rows during directory comparison.
pub trait RowDecoration: Send + Sync + std::fmt::Debug {
    fn style_for(&self, entry_index: Option<u32>) -> Option<RowStyleKey>;
}

/// What the pane asks the app to do (carried in `Action`, see Behaviour).
#[derive(Debug, Clone)]
pub enum PaneRequest {
    /// List `dir` (through `ListingCache` unless `force`).
    List { pane: PaneId, dir: PaneDir, request: RequestId, force: bool },
    /// Cancel an in-flight listing.
    CancelList { pane: PaneId, request: RequestId },
    /// A file operation on the selection (handled by T62/T63).
    FileOp { pane: PaneId, op: FileOp, selection: Selection },
    /// Navigate the other pane of the same tab to the equivalent path (`=`).
    MirrorToOtherPane { pane: PaneId },
}

/// The entries an operation applies to: marked entries, else the cursor entry.
/// `..` is never part of a selection.
#[derive(Debug, Clone)]
pub struct Selection { pub dir: PaneDir, pub entries: Arc<[Entry]> }

/// File operations the pane can request (names match T51 actions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOp { Transfer, QueueOnly, Move, Rename, Mkdir, MkdirEnter, NewFile,
                  Delete, View, Edit, Chmod, CopyUrl, CopyUrlOptions, CustomCommand, Refresh }

impl FileListState {
    pub fn new(id: PaneId, settings: &Settings) -> Self;
    /// Pure reducer: applies one input, returns requests for the app.
    pub fn reduce(&mut self, input: PaneInput, ctx: &PaneCtx<'_>) -> Vec<PaneRequest>;
    /// Rows in the view including the `..` row.
    pub fn row_count(&self) -> usize;
    pub fn has_parent_row(&self) -> bool;
    /// Entry under the cursor (`None` on `..` or empty view).
    pub fn cursor_entry(&self) -> Option<&Entry>;
    pub fn selection(&self) -> Option<Selection>;
    /// True when a T47 filter hid at least one entry or the quick filter is set.
    pub fn is_filtered(&self) -> bool;
    pub fn footer(&self) -> FooterSummary;
}

/// Inputs to the reducer (keymap actions, results, core events).
#[derive(Debug, Clone)]
pub enum PaneInput {
    Key(PaneCommand),
    ListingLoaded { request: RequestId, dir: PaneDir, result: Result<Arc<Listing>, Arc<Error>> },
    ListingUpdated { dir: PaneDir, listing: Arc<Listing> },   // T46 patch or refresh
    SortDone { generation: u64, view: Vec<u32> },
    Connected, Disconnected,
    FiltersChanged(Arc<FilterEngine>),
    SettingsChanged,
    Resize { body_rows: u16 },
}

/// Settings and engines the reducer reads (borrowed from `App`).
pub struct PaneCtx<'a> { pub settings: &'a Settings, pub filters: &'a FilterEngine, pub now: Instant }
```

`PaneCommand` is the set of keymap actions in mode `FileList` (table below). The
`Action` enum (T51) carries them as unit variants; `PaneRequest`s and
`PaneInput` results travel as `Action::Pane(PaneRequest)` /
`Action::PaneInput(PaneId, PaneInput)` variants marked `#[serde(skip)]`
(they are never bound to keys). Errors are wrapped in `Arc` because `Action`
is `Clone`.

The component `FileListPane` (implements `Component`) owns a `FileListState`,
forwards keys while focused, and draws with
`render::draw(&state, frame, area, &Theme, &Symbols, focused: bool)`, which is a
pure function of the state (no I/O, no allocation proportional to the listing).

### Behaviour

#### Layout inside the pane

| Row | Content |
|---|---|
| border top | title: `Local` / `Remote` + ` · ` + site name or `user@host` (remote, connected) + spinner while `Loading` (after 150 ms) + ` [filtered]` when `is_filtered()`; remote border uses the site colour accent (T31 `background_color`) when set |
| 1 | address bar: local path via `LocalPath::to_display()` (`~` for home), remote absolute path; while editing, the `PathInput` with cursor |
| 2 | header: column titles; the sort column shows `▲`/`▼` (ASCII `^`/`v`); Size header right-aligned |
| 3 … h−3 | entry rows (virtualised) |
| h−2 | footer (summary, quick filter input, or error) |
| border bottom | — |

Minimum pane size 20×6 (outer). Smaller: the body shows only `Terminal too small`
truncated to the width; no panic at any size including 0×0.

#### Mock-up: standalone pane at 80×24

Remote listing of `/var/www/html`, two files marked (`*`), cursor on `index.html`
(row 12, drawn in reverse video; not visible in plain text):

```
┌ Remote · web01 ──────────────────────────────────────────────────────────────┐
│/var/www/html                                                                 │
│ Name ▲                          Size Type         Modified         Perms     │
│ ..                                                                           │
│ assets/                              Directory    2026-10-01 12:00 drwxr-xr-x│
│ css/                                 Directory    2026-09-30 09:12 drwxr-xr-x│
│ js/                                  Directory    2026-09-30 09:12 drwxr-xr-x│
│ uploads/                             Directory    2026-10-07 23:59 drwxrwxr-x│
│ .htaccess                      412 B File         2026-03-14 08:00 -rw-r--r--│
│ backup-2026-10-01.tar.gz    1.21 GiB GZIP archive 2026-10-01 03:00 -rw-------│
│ favicon.ico                 15.0 KiB Icon file    2025-01-05       -rw-r--r--│
│*index.html                  4.10 KiB HTML file    2026-10-08 18:22 -rw-r--r--│
│ logo.png → static/logo.png           Link         2026-06-02 10:41 lrwxrwxrwx│
│ README.md                   2.31 KiB Markdown     2026-09-12 16:05 -rw-r--r--│
│ robots.txt                      68 B Text file    2024-11-30       -rw-r--r--│
│ sitemap.xml                 12.4 KiB XML file     2026-10-08 02:00 -rw-r--r--│
│*style.min.css               48.7 KiB CSS file     2026-10-08 18:20 -rw-r--r--│
│ very-long-file-name-that-…  1.00 KiB Text file    2026-10-02 07:30 -rw-r--r--│
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│Selected 2 files. Total size: 52.8 KiB                                        │
└──────────────────────────────────────────────────────────────────────────────┘
```

#### Mock-up: standalone pane at 160×48

All six columns fit; the name column takes the remaining width:

```
┌ Remote · web01 ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│/var/www/html                                                                                                                                                 │
│ Name ▲                                                                                         Size Type         Modified         Perms      Owner/Group     │
│ ..                                                                                                                                                           │
│ assets/                                                                                             Directory    2026-10-01 12:00 drwxr-xr-x deploy www-data │
│ css/                                                                                                Directory    2026-09-30 09:12 drwxr-xr-x deploy www-data │
│ js/                                                                                                 Directory    2026-09-30 09:12 drwxr-xr-x deploy www-data │
│ uploads/                                                                                            Directory    2026-10-07 23:59 drwxrwxr-x www-data www-da…│
│ .htaccess                                                                                     412 B File         2026-03-14 08:00 -rw-r--r-- deploy www-data │
│ backup-2026-10-01.tar.gz                                                                   1.21 GiB GZIP archive 2026-10-01 03:00 -rw------- deploy deploy   │
│ favicon.ico                                                                                15.0 KiB Icon file    2025-01-05       -rw-r--r-- deploy www-data │
│*index.html                                                                                 4.10 KiB HTML file    2026-10-08 18:22 -rw-r--r-- deploy www-data │
│ logo.png → static/logo.png                                                                          Link         2026-06-02 10:41 lrwxrwxrwx deploy www-data │
│ README.md                                                                                  2.31 KiB Markdown     2026-09-12 16:05 -rw-r--r-- deploy www-data │
│ robots.txt                                                                                     68 B Text file    2024-11-30       -rw-r--r-- deploy www-data │
│ sitemap.xml                                                                                12.4 KiB XML file     2026-10-08 02:00 -rw-r--r-- deploy www-data │
│*style.min.css                                                                              48.7 KiB CSS file     2026-10-08 18:20 -rw-r--r-- deploy www-data │
│ very-long-file-name-that-gets-truncated-in-the-pane.txt                                    1.00 KiB Text file    2026-10-02 07:30 -rw-r--r-- deploy www-data │
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
│10 files and 4 directories. Total size: 1.21 GiB                                                                                                              │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

#### Mock-up: one pane of the Classic layout at 80×24 (40×12)

Narrow panes drop columns and use the compact date (see column priorities):

```
┌ Remote · web01 ──────────────────────┐
│/var/www/html                         │
│ Name ▲               Size Modified   │
│ ..                                   │
│ assets/                   10-01 12:00│
│ css/                      09-30 09:12│
│ js/                       09-30 09:12│
│ uploads/                  10-07 23:59│
│ .htaccess           412 B 03-14 08:00│
│ backup-2026-10…  1.21 GiB 10-01 03:00│
│10 files and 4 dirs. 1.21 GiB         │
└──────────────────────────────────────┘
```

#### Columns and narrow terminals

Fixed widths (plus one separating space each): marker 1 (no separator), Size 9
(right-aligned), Type 12, Modified 16 (compact 11), Permissions 10, Owner/Group 16;
Name gets the rest, minimum 12. Text longer than its column is cut and ends with
`…` (ASCII `~`); widths use `unicode-width` (wide CJK and emoji count 2).

Algorithm (`columns::fit(inner_width, specs) -> ColumnLayout`, pure):
1. Start from the visible configured columns in configured order.
2. If `inner_width < 60`, Modified uses the compact form (11 columns).
3. While `1 + name_min + Σ(width+1) > inner_width`, drop the visible column with the
   lowest priority. **Drop order: Owner/Group, Type, Permissions, Modified, Size.**
4. Name width = remainder. Name is never dropped.

| Pane inner width | Columns shown (default remote config) |
|---|---|
| ≥ 81 | Name, Size, Type, Modified, Perms, Owner/Group |
| 64–80 | Name, Size, Type, Modified, Perms |
| 46–63 | Name, Size, Modified, Perms (compact date below 60) |
| 35–45 | Name, Size, Modified (compact) |
| 23–34 | Name, Size |
| < 23 | Name |

Default column config: remote = all six visible; local = Name, Size, Type, Modified
visible, Permissions and Owner/Group configured but hidden (FileZilla's local pane).
Column menu (`C` in the pane): a T52 `ListView` with checkboxes for visibility and
`K`/`J` to reorder; changes apply at once and are saved with `Settings::save_user`.

#### Rendering rules

- `..` row first unless the directory is the root (`RemotePath::is_root()`, local `/`,
  or the Windows drive list root from T06). It cannot be marked.
- Directories: name + `/`, style `file_list.dir` (bold). Size blank, Type `Directory`.
- Symlinks: `name → target` (ASCII `->`), target in `file_list.symlink_target` (dim);
  `target_kind` Dir is navigable with Enter. Size blank for dir links.
- Hidden entries (`Entry.hidden`) in `file_list.hidden` (dim) when shown.
- `EntryKind::Other`: Type `Special`, style `file_list.special`.
- Size (`interface.size_format`, `interface.thousands_separator`):
  `Bytes` → `1,234,567` (comma separator when enabled; T75 localises later);
  `Iec` → three significant digits with `B`, `KiB`, `MiB`, `GiB`, `TiB`
  (`412 B`, `4.10 KiB`, `48.7 KiB`, `1.21 GiB`); `Si` → same with `kB`, `MB`, `GB`, `TB`
  and base 1000. Unknown size → blank.
- Modified: converted to the local UTC offset (captured once at startup before the
  runtime spawns threads, fallback UTC). Format `interface.date_format` +
  ` ` + `interface.time_format` (defaults `%Y-%m-%d`, `%H:%M`). `Precision::Day`
  prints the date only. Compact form: `MM-DD HH:MM` for the current year, `YYYY-MM-DD`
  otherwise. Unknown → blank.
- Permissions: `Permissions::to_rwx_string()`; if only `raw` exists, `raw` cut to 10.
- Owner/Group: `owner group`, or the one that exists.
- Type: a built-in table of 48 extensions (`html`, `htm` → `HTML file`, `css` → `CSS file`,
  `md` → `Markdown`, `gz`, `tgz` → `GZIP archive`, `zip` → `ZIP archive`, `png`, `jpg` →
  `Image`, `ico` → `Icon file`, `txt` → `Text file`, …; full table in `format.rs`, strings
  go through T75 later); otherwise `<EXT> file` with the extension upper-cased (max 8
  chars), `File` for no extension or dotfiles, `Link` for symlinks.
- Marked rows: `*` in the marker column and style `file_list.marked` (bold + yellow;
  monochrome: bold + underline). Cursor row: `file_list.cursor` (reverse video, in both
  colour and monochrome); when the pane is not focused, the cursor row uses
  `file_list.cursor_inactive` (colour: dim reverse; monochrome: underline).
- Every displayed name, target, owner and group goes through
  `crate::ui::text::sanitize` (T50): control characters, ESC, DEL, C1 controls and
  bidi overrides are shown as visible escapes (`^[`, `^?`, `<U+202E>`) in dim style and
  never written raw to the terminal (T91).
- No information by colour alone: directories carry `/`, links `→`, marks `*`, errors
  the `Error:` prefix.

#### Footer

| State | Footer text |
|---|---|
| Normal | `N files and M directories. Total size: X` (`file`/`directory` singular forms; size in the pane's format; `Total size: at least X` if any size unknown) |
| Some marked | `Selected N files and M directories. Total size: X` (directory sizes not counted) |
| Quick filter editing | `/` + text + cursor, then `  (K of N)` |
| Quick filter set, not editing | normal/selected text + `  [/text]` |
| Error (10 s, or until the next key) | `Error: <message>` in `file_list.error` |
| Empty directory | `Empty directory.` |
| Narrow (< 46 columns) | short form `10 files, 4 dirs. 1.21 GiB` |

#### Body states

- `NotConnected` (remote): centered lines `Not connected to any server` and
  `Ctrl-s Site Manager · Ctrl-k Quickconnect` (keys rendered from the active keymap,
  T51 `SiteManager` / `FocusQuickconnect`). Address bar and header empty.
- `Loading` with no previous listing: centered `Loading…` with spinner after 150 ms.
- `Error` with no previous listing (first listing failed): centered `Error: <message>`.
- Empty view because everything is filtered: `All N entries are hidden by filters`.

#### Keybindings (mode `FileList`, from T51; all rebindable)

| Key(s) | `PaneCommand` / action | Behaviour |
|---|---|---|
| `j` `↓` / `k` `↑` | `CursorDown` / `CursorUp` | move 1 row, clamp (no wrap) |
| `ctrl-d` / `ctrl-u` | `HalfPageDown` / `HalfPageUp` | ½ body height (Disconnect is `ctrl-x d`, T61) |
| `PageDown` / `PageUp` | `PageDown` / `PageUp` | body height − 1 |
| `gg` `Home` / `G` `End` | `Top` / `Bottom` | |
| `l` `→` `Enter` | `Open` | dir/dir-link: navigate; file: `interface.enter_on_file` (`transfer` default, `view`, `edit`, `none`) |
| `h` `←` `Backspace` | `Parent` | navigate up, cursor lands on the directory we came from |
| `alt-left` `[` / `alt-right` `]` | `Back` / `Forward` | history (50 entries each way) |
| `Space` `Insert` | `ToggleMark` | toggle mark on cursor entry, then cursor down |
| `v` | `VisualMode` | anchor; moves extend the range; `v`/`Space` marks the range, `Esc` cancels |
| `ctrl-a` | `MarkAll` | mark all entries in the view |
| `*` | `InvertMarks` | invert marks in the view |
| `+` / `-` | `MarkPattern` / `UnmarkPattern` | T52 `prompt_text` for a glob (`*.html`), case-insensitive |
| `/` | `QuickFilter` | enter mode `Filter` |
| `s` then `n` `s` `t` `m` `p` `o` | `SortBy(col)` | Name/Size/Type/Modified/Permissions/Owner; same column again reverses |
| `.` | `ToggleHidden` | local: toggles `show_hidden_local`; remote: toggles `force_show_hidden_remote` and relists (`LIST -a`, T13) |
| `a` | `EditAddress` | address bar editing with completion (T52 `PathInput`) |
| `=` | `MirrorOtherPane` | other pane to the equivalent path (best effort) |
| `C` | `ColumnMenu` | column menu |
| `ctrl-r` (global, `Normal`) | `Refresh` | relist bypassing the cache (T62 owns the action; it reaches the pane as `FileOp::Refresh`) |
| `f5`; `shift-f5`/`f15`/`Q`; `f6`; `f2`; `f7`; `shift-f7`/`f17`/`M`; `f8`/`delete`; `f3`/`o`; `f4`/`e`; `c`; `y u`/`y U`; `:` | `Transfer`, `QueueOnly`, `Move`, `Rename`, `Mkdir`, `MkdirEnter`, `Delete`, `View`, `Edit`, `Chmod`, `CopyUrl`/`CopyUrlOptions`, `CustomCommand` | emit `PaneRequest::FileOp` (T62/T63) |
| `ctrl-x n` (global) | `NewFile` | delivered to the focused (else last focused) list, emits `PaneRequest::FileOp` |
| `Tab` / `Shift-Tab` | handled by T50 | switch pane |

Mode `Filter` (quick filter): printable chars append, `Backspace` deletes (empty +
`Backspace` leaves the mode and clears), `Enter` keeps the filter and returns to
`FileList`, `Esc` clears the filter and returns, `↑`/`↓` move the cursor while typing.

Hidden files are toggled with `.` only; `ctrl-h` is not bound anywhere (it arrives as
`Backspace` in many terminals, T51).

#### Navigation

1. `Open`/`Parent`/`Back`/`Forward`/address bar produce a target `PaneDir`.
2. The pane cancels any in-flight request (`PaneRequest::CancelList`), allocates a new
   `RequestId` (monotonic `u64`) and emits `PaneRequest::List { force: false }`; status
   becomes `Loading`. The previous listing stays visible and navigable.
3. T50's runner serves it from `ListingCache` (T46) on a hit (no backend call), else
   lists through the tab's `SessionHandle` (remote) or `LocalBackend` (local) with the
   request's `CancellationToken` and `connection.timeout_secs`; it answers with
   `PaneInput::ListingLoaded`.
4. On a result whose `request` is not the current one: dropped.
5. Success: `dir`, `listing` replaced; history push (unless Back/Forward); view rebuilt;
   cursor placed on (a) the entry named in `cursor_memory` for that dir, (b) on `Parent`,
   the directory we left, (c) else row 0. `Error::Cancelled` is ignored silently.
6. Failure: `dir` unchanged, status `Error { message }` with the user message mapping in
   **Errors**; the backend already logged it to the message log (T55).
7. `CoreEvent::ListingUpdated` for the shown dir (T46 patches after our own
   operations): the pane reloads the listing from the cache, keeps the cursor on the
   same entry name (or the nearest row index if it disappeared) and keeps marks by name.

Local paths typed in the address bar: `~` and `~/x` expand to the home dir; relative
paths are joined to the current dir; on Windows `C:` → `C:\`. Remote: relative paths
are joined with `RemotePath::join` per component, `..` normalised by `RemotePath`.

`MirrorOtherPane`: the other pane navigates to `other_current_dir` joined with the
path of this pane relative to the tab's sync base (T66) if set; without a base, it
uses the last component of this pane's dir as a child of the other pane's dir if it
exists in the other listing, else shows `No equivalent directory` in the footer.

#### View pipeline (filter, sort)

`view::build(listing, show_hidden, filters, quick, sort, natural, case_sensitive) -> Vec<u32>`:
1. Drop hidden entries unless `show_hidden` (remote: entries are shown as listed).
2. Drop entries `FilterEngine::excluded(entry, full_path)` (T47).
3. Quick filter: text with `*` or `?` → whole-name glob, otherwise substring; both
   case-insensitive (Unicode simple case folding).
4. Sort a `Vec<u32>` of indices with `sort_unstable_by` using a precomputed key vector
   (`SortKey` per entry: folded name or name, size, mtime, perms, owner). Directories
   first when `interface.dirs_first` (always on top in both directions). Name ties broken
   by byte-wise name, then index, so the order is total and stable across runs.
5. Natural order (`interface.natural_sort`, default true): digit runs compare by numeric
   value (`file2` < `file10`), leading zeros as tie-breaker (`a01` after `a1`).

Marks are cleared for entries the view no longer contains (a filter never leaves
invisible entries marked), so file operations only touch what the user can see.

#### Performance targets

| Measure | Target | How |
|---|---|---|
| Draw one frame, 100 000 entries, 160×48 | ≤ 2 ms median, ≤ 5 ms p99 on the CI runner | only rows `offset..offset+body_rows` are formatted; no per-frame allocation proportional to the listing |
| View build (filter + natural sort), 100 000 entries | ≤ 80 ms | runs inline for ≤ 10 000 entries; above, in `tokio::task::spawn_blocking`, result as `PaneInput::SortDone { generation }`; stale generations dropped; old view stays visible meanwhile |
| Cursor key → next frame, 100 000 entries | ≤ 16 ms | cursor/offset are integers; no rebuild on movement |
| Quick filter keystroke, 100 000 entries | ≤ 80 ms off-thread | debounced 50 ms above 10 000 entries |
| Memory, 100 000 entries | view 400 KB (`u32`), marks 12.5 KB (bitset), sort keys freed after the build | |

Benchmark `benches/file_list.rs` (`criterion`): `file_list_render_100k`,
`file_list_view_build_100k`; gates in `scripts/bench-gates.toml` (T00 §4).

### Data formats and configuration

| Key | Type | Default | Notes |
|---|---|---|---|
| `interface.size_format` | `bytes` \| `iec` \| `si` | `iec` | T05 |
| `interface.thousands_separator` | bool | `true` | T05; used by `Bytes` |
| `interface.date_format` | string (strftime subset `%Y %m %d %b`) | `%Y-%m-%d` | T05 |
| `interface.time_format` | string (`%H %M %S %I %p`) | `%H:%M` | T05 |
| `interface.dirs_first` | bool | `true` | T05 |
| `interface.sort_case_sensitive` | bool | `false` | T05 |
| `interface.natural_sort` | bool | `true` | T05 |
| `interface.show_hidden_local` | bool | `false` | T05 |
| `interface.force_show_hidden_remote` | bool | `false` | T05 |
| `interface.columns.local` / `.remote` | list of `{column, visible}` (`column` snake_case: `name`, `size`, `type`, `modified`, `permissions`, `owner_group`) | see above | T05 `PaneColumns` |
| `interface.sort.local` / `.remote` | `{column, descending}` | `{"column": "name", "descending": false}` | T05 `PaneSort`; saved on quit |
| `interface.enter_on_file` | `transfer` \| `view` \| `edit` \| `none` | `transfer` | T05 `EnterOnFile`; `none` = `Open` on a file does nothing |

Invalid date/time format strings fall back to the default with a warning (T05 rule).
Unknown column names in config are skipped with a warning; a missing `Name` is added.

Style keys (T50 `Theme`, `styles` config): `file_list.dir`, `file_list.symlink_target`,
`file_list.hidden`, `file_list.special`, `file_list.marked`, `file_list.cursor`,
`file_list.cursor_inactive`, `file_list.header`, `file_list.footer`, `file_list.error`,
`file_list.border_focused`, `file_list.border`. Under `NO_COLOR` only modifiers
(bold, dim, reverse, underline) are used.

### Errors

| Source | `courier_ftp_core::Error` | Footer / body text |
|---|---|---|
| Listing denied | `PermissionDenied` | `Error: Permission denied: <dir>` |
| Missing dir (address bar, stale history) | `NotFound(path)` | `Error: Directory not found: <dir>` |
| Timeout | `Timeout` | `Error: Timed out listing <dir>` |
| Connection lost | `Connection(_)` | `Error: Connection lost` (status → `NotConnected` when the tab reports `Disconnected`) |
| Server reply | `Protocol { code, message }` | `Error: <code> <message>` (sanitised, cut to the footer) |
| Address bar parse | `InvalidInput(msg)` | `Error: <msg>`, address bar reverts |
| Cancel | `Cancelled` | nothing |

No error panics or leaves the pane in an empty state when a previous listing exists.

### Security and logging

- File names, link targets, owners, groups and server messages are untrusted: always
  through `sanitize` before rendering (T91 §9 "terminal escape sequences").
- The pane never logs paths or names at `info`+ (T91 §4). `debug` may log
  `pane=<tab>/<side> request=<id> entries=<n> took_ms=<n>`, without paths.
- Selections handed to T62 contain `Entry` values only; no secrets pass through this
  component.
- Glob/quick-filter input is bounded to 256 characters.

## Implementation steps

1. `natural.rs` + `format.rs` (size, date, type table) with unit tests.
2. `columns.rs`: `ColumnSpec`, `fit()`, settings keys and defaults.
3. `state.rs`: `FileListState`, cursor/offset/marks/visual mode/history, `reduce` for
   movement and marking, with unit tests (no rendering yet).
4. `view.rs`: hidden, T47 filters, quick filter, sort; inline/off-thread switch with generations.
5. `render.rs`: header, rows, footer, title, body states; `sanitize` usage; snapshot tests.
6. Navigation requests and `ListingLoaded`/`ListingUpdated` handling; wire into T50's runner and `ListingCache`.
7. Address bar editing with `PathInput`; history; cursor memory.
8. Quick filter mode `Filter`; `.` hidden toggle; column menu; sort keys (`s n` … `s o`).
9. File-op requests (`Selection`) and `=`; remove T50's placeholder pane.
10. Benchmarks + bench gates; performance tests.

## Acceptance criteria

- [ ] AC1 Snapshot tests at 80×24 and 160×48 exist and pass for: local listing, remote listing, marked rows, quick filter editing, filtered view, empty dir, error with and without previous listing, not connected, loading, and the 40×12 narrow pane.
- [ ] AC2 `columns::fit` produces exactly the column sets in the table for inner widths 22, 23, 34, 35, 45, 46, 59, 60, 63, 64, 80, 81.
- [ ] AC3 Natural sort orders `file2 < file10`, `a1 < a01 < a2`; case-insensitive by default; dirs first in both directions.
- [ ] AC4 After `Parent`, the cursor is on the directory we came from; after `Back`, on the entry remembered for that directory.
- [ ] AC5 A stale `ListingLoaded` (older `RequestId`) never replaces the current listing.
- [ ] AC6 Rendering a 100 000-entry listing formats only the visible rows (counter test) and the `file_list_render_100k` bench meets ≤ 5 ms p99 (bench gate).
- [ ] AC7 View build for 100 000 entries runs off the UI thread and completes ≤ 80 ms (bench gate); the UI keeps handling keys meanwhile.
- [ ] AC8 Names with ESC, control and bidi characters render as visible escapes; no raw control byte reaches the `TestBackend` buffer.
- [ ] AC9 With `NO_COLOR` and ASCII symbols the marked, cursor, directory and link states are still distinguishable in the text snapshot (`*`, `/`, `->`) and every cell is ASCII.
- [ ] AC10 A failed listing keeps the previous directory and shows the mapped error text.
- [ ] AC11 Filters/quick filter that hide marked entries unmark them; footer counts match the view.
- [ ] AC12 `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check` and `cargo test --workspace` pass (T00 gates).
- [ ] AC13 The pane reacts to exactly the T51 `FileList` keys: `.` toggles hidden files, `ctrl-d`/`ctrl-u` move half a page, `Q`/`shift-f5` request `QueueOnly`, `M`/`shift-f7` request `MkdirEnter`; `ctrl-h` does nothing.

## Tests

### Unit tests
- `natural_cmp_orders_numeric_runs` — `file2 < file10`, `a1 < a01 < a2`, unicode names (AC3).
- `sort_dirs_first_in_both_directions` (AC3).
- `sort_is_total_with_duplicate_folded_names` — `A` vs `a` ties broken byte-wise (AC3).
- `format_size_iec_three_significant_digits` — 0, 412, 1023, 1024, 4198, 49_869, 1.3e9 (AC1).
- `format_size_bytes_with_separator`, `format_size_si`.
- `format_modified_day_precision_has_no_time`, `format_modified_compact_current_year`.
- `type_description_table_and_fallbacks` — `.htaccess` → `File`, `x.TAR.GZ` → `GZIP archive`, `a.weird` → `WEIRD file`.
- `columns_fit_matches_priority_table` — all widths from AC2 (AC2).
- `cursor_returns_to_previous_dir_on_parent` (AC4), `back_forward_restores_cursor_memory` (AC4).
- `stale_listing_result_is_dropped` (AC5).
- `listing_error_keeps_previous_dir` — each error variant → footer text (AC10).
- `filter_hiding_marked_entries_unmarks_them`, `footer_counts_selected_files_and_dirs` (AC11).
- `visual_mode_marks_range_both_directions`, `mark_pattern_glob_case_insensitive`, `invert_marks_skips_parent_row`.
- `quick_filter_substring_and_glob`, `quick_filter_esc_clears_enter_keeps`.
- `filelist_default_keys` — `AppHarness` with the default keymap: `.` toggles `show_hidden`, `ctrl-d` moves half a page, `Q` and `M` emit `FileOp` `QueueOnly` / `MkdirEnter`, `ctrl-h` changes nothing (AC13).
- `listing_updated_matches_server_identity` — `ListingUpdated { server: Some(id), dir }` reloads only panes whose session has `id` and show `dir`; `server: None` reloads local panes showing `dir`.
- `listing_updated_keeps_cursor_and_marks_by_name`.
- `address_bar_expands_tilde_and_relative_paths`, `address_bar_error_reverts`.
- `render_formats_only_visible_rows` — a counting formatter with 100 000 entries at 160×48 formats ≤ 46 rows (AC6).

### Property / fuzz tests
- `prop_view_is_permutation_of_unfiltered_entries` — for random listings and settings the view contains each surviving index exactly once.
- `prop_natural_cmp_is_total_order` — antisymmetric and transitive on random strings.
- `prop_render_never_panics` — random listings (random unicode, control chars) at random sizes 0–200 × 0–60 (AC8).
- `prop_rendered_buffer_has_no_control_chars` (AC8).

### Snapshot tests
`ratatui::backend::TestBackend` + `insta`, each at 80×24 and 160×48 (pane given the whole
terminal), plus `narrow_pane_40x12`: `local_listing`, `remote_listing`, `marked_rows`,
`quick_filter_editing`, `filtered_view`, `empty_dir`, `error_with_previous`,
`error_first_listing`, `not_connected`, `loading`, `hostile_names` (AC1, AC8). Each also in
`NO_COLOR` + ASCII (`*_mono_ascii`, AC9). Style assertions (not text snapshots) check that
the cursor cell is `REVERSED` and directories are bold.

### Integration tests
- `navigates_local_tempdir_with_local_backend` — `LocalBackend` on a `tempfile::TempDir`: enter, parent, refresh after creating a file.
- `remote_navigation_uses_cache_hit` — `MockBackend` (T03) call counter: second visit served by `ListingCache` (T46).
- `large_listing_sort_runs_off_thread` — 100 000 mock entries; keys handled while `SortDone` pending (AC7).
- Bench `file_list_render_100k`, `file_list_view_build_100k` (AC6, AC7).

### End-to-end tests
- PtyApp (T76) `browse_local_dir_and_sort` — start the binary in a temp home, navigate, `s m`, `.`, verify the screen text (AC13). Remote browsing e2e lives in T22/T14 scenarios.

## Out of scope

- File operations themselves (T62), view/edit (T63), comparison colours (T66).
- Mouse support (D7) and drag and drop (D8).
- Thumbnails/previews; per-directory sort memory (one sort per side).

## Open questions

1. FileZilla offers three folder placements (first / inline / always on top); T05 has only `dirs_first: bool`. This task maps `true` to "always on top". Should the three-way option be added?
