# T66 — Directory comparison and synchronized browsing UI

**Phase:** F TUI · **Milestone:** M6 · **Depends on:** T48, T53 · **Crate(s):** `courier-ftp` (`components/compare/`) · **Decisions:** D6, D7 · **FEATURES.md:** §7

## Goal

Keep the local and remote panes in the same relative directory while browsing
(`Ctrl-y`), and show FileZilla's coloured directory comparison in both panes
(`Ctrl-o`): rows aligned by name, yellow for entries on one side only, green for
the newer file, red for a size difference, with an option to hide identical files
and a quick way to select all differences on one side so F5 can push them.

## Context

Before this task:
- T48 provides `compare(left, right, opts) -> ComparedListing` with aligned
  `ComparedRow { left: Option<usize>, right: Option<usize>, status: RowStatus }`,
  `RowStatus { Equal, OnlyLeft, OnlyRight, LeftNewer, RightNewer, SizeDiffers,
  DirBoth, Unknown }`, `CompareOpts { mode: Size | ModificationTime,
  threshold_minutes, dirs_first, hide_identical, case_sensitive_names }`, and the
  "filters differ" flag (via T47 `FilterEngine::equivalent`).
- T53 provides both file list panes: navigation (address bar, enter, parent,
  back/forward), listing via the cache (T46), sorting, selection, quick filter,
  filters (T47), virtualised rendering, and emits navigation as actions.
- T50/T57 provide the status bar segments `⇄ sync` and `≠ compare`; T61 keeps
  per-tab sync/compare flags; T31 sites and T33/T64 bookmarks carry
  `sync_browsing` / `directory_comparison` flags.

Later tasks use from this task: T59 (connect with the site's flags), T64 (apply
bookmark flags), T62's F5 after "select by status", T67 (re-filter triggers a
recompare).

In this layout "left" in T48 terms is always the **local** pane and "right" the
**remote** pane, independent of `interface.swap_panes` (which only changes where
they are drawn).

## Technical specification

### Types and APIs

Module `crates/courier-ftp/src/components/compare/` (`sync.rs`, `state.rs`,
`render.rs`, `dialogs.rs`).

```rust
/// Synchronized browsing state of one tab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncBrowsing { pub base_local: LocalPath, pub base_remote: RemotePath }

/// Result of mapping a navigation target to the other side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapResult {
    /// Same relative position under the other base.
    Mapped(PanePath),
    /// Target is above or outside the base on its own side.
    OutsideBase,
    /// A component can't exist on the other side (e.g. `a:b` for a Windows local side).
    InvalidOnOtherSide(String),
}

/// Pure mapping: relative components of `target` under its side's base,
/// joined onto the other side's base.
pub fn map_to_other(sync: &SyncBrowsing, target: &PanePath) -> MapResult;

/// Comparison settings (persisted, see Data formats).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompareSettings { pub mode: CompareMode, pub threshold_minutes: u32, pub hide_identical: bool }

/// Per-tab comparison state.
pub struct CompareState {
    pub settings: CompareSettings,
    pub listing: Option<ComparedListing>,   // None until both panes are listed
    pub filters_warning_shown: bool,
}

/// How a row looks on one side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowLook { pub colour: Option<CompareColour>, pub marker: char, pub placeholder: bool }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareColour { Yellow, Green, Red }

pub fn row_look(status: RowStatus, side: PaneSide, present: bool, unicode: bool) -> RowLook;

/// Which rows "select by status" picks on `side`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusSelect { OnlyHere, NewerHere, SizeDiffers, AllDifferences }
pub fn select_by_status(listing: &ComparedListing, side: PaneSide, which: StatusSelect) -> Vec<usize>;

/// Builds T48 options from settings and the two sides.
pub fn compare_opts(s: &CompareSettings, dirs_first: bool, local_windows: bool,
                    remote_server_type: ServerTypeOverride) -> CompareOpts;

/// Public entry points used by T59 (site connect), T64 (bookmarks) and keys.
pub trait CompareControl {
    fn enable_sync_browsing(&mut self, tab: TabId) -> Result<(), Unavailable>;
    fn disable_sync_browsing(&mut self, tab: TabId);
    fn enable_comparison(&mut self, tab: TabId) -> Result<(), Unavailable>;
    fn disable_comparison(&mut self, tab: TabId);
}
```

New `Action` variants: `ToggleSyncBrowsing`, `ToggleComparison`,
`CompareOptions`, `SelectByStatus`, internal `SyncNavigate { tab, from: PaneSide,
target: PanePath }`, `SyncListingsReady { tab, .. }`.

### Behaviour

#### Synchronized browsing (`Ctrl-y`)

1. **Enable**: requires a connected remote pane ("Connect to a server first"
   otherwise). Base pair = the two current directories `(L0, R0)`. Status bar
   shows `⇄ sync`, both pane titles get a `⇄ ` prefix (`<> ` in ASCII mode).
   Status message "Synchronized browsing on: ~/site ⇄ /var/www".
2. **Navigation interception**: with sync on, every pane navigation (enter dir,
   parent, address bar, back/forward, tree pane T54, bookmark-free jumps) goes
   through `SyncNavigate`:
   - `map_to_other(sync, target)`:
     - `Mapped(other)` → list `target` on its side and `other` on the other side
       **concurrently** (cache first, T46). When both succeed, both panes switch in
       the same frame (no flicker, the comparison sees a consistent pair).
     - `OutsideBase` → dialog
       ```
       ┌ Synchronized browsing ──────────────────────────────────────┐
       │ /var is outside the synchronized base /var/www.             │
       │ Disable synchronized browsing to go there?                  │
       │        [ Disable and go ]    [ Stay ]                       │
       └─────────────────────────────────────────────────────────────┘
       ```
       Default *Stay*.
     - `InvalidOnOtherSide(name)` → message "\"a:b\" can't exist on this computer;
       synchronized browsing can't follow." and the pane stays.
   - Other side returns `NotFound`:
     ```
     ┌ Synchronized browsing ──────────────────────────────────────┐
     │ The directory does not exist on the other side:             │
     │   /var/www/assets/new                                       │
     │                                                             │
     │ [ Create it ]  [ Disable synchronized browsing ]  [ Stay ]  │
     └─────────────────────────────────────────────────────────────┘
     ```
     *Create it* → `mkdir` of the missing directory on the other side (its parent
     exists by the sync invariant; one call), cache patch, then both navigate.
     *Disable…* → sync off, the initiating pane navigates alone. *Stay* (default,
     `Esc`) → neither pane moves.
   - Before reporting `NotFound` on a case-insensitive pairing (local Windows or
     remote `Dos` server type, same rule as T48), the other side's parent listing is
     searched case-insensitively; a single match is used instead.
   - Other errors on either side (`PermissionDenied`, `Timeout`) → error message,
     neither pane moves, sync stays on.
3. **Disable**: `Ctrl-y` again, the dialogs above, disconnect of the remote side,
   or a new connection in the tab. Disabling sync leaves comparison as it is.
4. Mapping rules (`map_to_other`): relative components are computed after
   normalisation (T02); local paths use their native components (drive prefix
   excluded, so `C:\site\a` under base `C:\site` → `["a"]`); a component is
   invalid on the local side if `sanitize_local_name(c) != c` (T06), invalid on the
   remote side if it contains `/` or NUL.

#### Directory comparison (`Ctrl-o`)

1. **Enable**: requires a connected remote pane. Also enables synchronized
   browsing when it is off (FileZilla behaviour), with the current dirs as base.
   Status bar `≠ compare`.
2. **Input to T48**: the entries each pane would show after hidden-file and filter
   rules (T47/T53), **ignoring** the quick filter (the quick filter is then
   applied to the aligned rows by name, hiding both sides of a row together).
   `compare_opts`: mode/threshold/hide-identical from `CompareSettings`,
   `dirs_first = interface.dirs_first`, `case_sensitive_names = false` when the
   local OS is Windows or the remote server type is `Dos`, else true.
3. **Sorting**: while comparing, both panes are sorted by name (case rule as
   above), directories first per `interface.dirs_first`; sort keys (`s …`) show
   "Sorting is by name while comparing" and do nothing.
4. **Recompute** (synchronously on the update path, never in `draw`) when: either
   listing changes (`ListingUpdated`, navigation, refresh), settings change, filters
   change, hidden-file toggle. Target: 10 000 + 10 000 entries in < 20 ms.
5. **Rendering**: each pane renders the aligned rows; a side without an entry
   renders a blank placeholder row (dim `·` in the name column).

   | Status | Local row | Remote row | Marker (local / remote) |
   |---|---|---|---|
   | `OnlyLeft` | yellow | placeholder | `+` / ` ` |
   | `OnlyRight` | placeholder | yellow | ` ` / `+` |
   | `LeftNewer` | green | default | `>` / ` ` |
   | `RightNewer` | default | green | ` ` / `>` |
   | `SizeDiffers` | red | red | `≠` / `≠` (`!` in ASCII) |
   | `Equal`, `DirBoth` | default | default | ` ` |
   | `Unknown` | dim | dim | `?` / `?` |

   Colours come from the theme (`styles`, T50: `compare_only_one`,
   `compare_newer`, `compare_size_differs`); with `NO_COLOR` or a monochrome theme
   the marker column carries the meaning. The marker column (1 char) replaces the
   selection marker column's left padding, so widths don't change.
6. **Legend** (one line under the panes, above the queue):
   `■ only on one side  ■ newer  ■ size differs   by time ±1 min · identical shown`
   (squares coloured; ASCII mode uses `+ only  > newer  ! size`).
7. **Lockstep cursor**: the cursor row index and scroll offset are shared by both
   panes; moving in the focused pane moves the other. Placeholder rows can hold the
   cursor; operations on a placeholder (F5, F8, …) report "Nothing selected on this
   side" (T62 source rules). Selections stay per pane.
8. **Filters differ** (T48 flag): once per enable per tab, a message "The filters on
   the two sides differ, so the comparison may be misleading (Ctrl-x f to review
   filters)." The comparison is still shown.
9. **Disable**: `Ctrl-o` again or remote disconnect; panes return to their own
   sorting and cursors (the cursor stays on the same entry name when it exists).

#### Comparison options (`Ctrl-x c`)

```
┌ Directory comparison ─────────────────────────────────────────┐
│ Compare by:  (•) Modification time   ( ) File size            │
│ Threshold:   [1___] minutes (modification time only)          │
│ [ ] Hide identical files                                      │
│                                                               │
│                     [ OK ]    [ Cancel ]                      │
└───────────────────────────────────────────────────────────────┘
```
- Threshold 0–1440 minutes (`NumberInput`), disabled in size mode.
- *Hide identical files* hides `Equal` rows; `DirBoth` rows stay (so directories
  remain navigable).
- OK applies immediately (recompute) and saves via `Settings::save_user` (T05).
  The dialog can be opened with comparison off; the settings then apply next time.

#### Select by status (`Ctrl-x =`)

Only while comparing. `choose` dialog for the focused pane:
```
┌ Select on the local side ──────────────────┐
│ 1  Only on this side (yellow)              │
│ 2  Newer on this side (green)              │
│ 3  Size differs (red)                      │
│ 4  All of the above                        │
└────────────────────────────────────────────┘
```
`1`–`4` or Enter replaces the pane's selection with the matching rows
(`select_by_status`), directories included for "only on this side". Status
"Selected 7 entries"; the user then presses F5 (T62) to transfer them. No
automatic sync (FileZilla has none).

#### Site and bookmark flags

`CompareControl` is called by T59 after a site connection finished navigating to
its default dirs (`sync_browsing` → `enable_sync_browsing`,
`directory_comparison` → `enable_comparison`) and by T64 after a bookmark was
applied. An `Unavailable` result (e.g. remote not connected) is reported as a status
message.

### Data formats and configuration

| Key | Type | Default | Meaning |
|---|---|---|---|
| `compare.mode` | `CompareMode` (`ModificationTime` \| `Size`) | `ModificationTime` | T48 mode |
| `compare.threshold_minutes` | u32 (0–1440) | `1` | T48 threshold |
| `compare.hide_identical` | bool | `false` | hide `Equal` rows |
| `interface.dirs_first` | bool | `true` | row order while comparing |
| `interface.unicode_symbols` | auto/bool | auto | `⇄`, `≠`, `·` vs ASCII |

`compare.*` is a new section (see Open questions). Theme style keys
`compare_only_one` (yellow), `compare_newer` (green), `compare_size_differs` (red),
`compare_placeholder` (dim) in the `styles` config (T50).

Default bindings: `Ctrl-y` `ToggleSyncBrowsing`, `Ctrl-o` `ToggleComparison`
(existing in T51); `Ctrl-x c` `CompareOptions` and `Ctrl-x =` `SelectByStatus`
(added to T51's table by this task).

### Errors

| Situation | Error | User sees |
|---|---|---|
| Remote not connected | `Unavailable::NotConnected` | "Connect to a server first" |
| Other side missing dir | `Error::NotFound` | create / disable / stay dialog |
| Other side unreadable / timeout | `Error::PermissionDenied`, `Error::Timeout`, `Error::Connection` | error message, panes unchanged |
| `mkdir` on "Create it" fails | any core error | error message, panes unchanged, sync stays on |
| Name invalid on the other side | `MapResult::InvalidOnOtherSide` | message, pane unchanged |

### Security and logging

- Navigation targets on the other side are built only from normalised components
  that passed the validity check; server names containing `/`, NUL or `..` can't
  be mapped (T91 hostile names).
- `tracing` at `debug`: enable/disable events and recompute timings; no paths or
  hostnames at `info`+. The session log shows the usual listing lines.

## Implementation steps

1. `map_to_other` and the component validity check with unit tests (Unix and
   Windows local path shapes).
2. `SyncNavigate` interception in the tab controller: concurrent listing, atomic
   switch, outside-base and missing-dir dialogs, create-it, case-insensitive retry.
3. `CompareSettings` in settings (+ save), `compare_opts`, `CompareState`, recompute
   triggers, sort override.
4. Aligned rendering in both panes (`row_look`, placeholders, markers, legend),
   lockstep cursor and scroll.
5. Options dialog, select-by-status, filters-differ warning.
6. `CompareControl` for T59/T64; status bar and title indicators.
7. Snapshot tests with constructed listings and UI-flow tests.

## Acceptance criteria

- [ ] AC1 With sync on, entering a subdirectory or going to the parent in either pane moves the other pane to the matching directory; both panes switch in the same frame.
- [ ] AC2 Missing directory on the other side shows the dialog; *Create it* creates it with one `mkdir` and navigates both; *Stay* moves neither; *Disable* turns sync off and moves only the initiating pane.
- [ ] AC3 Navigating above the base (or an address-bar jump outside it) asks to disable sync; default is Stay.
- [ ] AC4 Enabling comparison also enables synchronized browsing; disabling comparison keeps sync on.
- [ ] AC5 Comparison rows are aligned and coloured per the table for every `RowStatus` (snapshot tests with constructed listings, colour and `NO_COLOR` variants).
- [ ] AC6 *Hide identical files* removes `Equal` rows and keeps `DirBoth` rows.
- [ ] AC7 Select-by-status selects exactly the rows of the chosen class on the focused side.
- [ ] AC8 The cursor moves in lockstep; operations on a placeholder row report "Nothing selected on this side".
- [ ] AC9 Filters that differ between sides produce one warning per enable.
- [ ] AC10 Recompare of 10 000 + 10 000 entries takes < 20 ms (bench, `#[ignore]`, gate in `bench.yml`).
- [ ] AC11 Snapshot tests at 80×24 and 160×48 for sync indicators, comparison (all statuses, hide identical, ASCII mode), legend, options dialog, missing-dir and outside-base dialogs.
- [ ] AC12 CI gates pass: `fmt`, `clippy -D warnings`, `docs`, `test-local-only`, `test-os`.

## Tests

### Unit tests

- `fn map_enter_and_parent_within_base` (AC1).
- `fn map_above_base_is_outside` / `fn map_sibling_of_base_is_outside` (AC3).
- `#[cfg(windows)] fn map_windows_local_drive_paths` and `fn map_invalid_component_on_windows_local` (AC1).
- `fn map_unicode_and_spaces_round_trip`.
- `fn compare_opts_case_insensitive_for_windows_or_dos` (AC5).
- `fn row_look_table_all_statuses_both_sides` (AC5).
- `fn select_by_status_each_class` (AC7).
- `fn hide_identical_keeps_dirboth` (AC6).

### Property / fuzz tests

- `proptest fn map_round_trip` — for any relative component list valid on both sides, mapping local→remote→local returns the original path (AC1).

### Snapshot tests

At 80×24 and 160×48 (AC11), built from constructed `Listing`s (no backend):
`snapshot_sync_indicator_titles`, `snapshot_compare_all_statuses`,
`snapshot_compare_all_statuses_no_color`, `snapshot_compare_ascii_markers`,
`snapshot_compare_hide_identical`, `snapshot_compare_legend`,
`snapshot_compare_options_dialog`, `snapshot_sync_missing_dir_dialog`,
`snapshot_sync_outside_base_dialog`, `snapshot_select_by_status_dialog`.

### Integration tests

UI-flow tests with a temp-dir `LocalBackend` and a `MockBackend` remote:
- `fn sync_enter_and_parent_follow_both_ways` (AC1).
- `fn sync_missing_dir_create_stay_disable` — counts `mkdir` calls (AC2).
- `fn sync_outside_base_prompt_default_stay` (AC3).
- `fn sync_case_insensitive_retry_with_dos_server_type`.
- `fn comparison_enables_sync_and_disable_keeps_sync` (AC4).
- `fn comparison_recomputes_on_listing_update_and_filter_change` (AC5).
- `fn lockstep_cursor_and_placeholder_operation_message` (AC8).
- `fn filters_differ_warning_once` (AC9).
- `fn site_flags_enable_on_connect` — T59 calls `CompareControl` (stubbed site connect).
- `bench recompare_10k_each_side` (criterion, AC10).

### End-to-end tests

`courier-ftp-e2e` (`#[ignore]`, `COURIER_E2E=1`): `fn e2e_compare_after_upload` —
`PtyApp` against the `sshd` `password` profile: enable comparison, see a yellow
row for a local-only file, select-by-status 1, F5, after the transfer the row turns
default (AC5, AC7).

## Out of scope

- Recursive comparison of subdirectories.
- Automatic one-way or two-way synchronisation (FileZilla has none, FEATURES §7).
- Comparing two remote servers or two local directories.

## Open questions

1. **T05 inconsistency**: there is no `compare` settings section in T05; this task
   needs `compare.mode`, `compare.threshold_minutes`, `compare.hide_identical`
   persisted (FileZilla remembers them). T05 should add the section.
2. **T51**: `Ctrl-x c` (comparison options) and `Ctrl-x =` (select by status) need
   to be added to the keymap table.
