# T65 — Search UI

**Phase:** F TUI · **Milestone:** M6 · **Depends on:** T41, T49, T52 · **Crate(s):** `courier-ftp` (`components/search/`) · **Decisions:** D6, D7 · **FEATURES.md:** §4 (remote search, local search)
**Related (integrates with, not blocking):** T63

## Goal

FileZilla's "Search remote files" dialog as a full-screen view for local and
remote searches: a condition builder (name, size, path, date), results that stream
in while the search runs, a stop key, and actions on the results — download or
upload with or without the directory structure, delete, view/edit, copy URL and
"go to" the result in its pane.

## Context

Before this task:
- T49 provides `SearchQuery { root, conditions, match_mode, case_sensitive,
  search_type }`, a streaming search on a dedicated session with
  `SearchEvent::{Found(path, Entry), Progress { dirs_scanned }, Done, Error}`,
  cancellation, and helpers to queue downloads preserving relative paths or
  flattened (rename on collision) and to delete selected results.
- T47 provides `Condition` (`Name`, `Path`, `Size`, `Date` with `StringOp`,
  `NumOp`, `DateOp`) and `MatchMode` (`All`, `Any`, `None`, `NotAll`).
- T41/T40 provide the queue and engine (`Queue::add_batch`, `Start`); T52 gives
  widgets (`Select`, `RadioGroup`, `PathInput`, `ListView`, `ProgressDialog`,
  `confirm`); T53 gives pane navigation and the file-list key conventions; T62 gives
  `PaneSide`, `PanePath`, the delete confirmation widget and the copy-URL helper.

Later: T63 (Related) provides View/Edit for results; T76 snapshot coverage.

## Technical specification

### Types and APIs

Module `crates/courier-ftp/src/components/search/` (`view.rs`, `form.rs`,
`results.rs`, `actions.rs`). `parse_size` and `parse_date` live in the shared
`crates/courier-ftp/src/components/forms/units.rs` (created by whichever of
T65/T67 lands first, used by both).

```rust
/// Field offered in the condition builder (FileZilla's search fields).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchField { Name, Size, Path, Date }

/// One editable condition row.
#[derive(Debug, Clone)]
pub struct ConditionRow { pub field: SearchField, pub op: usize, pub value: String }

/// Form state (kept per tab and side for the session).
#[derive(Debug, Clone)]
pub struct SearchForm {
    pub side: PaneSide,
    pub root: String,
    pub match_mode: MatchMode,
    pub case_sensitive: bool,
    pub search_type: SearchType,           // Files | Dirs | Both (T49)
    pub rows: Vec<ConditionRow>,           // 1..=MAX_CONDITIONS
}

pub const MAX_CONDITIONS: usize = 10;
pub const MAX_RESULTS: usize = 100_000;

/// Operators per field, in display order (index stored in `ConditionRow::op`).
pub fn operators(field: SearchField) -> &'static [(&'static str, OpKind)];

/// Validates the form and builds the T49 query. Errors are per row/field.
pub fn build_query(form: &SearchForm, local_tz: time::UtcOffset)
    -> Result<SearchQuery, Vec<(FormField, String)>>;

/// "10", "10K", "10 KiB", "1.5MB", "2G" → bytes. K/M/G/T = 1024ⁿ (KiB…), KB/MB/GB/TB = 1000ⁿ.
pub fn parse_size(s: &str) -> Result<u64, String>;

/// "2026-10-08" or "2026-10-08 14:30" in the local time zone.
pub fn parse_date(s: &str, tz: time::UtcOffset) -> Result<(OffsetDateTime, DatePrecision), String>;

/// One result row.
#[derive(Debug, Clone)]
pub struct SearchResult { pub path: PanePath, pub entry: Entry }

/// Running search: T49 handle + counters.
pub struct RunningSearch {
    pub cancel: CancellationToken,
    pub dirs_scanned: u64,
    pub skipped_dirs: u64,
    pub started: std::time::Instant,
}

/// The full-screen view (one per tab, kept while the tab lives).
pub struct SearchView { /* form, results, running, focus: Form | Results, last summary */ }

/// Result actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferLayout { KeepStructure, Flatten }
```

New `Action` variants: `Search` (open view), `SearchStart`, `SearchStop`,
`SearchEvent(TabId, SearchEvent)`, `SearchTransfer`, `SearchDelete`, `SearchGoTo`,
`SearchClose`.

### Behaviour

#### Opening

`Ctrl-f` (T51) opens the view for the current tab, full screen (panes hidden,
status bar kept). Side defaults to the focused pane's side; the root to that pane's
current directory. If the tab has a previous search, the form and its results are
shown as they were (the query is remembered per tab and per side for the running
session; nothing is persisted). Remote is disabled (with "Not connected") when the
tab has no connection.

#### Layout (160×48 shows everything; 80×24 below)

```
┌ Search ───────────────────────────────────────────────────────────────────────┐
│ Search in:  ( ) Local  (•) Remote      Directory: [/var/www_________________] │
│ Match:      (•) All  ( ) Any  ( ) None  ( ) Not all     [ ] Case sensitive    │
│ Find:       (•) Files  ( ) Directories  ( ) Both                              │
│ Conditions:                                                                   │
│   [Name ▾]  [contains       ▾]  [.log_________________________]  [-]          │
│   [Size ▾]  [greater than   ▾]  [10 MiB_______________________]  [-]          │
│   [+ Add condition]                                                           │
│                               [ Search ]   [ Close ]                          │
├ Results: 12 ─ Searching… 143 directories scanned ⠋ ───────────────────────────┤
│   Name          Directory               Size       Modified          Perms    │
│ > access.log    /var/www/logs           12.3 MiB   2026-10-08 10:00  rw-r--r--│
│ * error.log     /var/www/logs           20.1 MiB   2026-10-08 10:02  rw-r--r--│
│   old.log       /var/www/backup/2025    11.0 MiB   2025-12-31 23:59  rw-------│
│                                                                               │
├───────────────────────────────────────────────────────────────────────────────┤
│ F5 download  F8 delete  F3 view  F4 edit  Enter go to  / filter  Ctrl-c stop  │
└───────────────────────────────────────────────────────────────────────────────┘
```

On terminals shorter than 30 rows, when focus is on the results, the form
collapses to a one-line summary:
```
│ Remote /var/www · All of: Name contains ".log", Size > 10 MiB   (Esc: edit)   │
```
Width < 100 columns drops the Perms column, then Modified (T53 priority order).

#### Form

- Focus traversal: `Tab`/`Shift-Tab` through fields (T52 form rules); `Enter` on any
  field (except an open dropdown) starts the search; `Esc` in the form closes the view.
- Switching Local/Remote replaces the root with the other pane's directory unless
  the user edited the root.
- Condition rows: `Ctrl-n` or the `[+ Add condition]` button adds a row
  (`Name contains ""`), `[-]` or `Ctrl-d` on a focused row removes it (the last row
  can't be removed). At most 10 rows.
- Operators per field (mapping to T47):

| Field | Operators | Value input |
|---|---|---|
| Name | contains, doesn't contain, equals, doesn't equal, begins with, ends with, matches regex | text |
| Path | same as Name (matched against the full path) | text |
| Size | greater than, equals, doesn't equal, less than | `parse_size` |
| Date | before, equals, doesn't equal, after | `parse_date` |

- Validation (`build_query`), live, shown under the row; Search disabled until valid:
  empty value for any field → "Enter a value"; regex compiled with `regex::RegexBuilder` (`size_limit`
  1 MiB, case-insensitivity from the checkbox) → error text from the regex crate;
  size/date parse errors; root must be an absolute path on that side.
- Date semantics: a date without time means the whole local day, with time the
  whole minute; the precision is passed to T47's `DateOp` evaluation (see Open
  questions).

#### Running a search

1. `build_query` → T49 search start (local: `LocalBackend`; remote: T49's
   dedicated session built from the tab's `ConnectInfo`). The previous results are
   cleared; the Search button becomes **Stop**; focus moves to the results.
2. Events are drained once per frame (≤ 60 Hz) to keep rendering smooth:
   - `Found(path, entry)` → append a `SearchResult` (rows appear while the search runs).
   - `Progress { dirs_scanned }` → header "Searching… N directories scanned" with
     the T50 spinner.
   - `Error` for a subdirectory (permission denied etc.) → `skipped_dirs += 1`,
     `Error:` line in the tab log; the search continues.
   - `Done` → header "12 found in 143 directories (2.1 s)" (+ ", 3 skipped").
   - Fatal `Error` (connection lost, root not found) → header "Search failed:
     <reason>", results so far kept.
3. **Stop**: `Ctrl-c`, the Stop button, or `Esc` while running → cancel token;
   header "Search stopped: 12 found in 80 directories". T49 guarantees stop within 1 s.
4. At `MAX_RESULTS` (100 000) the search is cancelled with "Result limit reached;
   refine the search".
5. Closing the view (`Esc` in the form when idle, `q`, or Close) while a search runs
   asks "Stop the running search?" (default Yes).

#### Results list

Keys (results focused):

| Key | Action |
|---|---|
| `j`/`k`/`↓`/`↑`, `gg`/`G`, `PageUp`/`PageDown` | move |
| `Space` / `Insert`, `v`, `Ctrl-a`, `*` | select (T53 semantics) |
| `s` then `n` / `d` / `s` / `m` / `p` | sort by name / directory / size / modified / permissions (again = reverse) |
| `/` | quick filter on name (T53 rules: substring, glob with `*?`) |
| `Enter` | go to |
| `F5` | download (remote search) / upload (local search) |
| `F8` / `Delete` | delete |
| `F3` / `F4` | view / edit (T63) |
| `y u` | copy URL / path (T62 helper) |
| `Esc` | back to the form (stops a running search first) |

Sorting and filtering happen on a separate index vector (results stay in arrival
order underneath), so new results are merged into the sorted view without
re-sorting everything: insertion by binary search. Rendering is virtualised
(only visible rows formatted, like T53).

#### Actions

- **Go to** (`Enter`): hide the view (state kept), navigate the matching pane to the
  result's directory (T53) and place the cursor on the entry. `Ctrl-f` returns to the
  view with the same cursor.
- **Download / upload** (`F5`, on the selection or the cursor row):
  ```
  ┌ Download 2 files ─────────────────────────────────────────────┐
  │ Target directory: [~/Downloads/logs____________________]      │
  │                                                               │
  │ (•) Keep directory structure (relative to /var/www)           │
  │     → ~/Downloads/logs/logs/access.log                        │
  │ ( ) Flatten into the target directory                         │
  │     (name clashes become "name (1).ext")                      │
  │                                                               │
  │ [ ] Add to queue only                                         │
  │                    [ Download ]    [ Cancel ]                 │
  └───────────────────────────────────────────────────────────────┘
  ```
  Target defaults to the other pane's directory. An example line previews the
  first item's destination. Upload of local results requires a connected remote
  pane ("Not connected" message otherwise). Items come from T49's helpers (keep
  structure: path relative to the search root; flatten: rename on collision among
  the selected results and against the target listing when cached), then
  `Queue::add_batch` and `Start` unless queue-only. Directory results become
  recursive placeholders (T43). Status: "Queued 2 items".
- **Delete** (`F8`): the T62 delete confirmation (≤ 5 names + "… and N more",
  default Cancel, honours `interface.confirm_delete`); executes T49's delete helper
  with a `ProgressDialog` after 300 ms; deleted rows are removed from the results;
  failures listed as in T62.
- **View / edit** (`F3`/`F4`): T63 flows on the result's full path; when T63 isn't
  available the keys show "View/edit is not available yet".
- **Copy URL** (`y u`): T62 helper for each selected result.

### Data formats and configuration

No new settings. Uses `interface.confirm_delete`, `interface.size_format`,
`interface.date_format` / `time_format`, `interface.unicode_symbols` for display,
and T49/T47 types for the query. Queries and results are memory-only.

Default binding (T51): `Ctrl-f` → `Search` (existing). View-local keys as above
(mode `Dialog`-like full-screen view; global keys except `F1`, `Ctrl-q`/`F10` are
not active while the view is open).

### Errors

| Situation | Error | User sees |
|---|---|---|
| Invalid regex / size / date / root | form validation | inline message; Search disabled |
| Root not found / not a directory | `Error::NotFound` | header "Search failed: /x does not exist" |
| Subdirectory unreadable | `Error::PermissionDenied` (per dir) | counted as skipped; `Error:` log line |
| Connection lost | `Error::Connection` / `Error::Timeout` | header "Search failed: connection lost"; results kept |
| Remote not connected | — | Remote option disabled; upload action refused with message |
| Result limit | — | search stopped with "Result limit reached" |

### Security and logging

- Result names from the server are displayed only after control-character
  stripping (T53/T91); hostile names (containing `/`, NUL, `..`) are never used to
  build local paths — T49/T42 sanitise and reject.
- Regexes are size-limited (1 MiB compiled) so a pasted pattern can't exhaust memory.
- `tracing` at `debug`: counts, durations, cancel; no paths, patterns or hostnames
  at `info`+. The session log carries `Status:` lines like "Search finished: 12
  found" without the query.

## Implementation steps

1. `parse_size`, `parse_date`, `operators`, `build_query` with unit tests.
2. `SearchForm` widget (rows, add/remove, validation display) and the view shell
   with focus handling and the collapsed summary.
3. Running searches: T49 start, per-frame event draining, progress header, stop,
   result limit, close-while-running prompt.
4. Results list: virtualised rendering, sort index with binary insertion, quick
   filter, selection.
5. Actions: go to, download/upload dialog, delete, copy URL, T63 hooks.
6. Snapshot tests and UI-flow tests with a slow mock backend.

## Acceptance criteria

- [ ] AC1 With a `MockBackend` that delays each listing by 100 ms (paused time), the first results are rendered before `Done` arrives.
- [ ] AC2 `Ctrl-c` during a search stops it within 1 s; no further results are appended afterwards; the header says "Search stopped".
- [ ] AC3 Download with *Keep directory structure* queues items whose local paths mirror the paths relative to the search root; *Flatten* puts all files into the target dir with `name (1).ext` on collisions.
- [ ] AC4 Upload of local results queues uploads with the same two layouts.
- [ ] AC5 Delete removes the selected results from the backend and from the list after confirmation (default Cancel).
- [ ] AC6 Go to navigates the right pane to the result's directory with the cursor on the entry; reopening the view shows the previous results.
- [ ] AC7 Form validation: invalid regex, size and date values block Search with an inline message; size suffixes parse per the table tests.
- [ ] AC8 Conditions combine with All / Any / None / Not all as passed to T49 (query built correctly for each mode).
- [ ] AC9 100 000 results render at < 5 ms per frame (bench, `#[ignore]` in CI, gate in `bench.yml`) and the limit stops the search.
- [ ] AC10 Snapshot tests of the form (empty, conditions, validation error), results (streaming, done, stopped, failed), the collapsed 80×24 layout and the transfer dialog at 80×24 and 160×48.
- [ ] AC11 CI gates pass: `fmt`, `clippy -D warnings`, `docs`, `test-local-only`, `test-os`.

## Tests

### Unit tests

- `fn parse_size_table` — `"10"`, `"10K"`, `"10 KiB"`, `"1.5MB"`, `"2G"`, `"1TB"`, errors `"-1"`, `"10X"`, overflow (AC7).
- `fn parse_date_day_and_minute_precision_local_tz` / `fn parse_date_rejects_invalid` (AC7).
- `fn build_query_maps_each_operator_to_t47_condition` (AC8).
- `fn build_query_match_modes` — All/Any/None/NotAll passed through (AC8).
- `fn build_query_invalid_regex_reports_row` (AC7).
- `fn sorted_index_binary_insert_matches_full_sort` (AC1).
- `fn flatten_preview_and_keep_structure_preview` (AC3).

### Property / fuzz tests

- `proptest fn sorted_insert_equals_sort` — random arrival order and sort key; incremental index equals a full stable sort (AC1).
- `proptest fn parse_size_never_panics` (AC7).

### Snapshot tests

At 80×24 and 160×48 (AC10): `snapshot_search_form_empty`,
`snapshot_search_form_conditions`, `snapshot_search_form_regex_error`,
`snapshot_search_results_streaming`, `snapshot_search_results_done`,
`snapshot_search_results_stopped`, `snapshot_search_failed_connection`,
`snapshot_search_collapsed_form_80x24`, `snapshot_search_download_dialog`,
`snapshot_search_upload_not_connected`.

### Integration tests

UI-flow tests with scripted keys; `MockBackend` with per-listing latency and
`tokio::time::pause`; `LocalBackend` in a temp dir:
- `fn results_stream_before_done` (AC1).
- `fn ctrl_c_stops_within_1s` (AC2).
- `fn download_keep_structure_and_flatten_queue_items` (AC3).
- `fn upload_local_results_both_layouts` (AC4).
- `fn delete_results_confirm_and_remove` (AC5).
- `fn go_to_navigates_pane_and_restores_view` (AC6).
- `fn remote_disabled_when_not_connected`.
- `fn result_limit_stops_search` — limit lowered via a test constructor (AC9).
- `bench render_100k_results` (criterion, AC9).

### End-to-end tests

`courier-ftp-e2e` (`#[ignore]`, `COURIER_E2E=1`): `fn e2e_remote_search_and_download`
— `Headless`/`PtyApp` against the `proftpd` profile with a seeded tree: search
`Name ends with .log`, download with structure, verify files and SHA-256 locally (AC3).

## Out of scope

- Content (grep-like) search inside files.
- Saving named queries or persisting results.
- Searching across several servers at once.

## Open questions

1. **T47 date semantics**: `Condition::Date(DateOp, OffsetDateTime)` carries no
   precision; this UI needs "equals = same day / same minute". T47 should add a
   precision (or a range) to `Date` conditions.
2. Should search results also be exportable (e.g. copy all paths to the clipboard
   as a list)? Not specified by FileZilla; left out.
