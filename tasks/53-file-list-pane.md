# T53 — File list pane

**Phase:** F TUI · **Depends on:** T02, T06, T46, T47, T50, T51, T52 · **Crate:** `courier-ftp` (`components/file_list.rs`) · **FEATURES.md:** §3
**Related (integrates with, not blocking):** T13, T62

## Goal

The core widget of the app: a fast, sortable, multi-select file list with an
editable address bar, used for both local and remote sides.

## Scope

1. **Address bar** (top of pane): shows current path (local with `~`, remote absolute); `a` focuses it for editing with path completion (T52 `PathInput`); Enter navigates; error → message + revert. History back/forward (`Alt-←`/`Alt-→` or `[`/`]` in file list mode — finalise with T51).
2. **Columns**: Name, Size, Type (extension-based description, e.g. "HTML file"), Modified, Permissions, Owner/Group. Column visibility, order and width configurable (`interface.columns.local` / `.remote`) and toggled via a small column menu. Narrow terminals drop columns in priority order (Owner, Type, Perms, Modified, Size).
3. **Rendering details**
   - `..` row at top except at root.
   - Directories marked with trailing `/` and dir colour; symlinks `→ target` in dim text; hidden files dim.
   - Size per `size_format` (bytes with separators / IEC KiB / SI kB); dirs show blank (or `<DIR>`).
   - Date per `date_format`; precision-aware (day-only timestamps omit time).
   - Selection: marked rows highlighted + `*` marker column; cursor row reversed.
   - Footer: "N files and M directories. Total size: X" and for selection "Selected N files. Total size: X" (FileZilla's status line).
   - Pane title shows spinner while listing, `(filtered)` when filters/quick filter active, site colour accent for remote.
4. **Sorting**: by any column, asc/desc, `dirs_first` (Folders first / mixed / folders on top always), `sort_case_sensitive`, natural sort for names (`file2` < `file10`) — configurable.
5. **Navigation**: enter dir (list via backend, using cache T46), parent, keep cursor on the dir we came from when going up, remember cursor per directory for back/forward.
6. **Selection**: toggle, range (visual mode), select all, invert, select/deselect by glob pattern dialog.
7. **Quick filter** `/`: incremental, case-insensitive substring or glob if it contains `*?`; Esc clears; Enter keeps the filter active and returns to navigation.
8. **Hidden files**: toggle; remote "force show hidden" uses `LIST -a` (T13) and triggers refresh.
9. **Not connected** remote pane: shows "Not connected to any server" and a hint (`Ctrl-s` Site Manager / `Ctrl-k` quickconnect).
10. **Errors** (permission denied listing a dir): shown inline in the pane body and in the log; stay in previous dir.
11. **Performance**: virtualised rendering (only visible rows formatted); 100 000-entry directory scrolls smoothly; sorting off the render path.
12. Emits actions for operations (transfer, delete, rename…) handled by T62.

## Acceptance criteria

- [x] Snapshot tests: local listing, remote listing, filtered, selection, empty dir, error, not connected, narrow terminal.
- [x] Sorting/natural sort unit-tested.
- [x] Cursor restored on parent navigation.
- [x] 100k entries: render < 5 ms per frame (bench test).

## Tests

- Snapshot and unit tests with `MockBackend`/`LocalBackend` in temp dirs.
