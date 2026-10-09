# T66 — Directory comparison and synchronized browsing UI

**Phase:** F TUI · **Depends on:** T48, T53 · **Crate:** `courier-ftp` · **FEATURES.md:** §7

## Goal

Show FileZilla's coloured comparison in both panes and keep the panes'
directories in lockstep.

## Scope

1. **Synchronized browsing** (`Ctrl-y`)
   - On enable, record the base pair (local dir L0, remote dir R0). Navigation in either pane into a subdir/parent applies the same relative move to the other.
   - If the other side lacks the directory → message "Target directory does not exist on the other side" with options: *create it* / *disable sync browsing* / *stay*.
   - Navigating outside the base (above L0/R0, or address-bar jump) → ask to disable sync browsing.
   - Indicator in status bar and pane titles (`⇄`).
2. **Directory comparison** (`Ctrl-o`)
   - Turning it on also turns on synchronized browsing (FileZilla behaviour).
   - Both lists render aligned rows from T48 (`ComparedRow`), with blank placeholder rows for missing entries.
   - Row colours: **yellow** only one side, **green** newer, **red** size differs; legend in a footer line.
   - Options submenu: compare by *file size* / *modification time*; threshold minutes; *hide identical files*.
   - Warn (once) when filters differ between sides.
   - Cursor moves in lockstep in both panes while comparison is on (same row index).
3. **Quick actions on comparison** (beyond FileZilla, small and useful): "Select all yellow/green/red rows on this side" so the user can then press F5 to push differences. No automatic sync (FileZilla has none).
4. Site settings (`sync_browsing`, `directory_comparison`) and bookmarks can enable both on connect.

## Acceptance criteria

- [ ] Sync browsing follows enter/parent in both directions; missing-dir prompt works.
- [ ] Comparison rows aligned and coloured correctly (snapshot tests).
- [ ] Hide identical works.
- [ ] Select-by-status works.

## Tests

- Snapshot tests with constructed listings; unit tests for relative path mapping.
