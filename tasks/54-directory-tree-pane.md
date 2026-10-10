# T54 — Directory tree pane

**Phase:** F TUI · **Depends on:** T53 · **Crate:** `courier-ftp` (`components/dir_tree.rs`) · **FEATURES.md:** §3 (local and remote folder tree)
**Related (integrates with, not blocking):** T06, T46

## Goal

Optional (toggleable, off by default) folder trees for each side, like
FileZilla's upper panes, synced with the file list.

## Scope

1. Tree rows: indent guides (`├─`, `└─`), expand/collapse markers (`▸`/`▾`), folder names; current dir highlighted.
2. **Lazy loading**: children listed when expanded (via cache/backend); unknown-children nodes show `▸` until listed; remote nodes show `?` while loading.
3. Keys: `j/k` move, `l`/`→` expand (or enter), `h`/`←` collapse or go to parent, `Enter` navigate file list to that dir.
4. Sync: navigating in the file list expands the tree to the current path and scrolls it into view.
5. Local root: `/` on Unix; on Windows, drive list (T06) plus home and Desktop shortcuts at the top.
6. Remote root: `/` with path from home dir pre-expanded.
7. Layout placement handled by T50 (above the list in Classic, beside in Explorer/narrow screens hidden).

## Acceptance criteria

- [x] Tree stays consistent after create/delete/rename (cache events, T46).
- [x] Expanding a large directory doesn't block rendering.
- [x] Snapshot tests for collapsed/expanded/loading states.

**Status (T54 done):** the tree lives in `crates/courier-ftp/src/ui/dir_tree.rs`
(the binary has a `ui` module, not `components/`). `Ctrl-e` shows/hides the trees
(off by default, always shown in the Explorer layout), `T` moves focus between a
file list and its tree. Listings run in background tasks through the listing
cache and only for trees on screen; rows are rebuilt when data changes and only
visible rows are drawn. `CoreEvent::ListingUpdated` (cache patches) reloads the
affected node; the file operations that patch the cache from the UI come with
T62. The Windows Home/Desktop shortcuts are built and unit tested on Linux
(`DirTree::with_shortcuts`) but not yet run on Windows.

## Tests

- Snapshot tests; unit tests for path-expansion sync.
