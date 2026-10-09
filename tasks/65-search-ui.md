# T65 — Search UI

**Phase:** F TUI · **Depends on:** T41, T49, T52 · **Crate:** `courier-ftp` · **FEATURES.md:** §4 (remote search, local search)
**Related (integrates with, not blocking):** T63

## Goal

FileZilla's "Search remote files" dialog as a full-screen view.

## Scope

1. **Query form**: search in *Local* / *Remote*; start directory (prefilled with current); condition rows (add `+` / remove `-`): field (Name / Size / Path / Date), operator, value; match *All* / *Any*; case-sensitive; type Files / Dirs / Both.
2. **Results list** streaming in as found: Name, Path, Size, Modified, Permissions; count + "Searching… N dirs scanned" with spinner; `Esc`/`Ctrl-c` stops.
3. **Result actions**: download (remote) / upload (local) selected — dialog asks target dir and *keep directory structure* vs *flatten*; delete selected (confirm); edit/view (T63); "go to" — navigate the pane to the result's directory and select it.
4. Results sortable and filterable (`/`).
5. Previous query remembered for the session.

## Acceptance criteria

- [ ] Streaming results and cancel work with a slow mock backend.
- [ ] Actions queue correct transfers with/without structure.
- [ ] Snapshot tests of form and results.

## Tests

- UI-flow + snapshot tests.
