# T64 — Bookmarks UI

**Phase:** F TUI · **Depends on:** T33, T52, T53 · **Crate:** `courier-ftp` · **FEATURES.md:** §2 (bookmarks)
**Related (integrates with, not blocking):** T66

## Goal

Add, manage and jump to bookmarks quickly.

## Scope

1. **Bookmarks menu** (`Ctrl-b`): fuzzy list of global bookmarks plus the current site's bookmarks (sectioned); Enter applies; `a` add current dirs as bookmark; `e` edit; `x` delete; `J/K` reorder.
2. **Add bookmark dialog**: name; type *Global* / *Site-specific* (latter only when connected to a saved site); local dir (prefilled), remote dir (prefilled); checkbox "Use synchronized browsing"; checkbox "Directory comparison".
3. **Applying**: navigate local and/or remote; enable sync browsing/comparison if set (T66).
4. Quickconnect sessions: site bookmarks unavailable → explain ("Save this connection as a site to use site bookmarks").
5. Vault locked → bookmarks hidden, menu offers unlock.

## Acceptance criteria

- [ ] Add/edit/delete/reorder persisted.
- [ ] Applying navigates both panes and toggles sync/compare as configured.

## Tests

- UI-flow tests with mock backends.
