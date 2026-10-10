# T43 — Recursive operations

**Phase:** E Transfers · **Depends on:** T40, T41, T47 · **Crate:** `courier-ftp-core` (`transfer::recursive`) · **FEATURES.md:** §4 (recursive delete, recursive chmod), §5, §6 (empty dirs, symlinks), §8 (filters applied to transfers)
**Related (integrates with, not blocking):** T62

## Goal

Expand directories into individual operations for upload, download, delete and
chmod — lazily, cancellably, with filters applied.

## Scope

1. **Walker**: async, depth-first, over any `Backend` (local or remote), bounded memory (don't hold whole tree). Yields `(path, Entry)`.
   - Cancellable; reports progress ("Listing /a/b … 1 234 files found") as Status log + an event for the status bar.
   - Symlinks: if `follow_symlinks` false, symlinked dirs are not descended (symlink transferred as a file only if it points to a file); if true, detect loops via visited (dev,inode) locally or canonical path remotely.
   - Errors on a subdirectory (permission denied) logged and skipped, operation continues; summary lists skipped dirs.
2. **Recursive download/upload**: directory selection adds a **placeholder** queue item (T40 `is_dir_placeholder`); when the engine reaches it, it expands one directory level into child items inserted at the placeholder's position (keeps queue fast for huge trees, like FileZilla's "lazy" recursion).
   - Destination dirs created as needed (`mkdir` on remote, `create_dir_all` locally).
   - `empty_dirs` setting: create empty directories or skip them.
   - Filters (T47) applied: excluded entries never queued; filtered dirs not descended. Log count of filtered entries.
3. **Recursive delete**: walk post-order, `remove_file` then `rmdir`. Confirmation happens in UI (T62). Runs on the tab's browsing session (or a dedicated one) with progress; cancellable mid-way.
4. **Recursive chmod**: options from FileZilla's dialog — recurse into subdirectories: *apply to all files and dirs* / *files only* / *dirs only*. Also supports per-bit "leave unchanged" (tri-state checkbox in UI T62): mode computed per entry as `(old & !mask) | (new & mask)`.
5. **Recursive operations with filters**: a filtered-out directory is left untouched by delete and chmod as well.

## Acceptance criteria

- [x] 100 000-file tree (mock backend) expands without exceeding a bounded memory budget (count live entries in test).
- [x] Symlink loop doesn't hang with `follow_symlinks = true`.
- [x] Delete removes everything bottom-up; partial failure reports which entries remain.
- [x] Chmod tri-state masks computed correctly.
- [x] Filters prevent queuing excluded entries.

## Tests

- Mock backend trees; local backend in temp dir with symlink loops (Unix only).

## Status

Implemented in `courier_ftp_core::transfer::recursive` (`Walker`, `RecursiveExpander`,
`dir_placeholder`, `delete_recursive`, `chmod_recursive`, `ChmodSpec`), plus
`CoreEvent::RecursiveProgress`. The confirmation dialogs, the chmod dialog and the
status-bar display of the progress event are T62's (and T57's). Docker e2e tests
against real servers are not part of this task.
