# T48 — Directory comparison engine

**Phase:** E Transfers · **Depends on:** T02, T47 · **Crate:** `courier-ftp-core` (`compare` module) · **FEATURES.md:** §7
**Related (integrates with, not blocking):** T13, T66

## Goal

Compare the local and remote listings currently shown and classify every row,
exactly as FileZilla's directory comparison does.

## Scope

1. `compare(left: &[Entry], right: &[Entry], opts: CompareOpts) -> ComparedListing`
   - `CompareOpts { mode: Size | ModificationTime, threshold_minutes: u32 (default 1), dirs_first, hide_identical, case_sensitive_names }`.
   - Name matching case-insensitive when either side is Windows (local Windows or remote DOS server type), otherwise case-sensitive.
2. Output: aligned rows (so both panes show the same name on the same line; empty placeholder rows where an entry exists on one side only):
   ```rust
   pub struct ComparedRow { pub left: Option<usize>, pub right: Option<usize>, pub status: RowStatus }
   pub enum RowStatus { Equal, OnlyLeft, OnlyRight, LeftNewer, RightNewer, SizeDiffers, DirBoth, Unknown }
   ```
   - Colours (UI, T66): yellow = only one side, green = newer, red = size differs.
   - Mode Size: files compare by size; Mode Time: compare `modified` with threshold and coarser precision (T02), and a server time zone offset already applied (T13).
   - Directories: present on both = `DirBoth` (no recursion).
3. `hide_identical` filters out `Equal` (and optionally `DirBoth`) rows.
4. Warn (return flag) when the active filters differ between sides (T47 `equivalent`), since FileZilla requires identical filtering.

## Acceptance criteria

- [ ] All statuses covered by tests, including precision edge cases (minute vs second).
- [ ] Alignment correct with sorting by name and with dirs-first.
- [ ] Case-insensitive matching on Windows-like sides.

## Tests

- Table-driven unit tests.
