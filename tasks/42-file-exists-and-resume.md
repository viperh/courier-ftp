# T42 — File-exists policy, resume and transfer options

**Phase:** E Transfers · **Depends on:** T04, T05, T06, T41 · **Crate:** `courier-ftp-core` (`transfer::exists`, `transfer::options`) · **FEATURES.md:** §5 (file exists actions, resume), §6 (preallocate, timestamps, invalid chars, ASCII/binary)
**Related (integrates with, not blocking):** T11

## Goal

Everything that decides *how* a single file is transferred once the engine picks it.

## Scope

1. **ExistsAction** enum: `Ask`, `Overwrite`, `OverwriteIfNewer`, `OverwriteIfSizeDiffers`, `OverwriteIfNewerOrSizeDiffers`, `Resume`, `Rename`, `Skip`.
   - Defaults from settings `on_exists_download` / `on_exists_upload`; per-item override from the queue item; per-batch "apply to all" stored on the engine for the current queue run (with scope options: *this queue only* / *only for this server* / *only for uploads or downloads* — FileZilla offers "Apply to current queue only", "Apply only to uploads/downloads").
2. **Decision function** (pure, heavily tested):
   `decide(src: &Entry, dst: Option<&Entry>, action: ExistsAction, precision) -> Decision { Transfer{ mode: Create|Truncate|ResumeAt(n) } | Skip | Rename(new_name) | AskUser }`
   - "Newer" compares mtimes **at the coarser precision of the two** (T02 `Timestamp.precision`), and treats equal as not newer.
   - Resume: only if dst smaller than src; if dst ≥ src → Skip (log "already complete") unless sizes unknown → ask.
   - Rename: `name (1).ext`, `name (2).ext`, … first free name (requires a stat/list of the destination dir).
3. **Ask flow**: send `Prompt(FileExists { source entry, target entry, direction })` (T04); response = `{ action, apply_to: Once | AllInQueue | AllForDirection, new_name: Option<String> }`. While waiting, other workers continue; only this item is blocked. Multiple concurrent asks queue up one at a time in the UI.
4. **Transfer type**: `decide_transfer_type` (T11) used per file when `Auto`.
5. **Invalid characters**: on download, if `replace_invalid_chars`, run `sanitize_local_name` (T06) with the configured replacement; log when a name changes.
6. **Preallocate**: if enabled and size known, `set_len(size)` before writing (local download only); on failure (filesystem unsupported) continue without. Resume truncates back to the offset first.
7. **Preserve timestamps**: after download set local mtime from remote `modified`; after upload call `set_mtime` if the capability exists (else log once per session that the server doesn't support it).
8. **> 4 GiB**: all offsets `u64`; tests with sparse files to avoid real 4 GiB writes.

## Acceptance criteria

- [x] `decide` table-tested for every action × {dst missing, smaller, equal, larger, older, newer, unknown size, unknown time}.
- [x] Ask flow with "apply to all" works across concurrent workers (only one prompt shown, later items use the answer).
- [x] Rename never overwrites an existing file.
- [x] Resume of a 5 GiB sparse file at offset > 4 GiB correct (mock backend).

## Tests

- Pure unit tests for `decide` (aim for exhaustive table).
- Engine-level tests with mock backend for ask + apply-to-all.

## Status

Built in `transfer::exists` (`decide`, `FileExistsPolicy`, `first_free_name`),
`transfer::options` (download name safety), `local::prealloc` and the binary's
`ui/file_exists.rs` dialog (snapshots `ui/file_exists/snapshots/`).

- `decide(source, target, action, can_resume)`: the spec's `precision`
  argument became `can_resume`; precision comes from each `Timestamp`
  (`cmp_coarse`). A needed time or size that is unknown means overwrite for
  the *overwrite if…* actions (FileZilla), ask for *Resume*.
- Answer scopes: `ApplyTo::{Once, AllInQueue, AllInSession}` plus
  `same_direction_only` / `same_server_only`. Precedence: the item's
  `on_exists` (unless `Ask`), then the newest matching remembered answer,
  then the per-direction setting.
- Transfer type (4) was already per file in the T41 worker
  (`file_types.is_ascii`, there is no separate `decide_transfer_type`).
- Preallocation reserves with `set_len` (no `fallocate`, no unsafe) and trims
  back to the written length on shutdown or drop, so an interrupted file is
  a valid resume offset.
- Not wired into the binary yet: building the engine with
  `FileExistsPolicy` is part of the engine/queue UI integration (T56/T62);
  the dialog is reachable through `prompt_modal` as soon as a policy asks.
