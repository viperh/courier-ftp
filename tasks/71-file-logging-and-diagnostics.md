# T71 — Log to file, debug levels, raw listing

**Phase:** G App-level · **Depends on:** T04, T05, T55 · **Crate:** `courier-ftp` (`logging.rs`) + core · **FEATURES.md:** §9

## Goal

Two kinds of logs: the **application log** (tracing, already exists — for
developers) and the **session log** (FileZilla's message log written to a file
for users diagnosing connection problems).

## Scope

1. **Application log** (existing `logging.rs`): keep writing `<data dir>/courier-ftp.log`, but:
   - Open in append mode with size-based rotation (keep 3 × 10 MiB) instead of truncating on every start.
   - Make sure no secrets are logged (audit all `tracing` calls added by other tasks; add a test that greps logs produced by the integration suite for known test passwords).
2. **Session log to file** (`logging.log_to_file`): every `LogMessage` (T04) written as `2026-10-09 12:00:00 <session> Status: text`, rotated by `log_file_max_mib`/`log_file_keep`. Written by a background task with a bounded channel (drop + count if the disk can't keep up; note dropped count).
3. **Debug levels** 0–4 (T04) adjustable at runtime from Settings and via `--debug-level`; level 3+ also logs listing raw lines and TLS/SSH negotiation details.
4. **Raw directory listing**: when `show_raw_listing`, the raw MLSD/LIST text appears in the message log as `Listing:` lines; also an action "Show raw listing of current dir" opening a scrollable dialog with the text from `Listing.raw` (no setting needed).
5. "Copy log to clipboard" / "Save log as…" actions from the log pane (T55).

## Acceptance criteria

- [ ] Rotation works for both logs.
- [ ] Session log contains masked commands.
- [ ] Secret-leak test passes over the integration test logs.
- [ ] Raw listing dialog works for FTP (LIST/MLSD) and SFTP (longname lines).

## Tests

- Unit tests for rotation; integration secret-leak test.
