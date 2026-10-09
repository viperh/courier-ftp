# T55 — Message log pane

**Phase:** F TUI · **Depends on:** T04, T50, T51 · **Crate:** `courier-ftp` (`components/message_log.rs`) · **FEATURES.md:** §3 (message log), §9
**Related (integrates with, not blocking):** T62

## Goal

FileZilla's message log: protocol commands and replies, status and errors,
coloured by type, per tab.

## Scope

1. Line format: `HH:MM:SS  Status:   text` (timestamp optional, setting `logging.show_timestamps`). Prefixes: `Status:`, `Command:`, `Response:`, `Error:`, `Trace:` (debug), `Listing:` (raw listing lines when `show_raw_listing`).
2. Colours: Status default, Command blue, Response green, Error red bold, Trace dim. Configurable through `styles`.
3. **Per-tab log**: each tab shows its own session's messages; transfer workers' messages go to the tab that started the queue item, or a "Transfers" filter view (toggle `t` in the log) showing all.
4. Ring buffer of last N lines (default 5 000 per tab) to bound memory.
5. **Scrolling**: auto-follow at bottom; scrolling up pauses follow ("▼ new messages" indicator); `G` resumes.
6. **Search** in log: `/` to search, `n`/`N` next/prev, highlight matches.
7. **Copy**: `y` copies the selected line or visual range to clipboard (OSC 52, T62's clipboard helper).
8. **Clear** log: `Ctrl-x l` or similar (per T51).
9. Wrap long lines (toggle) vs horizontal scroll.
10. Debug level from settings (T05) filters at the source (T04); the pane also has a quick level filter (show errors only).

## Acceptance criteria

- [ ] Snapshot tests of each message kind's colour/prefix.
- [ ] Ring buffer caps memory.
- [ ] Follow/pause behaviour correct.
- [ ] Search and copy work.

## Tests

- Snapshot + unit tests.
