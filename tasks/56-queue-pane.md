# T56 — Queue pane

**Phase:** F TUI · **Depends on:** T40, T41, T50 · **Crate:** `courier-ftp` (`components/queue.rs`) · **FEATURES.md:** §5

## Goal

Display and control the transfer queue with FileZilla's three tabs.

## Scope

1. **Tabs**: `Queued files (N)`, `Failed transfers (N)`, `Successful transfers (N)`; switch with `1/2/3` when focused.
2. **Queued tab columns**: Server/Local file, Direction (`→`/`←`), Remote file, Size, Priority, Status. Rows grouped under a server header row (`sftp://alice@web01 — 12 files, 30 MiB`), collapsible.
3. **Active transfers** render a second line: progress bar, percent, bytes done/total, speed, elapsed, ETA. Paused rows show `⏸`.
4. **Failed tab**: adds Time and Reason (last error) columns; `r` reset and requeue selected; `x` remove.
5. **Successful tab**: Time, size, duration, average speed; `x` clear.
6. **Controls** (T51): pause/resume item, priority up/down, move up/down/top/bottom, remove, set "file exists" action for selected items (submenu), set "action after queue completion" (one-shot vs always, T45), process queue / stop.
7. **Header** shows totals: "Queue: 12 files, 30.2 MiB, ~00:02:14 remaining" (same data as status bar T57).
8. Virtualised rendering for 100 000 items.
9. Context menu (`m` key) listing all available actions for the selection, so users don't need to memorise keys.

## Acceptance criteria

- [ ] Snapshot tests for each tab with sample data, including an active transfer and a failed one.
- [ ] Every control maps to the correct engine/queue operation.
- [ ] Rendering 100k items stays responsive.

## Tests

- Snapshot + unit tests against a `Queue` built in-memory.
