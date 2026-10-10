# T56 — Queue pane

**Phase:** F TUI · **Depends on:** T40, T41, T50, T51 · **Crate:** `courier-ftp` (`components/queue.rs`) · **FEATURES.md:** §5
**Related (integrates with, not blocking):** T45, T57

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

- [x] Snapshot tests for each tab with sample data, including an active transfer and a failed one.
- [ ] Every control maps to the correct engine/queue operation.
- [x] Rendering 100k items stays responsive.

**Status (T56):** the pane lives in `crates/courier-ftp/src/ui/queue.rs` (the crate has
no `components/` module); the engine, persister and resolver wiring in
`src/transfers.rs` and `src/app/transfers.rs`. Every control in §6 is wired and
tested except **"action after queue completion"**, which is left to T45 (it builds on
`CoreEvent::QueueFinished`, which the app already logs). F5 / Shift-F5 queue the
selection of the focused list for the other side (directories as T43 placeholders);
the full file operations UI is T62. The engine runs with T42's file-exists policy,
T43's expander and T44's speed limiter. The 100k gate is a release-only test (`cargo test --release -p courier-ftp
hundred_thousand`), like T53's.

## Tests

- Snapshot + unit tests against a `Queue` built in-memory.
