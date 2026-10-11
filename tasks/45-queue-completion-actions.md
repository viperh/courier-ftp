# T45 — Queue completion actions

**Phase:** E Transfers · **Depends on:** T41, T46, T52, T56 · **Crates:** core + binary · **Decisions:** D8 (no sound/sleep/shutdown) · **FEATURES.md:** §5 (actions after queue finishes, auto refresh)

## Goal

Do something useful when the queue becomes empty.

## Scope

1. `queue.on_complete` options: `None`, `ShowMessage`, `RunCommand(String)`, `Disconnect`, `CloseApp`. (Sound, sleep and shutdown intentionally dropped, D8.)
2. Also a **one-shot** override for the current run, settable from the queue pane menu (FileZilla's "Action after queue completion" submenu resets after use unless "always" is chosen). Model: `oneshot: Option<OnComplete>` on the engine.
3. **ShowMessage**: UI popup "Queue finished: N files, X MiB transferred in T, F failed" + a terminal bell / OSC 9 / OSC 777 desktop notification (configurable `notify: None | Bell | Osc`). Terminals that don't support OSC ignore it.
4. **RunCommand**: run via the platform shell (`sh -c` / `cmd /C`) detached, with env vars `COURIER_FTP_FILES_OK`, `COURIER_FTP_FILES_FAILED`, `COURIER_FTP_BYTES`. Log exit code.
5. **Disconnect**: disconnect all tabs' sessions (keep tabs open).
6. **CloseApp**: graceful quit (persist queue/vault, restore terminal).
7. **Refresh after queue** (`queue.refresh_remote_after`): for each tab whose current remote/local dir was a transfer target, re-list it (via cache invalidation, T46).
8. Only trigger when the queue ran and finished (not on startup with an empty queue, not when user pressed Stop).

## Acceptance criteria

- [x] Each action works; one-shot override resets after use.
- [x] RunCommand receives the env vars.
- [x] Stopping the queue manually doesn't trigger the action.
- [x] Panes showing changed dirs refresh after completion.

## Tests

- Engine-level tests with mock backend asserting the `QueueFinished` event and action dispatch.

**Status (T45):** `courier_ftp_core::transfer::completion` picks the action
(`QueueCompletion`: the one-shot override, used up by the next run that
processed at least one file, else `queue.on_complete`), builds the command
(`command_line`/`split_command`: quoting only, never a shell — scope item 4's
`sh -c` was dropped so nothing in the line is interpreted; write
`sh -c '…'` explicitly if needed) and its environment (`command_env`). The
binary (`src/completion.rs`, `src/app/completion.rs`) reacts to
`CoreEvent::QueueFinished` in `App::transfer_event`: the summary goes to the
log and status bar; ShowMessage opens a message and sends the `queue.notify`
bell / OSC 9 + OSC 777; RunCommand starts the program detached and logs its
exit code; Disconnect and CloseApp run after a 10 s countdown dialog that Esc
cancels (CloseApp then goes through the normal quit check). The one-shot is
set from the queue pane (`a`, or "Action after queue completion…" in the `m`
menu) and shown in the pane's bottom line until used. The engine never sends
`QueueFinished` for a stopped run. Directories changed by transfers were
already refreshed per finished transfer (T56, `queue.refresh_remote_after`).
Side effects go through the `Effects` trait, recorded in tests
(`app/completion_tests.rs`); one Unix test runs a real command. With one tab
until T61, Disconnect closes the remote pane's session (T61 should loop over
tabs).
