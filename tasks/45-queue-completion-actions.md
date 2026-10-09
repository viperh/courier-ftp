# T45 — Queue completion actions

**Phase:** E Transfers · **Depends on:** T41 · **Crates:** core + binary · **Decisions:** D8 (no sound/sleep/shutdown) · **FEATURES.md:** §5 (actions after queue finishes, auto refresh)

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

- [ ] Each action works; one-shot override resets after use.
- [ ] RunCommand receives the env vars.
- [ ] Stopping the queue manually doesn't trigger the action.
- [ ] Panes showing changed dirs refresh after completion.

## Tests

- Engine-level tests with mock backend asserting the `QueueFinished` event and action dispatch.
