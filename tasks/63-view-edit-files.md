# T63 — View / edit files externally

**Phase:** F TUI · **Depends on:** T41, T62, T05 · **Crate:** `courier-ftp` (+ helpers in core) · **FEATURES.md:** §4 (view/edit with watched temp copy, file associations)

## Goal

Open remote files in an editor or viewer, watch for changes and offer to upload
them back — FileZilla's View/Edit feature, adapted to a terminal.

## Scope

1. **Download to temp**: `<cache dir>/edit/<session>/<random>/<filename>` (per-user, `0700`). Download goes through the engine with high priority (or direct on a transfer session).
2. **Choosing the program** (`editing.associations`, first match wins by glob):
   - `terminal: true` programs (vim, nano, less, `$EDITOR`): **suspend the TUI** (leave alternate screen, disable raw mode — reuse `Tui::exit`/`enter`), run the program in the foreground, wait, restore the TUI. After return, compare mtime/hash; if changed → prompt to upload.
   - GUI programs (`terminal: false`, e.g. `code --wait`, `xdg-open`, `open`, `start`): spawn detached; register a **watcher** (`notify` crate) on the temp file; on change → prompt "File X has changed. Upload it back to the server?" with *Yes* / *No* / *Always for this file* / *Stop watching*.
   - Default resolution: `$VISUAL`, then `$EDITOR`, then platform viewer (`xdg-open`/`open`/`start`); F3 View uses `$PAGER`/`less` for text and the platform opener for others.
3. **Local files**: F4 on the local pane opens the file directly (no temp copy, no upload).
4. **Edited files list**: dialog "Files being edited" (FileZilla has this) listing watched files with server, remote path, status; actions: upload now, stop watching, discard. On quit with watched modified files → warn.
5. **Remote file changed meanwhile** (optional check): before re-upload compare remote mtime/size with what was downloaded; if different → warn of conflict.
6. Uploads back use the original connection info (site/quickconnect) and overwrite.
7. Cleanup temp files when watching stops or on exit (unless upload pending — then keep and warn).
8. Large files (> `editing.max_size_mib`, default 50): confirm before downloading.

## Acceptance criteria

- [ ] Terminal editor round-trip: TUI restored correctly after the editor exits (including on Windows).
- [ ] GUI editor save triggers upload prompt.
- [ ] Associations matched by glob, first match wins.
- [ ] Temp files cleaned up.

## Tests

- Unit tests for association matching and change detection; manual test checklist for terminal suspend on each OS.
