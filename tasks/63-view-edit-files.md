# T63 — View / edit files externally

**Phase:** F TUI · **Depends on:** T05, T41, T62 · **Crate:** `courier-ftp` (+ helpers in core) · **FEATURES.md:** §4 (view/edit with watched temp copy, file associations)

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
- [x] GUI editor save triggers upload prompt.
- [x] Associations matched by glob, first match wins.
- [x] Temp files cleaned up.

**Status:** the terminal round trip is verified on Linux in a real PTY (pyte
driver: F4 on a local file and on an SFTP file with a fake `$VISUAL`, TUI
redrawn, prompt, upload, copies gone after quit); macOS and Windows still need
the manual check below. Changes are noticed by polling (size/mtime every
second, then SHA-256) instead of the `notify` crate: no new dependency, same
behaviour on every OS, and a save with unchanged content is not a change.

Manual check per OS (Linux done; macOS, Windows open):
1. Set `$VISUAL` (Windows: `editing.editor` = `notepad`, or an association
   with `[terminal]` for a console editor), connect to a server, F4 a file.
2. A terminal editor takes over the screen; quit it: the panes come back
   intact, keys work, no stray characters.
3. Save a change: "File changed" asks; *Yes* uploads it.
4. `<Ctrl-x><e>` lists the file; quit: no warning when uploaded; the
   `edit/` copy directory under the cache directory is gone.

## Tests

- Unit tests for association matching and change detection; manual test checklist for terminal suspend on each OS.
