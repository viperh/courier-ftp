# T62 — File operations UI

**Phase:** F TUI · **Depends on:** T52, T53, T40, T41, T43 · **Crate:** `courier-ftp` · **FEATURES.md:** §4

## Goal

The dialogs and flows for every file operation available from the panes.

## Scope

1. **Transfer (F5)**: selected entries (or cursor entry) from the focused pane to the other pane's current dir. Dialog optional (setting `interface.confirm_transfer`, default off): shows count/size and lets user pick transfer type and "add to queue only". Shift-F5 adds to queue without processing.
   - Local→local or remote→remote: FileZilla doesn't support these; we show an explanatory message (remote→remote across servers is out of scope; same-server move is Rename).
2. **Move (F6)**: on same side = rename/move dialog with a path input; across sides = transfer then delete source after successful transfer (confirm; extra queue flag `delete_source_after`).
3. **Rename (F2)**: inline edit of the name in the list (or dialog), Enter applies; rename into another dir if the new name contains `/`.
4. **Make directory (F7)** / **Make directory and enter it (Shift-F7)**: dialog prefilled with current path + `New directory` (FileZilla style), creates nested paths (mkdir -p semantics remotely by creating each component).
5. **Create new file** (`Ctrl-x n`?): name prompt; creates an empty file (upload of 0 bytes remotely), optionally opens in editor.
6. **Delete (F8)**: confirm dialog "Really delete N files and M directories from server?" listing first few names; recursive delete with `ProgressDialog` (T43). `confirm_delete` setting.
7. **Chmod (`c`)** — FileZilla's "File attributes" dialog:
   ```
   Owner permissions:  [x] Read [x] Write [ ] Execute
   Group permissions:  [x] Read [ ] Write [ ] Execute
   Public permissions: [x] Read [ ] Write [ ] Execute
   Numeric value: 644      (x = unchanged when multiple files differ)
   [ ] Recurse into subdirectories
       (•) Apply to all files and directories ( ) Files only ( ) Directories only
   ```
   Tri-state checkboxes when multiple entries with different modes are selected; numeric field accepts `x` digits for unchanged.
8. **Copy URL to clipboard** (`yu`): `sftp://user@host:port/path` (options: with/without password, with/without port — submenu); clipboard via OSC 52 (works over SSH) with fallback to `arboard` crate when local and available.
9. **Custom command** (`:`): input line; sends via `raw_command` on the browsing session; reply shown in the log; command history (up/down).
10. **Manual transfer dialog** (FileZilla's "Manual transfer"): specify local file, remote path, direction, server (current or other site), transfer type, start now or queue.
11. **Refresh**: re-list both panes, bypassing cache.
12. **Operation disabling**: actions not supported by the backend (`Capabilities`, T03) are disabled with an explanation message.
13. Every operation reports success/failure in the log and a transient status bar message.

## Acceptance criteria

- [ ] Each operation works on local and remote (mock backend) and updates both panes via cache patches.
- [ ] Chmod tri-state/numeric with `x` correct.
- [ ] OSC 52 clipboard works in tmux (with `set-clipboard on`) — manual check noted.
- [ ] Unsupported operations explain why instead of failing silently.

## Tests

- UI-flow tests with synthetic key events and mock backend.
