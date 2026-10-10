# T51 — Keybindings (hybrid)

**Phase:** F TUI · **Depends on:** T50 · **Crate:** `courier-ftp` (`crates/courier-ftp/config/default.json`, `config.rs`, `action.rs`) · **Decisions:** D6, D7 · **FEATURES.md:** §3 (keyboard shortcuts)
**Related (integrates with, not blocking):** T59, T62, T63, T64, T65, T68, T77

## Goal

A complete default keymap mixing Midnight Commander F-keys with vim motions,
fully rebindable through the existing config system.

## Default keymap (proposal — adjust during implementation, keep this table updated)

### Global (any mode except text input)
| Key | Action |
|---|---|
| `F1` / `?` | Help overlay |
| `F2` | Rename |
| `F3` | View file (T63) |
| `F4` | Edit file (T63) |
| `F5` | Copy = transfer selection to the other pane (upload/download) |
| `Shift-F5` | Add selection to queue without starting |
| `F6` | Move (transfer then delete source — confirm) / rename when same side |
| `F7` | Make directory |
| `Shift-F7` | Make directory and enter it |
| `F8` / `Delete` | Delete (confirm) |
| `F9` | Settings (T68) |
| `F10` / `Ctrl-q` | Quit |
| `Ctrl-s` | Site Manager (T59) |
| `Ctrl-k` | Focus quickconnect bar |
| `Ctrl-r` / `Ctrl-F5`* | Refresh both panes (*if terminal sends it) |
| `Ctrl-t` / `Ctrl-w` | New tab / close tab |
| `Alt-1..9`, `gt`/`gT` | Switch tab |
| `Ctrl-y` | Toggle synchronized browsing |
| `Ctrl-o` | Toggle directory comparison |
| `Ctrl-f` | Search (T65) |
| `Ctrl-b` | Bookmarks menu (T64) |
| `Ctrl-x d` | Disconnect current tab (`Ctrl-d` is half-page down in file lists) |
| `Ctrl-p` | Process queue (start/stop) |
| `Ctrl-l` | Toggle message log |
| `Ctrl-j` | Toggle queue pane |
| `Ctrl-e` | Toggle directory trees |
| `Ctrl-h` | Toggle hidden files |
| `Ctrl-z` | Suspend (existing) |

### File list
| Key | Action |
|---|---|
| `j`/`k`/`↓`/`↑` | Move cursor |
| `h`/`←`/`Backspace` | Parent directory |
| `l`/`→`/`Enter` | Enter dir / for files: transfer (FileZilla's double-click default, configurable to view/edit) |
| `gg` / `G` / `Home` / `End` | Top / bottom |
| `Ctrl-u`/`Ctrl-d`*, `PageUp`/`PageDown` | Half/full page (*`Ctrl-d` conflicts with disconnect — resolve: disconnect becomes `Ctrl-x d` or similar) |
| `Tab` / `Shift-Tab` | Switch pane |
| `Space` / `Insert` | Toggle selection and move down |
| `v` | Visual (range) selection mode |
| `*` | Invert selection, `+` / `-` select / deselect by pattern |
| `Ctrl-a` | Select all |
| `/` | Quick filter (live, Esc clears) |
| `s` then `n/s/m/p/o` | Sort by name/size/modified/permissions/owner (repeat to reverse) |
| `.` | Toggle hidden files (vim/ranger habit) |
| `:` | Command line for custom FTP commands (T62) |
| `y` then `u` | Copy URL to clipboard (T62) |
| `c` | Chmod dialog |
| `e` / `o` | Edit / open (alias of F4 / F3) |
| `a` | Edit address bar (type a path) |
| `=` | Make other pane show same dir (local↔remote equivalent path, best effort) |

### Queue pane
| Key | Action |
|---|---|
| `Space` | Pause/resume item |
| `+` / `-` | Raise / lower priority |
| `K` / `J` | Move item up / down |
| `x` / `Delete` | Remove item |
| `r` | Reset and requeue (failed tab) |
| `1` `2` `3` | Queued / Failed / Successful tab |

## Scope

1. Extend `Action` enum with every action above (named, serialisable, documented). Remove `Help` duplication.
2. Update `crates/courier-ftp/config/default.json` with the defaults, organised by `Mode` (Normal/FileList/Queue/Log/Input/Dialog/Filter). Context-specific bindings require mode refinement from T50.
3. Key-parser additions in `config.rs`: function keys `<F1>`…`<F12>` with modifiers, `<Space>`, `<Insert>`, `<Delete>`, `<Backspace>`, `<Tab>`/`<BackTab>`, punctuation keys. Fix `parse_key_sequence(..).unwrap()` → proper error naming the bad key string.
4. **Multi-key sequences** (`gg`, `gt`, `yu`, `s n`): the current template clears pending keys on each tick (`last_tick_key_events`), which breaks slow typing. Replace with a timeout (default 1 s, configurable) and show pending keys in the status bar (like vim's showcmd).
5. **Conflict detection** at load: two actions bound to the same sequence in the same mode, or a prefix of another sequence that is also bound → log a warning naming both.
6. Generate the help overlay (T50) and `docs/keybindings.md` (T77) from the same table.
7. Terminal caveats: document keys many terminals don't send (Ctrl-F5, Shift-F-keys in some terminals), and ensure every action has at least one binding that works in a plain xterm, tmux and Windows Terminal.

## Acceptance criteria

- [ ] Every action reachable by keyboard in xterm, tmux, Windows Terminal (manual checklist).
- [x] Sequences work with up to 1 s between keys.
- [x] Bad key strings in user config produce a readable error, not a panic.
- [x] Conflicts are reported.
- [x] `Ctrl-d` conflict resolved and documented.

## Tests

- Key parser unit tests for all new key names.
- Sequence matcher tests with timeout using paused time.
