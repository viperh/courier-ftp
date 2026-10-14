# T61 — Connection tabs

**Phase:** F TUI · **Depends on:** T50, T53, T58, T59 · **Crate:** `courier-ftp` · **FEATURES.md:** §2 (tabs: several connections at once)

## Goal

Multiple simultaneous connections, each in its own tab with its own local and
remote panes, log and settings (sync browsing, comparison, filters).

## Scope

1. `Tab` state: id, title (site name or `user@host`), connection `SessionHandle` (or none), local pane state, remote pane state, log buffer, sync/compare flags, site colour.
2. Tab bar: `[1 web01 ●] [2 backup ○]` — `●` connected, `○` disconnected, `◌` connecting, `!` error; site colour as tab accent; overflow scrolls with `«`/`»`.
3. Actions: new tab (disconnected, local dir copied from current), close tab (confirm if connected; transfers already queued keep running — they use their own sessions), switch by number/next/prev, rename tab title, duplicate tab (new connection to same server/dir).
4. Connecting from Site Manager or quickconnect uses the current tab if disconnected, else asks *open in new tab* / *replace current connection* (with a remember-choice option) — this task adds that choice to T58 and T59.
5. Queue is **global** (shared by all tabs), like FileZilla.
6. Closing the last tab leaves one empty tab (never zero).
7. Session restore (optional setting `interface.restore_tabs`): reopen tabs with their sites and dirs on startup (stored in vault since it includes server identities).

## Acceptance criteria

- [x] Two tabs connected to different servers browse independently.
- [x] Closing a connected tab disconnects only that tab's browsing session.
- [x] Snapshot tests of tab bar states and overflow.

**Status (T61):** done. The current tab's state stays where it was (`App::remote`,
`App::last_connect`, the screen's panes); other tabs are parked in `app/tabs.rs`
and swapped in when shown (`MainScreen::swap_tab`). Late listings and connects
are routed by session id (remote) or tab id (local) and applied to a background
tab at once; what they ask for next runs when the tab is shown; results for a
closed tab are dropped. Keys: `Ctrl-t` new, `Ctrl-w` close, `Alt-1`…`Alt-9`,
`Ctrl-PgUp`/`Ctrl-PgDn` (and `gt`/`gT` in lists) switch, `<Ctrl-x><R>` rename,
`<Ctrl-x><T>` duplicate. Connecting while connected asks (new tab / this tab,
"Remember my choice" → new setting `interface.connect_in_tab`); the Site
Manager has a *New tab* button. `interface.restore_tabs` (default off) saves the
tabs as the device blob `tabs` when quitting and reopens them after the first
unlock (sites reconnect with their credentials, quickconnect servers ask for the
password again). The message log hides the other tabs' connections (`t` in the
log shows all). T45 "Disconnect" and `vault.lock_disconnects` close every tab's
connection. Launch intents (URL/site on the command line) are left to T70,
which isn't built yet.

## Tests

- Unit tests with mock backends for tab lifecycle.
