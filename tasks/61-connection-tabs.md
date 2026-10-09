# T61 — Connection tabs

**Phase:** F TUI · **Depends on:** T50, T53, T58, T59 · **Crate:** `courier-ftp` · **FEATURES.md:** §2 (tabs: several connections at once)

## Goal

Multiple simultaneous connections, each in its own tab with its own local and
remote panes, log and settings (sync browsing, comparison, filters).

## Scope

1. `Tab` state: id, title (site name or `user@host`), connection `SessionHandle` (or none), local pane state, remote pane state, log buffer, sync/compare flags, site colour.
2. Tab bar: `[1 web01 ●] [2 backup ○]` — `●` connected, `○` disconnected, `◌` connecting, `!` error; site colour as tab accent; overflow scrolls with `«`/`»`.
3. Actions: new tab (disconnected, local dir copied from current), close tab (confirm if connected; transfers already queued keep running — they use their own sessions), switch by number/next/prev, rename tab title, duplicate tab (new connection to same server/dir).
4. Connecting from Site Manager or quickconnect uses the current tab if disconnected, else asks (T58).
5. Queue is **global** (shared by all tabs), like FileZilla.
6. Closing the last tab leaves one empty tab (never zero).
7. Session restore (optional setting `interface.restore_tabs`): reopen tabs with their sites and dirs on startup (stored in vault since it includes server identities).

## Acceptance criteria

- [ ] Two tabs connected to different servers browse independently.
- [ ] Closing a connected tab disconnects only that tab's browsing session.
- [ ] Snapshot tests of tab bar states and overflow.

## Tests

- Unit tests with mock backends for tab lifecycle.
