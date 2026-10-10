# T58 — Quickconnect bar

**Phase:** F TUI · **Depends on:** T03, T22, T52, T53 · **Crate:** `courier-ftp` (`components/quickconnect.rs`) · **FEATURES.md:** §2 (quickconnect, history, reconnect)
**Related (integrates with, not blocking):** T14, T33, T61

## Goal

Connect to a server without creating a site: host, user, password, port, a
connect button and a history dropdown.

## Scope

1. Fields: Host, Username, Password (masked), Port, `[Connect]`, `[▾ history]`. `Ctrl-k` focuses Host; Tab moves between fields; Enter anywhere connects.
2. **Host field accepts URLs**: `sftp://alice@host:2222/var/www` fills protocol, user, port and initial remote dir; `ftpes://`, `ftps://`, `ftp://` as in T02. Without scheme: port 22 → SFTP, otherwise FTP with `ExplicitIfAvailable` (FileZilla's default for quickconnect).
3. **Connect** opens in the current tab, replacing an existing connection after a confirm. (Once tabs exist, T61 adds the choice *open in new tab* / *replace current connection*.)
3b. **Backend factory wiring**: this task implements `BackendFactory` (T03) in the binary with the SFTP backend (T22). T14 adds the FTP/FTPS arm. Until T33 exists the history dropdown is hidden.
4. **History dropdown**: last 10 entries (T33) — selecting fills fields and connects; "Clear history" item at the bottom; hidden when vault is locked.
5. **Reconnect**: action "Reconnect to last server" (bound in T51, e.g. `Ctrl-x r`).
6. Password not stored in history unless `vault.store_passwords` and vault unlocked; else prompt on reconnect.
7. "Save as site" action from the current quickconnect connection → opens Site Manager with a prefilled new site **including the password** that was typed (T33 helper); a checkbox "Save password" (default on, follows `vault.store_passwords`).
8. Bar can be hidden (`interface.show_quickconnect`).

## Acceptance criteria

- [x] URL parsing populates fields correctly (snapshot of field state).
- [ ] History selection connects.
- [x] Busy tab prompt works.
- [x] Password never shown or logged.

## Tests

- Unit tests for field population from URLs; snapshot tests of the bar.
