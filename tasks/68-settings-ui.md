# T68 — Settings screen

**Phase:** F TUI · **Depends on:** T05, T52, T60 · **Crate:** `courier-ftp` · **FEATURES.md:** §1, §3, §5, §6, §9, §10
**Related (integrates with, not blocking):** T12, T21, T73, T74, T75, T90

## Goal

Edit every setting from T05 inside the app (F9), organised like FileZilla's
Settings dialog, saving to the user config file.

## Scope

1. Left: section list; right: form for the section (T52 `TabbedForm`-like). Sections:
   - **Connection**: timeout, retries, retry delay, keep-alive, IPv6 preference.
     - **FTP**: passive/active, fallback, active mode external IP + port range, ignore unroutable PASV IP, use MLSD, keep-alive command.
     - **FTP Proxy**: type + host/port/user/password (password → vault) + custom script editor.
     - **Generic proxy**: none/HTTP/SOCKS4/SOCKS5 + host/port/user/password (password → vault).
     - **SFTP**: list/remove stored host keys (T21); manage key files list for agent-like default keys (optional).
     - **TLS**: list/remove trusted certificates (T12) with details view.
   - **Transfers**: concurrency limits, speed limits + burst tolerance, preallocate, preserve timestamps, invalid char replacement, empty dirs, follow symlinks.
     - **File types**: default type, ASCII extension list editor, dotfiles/no-extension ASCII.
     - **File exists action**: download/upload defaults.
   - **Interface**: layout, swap panes, show tree/log/queue/quickconnect, unicode symbols, confirm delete/transfer, restore tabs, language (T75), splash, update check (T74).
     - **File lists**: size format, thousands separator, date/time format (live preview), dirs first, sort case sensitivity, natural sort, columns.
     - **Theme**: pick from built-in colour schemes (default, high contrast, monochrome); note that fine-grained styles live in config.
     - **Keybindings**: read-only list with "open config file" hint (full rebinding UI is out of scope v1).
   - **Editing**: default editor, associations list editor (pattern, command, terminal flag), watch & prompt upload, max size.
   - **Queue**: on complete action + command, notify method, persist queue, refresh after queue.
   - **Logging**: debug level, show timestamps, raw listing, log to file + path + size + keep count.
   - **Security / Vault**: flows from T60 (change master password, keyring unlock on this device, lock now, auto-lock, lock on suspend, store passwords, Argon2 cost, local approvals list with revoke).
   - **Sync & teams**: T90 screens (account, devices, teams, sync status, `sync.history`).
   - **Import/Export settings** buttons (T73).
2. **Apply semantics**: changes apply live where possible (speed limits, formats, layout, log level); network settings apply to new connections (note shown).
3. **Save**: `Settings::save_user` writes only non-default values; **Reset section to defaults** button; **Cancel** reverts unsaved edits.
4. Validation identical to T05, shown inline.
5. Each field shows a one-line help text (from the same doc strings as T05 where practical).

## Acceptance criteria

- [ ] Every T05 setting editable, validated and persisted.
- [ ] Live-apply settings take effect without restart.
- [ ] Host key/cert stores manageable.
- [ ] Snapshot tests per section.

## Tests

- Snapshot + UI-flow tests.
