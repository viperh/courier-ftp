# T57 — Status bar

**Phase:** F TUI · **Depends on:** T50 · **Crate:** `courier-ftp` (`components/status_bar.rs`) · **FEATURES.md:** §3 (status bar), §6 (speed limit toggle), §8 (filter indicator)
**Related (integrates with, not blocking):** T44, T66, T69

## Goal

A one-line bottom bar with connection security, limits, filter state, queue
summary and key hints.

## Scope

Segments (left → right, each collapsible on narrow terminals):

1. **Connection security** for the current tab: `🔒 TLS 1.3` (FTPS), `🔒 SSH` (SFTP), `🔓 plain` (FTP, coloured warning), `—` when disconnected. Key (`Ctrl-x i` or via menu) opens a **server info dialog**: protocol, server software (greeting/SYST/SSH banner), TLS version & cipher or SSH kex/cipher/MAC, and the certificate/host key details (reuse T69 renderer).
2. **Transfer type indicator**: `Auto`/`ASCII`/`Binary`; key cycles it (FileZilla has Transfer → Transfer type menu).
3. **Speed limit**: `⇅ off` / `⇅ ↓500K ↑100K`; key toggles `speed_limit_enabled` (T44).
4. **Filters**: `⚑ filters` shown when any filter or quick filter is active on either side.
5. **Sync / compare**: `⇄ sync` and `≠ compare` when enabled (T66).
6. **Vault**: `🔐 locked` / nothing when unlocked.
7. **Queue**: `Queue: 2 files, 8 KiB, ↓1.2 MiB/s`.
8. **Pending keys** (vim showcmd, T51) and transient messages ("Copied URL to clipboard") that fade after 3 s.
9. **Hints**: `F1 help  F5 copy  F8 delete …` (from keymap) when space allows.
10. ASCII fallback for terminals without emoji/unicode support (setting `interface.unicode_symbols`, default auto).

## Acceptance criteria

- [x] Snapshot tests at 80, 120, 200 columns.
- [x] Indicators update on state changes.
- [x] Server info dialog shows correct details for FTP, FTPS, SFTP.

## Tests

- Snapshot tests.
