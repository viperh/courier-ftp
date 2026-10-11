# T90 — Sync and teams UI

**Phase:** H Sync · **Depends on:** T52, T59, T60, T87, T88 · **Crate:** `courier-ftp`
**Related (integrates with, not blocking):** T89

## Goal

Screens for everything sync-related, plus status and notifications.

## Scope

1. **Account wizard** (Settings → Sync, or first-run "log in to a sync server"):
   - Server URL (validated, must be `https://` except loopback), email.
   - Register: setup token / invite token field when needed, device name (defaults to
     hostname), uses the current master password (re-entered for confirmation).
   - Recovery key screen: 24 words in a grid, "I wrote it down", then re-type 3 random
     words. Warn that the words are never shown again.
   - Login: email + master password + TOTP if enabled; duplicate preview screen with
     keep both / keep local / keep account per conflict group.
2. **Status**: status bar segment `⟳ synced` / `⟳ syncing` / `⟳ offline (3)` /
   `⟳ error` / `⟳ login needed`; key opens a sync panel with last sync time, pending
   count, per-vault cursors and errors, and "sync now".
3. **Devices screen**: list with this device marked; revoke with confirm.
4. **Account screen**: change password (online only), enable/disable TOTP (QR code
   rendered with unicode blocks + secret text), request recovery, log out, delete account.
5. **Teams screens**: orgs list; members with roles and safety-number verification
   (`✔ verified`); invite (email or copy link); vaults with permissions; audit log.
   Key-change warning dialog for pinned members.
6. **Site Manager integration** (T59): tree shows vaults as top-level roots
   (`Personal`, `Team: Ops`, …); read-only items with 🔒; "Copy to vault…" / "Move to
   vault…" actions.
7. **Toasts**: resurrected item, clock skew warning, access granted/revoked, rotation
   in progress, conflict merged.

## Acceptance criteria

- [ ] Full register → second device login → team invite flow usable by keyboard only.
  *Status:* register → second device login (duplicate preview) → live sync, devices,
  revoke, password change and re-login, TOTP, recovery and logout are keyboard-only and
  tested against the in-process server (`app/sync_tests.rs`). The team part waits for
  T89 (not in `next` when T90 was built): scope 5 (teams screens), scope 6 (vault roots,
  🔒 read-only items, copy/move to vault) and the team toasts are open; the panel has a
  "Teams and shared vaults" placeholder page. Settings → Sync (scope 1 entry point) is
  T68's; the panel is `<Ctrl-x><y>` (`SyncPanel`).
- [x] Recovery words never logged or kept in memory after the screen closes.
  (Held in `Zeroizing` strings only while the words/check pages are open; confirm inputs
  are zeroizing `TextInput::sensitive` fields; `SyncRequest`/`SyncMsg` `Debug` print names
  only. The terminal back buffer keeps the drawn cells until the next redraw.)
- [ ] Snapshot tests for every screen.
  *Status:* every personal-sync screen has a snapshot (`ui/sync/snapshots/`, plus the
  vault recovery pages and the status bar segment); team screens wait for T89.

## Tests

- UI-flow tests against an in-process server.
