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
- [ ] Recovery words never logged or kept in memory after the screen closes.
- [ ] Snapshot tests for every screen.

## Tests

- UI-flow tests against an in-process server.
