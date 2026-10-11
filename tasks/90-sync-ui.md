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

- [x] Full register → second device login → team invite flow usable by keyboard only.
  *Status:* register → second device login (duplicate preview) → live sync, devices,
  revoke, password change and re-login, TOTP, recovery and logout are keyboard-only and
  tested against the in-process server (`app/sync_tests.rs`). Teams (§5): create a team,
  invite by email (link shown without SMTP), a second account registers with the invite
  link as its token (joins at once) and joins another team with a pasted link, a shared
  vault is created and the member given read access, the member sees the shared site with
  🔒 and can't edit, delete or save it, safety numbers match on both sides and are marked
  verified, a server-side key swap shows "⚠ key changed" and the key-change warning (a
  grant is refused until the new key is accepted), removing the member rotates the vault
  key with toasts and the vault leaves their device
  (`teams_share_a_vault_read_only_verify_keys_and_remove_a_member`). Site Manager (§6):
  vault roots `Personal` / `Team: <name>` (only when a team vault is on the device),
  🔒 items with disabled fields, `c`/`m` copy/move to vault, `o` the member's own login
  (credential override). The panel opens with `<Ctrl-x><y>` (`SyncPanel`) or from
  Settings → Sync. A first-run "log in to a sync server" shortcut isn't offered: create
  the local vault, then log in from the panel.
- [x] Recovery words never logged or kept in memory after the screen closes.
  (Held in `Zeroizing` strings only while the words/check pages are open; confirm inputs
  are zeroizing `TextInput::sensitive` fields; `SyncRequest`/`SyncMsg` `Debug` print names
  only. The terminal back buffer keeps the drawn cells until the next redraw.)
- [x] Snapshot tests for every screen.
  (`ui/sync/snapshots/`: every sync and teams page incl. the key-change warning; the
  vault recovery pages and the status bar segment; `ui/site_manager/snapshots/`: vault
  roots, a read-only site, copy to vault, the credential override editor.)

## Tests

- UI-flow tests against an in-process server.
