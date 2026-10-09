# T60 — Vault unlock and master password UI

**Phase:** F TUI · **Depends on:** T30, T52 · **Crate:** `courier-ftp` · **Decisions:** D3 · **FEATURES.md:** §2 (master password)

## Goal

All user-facing flows around the vault: first-run setup, unlock at startup,
changing protection, and recovery messages.

## Scope

1. **First run** (no vault file): setup dialog
   - Explains: sites, passwords and history are stored encrypted.
   - Options: **Use system keyring** (checked if keyring available), **Set a master password** (recommended; required if no keyring). Password + confirm fields with a strength hint (length-based, no external lib needed; optionally `zxcvbn`).
   - Warning when keyring-only is chosen: "If the keyring entry is lost, saved sites cannot be recovered."
   - "Skip for now" — app works without a vault (quickconnect only, nothing saved); status bar shows `🔐 none`.
2. **Startup unlock**
   - Keyring enabled → unlock silently; failure falls back to the password prompt with an explanation.
   - Password only → unlock dialog when first needed (lazy: on opening Site Manager, history, or connecting a saved site) or at startup (setting `vault.unlock_at_startup`, default true).
   - Wrong password → shake/red message, retry; Esc continues locked.
3. **Settings → Security** (part of T68): change master password, add/remove master password, enable/disable keyring, lock now, auto-lock minutes, store passwords on/off, rekey vault. Each action confirms and requires the current password where appropriate.
4. **Recovery**: corrupted main file but valid backup → dialog offering to restore backup; both broken → offer to move them aside (`vault.cfv.broken-<date>`) and start fresh.
5. **Second instance** read-only warning (T30 lock file).
6. Locked state indicator in status bar (T57).

## Acceptance criteria

- [ ] All flows reachable and tested with mock keyring and low-cost Argon2 params.
- [ ] No path leaves the user stuck (every dialog has a way to continue locked).
- [ ] Passwords never rendered or logged.

## Tests

- UI flow tests driving dialogs with synthetic key events.
