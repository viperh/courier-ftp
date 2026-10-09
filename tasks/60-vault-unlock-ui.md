# T60 — Vault unlock, keyring and recovery UI

**Phase:** F TUI · **Depends on:** T30, T50, T52 · **Crate:** `courier-ftp` · **Decisions:** D3 · **FEATURES.md:** §2 (master password)
**Related (integrates with, not blocking):** T73, T87, T90
**Reference:** sverb `crates/sverb-tui/src/app/vault.rs` (startup flow), SPEC §5.3, §11.2.

## Goal

The master password screen at TUI start, optional per-device keyring unlock,
first-run setup, recovery, and every other vault-related screen — matching sverb.

## Scope

1. **Startup** (D3): the app starts `Locked`.
   - If keyring unlock is enabled on this device, try it first (no prompt). On failure
     show the password screen with a one-line reason ("Keyring unavailable").
   - Otherwise show the full-screen unlock view before any pane:
     ```
                 courier-ftp

          Master password: ••••••••••
          [ Unlock ]   [ Continue without vault ]   [ Forgot password? ]

          3 failed attempts · next try in 4 s
     ```
   - Enter unlocks; a spinner shows while Argon2 runs in the background.
   - Wrong password: inline error, field cleared, attempt counter and backoff countdown
     (T30); Unlock disabled during backoff.
   - **Continue without vault**: quickconnect only, nothing saved; status bar `🔐 locked`;
     Site Manager, bookmarks and history offer to unlock.
   - Command-line launch intents (T70: `--site`, URL) wait until unlock, then run.
2. **Forgot password?** shows the options that exist on this device:
   - Keyring enabled → "Unlock with the system keyring and set a new password" → new
     password + confirm (strength rules) → LMK re-wrapped.
   - Sync account → recovery flow (T90: recovery code + 24 words + new password).
   - Neither → explains there is no way to recover; offers restore from a
     `.cftp-backup` (T73) or starting a new empty vault (old DB moved aside, never deleted silently).
3. **First run** (no vault yet):
   - Explains: sites, passwords, history and trusted keys are stored encrypted; the master
     password is the only key, and with sync it is also the account password.
   - Password + confirm with live zxcvbn meter and feedback; score ≥ 3 required.
   - Checkbox **Unlock with system keyring on this device** (off by default; hidden when no
     keyring), with the note that the keyring is also the only local recovery path.
   - Clear warning: "Without the keyring option or a sync account (which gives you a
     recovery key), a forgotten password means your saved sites are lost."
   - Alternatives: restore from `.cftp-backup` (T73) or log in to a sync server (T90).
4. **Lock overlay**: after auto-lock or manual lock the same unlock view is drawn over
   the app (panes hidden, input blocked). Running transfers continue; progress stays in
   the status bar.
5. **Settings → Security** (part of T68): change master password (online flow when sync
   is on, T87), keyring unlock on/off for this device (asks for the password to enable),
   auto-lock minutes, lock on suspend, lock disconnects sessions, lock now, store
   passwords on/off, Argon2 cost (presets, shows measured unlock time).
6. **"Password changed on another device"** dialog (sync): shown when the server rejects
   this device's login; asks for the new password and re-wraps the LMK (T87).
7. **Database busy** (another courier-ftp writing): error with retry.
8. Passwords and recovery words never rendered, logged or kept after use (buffers zeroized on drop).

## Acceptance criteria

- [ ] Without keyring: every start shows the unlock view.
- [ ] With keyring enabled: start unlocks silently; keyring failure falls back to the prompt.
- [ ] Forgot-password paths: keyring reset, sync recovery, and the no-recovery explanation.
- [ ] Backoff countdown displayed and enforced.
- [ ] First-run creates the vault only with a strong enough password.
- [ ] Snapshot tests for unlock, first run, forgot password, backoff and lock overlay.

## Tests

- UI-flow tests with synthetic key events, a mock keyring and cheap Argon2 params.
