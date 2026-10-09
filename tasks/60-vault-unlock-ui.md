# T60 — Vault unlock and master password UI

**Phase:** F TUI · **Depends on:** T30, T52 · **Crate:** `courier-ftp` · **Decisions:** D3 · **FEATURES.md:** §2 (master password)
**Reference:** sverb `crates/sverb-tui/src/app/vault.rs` (startup flow).

## Goal

The master password screen at every TUI start, first-run setup, and all other
vault-related screens.

## Scope

1. **Startup** (D3): the app starts `Locked`. Before any pane is shown, a full-screen
   unlock view appears:
   ```
               courier-ftp

        Master password: ••••••••••
        [ Unlock ]   [ Continue without vault ]

        3 failed attempts · next try in 4 s
   ```
   - Enter unlocks; the spinner shows while Argon2 runs (in the background).
   - Wrong password: inline error, field cleared, attempt counter and backoff countdown
     (T30) shown; the Unlock button is disabled during backoff.
   - **Continue without vault**: quickconnect only, nothing saved; status bar shows
     `🔐 locked`; Site Manager, bookmarks and history offer to unlock.
   - Command-line launch intents (T70: `--site`, URL) wait until unlock finishes,
     then run.
2. **First run** (no vault yet):
   - Explains: sites, passwords, history and trusted keys are stored encrypted;
     you will be asked for the master password every time courier-ftp starts.
   - Password + confirm fields with live zxcvbn strength meter and its feedback;
     must reach score ≥ 3.
   - Clear warning: "If you forget this password, your saved sites cannot be
     recovered unless you enable sync (which gives you a recovery key)."
   - Option to restore from a `.cftp-backup` file (T73) or to log in to a sync server
     (T90) instead of starting empty.
3. **Lock overlay**: after auto-lock or manual lock, the same unlock view is drawn over
   the app (panes hidden). Running transfers continue; their progress stays in the
   status bar line.
4. **Settings → Security** (part of T68): change master password (old, new, confirm,
   strength), auto-lock minutes, lock now, store passwords on/off, Argon2 cost
   (presets: default / high; shows measured unlock time).
5. **Second process busy**: show the "database busy" error with retry.
6. Passwords never rendered, logged or kept after use (field buffers zeroized on drop).

## Acceptance criteria

- [ ] Every start shows the unlock view; no keyring path exists.
- [ ] Backoff countdown displayed and enforced.
- [ ] First-run flow creates the vault only when the password is strong enough.
- [ ] Continue-without-vault works and can unlock later.
- [ ] Snapshot tests for unlock, first run, backoff and lock overlay.

## Tests

- UI-flow tests with synthetic key events and cheap Argon2 params.
