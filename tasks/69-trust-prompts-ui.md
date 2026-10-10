# T69 — Trust prompts (host keys and certificates)

**Phase:** F TUI · **Depends on:** T04, T52 · **Crate:** `courier-ftp` · **FEATURES.md:** §1 (host key confirmation, certificate trust dialog)
**Related (integrates with, not blocking):** T12, T21, T42

## Goal

Clear, safe dialogs for the security prompts the protocols raise, plus the
other interactive prompts (passwords, passphrases, keyboard-interactive).

## Scope

Each prompt type is built when its producer exists: host-key and password/keyboard-interactive prompts with SFTP (T20/T21), certificate prompts with FTPS (T12), the file-exists prompt with the transfer policy (T42). The queueing mechanism (§7) comes first.


1. **Unknown host key**
   ```
   ┌ Unknown host key ─────────────────────────────────────┐
   │ The server's host key is unknown. You have no         │
   │ guarantee that the server is the computer you think.  │
   │                                                       │
   │ Host:        web01.example.com:22                     │
   │ Key type:    ssh-ed25519 256                          │
   │ Fingerprint: SHA256:abc...                            │
   │              MD5: 12:34:...                           │
   │                                                       │
   │ [x] Always trust this host, add this key to the cache │
   │            [ OK ]          [ Cancel ]                 │
   └───────────────────────────────────────────────────────┘
   ```
   "Always trust" disabled with a note when the vault is locked.
2. **Changed host key**: red title "WARNING: host key changed", old and new fingerprints side by side, explanation of possible MITM; default button *Cancel*; trusting requires typing `yes` or ticking an explicit checkbox.
3. **Certificate prompt**: summary (subject CN, issuer, validity with expired/not-yet-valid highlighted, hostname match ✔/✘, fingerprints SHA-256/SHA-1), session details (TLS version, cipher), and an expandable **Details** view per chain certificate (scrollable). Buttons: *Trust once* / *Always trust* / *Cancel*. Changed-cert variant like (2).
4. **Password / passphrase prompt**: masked input, "Remember for this session" checkbox, and "Save in vault" (when allowed).
5. **Keyboard-interactive**: renders server name/instructions and one input per prompt, echo respected.
6. **File exists prompt** (T42): source vs target rows (size, modified), radio list of actions, *new name* field for Rename, scope checkboxes (*always use this action* / *apply only to current queue* / *apply only to uploads|downloads*).
7. Prompts arriving while another dialog is open queue up (one at a time); prompts for background transfers don't steal focus from text input — they show a status-bar badge `⚠ 1 prompt` and open on `Ctrl-x p` or when the user is idle in normal mode (decide; document).

## Acceptance criteria

- [ ] Snapshot tests for each prompt type and the changed-key/cert variants.
- [x] Dangerous defaults impossible (Enter on changed-key dialog = Cancel).
- [x] Prompt queueing works with concurrent transfers.

## Status (M2 pass)

Built: unknown/changed host key (1, 2), certificate and changed-certificate
dialogs with the Details view (3; ready for T12), and the queue (7).
Not yet: the "Remember for this session" / "Save in vault" options of the
password prompt (4) and file-exists (6, T42). Password, passphrase and
keyboard-interactive (5) prompts use the T52 dialogs. The first acceptance box
stays open until (4) and (6) have their snapshots.

Queue decision (7): one prompt at a time, never on top of another dialog. A
prompt opens by itself when no dialog is open, the user isn't typing (input
or filter mode) and no key was pressed for 1 s; until then the status bar
shows `⚠ N prompt(s)` and `<Ctrl-x><p>` opens the next one at once. Prompts
the core stopped waiting for leave the queue, and an open trust dialog closes
itself.

## Tests

- Snapshot + UI-flow tests with synthetic prompts.
