# T73 — Settings import / export

**Phase:** G App-level · **Depends on:** T05, T30, T32, T40, T68 · **Crate:** `courier-ftp` · **FEATURES.md:** §10 (settings import and export)
**Related (integrates with, not blocking):** T60

## Goal

Move a whole courier-ftp setup to another machine.

## Scope

1. **Export** dialog with checkboxes: *Settings* (config incl. keybindings, styles, filters), *Sites & bookmarks* (T32 export, with/without passwords), *Queue* (T40 export), *Trusted host keys and certificates*.
2. Output: one archive file (`.cftp-backup`) in the backup format from T30 §10 (Argon2id + XChaCha20-Poly1305 over `zstd(cbor)`), encrypted with a passphrase the user enters. An optional plain-JSON export without secrets is offered for settings only. Restoring a backup is also offered on the first-run screen (T60).
3. **Import**: choose file → shows contained sections → choose which to import → for settings: *replace* or *merge*; for sites: into a new folder; conflicts reported.
4. Version field and forward-compat: unknown sections skipped with a warning.

## Acceptance criteria

- [ ] Export → import on a fresh data/config dir reproduces settings and sites.
- [ ] Plain export contains no secrets.
- [ ] Partial import works.

## Tests

- Round-trip tests in temp dirs.
