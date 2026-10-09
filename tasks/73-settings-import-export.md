# T73 — Settings import / export

**Phase:** G App-level · **Depends on:** T05, T32, T68 · **Crate:** `courier-ftp` · **FEATURES.md:** §10 (settings import and export)

## Goal

Move a whole courier-ftp setup to another machine.

## Scope

1. **Export** dialog with checkboxes: *Settings* (config incl. keybindings, styles, filters), *Sites & bookmarks* (T32 export, with/without passwords), *Queue* (T40 export), *Trusted host keys and certificates*.
2. Output: one archive file (`.cftp-backup`) — a JSON envelope; sections containing secrets are encrypted with a user passphrase (T30 container format). Without secrets → plain JSON readable by humans.
3. **Import**: choose file → shows contained sections → choose which to import → for settings: *replace* or *merge*; for sites: into a new folder; conflicts reported.
4. Version field and forward-compat: unknown sections skipped with a warning.

## Acceptance criteria

- [ ] Export → import on a fresh data/config dir reproduces settings and sites.
- [ ] Plain export contains no secrets.
- [ ] Partial import works.

## Tests

- Round-trip tests in temp dirs.
