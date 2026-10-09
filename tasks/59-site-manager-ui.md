# T59 — Site Manager screen

**Phase:** F TUI · **Depends on:** T31, T32, T33, T52, T58, T60 · **Crate:** `courier-ftp` (`components/site_manager/`) · **FEATURES.md:** §2
**Related (integrates with, not blocking):** T64, T70

## Goal

Full-screen (or large modal) Site Manager: folder tree on the left, tabbed site
editor on the right, connect buttons at the bottom.

## Layout

```
┌ Site Manager ────────────────────────────────────────────────────────────┐
│ My Sites                   │ [General] Advanced  Transfer  Charset        │
│ ▾ Work                     │ Protocol:   [SFTP ▾]                        │
│   ▾ Production             │ Host:       web01.example.com   Port: [22 ] │
│     ● web01                │ Logon type: [Key file ▾]                    │
│     ● db01                 │ User:       deploy                          │
│ ▸ Personal                 │ Key file:   ~/.ssh/id_ed25519   [browse]    │
│                            │ Colour:     [Red ▾]                         │
│                            │ Comments:   ...                             │
│ [n]ew site [f]older [d]up  │                                             │
│ [r]ename [x] delete        │                                             │
├────────────────────────────┴─────────────────────────────────────────────┤
│ [Connect]  [Connect in new tab]  [Save]  [Import…]  [Export…]  [Close]   │
└──────────────────────────────────────────────────────────────────────────┘
```

## Scope

1. **Tree** (left): folders and sites, expand/collapse, type-to-search, keys: `n` new site, `f` new folder, `d` duplicate, `r`/`F2` rename (inline), `x`/`Delete` delete (confirm; folder deletion lists count), `Ctrl-x`/`Ctrl-v` cut/paste to move, `J/K` reorder? (sorted alphabetically by default — then no manual order). Site colour shown as dot.
2. **Editor tabs** (right) — fields from T31, shown/hidden by protocol and logon type:
   - **General**: protocol (FTP / SFTP), encryption (FTP only: 4 options), host, port, logon type (only those valid for the protocol), user, password (masked; "stored in vault" note; disabled when vault locked or store_passwords off), account (Account type), key file (PathInput with completion; SFTP only), try agent first (SFTP), background colour, comments (multiline).
   - **Advanced**: server type, bypass proxy, default local dir, default remote dir, use synchronized browsing, directory comparison, server time zone offset (hours + minutes).
   - **Transfer settings**: transfer mode (default/active/passive; FTP only), limit simultaneous connections + max.
   - **Charset**: autodetect / force UTF-8 / custom (select from `encoding_rs` labels).
   - **Bookmarks** sub-section listing site bookmarks (edit via T64).
3. **Dirty tracking**: unsaved changes marked `*`; switching site or closing with unsaved changes → *Save / Discard / Cancel*.
4. **Validation** errors shown inline (T31 rules).
5. **Connect** / **Connect in new tab**: save first if dirty, then connect (applies default dirs, sync browsing, comparison).
6. **Import…**: choose FileZilla XML (auto-detect default path) or courier-ftp export; shows import report (T32). **Export…**: selected site/folder/all, with/without passwords (passphrase prompt).
7. **Vault locked**: opening Site Manager triggers unlock (T60); if user cancels, show read-only message "Unlock the vault to view sites".
8. Open via `Ctrl-s`, and a `--site-manager` CLI flag? (No — use T70's `--site`.) Also a "Site Manager" quick list (`Ctrl-x s`?) that shows a fuzzy picker of sites for fast connect — FileZilla has a site-manager dropdown on the toolbar.

## Acceptance criteria

- [ ] All fields editable and persisted; fields hide/show by protocol/logon type.
- [ ] Unsaved changes guarded.
- [ ] Import/export flows work end-to-end.
- [ ] Fuzzy site picker connects in ≤ 3 keystrokes for a known site name.
- [ ] Snapshot tests for each tab and protocol variant.

## Tests

- Snapshot tests; unit tests for field visibility rules and dirty tracking.
