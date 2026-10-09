# T32 — Site import / export (incl. FileZilla XML)

**Phase:** D Vault & sites · **Depends on:** T31 · **Crate:** `courier-ftp-core` (`sites::import`, `sites::export`) · **FEATURES.md:** §2 (import and export of sites as XML; import from other clients)

## Goal

Let users move their sites in from FileZilla and between courier-ftp installs.

## Scope

1. **Import FileZilla `sitemanager.xml`** (`quick-xml`):
   - Locations to auto-suggest: Linux `~/.config/filezilla/sitemanager.xml`, macOS `~/.config/filezilla/` (FileZilla uses the same), Windows `%APPDATA%\FileZilla\sitemanager.xml`.
   - Map `<Folder>` → folder, `<Server>` → site. Fields: `Host`, `Port`, `Protocol` (0 FTP, 1 SFTP, 3 FTPS implicit, 4 FTPES explicit, 6 insecure FTP? — verify current mapping against FileZilla source docs), `Type` (server type), `User`, `Pass` (`encoding="base64"` → decode; `encoding="crypt"` = encrypted with FileZilla's master password → ask the user for it **or** skip the password and log; implementing FileZilla's crypto is optional — check its scheme, it's public key based), `Logontype` (0 anonymous, 1 normal, 2 ask, 3 interactive, 4 account, 5 key file — verify), `Account`, `Keyfile`, `TimezoneOffset`, `PasvMode`, `MaximumMultipleConnections`, `EncodingType`/`CustomEncoding`, `BypassProxy`, `Name`, `Comments`, `Colour`, `LocalDir`, `RemoteDir` (FileZilla's encoded format `1 0 4 home 4 user` → `/home/user`), `SyncBrowsing`, `DirectoryComparison`, `<Bookmark>` children → site bookmarks (T33).
   - Import into a new folder "Imported from FileZilla <date>" to avoid name clashes.
   - Report: N sites imported, M passwords imported, K skipped with reasons.
2. **Import FileZilla queue / filters**: out of scope (only sites).
3. **courier-ftp export format**: JSON file containing the site subtree.
   - Options: include passwords **yes/no**. If yes, the export file is itself encrypted with a passphrase the user enters (same container format as T30, separate magic `CFTPEXP\0`). If no, secrets are stripped and logon types needing them become `AskForPassword`.
   - Export a single site, a folder, or everything.
4. **courier-ftp import**: reads both encrypted and plain exports; on id collision, generate new ids.
5. Optional: export to FileZilla XML (without passwords) for users moving back. Low priority — mark as stretch.

## Acceptance criteria

- [ ] A real FileZilla 3.x `sitemanager.xml` with folders, all logon types, bookmarks and base64 passwords imports correctly (fixture in `tests/fixtures/`, using fake hosts).
- [ ] Remote dir encoding decoded correctly (including names with spaces).
- [ ] Encrypted export round-trips; wrong passphrase errors.
- [ ] Plain export contains no secrets (`grep` test).

## Tests

- Fixture-based import test with snapshot of resulting tree.
- Export/import round-trip with and without passwords.
