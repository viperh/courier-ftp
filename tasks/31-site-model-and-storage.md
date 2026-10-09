# T31 — Site model and storage

**Phase:** D Vault & sites · **Depends on:** T02, T30 · **Crate:** `courier-ftp-core` (`sites` module) · **Decisions:** D4 · **FEATURES.md:** §2 (Site Manager)

## Goal

The data model behind the Site Manager: a folder tree of sites with every
setting FileZilla exposes per site, stored in the vault.

## Scope

1. **Tree**
   ```rust
   pub enum SiteNode { Folder { id, name, children: Vec<SiteNode>, expanded: bool }, Site(Site) }
   ```
   - Operations: add site/folder under a folder, rename, delete (folder deletes recursively after confirmation in UI), move (drag-equivalent: cut/paste), duplicate (deep copy with new ids and " (copy)" suffix; secrets duplicated to new `SecretId`s), sort children (folders first, then name).
   - Lookup by id and by path string (`"Work/Production/web01"`, used by CLI `--site`, T70). Names may not contain `/`; validate.
2. **`Site`** fields, grouped by FileZilla's Site Manager tabs:
   - **General**: `id: Uuid`, `name`, `protocol`, `encryption` (FTP only), `host`, `port: Option<u16>` (None = default), `logon: LogonType` with secret references (`SecretId` instead of inline passwords), `background_color: Option<SiteColor>` (none/red/green/blue/yellow/cyan/magenta — used as tab/pane accent), `comments: String`.
   - **Advanced**: `server_type: ServerTypeOverride` (Auto/Unix/Dos/Vms/Mvs/…), `bypass_proxy: bool`, `default_local_dir: Option<LocalPath>`, `default_remote_dir: Option<RemotePath>`, `sync_browsing: bool`, `directory_comparison: bool`, `timezone_offset_minutes: i32`.
   - **Transfer settings**: `transfer_mode: Default/Active/Passive`, `limit_connections: Option<u8>` (1–10).
   - **Charset**: `charset: Charset`.
   - **SFTP extras**: `key_file`, `try_agent_first`.
   - Metadata: `created_at`, `last_connected_at` (for "recent").
3. **`SiteConnectInfo`**: resolved, ready-to-connect struct (secrets fetched from the vault, settings merged with globals) — what `BackendFactory` receives (T03).
4. **Persistence**: `SiteStore` operates on the unlocked `VaultData.sites`; every mutation marks the vault dirty; save is debounced (≤ 1 s) and also forced on quit.
5. **Passwords**: when logon type changes away from one that uses a password, delete the orphaned secret. Garbage-collect unreferenced secrets on save.
6. **"Save password" off** (FileZilla's "do not save passwords" global option): setting `vault.store_passwords` (default true); when false, logon `Normal` behaves like `AskForPassword` and no secrets are written.
7. **Validation**: host non-empty, port 1–65535, key file exists (warn only), timezone offset within ±24 h.

## Acceptance criteria

- [ ] All fields exist and serialise; schema version bump path documented.
- [ ] Tree operations covered by tests including move into own descendant (rejected).
- [ ] Duplicate creates new secret ids.
- [ ] Orphaned secrets removed on save.
- [ ] Lookup by path works with nested folders and unicode names.

## Tests

- Unit tests for every tree operation and validation rule.
- Round-trip through a test vault.
