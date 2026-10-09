# T31 — Site model and storage

**Phase:** D Vault & sites · **Depends on:** T02, T03, T30, T81, T82 · **Crate:** `courier-ftp-core` (`sites` module) · **Decisions:** D4 · **FEATURES.md:** §2 (Site Manager)
**Related (integrates with, not blocking):** T70, T88, T89

## Goal

The data model behind the Site Manager: a folder tree of sites with every
setting FileZilla exposes per site, stored in the vault.

## Scope

1. **Tree**
   ```rust
   pub enum SiteNode { Folder { id, name, children: Vec<SiteNode>, expanded: bool }, Site(Site) }
   ```
   - Operations: add site/folder under a folder, rename, delete (folder deletes recursively after confirmation in UI), move (drag-equivalent: cut/paste), duplicate (deep copy with new ids and " (copy)" suffix, passwords included), sort children (folders first, then name).
   - Lookup by id and by path string (`"Work/Production/web01"`, used by CLI `--site`, T70). Names may not contain `/`; validate.
2. **`Site`** fields, grouped by FileZilla's Site Manager tabs:
   - **General**: `id: Uuid`, `name`, `protocol`, `encryption` (FTP only), `host`, `port: Option<u16>` (None = default), `logon: LogonType` **including the password / account / key passphrase** (stored inside the encrypted item, T30 §8; `SecretString` in memory), `background_color: Option<SiteColor>` (none/red/green/blue/yellow/cyan/magenta — used as tab/pane accent), `comments: String`.
   - **Advanced**: `server_type: ServerTypeOverride` (Auto/Unix/Dos/Vms/Mvs/…), `bypass_proxy: bool`, `default_local_dir: Option<LocalPath>`, `default_remote_dir: Option<RemotePath>`, `sync_browsing: bool`, `directory_comparison: bool`, `timezone_offset_minutes: i32`.
   - **Transfer settings**: `transfer_mode: Default/Active/Passive`, `limit_connections: Option<u8>` (1–10).
   - **Charset**: `charset: Charset`.
   - **SFTP extras**: `key_file`, `try_agent_first`.
   - Metadata: `created_at`, `last_connected_at` (for "recent").
3. **`Site::to_connect_info()`**: builds the `ConnectInfo` from T03 (secrets taken from the decrypted item, device-local overrides applied, settings merged with globals) — what `BackendFactory` receives.
4. **Persistence**: each site is a `site` item and each folder a `site-folder` item (T81) in a vault (personal or team, T89). Folders and sites point to their parent folder by id; the tree is rebuilt from items on unlock. Every change goes through `VaultEngine::put` (T30), which writes immediately and queues it for sync. `default_local_dir` and `last_connected_at` are device-local (T82 `device_local`), not part of the synced item.
5. **Passwords**: when the logon type changes to one without a password, the password fields are cleared in the item (the old value is gone once the change syncs).
6. **"Save password" off** (FileZilla's "do not save passwords" global option): setting `vault.store_passwords` (default **true**); when false, logon `Normal` behaves like `AskForPassword` and password fields are never written.
7. **SSH keys in the vault**: the key file can be either a local path (device-local) or an `ssh-key` item (T81) imported into the vault, so the site works on every synced device.
8. **Validation**: host non-empty, port 1–65535, key file exists (warn only), timezone offset within ±24 h.

## Acceptance criteria

- [ ] All fields exist and serialise; schema version bump path documented.
- [ ] Tree operations covered by tests including move into own descendant (rejected).
- [ ] Saving a site with a password and reopening the app (after unlock) connects without asking for the password.
- [ ] A site edited on one device appears on another after sync (with T88).
- [ ] Lookup by path works with nested folders and unicode names.

## Tests

- Unit tests for every tree operation and validation rule.
- Round-trip through a test vault.
