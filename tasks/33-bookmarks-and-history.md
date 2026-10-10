# T33 — Bookmarks and connection history

**Phase:** D Vault & sites · **Milestone:** M5 · **Depends on:** T31, T81, T82 · **Crate(s):** `courier-ftp-core` (`sites::bookmarks`, `sites::history`, `sites::recent`) · **Decisions:** D4 · **FEATURES.md:** §2 (bookmarks global or per site with synchronized browsing; quickconnect history; reconnect to the last server; recent servers list)
**Related (integrates with, not blocking):** T66

## Goal

The data model and operations for bookmarks (global and per site, optionally with
synchronized browsing and directory comparison), the quickconnect history (last 10 servers)
and the recent-servers list used by "Reconnect to last server". Bookmarks and history are
vault items, so they are encrypted and can sync; the recent list and per-device local
directories stay on the device.

## Context

- Before: T31 (`SiteManager`, `SiteTree`, `SiteId`, `Site`, `Location`), T30 (`VaultEngine`:
  `list`/`get`/`put`/`delete_many`, `touch_connected`, `set_local_dir_override`,
  `device_local`, write policy for `history-entry`), T81 (`bookmark` and `history-entry`
  field tables, `ItemView`, `SecretField`), T82 (`device_local`), T02 (`ServerAddress`,
  `ServerIdentity`, `LogonType`, `LogonKind`, `RemotePath`, `LocalPath`).
- After: T64 (Bookmarks UI) and T59 (Site Manager bookmark list) call `Bookmarks`; T58
  (quickconnect) calls `QuickconnectHistory::record` after a successful login and fills its
  dropdown from `entries()`; T58/T51 "Reconnect to last server" and T61 use
  `recent_servers()`; T66 is invoked when an applied bookmark asks for synchronized browsing
  or comparison; T32 imports FileZilla `<Bookmark>` elements through `Bookmarks::add`.

## Technical specification

### Types and APIs

```rust
// sites::bookmarks
/// A bookmark (`bookmark` item, T81). For site bookmarks `local_dir` is the device-local
/// override; for global bookmarks it is the synced item field.
pub struct Bookmark {
    pub name: String,
    pub site_id: Option<SiteId>,          // None = global
    pub local_dir: Option<LocalPath>,
    pub remote_dir: Option<RemotePath>,
    pub sync_browsing: bool,
    pub comparison: bool,                 // item key `directory_comparison`
    pub position: f64,
}
impl ItemView for Bookmark { const KIND: ItemKind = ItemKind::Bookmark; .. }
pub struct BookmarkEntry { pub id: ItemId, pub vault: VaultId, pub bookmark: Bookmark, pub read_only: bool }
pub enum BookmarkField { Name, LocalDir, RemoteDir, SyncBrowsing, Comparison }
pub struct BookmarkIssue { pub field: BookmarkField, pub message: String }

pub struct Bookmarks { vault: VaultEngine }
impl Bookmarks {
    pub fn new(vault: VaultEngine) -> Self;
    pub fn list_global(&self) -> Result<Vec<BookmarkEntry>, Error>;                 // sorted by (position, name, id)
    pub fn list_for_site(&self, site: SiteId) -> Result<Vec<BookmarkEntry>, Error>;
    pub async fn add(&self, b: Bookmark) -> Result<ItemId, Error>;                  // appended (position = last + 1.0)
    pub async fn edit(&self, id: ItemId, b: Bookmark) -> Result<ItemId, Error>;     // new id if it moves to another vault
    pub async fn rename(&self, id: ItemId, name: &str) -> Result<(), Error>;
    pub async fn delete(&self, id: ItemId) -> Result<(), Error>;
    pub async fn reorder(&self, id: ItemId, new_index: usize) -> Result<(), Error>;
    pub async fn copy_site_bookmarks(&self, from: SiteId, to: SiteId, to_vault: VaultId) -> Result<usize, Error>; // T31 duplicate/copy
}
pub fn validate_bookmark(b: &Bookmark, sibling_names: &[&str]) -> Result<(), Vec<BookmarkIssue>>;

// sites::history
pub const HISTORY_CAP: usize = 10;
/// One quickconnect history entry (`history-entry` item, T81).
pub struct HistoryEntry {
    pub address: ServerAddress,           // protocol, encryption, host, port, user
    pub logon: LogonKind,                 // anonymous | normal | ask-for-password | interactive | agent
    pub password: SecretField,
    pub remote_dir: Option<RemotePath>,
    pub last_used_at: UnixMillis,
}
impl ItemView for HistoryEntry { const KIND: ItemKind = ItemKind::HistoryEntry; .. }
pub struct QuickconnectHistory { vault: VaultEngine }
impl QuickconnectHistory {
    pub fn new(vault: VaultEngine) -> Self;
    /// Newest first, at most HISTORY_CAP (secrets not loaded).
    pub fn entries(&self) -> Result<Vec<Loaded<HistoryEntry>>, Error>;
    /// After a successful login: dedup by ServerAddress::identity(), update or insert,
    /// prune beyond the cap, touch device_local. Returns the entry id.
    pub async fn record(&self, address: &ServerAddress, logon: &LogonType,
                        remote_dir: Option<&RemotePath>) -> Result<ItemId, Error>;
    /// Address, logon (with the stored password when allowed) and remote dir to reconnect.
    pub async fn load(&self, id: ItemId) -> Result<(ServerAddress, LogonType, Option<RemotePath>), Error>;
    pub async fn remove(&self, id: ItemId) -> Result<(), Error>;
    pub async fn clear(&self) -> Result<usize, Error>;
}
/// "Convert to site" / quickconnect "Save as site" (T58): a Site in the personal root.
pub fn site_from_quickconnect(address: &ServerAddress, logon: &LogonType,
                              remote_dir: Option<&RemotePath>, taken_names: &[&str]) -> Site;
impl SiteManager { pub async fn add_from_history(&self, id: ItemId) -> Result<SiteId, Error>; }

// sites::recent
pub const RECENT_CAP: usize = 10;
pub enum RecentTarget { Site(SiteId), Quickconnect(ItemId /* history entry */) }
pub struct RecentEntry { pub target: RecentTarget, pub label: String, pub last_connected_at: i64 }
/// Last RECENT_CAP successful connections, newest first (pure over T30 caches).
pub fn recent_servers(vault: &VaultEngine, tree: &SiteTree) -> Result<Vec<RecentEntry>, Error>;
```

### Behaviour

**Bookmarks**
- *Global* bookmarks (`site_id = None`) live in the personal vault; `local_dir` is a synced item
  field (required); `remote_dir` optional and applied to whatever server the tab is connected
  to. *Site* bookmarks (`site_id = Some`) live in the same vault as their site (T81 cross-vault
  rule); `remote_dir` is required; their `local_dir` is stored only on this device
  (`device_local.local_dir_override` keyed by the bookmark id, so the item never carries it)
  and is optional.
- Validation (`validate_bookmark`, same rules T64 shows inline): name 1–100 characters after
  trim, no control characters, unique in its list (global list, or one site's list)
  case-insensitively; global needs `local_dir`; site needs `remote_dir`; local dir absolute after
  `~` expansion (existence not required); remote dir absolute `RemotePath`; `sync_browsing` or
  `comparison` need both dirs; `comparison = true` forces `sync_browsing = true` (FileZilla:
  comparison implies synchronized browsing).
- `add`: position = (max position in its list) + 1.0 (1.0 for an empty list).
- `reorder(id, new_index)`: fractional index — the new position is the midpoint of the
  neighbours at the target slot (first: `next − 1.0`, last: `prev + 1.0`); if the gap to a
  neighbour falls below `1e-9`, the whole list is renumbered `1.0, 2.0, …` in one `put_many`
  transaction. Only the moved item's `position` changes otherwise, so concurrent reorders on two
  devices merge per item (T81 LWW) and the list stays sorted by `(position, name, id)`.
- `edit` changing `site_id` (Global ↔ Site, or to another site): same vault → `put`; another
  vault → new item in the target vault + tombstone of the old one in one `put_many`; the local
  dir moves between the item field and the device-local override accordingly.
- `delete` tombstones the item and removes its device-local row. Deleting a site deletes its
  bookmarks (T31 `delete`).
- Applying a bookmark (navigation, synchronized browsing T66) is done by T64 (`plan_apply`);
  this task only provides the data.

**Quickconnect history** (FileZilla's quickconnect dropdown):
- `record` runs after a successful login (T58). Key = `ServerAddress::identity()` (protocol,
  lowercase host, effective port, user; encryption is not part of it). An existing live entry
  with the same key is updated (encryption, logon, password, remote dir, `last_used_at = now`);
  otherwise a new item is created. Then entries beyond `HISTORY_CAP` (oldest `last_used_at`
  first, ties by id) are tombstoned with `delete_many`, and `touch_connected(id)` records the
  connection for the recent list.
- Password: written only when `vault.store_passwords` is true **and** the logon is `Normal`
  (T30 enforces the setting; otherwise `Absent`). `load` returns
  `LogonType::Normal { password: None }` when no password is stored, which makes the backend
  prompt. Key-file and account logons are not recorded (quickconnect cannot express them,
  as in FileZilla); `record` stores them as `ask-for-password`.
- Vault locked or "continue without vault": `entries` and `record` return `Error::VaultLocked`;
  T58 hides the dropdown and saves nothing.
- Sync: `history-entry` items are written with `dirty = 0` while `sync.history = false`
  (default), so they never leave the device; turning it on syncs entries written afterwards
  (T30 policy). After a merge more than 10 entries can exist; `entries()` returns the newest 10
  and the next `record` prunes the rest.
- `clear` tombstones all entries (and their device-local rows) in one transaction.
- `site_from_quickconnect`: name = `user@host` (or `host` without user), made unique among the
  personal root's children with `" (2)"`, `" (3)"`…; protocol, encryption, host, port, user,
  logon kind, password (as `SecretField::Value`) and remote dir copied; everything else default.
  `add_from_history` loads the entry with its password and calls `SiteManager::add_site` at the
  personal root.

**Recent servers** (device-local, never synced):
- Built from `device_local.last_connected_at` of live `site` items and live `history-entry`
  items, newest first, at most `RECENT_CAP = 10`. Sites update it through
  `SiteManager::mark_connected` (T31) and history entries through `record`, both only after a
  successful login.
- A deleted site or history entry disappears from the list automatically (deleted items are not
  listed; T30 removes their device-local rows).
- Label: the site's tree path (T31 `path_of`) or the history entry's `ServerAddress` URL
  without password.
- "Reconnect to last server" (T58, `Ctrl-x r` ReconnectLast) uses entry 0. With the vault locked the list is empty; T58
  then reconnects to the in-memory last `ConnectInfo` of this process if there is one.

### Data formats and configuration

Items: `bookmark` and `history-entry` (T81 tables). Device-local: `device_local.local_dir_override`
(site bookmark local dir), `device_local.last_connected_at`/`frecency` (recent list), T82.

Settings read: `vault.store_passwords` (T30), `sync.history` (T88; bool, default `false`).
No new settings keys.

### Errors

| Error | When | UI |
|---|---|---|
| `Error::InvalidInput(msg)` | validation (one message per `BookmarkIssue`), unknown id | inline (T64) |
| `Error::VaultLocked` | any call while locked | T64 offers unlock; T58 hides history |
| `Error::Vault(msg)` (`ReadOnlyVault`, `ReadOnlyItem`, `Busy`) | team `read` vault, newer schema, DB busy | "This bookmark is read-only" / Retry |

### Security and logging

- Stored history passwords are `SecretField`/`SecretString`, exposed only when building the
  `LogonType`; `HistoryEntry` and `Bookmark` `Debug` redact secrets (bookmarks have none).
- Logs: ids and counts only (`debug`); never hostnames, user names, bookmark names or paths at
  `info`+ (T91 §4).
- Bookmark names and paths may come from a teammate (team vault) or an import: rendered by T64
  after control-character stripping; this module rejects control characters in names on write.

## Implementation steps

1. `Bookmark` view, `validate_bookmark`, `Bookmarks` list/add/edit/rename/delete with the
   global/site local-dir split.
2. Fractional `reorder` with renumbering.
3. `HistoryEntry` view, `QuickconnectHistory::{entries, record, load, remove, clear}`.
4. `site_from_quickconnect`, `SiteManager::add_from_history`.
5. `recent_servers`.
6. Wire T31's site delete/duplicate/copy to `Bookmarks::copy_site_bookmarks`.

## Acceptance criteria

- [ ] AC1 Bookmarks round-trip through the vault: add global and site bookmarks, lock, unlock,
  `list_global`/`list_for_site` return equal values; a site bookmark's local dir is absent from
  the decrypted item and present via `device_local`.
- [ ] AC2 Validation rejects every rule in the Behaviour list with the matching
  `BookmarkField`; `comparison = true` saves with `sync_browsing = true`.
- [ ] AC3 `reorder` produces the requested order; 40 successive moves into the same gap trigger
  exactly one renumbering (at the 30th move, when the gap falls below `1e-9`) and keep the order; two engines reordering different bookmarks
  offline converge to the same order after `sync_sim` (T31 helper).
- [ ] AC4 History dedup: recording `sftp://alice@Example.com` and then
  `sftp://alice@example.com:22` leaves one entry; recording 12 distinct servers leaves exactly 10
  live entries, the 2 oldest tombstoned.
- [ ] AC5 With `vault.store_passwords = false` a recorded `Normal` entry stores no password and
  `load` returns `Normal { password: None }`; with `true` it returns the password.
- [ ] AC6 `recent_servers` lists the last 10 successful connections across sites and
  quickconnect entries, newest first; deleting a site removes it from the list.
- [ ] AC7 `add_from_history` creates a site named `alice@example.com` (then
  `alice@example.com (2)`) in the personal root with the same address, logon and password.
- [ ] AC8 With the vault locked, `entries`, `record` and `list_global` return
  `Error::VaultLocked` and nothing is written.
- [ ] AC9 CI gates `fmt`, `clippy`, `docs`, `test-local-only`, `test-os` pass.

## Tests

### Unit tests
- `bookmarks::tests::validate_rules` — one case per rule (AC2).
- `bookmarks::tests::reorder_midpoints_and_renumber` — pure position computation (AC3).
- `history::tests::dedup_key_is_identity` — host case, default port, encryption ignored (AC4).
- `history::tests::site_from_quickconnect_names` — `user@host`, `host`, suffixes (AC7).
- `recent::tests::ordering_and_cap` — synthetic device-local rows (AC6).

### Property / fuzz tests
- `tests/bookmark_props.rs::reorder_sequences_keep_total_order` (proptest, 500 cases): random
  `reorder` sequences on a list of 2..30 bookmarks match a `Vec` model (AC3).

### Snapshot tests
Not applicable (UI is T64/T58).

### Integration tests
(`crates/courier-ftp-core/tests/bookmarks_history.rs`, `Argon2Cost::TEST`)
- `t01_bookmarks_roundtrip_relock` (AC1).
- `t02_site_bookmark_local_dir_is_device_local` (AC1).
- `t03_edit_moves_between_global_and_site` — including a team-vault site (new id).
- `t04_concurrent_reorder_converges` (AC3).
- `t05_history_dedup_and_cap` (AC4).
- `t06_history_store_passwords_off` (AC5).
- `t07_history_not_dirty_without_sync_history` — `items.dirty = 0`, no outbox row.
- `t08_recent_servers_and_site_delete` (AC6).
- `t09_add_from_history` (AC7).
- `t10_locked_vault_refuses` (AC8).
- `t11_site_delete_removes_bookmarks` — T31 delete cascades.

### End-to-end tests
Not applicable here; T58/T64 PTY flows cover the UI (T76).

## Out of scope

- Bookmark menu, dialogs and applying bookmarks (T64), quickconnect bar (T58), synchronized
  browsing and comparison (T66).
- FileZilla's global `bookmarks.xml` import (only site bookmarks from `sitemanager.xml`, T32).

## Open questions

None.
