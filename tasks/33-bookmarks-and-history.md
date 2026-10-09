# T33 — Bookmarks and connection history

**Phase:** D Vault & sites · **Depends on:** T31 · **Crate:** `courier-ftp-core` · **Decisions:** D4 · **FEATURES.md:** §2 (bookmarks, quickconnect history, reconnect, recent servers)

## Goal

Data model for bookmarks, the quickconnect history and the recent-servers list,
all stored in the vault.

## Scope

1. **Bookmarks**
   - `Bookmark { id, name, local_dir: Option<LocalPath>, remote_dir: Option<RemotePath>, sync_browsing: bool, comparison: bool }`.
   - **Global bookmarks** (`VaultData.bookmarks`) — local dir only, or local+remote applied to whatever is connected.
   - **Site bookmarks** (`Site.bookmarks: Vec<Bookmark>`) — remote dir required.
   - Ops: add, rename, edit, delete, reorder.
   - Applying a bookmark: navigate local and/or remote; if `sync_browsing`, enable synchronized browsing (T66).
2. **Quickconnect history**
   - Last 10 quickconnect entries (`ServerAddress` + logon type; password only if `vault.store_passwords`), most recent first, deduplicated by protocol+host+port+user.
   - "Clear history" API.
   - Vault locked → history neither shown nor saved (explain in UI).
3. **Recent servers**: last 10 successful connections from either Site Manager or quickconnect (site entries by id). "Reconnect to last server" uses item 0.
4. "Convert quickconnect entry to site" helper → creates a `Site` in the root folder with the history entry's data.

## Acceptance criteria

- [ ] History dedup and cap of 10 enforced.
- [ ] Deleting a site removes it from recent servers.
- [ ] Bookmarks round-trip through the vault.

## Tests

- Unit tests for dedup, cap, removal, conversion to site.
