# T33 — Bookmarks and connection history

**Phase:** D Vault & sites · **Depends on:** T31, T81, T82 · **Crate:** `courier-ftp-core` · **Decisions:** D4 · **FEATURES.md:** §2 (bookmarks, quickconnect history, reconnect, recent servers)
**Related (integrates with, not blocking):** T66

## Goal

Data model for bookmarks, the quickconnect history and the recent-servers list,
all stored in the vault.

## Scope

1. **Bookmarks**
   - `Bookmark { id, name, local_dir: Option<LocalPath>, remote_dir: Option<RemotePath>, sync_browsing: bool, comparison: bool }`.
   - **Global bookmarks** (`bookmark` items with no `site_id`) — local dir only, or local+remote applied to whatever is connected.
   - **Site bookmarks** (`bookmark` items with `site_id`) — remote dir required. The local dir of a bookmark is device-local when it differs per machine (stored as an override, like a site's default local dir).
   - Ops: add, rename, edit, delete, reorder.
   - Applying a bookmark: navigate local and/or remote; if `sync_browsing`, enable synchronized browsing (T66).
2. **Storage**: bookmarks are `bookmark` items (synced). Quickconnect history entries are `history-entry` items (synced only with `sync.history`). The recent-servers list is device-local (T82).
3. **Quickconnect history**
   - Last 10 quickconnect entries (`ServerAddress` + logon type; password only if `vault.store_passwords`), most recent first, deduplicated by protocol+host+port+user.
   - "Clear history" API.
   - Vault locked → history neither shown nor saved (explain in UI).
4. **Recent servers**: last 10 successful connections from either Site Manager or quickconnect (site entries by id). "Reconnect to last server" uses item 0.
5. "Convert quickconnect entry to site" helper → creates a `Site` in the root folder with the history entry's data.

## Acceptance criteria

- [ ] History dedup and cap of 10 enforced.
- [ ] Deleting a site removes it from recent servers.
- [ ] Bookmarks round-trip through the vault.

## Tests

- Unit tests for dedup, cap, removal, conversion to site.
