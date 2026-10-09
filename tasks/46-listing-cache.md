# T46 — Directory listing cache

**Phase:** E Transfers · **Depends on:** T03, T04 · **Crate:** `courier-ftp-core` (`cache` module) · **FEATURES.md:** §3 (directory listing cache, option to refresh or not)

## Goal

Avoid re-listing directories the user just visited, while keeping panes
accurate after our own changes.

## Scope

1. `ListingCache` keyed by `(server identity = protocol+host+port+user, RemotePath)` → `Listing` + `fetched_at`. In memory only (never persisted — avoids leaking file names to disk).
2. Shared across tabs connected to the same server.
3. Policy: `cache.listing_cache` on/off; `ttl_secs` (0 = valid until explicit refresh). Navigating back to a cached dir shows it instantly; F5/`Ctrl-r` forces refresh.
4. **Invalidation / patching** after our own operations so a refresh isn't needed:
   - mkdir → insert entry; delete/rmdir → remove; rename → move entry (across dirs: remove + insert); chmod → update permissions; upload complete → insert/update entry with known size and mtime (mark mtime precision as approximate).
   - Recursive delete of a dir → drop cached subtree.
5. Memory cap (e.g. 200 directories, LRU eviction).
6. Event `ListingUpdated { dir }` emitted on change so panes showing that dir re-render.

## Acceptance criteria

- [ ] Cache hit avoids a backend call (mock counts calls).
- [ ] Each mutating operation patches the cache correctly.
- [ ] LRU eviction respects the cap.
- [ ] Disabled cache always lists.

## Tests

- Unit tests for each patch operation and eviction.
