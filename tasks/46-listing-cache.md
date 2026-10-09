# T46 — Directory listing cache

**Phase:** E Transfers · **Milestone:** M1 · **Depends on:** T03, T04 · **Crate(s):** `courier-ftp-core` (`cache` module) · **Decisions:** D10 · **FEATURES.md:** §3 (directory listing cache, option to refresh or not)
**Related (integrates with, not blocking):** T05, T43, T49, T53, T54, T62

## Goal

Remote directories the user has already visited show instantly instead of being
listed again, and panes stay accurate after the app's own operations (mkdir, delete,
rename, chmod, upload) without a manual refresh. The cache lives in memory only,
is shared by every tab connected to the same server, and is bounded in size.

## Context

- Before: T03 provides `Backend::list(&mut self, dir, cancel) -> Result<Listing>` with
  `Listing { dir: RemotePath, entries: Vec<Entry>, fetched_at: Instant, raw: Option<String> }`
  and `SessionHandle`; T02 provides `ServerAddress`, `Protocol`, `RemotePath`, `Entry`,
  `Timestamp`, `Permissions`; T04 provides `EventSender` and `CoreEvent`; T05 provides
  `Settings.cache.listing_cache` and `Settings.cache.listing_cache_ttl_secs`.
- After: the file list (T53) and directory tree (T54) read through the cache; file
  operations (T62) and the transfer engine (T41) call the patch API after success;
  recursive delete (T43) drops subtrees; search (T49) reads and fills the cache.
- Local listings are **not** cached: the local filesystem is fast and is changed by other
  programs all the time. The local pane always lists through `LocalBackend` (T06).

## Technical specification

### Types and APIs

Module `courier_ftp_core::cache`.

```rust
/// Identifies one server for caching. Two tabs with equal keys share cached listings.
/// Built from the session's `ServerAddress`; the host is lower-cased and the port
/// resolved to the protocol default when absent, so `HOST:21` and `host` are equal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerKey {
    pub protocol: Protocol,   // FtpsExplicit and Ftp are different keys (different sessions)
    pub host: String,
    pub port: u16,
    pub user: String,
}

impl ServerKey {
    pub fn from_address(addr: &ServerAddress) -> Self;
}

/// How a caller wants a listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListMode {
    /// Fresh or stale cached listing is fine (panes). Stale listings are returned and
    /// the caller is told to revalidate in the background.
    PreferCache,
    /// Only a fresh cached listing is used; stale or missing → fetch (search, T49).
    FreshOnly,
    /// Always fetch and replace the cached listing (F5 / `Ctrl-r`, T62 refresh).
    Refresh,
}

/// Result of a lookup without fetching.
#[derive(Debug, Clone)]
pub enum Lookup {
    Fresh(Arc<Listing>),
    /// Expired by TTL or marked unsure by a patch: show it, then revalidate.
    Stale(Arc<Listing>),
    Miss,
}

/// Where a listing returned by `get_or_fetch` came from.
#[derive(Debug, Clone)]
pub struct CachedListing {
    pub listing: Arc<Listing>,
    pub source: ListingSource,      // Cache | CacheStale | Backend
}

/// One change made by courier-ftp itself, applied without re-listing.
#[derive(Debug, Clone)]
pub enum CachePatch {
    /// mkdir, new empty file (T62), or upload finished (T41).
    Created { path: RemotePath, entry: Entry },
    /// remove_file.
    RemovedFile { path: RemotePath },
    /// rmdir or recursive delete finished: entry removed from the parent and the
    /// cached subtree under `path` dropped.
    RemovedDir { path: RemotePath },
    /// rename / move (same or different parent).
    Renamed { from: RemotePath, to: RemotePath },
    /// chmod succeeded with exactly this mode.
    ModeChanged { path: RemotePath, mode: u32 },
    /// Upload finished; `modified` is `Some` only when preserve_timestamps set it.
    Uploaded { path: RemotePath, size: u64, modified: Option<Timestamp> },
}

/// Cheap to clone (`Arc` inside). Thread-safe; never holds its lock across `.await`.
#[derive(Debug, Clone)]
pub struct ListingCache { /* Arc<Inner> */ }

impl ListingCache {
    /// `policy` comes from `Settings.cache`; `events` from T04.
    pub fn new(policy: CachePolicy, events: EventSender) -> Self;
    /// Apply new settings (enable/disable, TTL). Disabling clears everything.
    pub fn set_policy(&self, policy: CachePolicy);
    pub fn lookup(&self, server: &ServerKey, dir: &RemotePath) -> Lookup;
    /// Store a listing just fetched. Strips `Listing.raw` and every `Entry.raw`.
    pub fn store(&self, server: &ServerKey, listing: Listing) -> Arc<Listing>;
    /// Fetch through the cache. Concurrent calls for the same (server, dir) are
    /// coalesced: only one runs `fetch`, the others wait and reuse its result.
    pub async fn get_or_fetch<F, Fut>(
        &self, server: &ServerKey, dir: &RemotePath, mode: ListMode, fetch: F,
    ) -> Result<CachedListing>
    where F: FnOnce() -> Fut, Fut: Future<Output = Result<Listing>>;
    pub fn patch(&self, server: &ServerKey, patch: CachePatch);
    /// Drop one directory (used when a fetch says NotFound, or after an operation
    /// whose result is unknown, e.g. a failed rename).
    pub fn invalidate(&self, server: &ServerKey, dir: &RemotePath);
    /// Drop `dir` and every cached directory below it.
    pub fn invalidate_subtree(&self, server: &ServerKey, dir: &RemotePath);
    pub fn clear_server(&self, server: &ServerKey);
    /// Called on vault lock (T60) and on quit.
    pub fn clear_all(&self);
    pub fn stats(&self) -> CacheStats;   // dirs, entries, hits, misses, evictions
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachePolicy {
    pub enabled: bool,               // cache.listing_cache
    pub ttl: Option<Duration>,       // cache.listing_cache_ttl_secs; 0 → None (no expiry)
}

/// Hard limits (constants, not settings).
pub const MAX_CACHED_DIRS: usize = 200;
pub const MAX_CACHED_ENTRIES: usize = 500_000;
```

### Behaviour

**Storage.** `Inner` holds a `std::sync::Mutex<State>`:
`State { dirs: HashMap<(ServerKey, RemotePath), Slot>, total_entries: usize, clock: u64 }`,
`Slot { listing: Arc<Listing>, cached_at: tokio::time::Instant, unsure: bool, last_used: u64 }`.
`clock` increments on every lookup hit or store; `last_used` is set from it (LRU order).
A separate `fetch_locks: Mutex<HashMap<(ServerKey, RemotePath), Arc<tokio::sync::Mutex<()>>>>`
provides single-flight fetching; an entry is removed when its last waiter finishes.

**Freshness.** A slot is *fresh* when `!unsure` and (`ttl` is `None` or
`now - cached_at < ttl`). Otherwise it is *stale*. TTL uses `tokio::time::Instant` so
tests can use `tokio::time::pause`.

**`lookup`**: cache disabled → `Miss`. Present → `Fresh`/`Stale` and bumps `last_used`
(counts a hit). Absent → `Miss` (counts a miss).

**`get_or_fetch` algorithm**

| Mode | Fresh slot | Stale slot | Missing |
|---|---|---|---|
| `PreferCache` | return `Cache` | return `CacheStale` (caller revalidates with `Refresh` in the background) | fetch |
| `FreshOnly` | return `Cache` | fetch | fetch |
| `Refresh` | fetch | fetch | fetch |

"fetch" = record `requested_at = now`, acquire the per-key async lock, then re-check:
if a slot now exists with `cached_at >= requested_at` (another caller fetched it while
we waited), return it as `Cache`. Otherwise run `fetch()`; on `Ok` call `store` and
return `Backend`; on `Err(Error::NotFound(_))` call `invalidate_subtree(dir)` and return
the error; on any other error leave the cache unchanged and return the error.
Cancellation: dropping the future releases the lock; the next waiter fetches itself.
Cache disabled → `fetch()` is always called and nothing is stored.

**`store`**: replaces the slot, sets `unsure = false`, strips raw text, updates
`total_entries`, emits `ListingUpdated`, then evicts.

**Eviction.** After every insert, while `dirs.len() > MAX_CACHED_DIRS` or
`total_entries > MAX_CACHED_ENTRIES`, remove the slot with the smallest `last_used`
(linear scan, at most 200 slots). The slot just inserted is never evicted in the same
pass, so a single directory larger than `MAX_CACHED_ENTRIES` is still served (it
evicts everything else). Eviction is silent (no event).

**Patches** (all O(entries in the affected directory); no-op if the parent is not cached):

| Patch | Effect on cached directories |
|---|---|
| `Created { path, entry }` | In `parent(path)`: replace the entry with the same name or append; `unsure = true` when `entry` came from mkdir (only kind and name known). |
| `RemovedFile { path }` | Remove the entry from `parent(path)`. |
| `RemovedDir { path }` | Remove the entry from `parent(path)`; `invalidate_subtree(path)`. |
| `Renamed { from, to }` | Remove from `parent(from)`; if `parent(to)` is cached, insert the moved entry renamed to `to.file_name()` (replacing a same-name entry). If the moved entry was a directory, `invalidate_subtree(from)` (cached children are not re-keyed). If `from`'s entry was not cached, `invalidate(parent(to))`. |
| `ModeChanged { path, mode }` | Set `permissions = Some(Permissions::from_mode(mode))` (raw cleared) on the entry. |
| `Uploaded { path, size, modified }` | Upsert a `File` entry with `size = Some(size)`; `modified` as given (`None` keeps the old value only if the entry existed and was not replaced by a different kind); `unsure = true` (owner, group, permissions and server-side mtime are unknown). |

`unsure = true` makes the directory stale: it is still shown immediately, and the
next `PreferCache` read tells the pane to revalidate in the background (FileZilla's
"unsure" listing behaviour). Every patch that changes a cached directory emits one
`ListingUpdated` for it. Listings are held as `Arc<Listing>` and patched with
`Arc::make_mut`, so readers holding an older `Arc` are never disturbed.

**Disabled cache.** `lookup` → `Miss`, `store` and `patch` do nothing except emit
`ListingUpdated` for the affected parent directory, so panes re-list after our own
operations even without caching.

**Events.** The cache emits `CoreEvent::ListingUpdated` (T04) on store, patch and
invalidate. Panes showing `(server, dir)` re-read the cache (never refetch because of
the event alone, which prevents refresh loops). See Open questions about the event's
key.

**Complexity limits.** `lookup`: O(1) average plus O(path length) hashing.
`store`: O(entries) for raw stripping plus O(200) eviction scan. Patches: O(entries in
the parent directory). Memory: bounded by `MAX_CACHED_ENTRIES` entries plus 200
`Listing` headers.

### Data formats and configuration

Settings (defined in T05, consumed here):

| Key | Type | Default | Meaning |
|---|---|---|---|
| `cache.listing_cache` | bool | `true` | Use the cache. `false` = always list (FileZilla "don't cache"). |
| `cache.listing_cache_ttl_secs` | u64 | `0` | Seconds a listing stays fresh; `0` = until refreshed or patched. Values above 86 400 are clamped to 86 400 with a warning (T05 validation). |

Nothing is persisted. There is no on-disk format.

### Errors

The cache itself never fails. `get_or_fetch` returns the `courier_ftp_core::Error` of
the `fetch` closure unchanged. `Error::NotFound` additionally removes the directory and
its subtree from the cache; the pane (T53) shows its normal "directory not found" error.

### Security and logging

- Listings contain file names, which are user data: memory only, never written to disk,
  never synced. `clear_all` runs on vault lock (T60) so a locked app holds no remote
  file names, and on quit.
- `Listing.raw` / `Entry.raw` are stripped before caching (less memory; the raw view of
  T71 always uses a fresh listing).
- Logging: `debug!` may include the directory path and server key (debug-only per T91);
  `trace!` for hit/miss per lookup. At `info` and above only counts (`evicted 3 dirs`),
  never hosts, users or paths.
- Server-provided names are untrusted but only stored and compared here; display
  sanitising is the UI's job (T50).

## Implementation steps

1. `cache` module skeleton: `ServerKey`, `CachePolicy`, `ListMode`, `Lookup`, `ListingSource`, constants; `ServerKey::from_address` with tests.
2. `ListingCache::new/lookup/store/clear_*`, freshness and TTL with `tokio::time::Instant`.
3. LRU eviction with both limits; `stats()`.
4. `get_or_fetch` with per-key single-flight lock and the mode table.
5. `CachePatch` and `patch()`; `invalidate`, `invalidate_subtree`.
6. `ListingUpdated` emission; disabled-cache behaviour; `set_policy`.
7. Bench `cache_patch_100k` and docs (module rustdoc with the mode table).

## Acceptance criteria

- [ ] AC1 A `PreferCache` read of a cached fresh directory makes zero backend calls (mock call counter).
- [ ] AC2 `Refresh` always calls the backend exactly once and replaces the cached listing.
- [ ] AC3 Ten concurrent `get_or_fetch` calls for the same uncached directory run `fetch` exactly once.
- [ ] AC4 Every `CachePatch` variant produces the listing described in the patch table (one test per variant and per edge case listed there).
- [ ] AC5 Never more than 200 directories or 500 000 entries cached after any sequence of stores; the least recently used directory is evicted first.
- [ ] AC6 With `cache.listing_cache = false`, every read calls the backend, nothing is stored, and patches still emit `ListingUpdated`.
- [ ] AC7 With TTL 30 s, a listing is fresh at 29 s and stale at 30 s (paused tokio time).
- [ ] AC8 A fetch returning `NotFound` removes that directory and its cached subtree.
- [ ] AC9 `clear_all` leaves `stats().dirs == 0`; no cache content is written to disk (no file I/O in the module; checked by review and the T91 canary scan).
- [ ] AC10 Patching a 100 000-entry cached directory takes < 5 ms (criterion bench `cache_patch_100k`, release).
- [ ] AC11 CI gates `fmt`, `clippy`, `docs`, `test-local-only`, `test-os` pass.

## Tests

### Unit tests
- `server_key_normalises_host_case_and_default_port` — `FTP://HOST` and `ftp://host:21` give equal keys; `sftp` vs `ftp` differ.
- `prefer_cache_hit_makes_no_backend_call` — AC1.
- `refresh_always_fetches_and_replaces` — AC2.
- `fresh_only_refetches_stale_listing` — mode table row for `FreshOnly`.
- `prefer_cache_returns_stale_with_source_cachestale` — unsure listing returned, source flagged.
- `ttl_boundary_29s_fresh_30s_stale` (`#[tokio::test(start_paused = true)]`) — AC7.
- `ttl_zero_never_expires` — fresh after 10 days of paused time.
- `patch_created_appends_and_replaces_same_name` — AC4.
- `patch_mkdir_marks_unsure` — AC4.
- `patch_removed_file_removes_entry` — AC4.
- `patch_removed_dir_drops_subtree` — `/a/b` and `/a/b/c` cached; removing `/a/b` drops both and the entry in `/a`; `/a/bc` kept (prefix is per component). AC4, AC8.
- `patch_rename_same_dir`, `patch_rename_across_dirs`, `patch_rename_dir_invalidates_old_subtree`, `patch_rename_unknown_source_invalidates_target_parent` — AC4.
- `patch_mode_changed_sets_permissions` — AC4.
- `patch_uploaded_upserts_with_size_and_marks_unsure` — AC4.
- `patch_on_uncached_parent_is_noop_but_emits_event_when_disabled` — AC4, AC6.
- `lru_evicts_least_recently_used_dir` — store 201 dirs, touch dir 0, dir 1 evicted. AC5.
- `entry_cap_evicts_until_under_limit` — three 200 000-entry listings → oldest evicted. AC5.
- `single_huge_listing_still_served` — one 600 000-entry listing kept alone. AC5.
- `disabled_cache_always_fetches_and_stores_nothing` — AC6.
- `not_found_invalidates_subtree` — AC8.
- `store_strips_raw_text` — `Listing.raw` and `Entry.raw` are `None` after store.
- `clear_all_empties_cache` — AC9.
- `listing_updated_emitted_once_per_changed_dir` — event receiver from T04 counts events.

### Property / fuzz tests
- `prop_cache_never_exceeds_limits` — random sequences of store/lookup/patch/invalidate (proptest, 256 cases) keep `dirs <= 200`, `entries <= 500_000` (allowing the single-huge-listing exception) and `total_entries` equal to the real sum. AC5.
- `prop_patches_match_reference_model` — random patch sequences applied to the cache and to a plain `BTreeMap` model give the same entry names per directory. AC4.

### Snapshot tests
Not applicable (no UI).

### Integration tests
- `single_flight_coalesces_concurrent_fetches` — `MockBackend` (T03) with 50 ms latency, 10 concurrent tasks, `fetch` counter = 1. AC3.
- `cancelled_fetch_lets_next_waiter_fetch` — first caller dropped mid-fetch; second completes with its own fetch.
- Bench `cache_patch_100k` (criterion, `crates/courier-ftp-core/benches/cache.rs`, added to `scripts/bench-gates.toml`). AC10.

### End-to-end tests
None specific; T53/T62 e2e flows exercise the cache against real servers (T76).

## Out of scope

- Persisting the cache across restarts (never: it would leak file names to disk).
- Caching local listings.
- Re-keying cached subtrees on directory rename (they are dropped instead).
- Change notification from the server (FTP/SFTP have none).

## Open questions

- **Inconsistency with T04 (not owned):** T04 defines `CoreEvent::ListingUpdated { session, dir }`, but the cache is shared per server and does not know which sessions show a directory. This task needs `ListingUpdated { server: ServerKey, dir: RemotePath }` (or both fields). T04's owner should change the variant; until then the cache emits one event with `session` set to the session id of the operation's origin and the UI must refresh every tab whose `ServerKey` matches.
- Should the cache also be cleared when the last session to a server disconnects? FileZilla keeps it so reconnecting is instant; this task keeps it (cleared only on lock and quit). Product decision for the owner.
