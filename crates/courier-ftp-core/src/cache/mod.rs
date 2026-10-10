//! The directory listing cache (T46).
//!
//! Remote directories already visited show instantly instead of being listed again,
//! and panes stay accurate after courier-ftp's own operations (mkdir, delete, rename,
//! chmod, upload) through [`CachePatch`]es, without a manual refresh. The cache lives
//! in memory only (it holds remote file names, so it is never written to disk), is
//! keyed by [`ServerIdentity`] (protocol, lower-case host, effective port, user; plain
//! and TLS sessions to one server share listings), is shared by every tab through
//! cheap [`ListingCache`] clones, and is bounded: at most `max_dirs` directories
//! (LRU), [`MAX_CACHED_ENTRIES`] entries and [`MAX_CACHED_RAW_BYTES`] of raw listing
//! text. Local listings are never cached.
//!
//! # Reading: [`ListingCache::get_or_fetch`]
//!
//! | Mode | Fresh slot | Stale slot | Missing |
//! |---|---|---|---|
//! | [`ListMode::PreferCache`] | return `Cache` | return `CacheStale` (caller revalidates with `Refresh` in the background) | fetch |
//! | [`ListMode::FreshOnly`] | return `Cache` | fetch | fetch |
//! | [`ListMode::Refresh`] | fetch | fetch | fetch |
//!
//! A slot is *fresh* when no patch marked it unsure and the TTL (if any) has not
//! expired; otherwise it is *stale*. Concurrent fetches of one (server, directory)
//! are coalesced: one caller runs its `fetch` closure, the others wait and reuse the
//! stored result. A fetch that fails with [`Error::NotFound`] drops the directory and
//! its cached subtree.
//!
//! # Events
//!
//! Every store, patch and invalidation sends
//! [`CoreEvent::ListingUpdated`]` { server: Some(identity), dir }` once per affected
//! directory. Panes re-read the cache on it and never refetch because of the event
//! alone. With the cache disabled nothing is stored, but patches still send the event
//! for the affected parent directories, so panes re-list after our own operations.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::time::Instant;

use crate::backend::Listing;
use crate::events::{CoreEvent, EventSender};
use crate::model::{Entry, EntryKind, Permissions, RemotePath, ServerIdentity, Timestamp};
use crate::settings::CacheSettings;
use crate::{Error, Result};

#[cfg(test)]
mod tests;

/// Hard limit on cached entries over all directories (a constant, not a setting).
pub const MAX_CACHED_ENTRIES: usize = 500_000;
/// Hard limit on cached raw listing text over all directories (64 MiB).
pub const MAX_CACHED_RAW_BYTES: usize = 64 * 1024 * 1024;

/// How the cache behaves; built from `Settings.cache` with [`CachePolicy::from_settings`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachePolicy {
    /// `cache.listing_cache`.
    pub enabled: bool,
    /// `cache.listing_cache_ttl_secs`; 0 → `None` (no expiry).
    pub ttl: Option<Duration>,
    /// `cache.listing_cache_max_dirs` (default 200).
    pub max_dirs: usize,
}

impl CachePolicy {
    /// The policy for these settings. `max_dirs` is at least 1.
    pub fn from_settings(settings: &CacheSettings) -> Self {
        let ttl = (settings.listing_cache_ttl_secs > 0)
            .then(|| Duration::from_secs(u64::from(settings.listing_cache_ttl_secs)));
        Self {
            enabled: settings.listing_cache,
            ttl,
            max_dirs: usize::try_from(settings.listing_cache_max_dirs)
                .unwrap_or(usize::MAX)
                .max(1),
        }
    }
}

impl Default for CachePolicy {
    fn default() -> Self {
        Self::from_settings(&CacheSettings::default())
    }
}

/// How a caller wants a listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListMode {
    /// Fresh or stale cached listing is fine (panes). Stale listings are returned and
    /// the caller is told to revalidate in the background.
    PreferCache,
    /// Only a fresh cached listing is used; stale or missing → fetch (search, T49).
    FreshOnly,
    /// Always fetch and replace the cached listing (`Refresh`, `ctrl-r`, T62; tree
    /// `TreeRefresh`, T54).
    Refresh,
}

/// Result of a lookup without fetching.
#[derive(Debug, Clone)]
pub enum Lookup {
    /// Cached and fresh.
    Fresh(Arc<Listing>),
    /// Expired by TTL or marked unsure by a patch: show it, then revalidate.
    Stale(Arc<Listing>),
    /// Not cached (or the cache is disabled).
    Miss,
}

/// Where a listing returned by [`ListingCache::get_or_fetch`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListingSource {
    /// A fresh cached listing (or one another caller fetched while this one waited).
    Cache,
    /// A stale cached listing (`PreferCache` only): revalidate in the background.
    CacheStale,
    /// Fetched by this call.
    Backend,
}

/// A listing returned by [`ListingCache::get_or_fetch`].
#[derive(Debug, Clone)]
pub struct CachedListing {
    /// The listing.
    pub listing: Arc<Listing>,
    /// Where it came from.
    pub source: ListingSource,
}

/// One change made by courier-ftp itself, applied without re-listing.
#[derive(Debug, Clone)]
pub enum CachePatch {
    /// mkdir, new empty file (T62), or upload finished (T41).
    Created {
        /// The new entry's path.
        path: RemotePath,
        /// The new entry; one with only a name and a kind (mkdir) marks the parent unsure.
        entry: Entry,
    },
    /// remove_file.
    RemovedFile {
        /// The removed file.
        path: RemotePath,
    },
    /// rmdir or recursive delete finished: entry removed from the parent and the
    /// cached subtree under `path` dropped.
    RemovedDir {
        /// The removed directory.
        path: RemotePath,
    },
    /// rename / move (same or different parent).
    Renamed {
        /// Old path.
        from: RemotePath,
        /// New path.
        to: RemotePath,
    },
    /// chmod succeeded with exactly this mode.
    ModeChanged {
        /// The changed entry.
        path: RemotePath,
        /// The new mode.
        mode: u32,
    },
    /// Upload finished; `modified` is `Some` only when preserve_timestamps set it.
    Uploaded {
        /// The uploaded file.
        path: RemotePath,
        /// Its size.
        size: u64,
        /// Its modification time, when set by us.
        modified: Option<Timestamp>,
    },
}

impl CachePatch {
    /// The parent directories this patch touches (for the disabled cache's events).
    fn parents(&self) -> Vec<RemotePath> {
        match self {
            Self::Created { path, .. }
            | Self::RemovedFile { path }
            | Self::RemovedDir { path }
            | Self::ModeChanged { path, .. }
            | Self::Uploaded { path, .. } => path.parent().into_iter().collect(),
            Self::Renamed { from, to } => from.parent().into_iter().chain(to.parent()).collect(),
        }
    }
}

/// Counters for diagnostics (T71) and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    /// Cached directories.
    pub dirs: usize,
    /// Entries over all cached directories.
    pub entries: usize,
    /// Raw listing text over all cached directories, in bytes.
    pub raw_bytes: usize,
    /// Lookups that found a cached listing (fresh or stale).
    pub hits: u64,
    /// Lookups that found nothing.
    pub misses: u64,
    /// Directories evicted by the size limits.
    pub evictions: u64,
}

/// The shared, in-memory directory listing cache.
///
/// Cheap to clone (`Arc` inside). Thread-safe; never holds its lock across `.await`.
#[derive(Clone)]
pub struct ListingCache {
    inner: Arc<Inner>,
}

impl fmt::Debug for ListingCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No paths or hosts: the stats only.
        f.debug_struct("ListingCache")
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

struct Inner {
    state: Mutex<State>,
    fetch_locks: Mutex<HashMap<Key, Flight>>,
    events: EventSender,
}

type Key = (ServerIdentity, RemotePath);

/// One single-flight lock and the number of callers holding or waiting for it.
struct Flight {
    lock: Arc<tokio::sync::Mutex<()>>,
    users: usize,
}

struct Slot {
    listing: Arc<Listing>,
    cached_at: Instant,
    unsure: bool,
    last_used: u64,
    /// `State::store_seq` at the time of the store (coalescing re-check).
    stored_seq: u64,
}

struct State {
    policy: CachePolicy,
    dirs: HashMap<ServerIdentity, HashMap<RemotePath, Slot>>,
    dir_count: usize,
    total_entries: usize,
    total_raw_bytes: usize,
    clock: u64,
    store_seq: u64,
    hits: u64,
    misses: u64,
    evictions: u64,
}

fn raw_len(listing: &Listing) -> usize {
    listing.raw.as_ref().map_or(0, String::len)
}

/// Fresh: not marked unsure by a patch and the TTL (if any) not expired.
fn is_fresh(policy: &CachePolicy, slot: &Slot, now: Instant) -> bool {
    !slot.unsure
        && policy
            .ttl
            .is_none_or(|ttl| now.saturating_duration_since(slot.cached_at) < ttl)
}

fn find(entries: &[Entry], name: &str) -> Option<usize> {
    entries.iter().position(|e| e.name == name)
}

/// Replaces the entry with the same name or appends it.
fn upsert(entries: &mut Vec<Entry>, entry: Entry) {
    match find(entries, &entry.name) {
        Some(i) => entries[i] = entry,
        None => entries.push(entry),
    }
}

/// True when only the name and kind are known (mkdir).
fn is_bare(entry: &Entry) -> bool {
    entry.size.is_none()
        && entry.modified.is_none()
        && entry.permissions.is_none()
        && entry.owner.is_none()
        && entry.group.is_none()
}

impl State {
    fn new(policy: CachePolicy) -> Self {
        Self {
            policy,
            dirs: HashMap::new(),
            dir_count: 0,
            total_entries: 0,
            total_raw_bytes: 0,
            clock: 0,
            store_seq: 0,
            hits: 0,
            misses: 0,
            evictions: 0,
        }
    }

    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    fn lookup(&mut self, server: &ServerIdentity, dir: &RemotePath) -> Lookup {
        if !self.policy.enabled {
            return Lookup::Miss;
        }
        let now = Instant::now();
        let policy = self.policy;
        let tick = self.clock + 1;
        let Some(slot) = self.dirs.get_mut(server).and_then(|m| m.get_mut(dir)) else {
            self.misses += 1;
            tracing::trace!("listing cache miss");
            return Lookup::Miss;
        };
        slot.last_used = tick;
        let listing = Arc::clone(&slot.listing);
        let fresh = is_fresh(&policy, slot, now);
        self.clock = tick;
        self.hits += 1;
        tracing::trace!(fresh, "listing cache hit");
        if fresh {
            Lookup::Fresh(listing)
        } else {
            Lookup::Stale(listing)
        }
    }

    fn remove(&mut self, server: &ServerIdentity, dir: &RemotePath) -> Option<Slot> {
        let map = self.dirs.get_mut(server)?;
        let slot = map.remove(dir)?;
        if map.is_empty() {
            self.dirs.remove(server);
        }
        self.dir_count -= 1;
        self.total_entries -= slot.listing.entries.len();
        self.total_raw_bytes -= raw_len(&slot.listing);
        Some(slot)
    }

    fn insert(
        &mut self,
        server: &ServerIdentity,
        dir: RemotePath,
        listing: Listing,
    ) -> Arc<Listing> {
        self.remove(server, &dir);
        let listing = Arc::new(listing);
        self.dir_count += 1;
        self.total_entries += listing.entries.len();
        self.total_raw_bytes += raw_len(&listing);
        self.store_seq += 1;
        let slot = Slot {
            listing: Arc::clone(&listing),
            cached_at: Instant::now(),
            unsure: false,
            last_used: self.tick(),
            stored_seq: self.store_seq,
        };
        self.dirs
            .entry(server.clone())
            .or_default()
            .insert(dir, slot);
        listing
    }

    /// The least recently used slot, skipping `protect` (and slots without raw text
    /// when `with_raw`).
    fn lru(&self, protect: Option<(&ServerIdentity, &RemotePath)>, with_raw: bool) -> Option<Key> {
        let mut best: Option<(u64, &ServerIdentity, &RemotePath)> = None;
        for (server, map) in &self.dirs {
            for (dir, slot) in map {
                if protect.is_some_and(|(s, d)| s == server && d == dir)
                    || (with_raw && slot.listing.raw.is_none())
                {
                    continue;
                }
                if best.is_none_or(|(used, _, _)| slot.last_used < used) {
                    best = Some((slot.last_used, server, dir));
                }
            }
        }
        best.map(|(_, s, d)| (s.clone(), d.clone()))
    }

    /// Applies the size limits; `protect` (the slot just inserted) is never evicted.
    fn evict(&mut self, protect: Option<(&ServerIdentity, &RemotePath)>) {
        let mut evicted = 0usize;
        while self.dir_count > self.policy.max_dirs || self.total_entries > MAX_CACHED_ENTRIES {
            let Some((server, dir)) = self.lru(protect, false) else {
                break;
            };
            self.remove(&server, &dir);
            evicted += 1;
        }
        let mut dropped_raw = 0usize;
        while self.total_raw_bytes > MAX_CACHED_RAW_BYTES {
            let Some((server, dir)) = self.lru(protect, true) else {
                break;
            };
            if let Some(slot) = self.dirs.get_mut(&server).and_then(|m| m.get_mut(&dir)) {
                let len = raw_len(&slot.listing);
                Arc::make_mut(&mut slot.listing).raw = None;
                self.total_raw_bytes -= len;
                dropped_raw += 1;
            }
        }
        if evicted > 0 || dropped_raw > 0 {
            self.evictions += evicted as u64;
            tracing::debug!(
                "listing cache: evicted {evicted} dirs, dropped raw text of {dropped_raw}"
            );
        }
    }

    /// Runs `f` on the cached slot of `dir` and keeps the entry count right. `None`
    /// when `dir` is not cached.
    fn with_slot<R>(
        &mut self,
        server: &ServerIdentity,
        dir: &RemotePath,
        f: impl FnOnce(&mut Slot) -> R,
    ) -> Option<R> {
        let slot = self.dirs.get_mut(server)?.get_mut(dir)?;
        let before = slot.listing.entries.len();
        let r = f(slot);
        let after = slot.listing.entries.len();
        self.total_entries = self.total_entries - before + after;
        Some(r)
    }

    /// Drops `dir` and every cached directory below it; pushes the dropped paths.
    fn drop_subtree(
        &mut self,
        server: &ServerIdentity,
        dir: &RemotePath,
        dropped: &mut Vec<RemotePath>,
    ) {
        let Some(map) = self.dirs.get(server) else {
            return;
        };
        let mut below: Vec<RemotePath> =
            map.keys().filter(|d| d.starts_with(dir)).cloned().collect();
        below.sort();
        for d in below {
            self.remove(server, &d);
            dropped.push(d);
        }
    }

    fn drop_dir(
        &mut self,
        server: &ServerIdentity,
        dir: &RemotePath,
        dropped: &mut Vec<RemotePath>,
    ) {
        if self.remove(server, dir).is_some() {
            dropped.push(dir.clone());
        }
    }

    /// Removes the entry named like `path` from its cached parent; returns it.
    fn take_entry(&mut self, server: &ServerIdentity, path: &RemotePath) -> Option<Entry> {
        let (parent, name) = (path.parent()?, path.file_name()?);
        self.with_slot(server, &parent, |slot| {
            let i = find(&slot.listing.entries, name)?;
            Some(Arc::make_mut(&mut slot.listing).entries.remove(i))
        })
        .flatten()
    }

    /// Inserts `entry` (renamed to `path`'s name) into `path`'s cached parent; true
    /// when the parent is cached.
    fn put_entry(
        &mut self,
        server: &ServerIdentity,
        path: &RemotePath,
        mut entry: Entry,
        unsure: bool,
    ) -> bool {
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            return false;
        };
        name.clone_into(&mut entry.name);
        self.with_slot(server, &parent, |slot| {
            upsert(&mut Arc::make_mut(&mut slot.listing).entries, entry);
            slot.unsure |= unsure;
        })
        .is_some()
    }

    /// Applies a patch to the cached directories; pushes every changed or dropped one.
    fn apply(&mut self, server: &ServerIdentity, patch: CachePatch, changed: &mut Vec<RemotePath>) {
        match patch {
            CachePatch::Created { path, entry } => {
                let is_file = matches!(entry.kind, EntryKind::File);
                let unsure = is_bare(&entry);
                if self.put_entry(server, &path, entry, unsure) {
                    changed.extend(path.parent());
                }
                if !is_file {
                    // A listing cached for an older directory at this path is wrong now.
                    self.drop_subtree(server, &path, changed);
                }
            }
            CachePatch::RemovedFile { path } => {
                if self.take_entry(server, &path).is_some() {
                    changed.extend(path.parent());
                }
            }
            CachePatch::RemovedDir { path } => {
                if self.take_entry(server, &path).is_some() {
                    changed.extend(path.parent());
                }
                self.drop_subtree(server, &path, changed);
            }
            CachePatch::Renamed { from, to } => {
                match self.take_entry(server, &from) {
                    Some(entry) => {
                        changed.extend(from.parent());
                        let is_file = matches!(entry.kind, EntryKind::File);
                        if self.put_entry(server, &to, entry, false) {
                            changed.extend(to.parent());
                        }
                        if !is_file {
                            // Cached children are not re-keyed.
                            self.drop_subtree(server, &from, changed);
                        }
                    }
                    None => {
                        if let Some(parent) = to.parent() {
                            self.drop_dir(server, &parent, changed);
                        }
                    }
                }
                // Whatever was cached at the target path before is gone.
                self.drop_subtree(server, &to, changed);
            }
            CachePatch::ModeChanged { path, mode } => {
                let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
                    return;
                };
                let found = self.with_slot(server, &parent, |slot| {
                    let i = find(&slot.listing.entries, name)?;
                    Arc::make_mut(&mut slot.listing).entries[i].permissions =
                        Some(Permissions::from_mode(mode));
                    Some(())
                });
                if found.flatten().is_some() {
                    changed.push(parent);
                }
            }
            CachePatch::Uploaded {
                path,
                size,
                modified,
            } => {
                let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
                    return;
                };
                let done = self.with_slot(server, &parent, |slot| {
                    let entries = &mut Arc::make_mut(&mut slot.listing).entries;
                    match find(entries, name) {
                        Some(i) if matches!(entries[i].kind, EntryKind::File) => {
                            let e = &mut entries[i];
                            e.size = Some(size);
                            if modified.is_some() {
                                e.modified = modified;
                            }
                        }
                        found => {
                            let mut e = Entry::new(name, EntryKind::File);
                            e.size = Some(size);
                            e.modified = modified;
                            match found {
                                Some(i) => entries[i] = e,
                                None => entries.push(e),
                            }
                        }
                    }
                    slot.unsure = true;
                });
                if done.is_some() {
                    changed.push(parent);
                }
            }
        }
    }
}

fn dedup(paths: &mut Vec<RemotePath>) {
    let mut seen = std::collections::HashSet::with_capacity(paths.len());
    paths.retain(|p| seen.insert(p.clone()));
}

/// Releases a single-flight registration when dropped (also on cancellation).
struct FlightGuard<'a> {
    inner: &'a Inner,
    key: Key,
}

impl Drop for FlightGuard<'_> {
    fn drop(&mut self) {
        let mut locks = lock(&self.inner.fetch_locks);
        if let Some(flight) = locks.get_mut(&self.key) {
            flight.users -= 1;
            if flight.users == 0 {
                locks.remove(&self.key);
            }
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl ListingCache {
    /// `policy` comes from `Settings.cache`; `events` from T04.
    pub fn new(policy: CachePolicy, events: EventSender) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::new(policy)),
                fetch_locks: Mutex::new(HashMap::new()),
                events,
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        lock(&self.inner.state)
    }

    fn emit(&self, server: &ServerIdentity, mut dirs: Vec<RemotePath>) {
        dedup(&mut dirs);
        for dir in dirs {
            self.inner.events.send(CoreEvent::ListingUpdated {
                server: Some(server.clone()),
                dir,
            });
        }
    }

    /// The current policy.
    pub fn policy(&self) -> CachePolicy {
        self.state().policy
    }

    /// Apply new settings (enable/disable, TTL, capacity). Disabling clears everything;
    /// a smaller capacity evicts at once.
    pub fn set_policy(&self, policy: CachePolicy) {
        let mut st = self.state();
        st.policy = CachePolicy {
            max_dirs: policy.max_dirs.max(1),
            ..policy
        };
        if policy.enabled {
            st.evict(None);
        } else {
            Self::clear_state(&mut st);
        }
    }

    /// Looks `dir` up without fetching. Disabled → `Miss`.
    pub fn lookup(&self, server: &ServerIdentity, dir: &RemotePath) -> Lookup {
        self.state().lookup(server, dir)
    }

    /// Stores a listing just fetched under `listing.dir` (including `Listing.raw`, used
    /// by T71's raw view), sends `ListingUpdated` and applies the size limits. With the
    /// cache disabled nothing is stored and no event is sent.
    pub fn store(&self, server: &ServerIdentity, listing: Listing) -> Arc<Listing> {
        let dir = listing.dir.clone();
        self.store_at(server, dir, listing)
    }

    fn store_at(&self, server: &ServerIdentity, dir: RemotePath, listing: Listing) -> Arc<Listing> {
        let stored = {
            let mut st = self.state();
            if !st.policy.enabled {
                return Arc::new(listing);
            }
            let stored = st.insert(server, dir.clone(), listing);
            st.evict(Some((server, &dir)));
            stored
        };
        tracing::debug!(dir = %dir, "listing cached");
        self.emit(server, vec![dir]);
        stored
    }

    /// Fetch through the cache (see the module docs for the mode table). Concurrent
    /// calls for the same (server, dir) are coalesced: only one runs `fetch`, the
    /// others wait and reuse its result. Errors are those of `fetch`, unchanged;
    /// `NotFound` also drops `dir` and its cached subtree.
    pub async fn get_or_fetch<F, Fut>(
        &self,
        server: &ServerIdentity,
        dir: &RemotePath,
        mode: ListMode,
        fetch: F,
    ) -> Result<CachedListing>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Listing>>,
    {
        let requested_seq = {
            let mut st = self.state();
            if !st.policy.enabled {
                None
            } else {
                if mode != ListMode::Refresh {
                    match st.lookup(server, dir) {
                        Lookup::Fresh(listing) => {
                            return Ok(CachedListing {
                                listing,
                                source: ListingSource::Cache,
                            });
                        }
                        Lookup::Stale(listing) if mode == ListMode::PreferCache => {
                            return Ok(CachedListing {
                                listing,
                                source: ListingSource::CacheStale,
                            });
                        }
                        Lookup::Stale(_) | Lookup::Miss => {}
                    }
                }
                Some(st.store_seq)
            }
        };
        let Some(requested_seq) = requested_seq else {
            let listing = fetch().await?;
            return Ok(CachedListing {
                listing: Arc::new(listing),
                source: ListingSource::Backend,
            });
        };

        let key: Key = (server.clone(), dir.clone());
        let mutex = {
            let mut locks = lock(&self.inner.fetch_locks);
            let flight = locks.entry(key.clone()).or_insert_with(|| Flight {
                lock: Arc::new(tokio::sync::Mutex::new(())),
                users: 0,
            });
            flight.users += 1;
            Arc::clone(&flight.lock)
        };
        let _flight = FlightGuard {
            inner: &self.inner,
            key,
        };
        let _turn = mutex.lock().await;

        // Another caller may have fetched it while we waited.
        {
            let mut st = self.state();
            let tick = st.clock + 1;
            let reuse = st
                .dirs
                .get_mut(server)
                .and_then(|m| m.get_mut(dir))
                .filter(|slot| slot.stored_seq > requested_seq)
                .map(|slot| {
                    slot.last_used = tick;
                    Arc::clone(&slot.listing)
                });
            if let Some(listing) = reuse {
                st.clock = tick;
                st.hits += 1;
                return Ok(CachedListing {
                    listing,
                    source: ListingSource::Cache,
                });
            }
        }

        match fetch().await {
            Ok(listing) => Ok(CachedListing {
                listing: self.store_at(server, dir.clone(), listing),
                source: ListingSource::Backend,
            }),
            Err(Error::NotFound(path)) => {
                let mut dropped = Vec::new();
                self.state().drop_subtree(server, dir, &mut dropped);
                // Only directories that were actually cached: a pane re-reading after
                // the event must not trigger another NotFound fetch loop.
                self.emit(server, dropped);
                Err(Error::NotFound(path))
            }
            Err(e) => Err(e),
        }
    }

    /// Applies one change made by courier-ftp itself (see [`CachePatch`]) and sends
    /// `ListingUpdated` once per changed directory. Disabled cache: only the events
    /// for the affected parent directories.
    pub fn patch(&self, server: &ServerIdentity, patch: CachePatch) {
        let changed = {
            let mut st = self.state();
            if st.policy.enabled {
                let mut changed = Vec::new();
                st.apply(server, patch, &mut changed);
                changed
            } else {
                patch.parents()
            }
        };
        self.emit(server, changed);
    }

    /// Drop one directory (used when a fetch says NotFound, or after an operation
    /// whose result is unknown, e.g. a failed rename). Always sends `ListingUpdated`
    /// for `dir`.
    pub fn invalidate(&self, server: &ServerIdentity, dir: &RemotePath) {
        self.state().remove(server, dir);
        self.emit(server, vec![dir.clone()]);
    }

    /// Drop `dir` and every cached directory below it. Sends `ListingUpdated` for
    /// `dir` and every dropped directory.
    pub fn invalidate_subtree(&self, server: &ServerIdentity, dir: &RemotePath) {
        let mut dirs = vec![dir.clone()];
        self.state().drop_subtree(server, dir, &mut dirs);
        self.emit(server, dirs);
    }

    /// Drops every listing of one server (no events).
    pub fn clear_server(&self, server: &ServerIdentity) {
        let mut st = self.state();
        let dirs: Vec<RemotePath> = st
            .dirs
            .get(server)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        for dir in dirs {
            st.remove(server, &dir);
        }
    }

    /// Drops everything (no events). Called on vault lock (T60) and on quit.
    pub fn clear_all(&self) {
        Self::clear_state(&mut self.state());
    }

    fn clear_state(st: &mut State) {
        st.dirs = HashMap::new();
        st.dir_count = 0;
        st.total_entries = 0;
        st.total_raw_bytes = 0;
    }

    /// Counters: directories, entries, raw bytes, hits, misses, evictions.
    pub fn stats(&self) -> CacheStats {
        let st = self.state();
        CacheStats {
            dirs: st.dir_count,
            entries: st.total_entries,
            raw_bytes: st.total_raw_bytes,
            hits: st.hits,
            misses: st.misses,
            evictions: st.evictions,
        }
    }
}
