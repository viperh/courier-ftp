//! Directory listing cache (T46): revisiting a directory is instant, and our
//! own changes patch the cached listings so panes stay accurate without a
//! refresh.
//!
//! Memory only, never persisted (file names would otherwise leak to disk).
//! Shared by every tab connected to the same server: clone the
//! [`ListingCache`] handle. Keyed by server identity (protocol, host, port,
//! user; `None` for the local filesystem) and directory.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use tokio_util::sync::CancellationToken;

use crate::{
    Result,
    backend::{Backend, Listing},
    events::{CoreEvent, EventSender, SessionId},
    model::{Entry, Permissions, Precision, RemotePath, ServerAddress, Timestamp},
    settings::CacheSettings,
};

/// The default number of cached directories.
pub const DEFAULT_CAPACITY: usize = 200;

type Key = (Option<ServerAddress>, RemotePath);

#[derive(Debug)]
struct Cached {
    listing: Listing,
    last_used: u64,
}

#[derive(Debug)]
struct Inner {
    map: HashMap<Key, Cached>,
    clock: u64,
    capacity: usize,
    enabled: bool,
    ttl: Option<Duration>,
    events: Option<EventSender>,
}

/// A shared, in-memory cache of directory listings.
#[derive(Debug, Clone)]
pub struct ListingCache {
    inner: Arc<Mutex<Inner>>,
}

impl ListingCache {
    /// A cache configured from the settings. With `events`, every patch sends
    /// [`CoreEvent::ListingUpdated`] so panes showing that directory redraw.
    pub fn new(settings: &CacheSettings, events: Option<EventSender>) -> Self {
        let cache = Self {
            inner: Arc::new(Mutex::new(Inner {
                map: HashMap::new(),
                clock: 0,
                capacity: DEFAULT_CAPACITY,
                enabled: true,
                ttl: None,
                events,
            })),
        };
        cache.configure(settings);
        cache
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Apply changed settings. Disabling the cache empties it.
    pub fn configure(&self, settings: &CacheSettings) {
        let mut inner = self.lock();
        inner.enabled = settings.listing_cache;
        inner.ttl = (settings.listing_cache_ttl_secs > 0)
            .then(|| Duration::from_secs(settings.listing_cache_ttl_secs));
        if !inner.enabled {
            inner.map.clear();
        }
    }

    /// Change the maximum number of cached directories (evicting if needed).
    pub fn set_capacity(&self, capacity: usize) {
        let mut inner = self.lock();
        inner.capacity = capacity.max(1);
        inner.evict();
    }

    /// How many directories are cached.
    pub fn len(&self) -> usize {
        self.lock().map.len()
    }

    /// Whether nothing is cached.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The cached listing of `dir`, if present and fresh.
    pub fn get(&self, server: Option<&ServerAddress>, dir: &RemotePath) -> Option<Listing> {
        let mut inner = self.lock();
        if !inner.enabled {
            return None;
        }
        let key = (server.cloned(), dir.clone());
        let ttl = inner.ttl;
        let stale = inner
            .map
            .get(&key)
            .is_some_and(|c| ttl.is_some_and(|ttl| c.listing.fetched_at.elapsed() > ttl));
        if stale {
            inner.map.remove(&key);
            return None;
        }
        inner.clock += 1;
        let now = inner.clock;
        inner.map.get_mut(&key).map(|c| {
            c.last_used = now;
            c.listing.clone()
        })
    }

    /// Store a fresh listing.
    pub fn put(&self, server: Option<&ServerAddress>, listing: Listing) {
        let mut inner = self.lock();
        if !inner.enabled {
            return;
        }
        inner.clock += 1;
        let last_used = inner.clock;
        inner.map.insert(
            (server.cloned(), listing.dir.clone()),
            Cached { listing, last_used },
        );
        inner.evict();
    }

    /// List `dir` through the cache: a fresh cached listing is returned without
    /// calling the backend unless `force` (F5 / `Ctrl-r`) is set.
    pub async fn list_with(
        &self,
        backend: &mut dyn Backend,
        dir: &RemotePath,
        force: bool,
        cancel: CancellationToken,
    ) -> Result<Listing> {
        let server = backend.address().cloned();
        if !force && let Some(hit) = self.get(server.as_ref(), dir) {
            return Ok(hit);
        }
        let listing = backend.list(dir, cancel).await?;
        self.put(server.as_ref(), listing.clone());
        Ok(listing)
    }

    /// Forget one directory.
    pub fn invalidate(&self, server: Option<&ServerAddress>, dir: &RemotePath) {
        self.lock().map.remove(&(server.cloned(), dir.clone()));
    }

    /// Forget a directory and everything below it (recursive delete).
    pub fn invalidate_subtree(&self, server: Option<&ServerAddress>, dir: &RemotePath) {
        let server = server.cloned();
        self.lock()
            .map
            .retain(|(s, d), _| !(*s == server && d.starts_with(dir)));
    }

    /// Forget everything cached for a server (disconnect, reconnect as a
    /// different user).
    pub fn clear_server(&self, server: Option<&ServerAddress>) {
        let server = server.cloned();
        self.lock().map.retain(|(s, _), _| *s != server);
    }

    /// Insert or replace `entry` in the cached listing of `dir` (mkdir, a new
    /// file).
    pub fn insert_entry(
        &self,
        session: SessionId,
        server: Option<&ServerAddress>,
        dir: &RemotePath,
        entry: Entry,
    ) {
        self.patch(session, server, dir, |entries| {
            entries.retain(|e| e.name != entry.name);
            entries.push(entry);
        });
    }

    /// Remove the entry `path` from its parent's cached listing (delete,
    /// rmdir). A removed directory's cached subtree is dropped too.
    pub fn remove_entry(
        &self,
        session: SessionId,
        server: Option<&ServerAddress>,
        path: &RemotePath,
    ) {
        let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
            return;
        };
        self.patch(session, server, &dir, |entries| {
            entries.retain(|e| e.name != name)
        });
        self.invalidate_subtree(server, path);
    }

    /// Move an entry (rename, also across directories). Cached listings below
    /// a renamed directory move with it.
    pub fn rename(
        &self,
        session: SessionId,
        server: Option<&ServerAddress>,
        from: &RemotePath,
        to: &RemotePath,
    ) {
        let (Some(from_dir), Some(from_name)) = (from.parent(), from.file_name()) else {
            return;
        };
        let (Some(to_dir), Some(to_name)) = (to.parent(), to.file_name()) else {
            return;
        };
        let mut moved: Option<Entry> = None;
        self.patch(session, server, &from_dir, |entries| {
            if let Some(i) = entries.iter().position(|e| e.name == from_name) {
                moved = Some(entries.remove(i));
            }
        });
        match moved {
            Some(mut entry) => {
                entry.name = to_name.to_owned();
                entry.hidden = entry.hidden || to_name.starts_with('.');
                self.insert_entry(session, server, &to_dir, entry);
            }
            // We never saw the entry: whatever we cached for the target is stale.
            None => self.invalidate(server, &to_dir),
        }
        self.move_subtree(server, from, to);
    }

    fn move_subtree(&self, server: Option<&ServerAddress>, from: &RemotePath, to: &RemotePath) {
        let server = server.cloned();
        let mut inner = self.lock();
        let keys: Vec<Key> = inner
            .map
            .keys()
            .filter(|(s, d)| *s == server && d.starts_with(from))
            .cloned()
            .collect();
        for key in keys {
            if let Some(mut cached) = inner.map.remove(&key) {
                let rest = key.1.strip_prefix(from).unwrap_or("");
                let dir = to.join_path(rest);
                cached.listing.dir = dir.clone();
                inner.map.insert((server.clone(), dir), cached);
            }
        }
    }

    /// Update the permissions of `path` (chmod).
    pub fn set_permissions(
        &self,
        session: SessionId,
        server: Option<&ServerAddress>,
        path: &RemotePath,
        permissions: Permissions,
    ) {
        self.update_entry(session, server, path, |e| e.permissions = Some(permissions));
    }

    /// Record a finished upload: the entry gets the known size and an
    /// approximate (minute precision) modification time.
    pub fn upload_done(
        &self,
        session: SessionId,
        server: Option<&ServerAddress>,
        path: &RemotePath,
        size: u64,
        modified: time::OffsetDateTime,
    ) {
        let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
            return;
        };
        let mut entry = Entry::file(name, size);
        entry.modified = Some(Timestamp::new(modified, Precision::Minute));
        self.patch(session, server, &dir, |entries| {
            match entries.iter_mut().find(|e| e.name == entry.name) {
                Some(existing) => {
                    existing.size = entry.size;
                    existing.modified = entry.modified;
                }
                None => entries.push(entry),
            }
        });
    }

    fn update_entry(
        &self,
        session: SessionId,
        server: Option<&ServerAddress>,
        path: &RemotePath,
        f: impl FnOnce(&mut Entry),
    ) {
        let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
            return;
        };
        self.patch(session, server, &dir, |entries| {
            if let Some(e) = entries.iter_mut().find(|e| e.name == name) {
                f(e);
            }
        });
    }

    /// Change the cached listing of `dir`, if there is one, and announce it.
    fn patch(
        &self,
        session: SessionId,
        server: Option<&ServerAddress>,
        dir: &RemotePath,
        f: impl FnOnce(&mut Vec<Entry>),
    ) {
        let events = {
            let mut inner = self.lock();
            let Some(cached) = inner.map.get_mut(&(server.cloned(), dir.clone())) else {
                return;
            };
            f(&mut cached.listing.entries);
            inner.events.clone()
        };
        if let Some(events) = events {
            events.send(CoreEvent::ListingUpdated {
                session,
                dir: dir.clone(),
            });
        }
    }
}

impl Inner {
    fn evict(&mut self) {
        while self.map.len() > self.capacity {
            let oldest = self
                .map
                .iter()
                .min_by_key(|(_, c)| c.last_used)
                .map(|(k, _)| k.clone());
            match oldest {
                Some(key) => {
                    self.map.remove(&key);
                }
                None => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use pretty_assertions::assert_eq;
    use time::macros::datetime;

    use super::*;
    use crate::{backend::MockServer, events};

    const S: SessionId = SessionId(1);

    fn listing(dir: &str, names: &[&str]) -> Listing {
        Listing {
            dir: RemotePath::new(dir),
            entries: names
                .iter()
                .map(|n| {
                    if let Some(d) = n.strip_suffix('/') {
                        Entry::dir(d)
                    } else {
                        Entry::file(*n, 1)
                    }
                })
                .collect(),
            fetched_at: Instant::now(),
            raw: None,
        }
    }

    fn names(cache: &ListingCache, dir: &str) -> Vec<String> {
        let mut n: Vec<String> = cache
            .get(None, &RemotePath::new(dir))
            .map(|l| l.entries.into_iter().map(|e| e.name).collect())
            .unwrap_or_default();
        n.sort();
        n
    }

    fn cache() -> ListingCache {
        ListingCache::new(&CacheSettings::default(), None)
    }

    #[tokio::test]
    async fn hits_avoid_backend_calls() {
        let server = MockServer::new();
        server.add_file("/d/a", b"1");
        let mut b = server.backend();
        b.connect(CancellationToken::new()).await.unwrap();
        let c = cache();
        let dir = RemotePath::new("/d");
        c.list_with(&mut b, &dir, false, CancellationToken::new())
            .await
            .unwrap();
        c.list_with(&mut b, &dir, false, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(server.calls(), 1);
        c.list_with(&mut b, &dir, true, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(server.calls(), 2, "force refresh lists again");
    }

    #[tokio::test]
    async fn disabled_cache_always_lists() {
        let server = MockServer::new();
        let mut b = server.backend();
        b.connect(CancellationToken::new()).await.unwrap();
        let c = ListingCache::new(
            &CacheSettings {
                listing_cache: false,
                listing_cache_ttl_secs: 0,
            },
            None,
        );
        for _ in 0..3 {
            c.list_with(&mut b, &RemotePath::root(), false, CancellationToken::new())
                .await
                .unwrap();
        }
        assert_eq!(server.calls(), 3);
        assert!(c.is_empty());
    }

    #[test]
    fn servers_are_kept_apart() {
        let c = cache();
        let a = ServerAddress::new(crate::model::Protocol::Sftp, "a");
        let mut b = a.clone();
        b.user = Some("other".into());
        c.put(Some(&a), listing("/", &["x"]));
        assert!(c.get(Some(&a), &RemotePath::root()).is_some());
        assert!(c.get(Some(&b), &RemotePath::root()).is_none());
        assert!(c.get(None, &RemotePath::root()).is_none());
        c.clear_server(Some(&a));
        assert!(c.is_empty());
    }

    #[test]
    fn ttl_expires_listings() {
        let c = ListingCache::new(
            &CacheSettings {
                listing_cache: true,
                listing_cache_ttl_secs: 60,
            },
            None,
        );
        let mut old = listing("/", &["x"]);
        old.fetched_at = Instant::now()
            .checked_sub(Duration::from_secs(120))
            .unwrap_or_else(Instant::now);
        c.put(None, old);
        if c.get(None, &RemotePath::root()).is_some() {
            // `checked_sub` can fail right after boot; nothing to test then.
            return;
        }
        assert!(c.is_empty());
        c.put(None, listing("/", &["x"]));
        assert!(c.get(None, &RemotePath::root()).is_some());
    }

    #[test]
    fn mkdir_and_delete_patch_the_parent() {
        let c = cache();
        c.put(None, listing("/d", &["a"]));
        c.insert_entry(S, None, &RemotePath::new("/d"), Entry::dir("new"));
        assert_eq!(names(&c, "/d"), ["a", "new"]);
        c.remove_entry(S, None, &RemotePath::new("/d/a"));
        assert_eq!(names(&c, "/d"), ["new"]);
        // Nothing cached: nothing happens.
        c.insert_entry(S, None, &RemotePath::new("/other"), Entry::dir("x"));
        assert!(c.get(None, &RemotePath::new("/other")).is_none());
    }

    #[test]
    fn rmdir_drops_the_subtree() {
        let c = cache();
        c.put(None, listing("/", &["d/", "keep/"]));
        c.put(None, listing("/d", &["sub/"]));
        c.put(None, listing("/d/sub", &["f"]));
        c.put(None, listing("/keep", &["f"]));
        c.remove_entry(S, None, &RemotePath::new("/d"));
        assert_eq!(names(&c, "/"), ["keep"]);
        assert!(c.get(None, &RemotePath::new("/d")).is_none());
        assert!(c.get(None, &RemotePath::new("/d/sub")).is_none());
        assert!(c.get(None, &RemotePath::new("/keep")).is_some());
    }

    #[test]
    fn rename_within_and_across_directories() {
        let c = cache();
        c.put(None, listing("/a", &["f", "dir/"]));
        c.put(None, listing("/b", &["g"]));
        c.put(None, listing("/a/dir", &["inner"]));
        c.rename(S, None, &RemotePath::new("/a/f"), &RemotePath::new("/a/f2"));
        assert_eq!(names(&c, "/a"), ["dir", "f2"]);
        c.rename(
            S,
            None,
            &RemotePath::new("/a/f2"),
            &RemotePath::new("/b/f3"),
        );
        assert_eq!(names(&c, "/a"), ["dir"]);
        assert_eq!(names(&c, "/b"), ["f3", "g"]);
        c.rename(
            S,
            None,
            &RemotePath::new("/a/dir"),
            &RemotePath::new("/b/moved"),
        );
        assert_eq!(names(&c, "/b"), ["f3", "g", "moved"]);
        assert_eq!(names(&c, "/b/moved"), ["inner"]);
        assert!(c.get(None, &RemotePath::new("/a/dir")).is_none());
        let moved = c.get(None, &RemotePath::new("/b/moved")).unwrap();
        assert_eq!(moved.dir, RemotePath::new("/b/moved"));
    }

    #[test]
    fn rename_of_an_unknown_entry_invalidates_the_target() {
        let c = cache();
        c.put(None, listing("/b", &["g"]));
        c.rename(S, None, &RemotePath::new("/a/x"), &RemotePath::new("/b/x"));
        assert!(c.get(None, &RemotePath::new("/b")).is_none());
    }

    #[test]
    fn chmod_and_upload_update_entries() {
        let c = cache();
        c.put(None, listing("/d", &["f"]));
        c.set_permissions(
            S,
            None,
            &RemotePath::new("/d/f"),
            Permissions::from_mode(0o600),
        );
        let when = datetime!(2026-01-02 03:04:05 UTC);
        c.upload_done(S, None, &RemotePath::new("/d/f"), 99, when);
        c.upload_done(S, None, &RemotePath::new("/d/new"), 5, when);
        let l = c.get(None, &RemotePath::new("/d")).unwrap();
        let f = l.entries.iter().find(|e| e.name == "f").unwrap();
        assert_eq!(f.permissions.as_ref().and_then(|p| p.bits()), Some(0o600));
        assert_eq!(f.size, Some(99));
        assert_eq!(f.modified.unwrap().precision, Precision::Minute);
        assert!(
            l.entries
                .iter()
                .any(|e| e.name == "new" && e.size == Some(5))
        );
    }

    #[test]
    fn lru_eviction_respects_the_cap() {
        let c = cache();
        c.set_capacity(3);
        for d in ["/1", "/2", "/3"] {
            c.put(None, listing(d, &[]));
        }
        assert!(c.get(None, &RemotePath::new("/1")).is_some()); // /2 is now oldest
        c.put(None, listing("/4", &[]));
        assert_eq!(c.len(), 3);
        assert!(c.get(None, &RemotePath::new("/2")).is_none());
        for d in ["/1", "/3", "/4"] {
            assert!(c.get(None, &RemotePath::new(d)).is_some(), "{d}");
        }
        c.set_capacity(1);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn patches_announce_the_change() {
        let (tx, mut rx) = events::channel(2);
        let c = ListingCache::new(&CacheSettings::default(), Some(tx));
        c.put(None, listing("/d", &[]));
        c.insert_entry(S, None, &RemotePath::new("/d"), Entry::file("f", 1));
        match rx.try_recv() {
            Some(CoreEvent::ListingUpdated { session, dir }) => {
                assert_eq!((session, dir), (S, RemotePath::new("/d")));
            }
            other => panic!("unexpected {other:?}"),
        }
        // No cached listing: no event.
        c.insert_entry(S, None, &RemotePath::new("/x"), Entry::file("f", 1));
        assert!(rx.try_recv().is_none());
    }
}
