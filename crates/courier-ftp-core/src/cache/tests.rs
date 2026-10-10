//! Tests of the listing cache (T46).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use proptest::prelude::*;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::backend::Backend;
use crate::backend::mock::{MockOp, MockServer, test_context};
use crate::events::{EventReceiver, channel};
use crate::model::{Precision, ServerAddress};
use crate::settings::DebugLevel;

// ------------------------------------------------------------------ helpers

fn server() -> ServerIdentity {
    "sftp://alice@example.com"
        .parse::<ServerAddress>()
        .unwrap()
        .identity()
}

fn p(s: &str) -> RemotePath {
    RemotePath::parse(s).unwrap()
}

fn file(name: &str) -> Entry {
    let mut e = Entry::new(name, EntryKind::File);
    e.size = Some(1);
    e
}

fn dir_entry(name: &str) -> Entry {
    let mut e = Entry::new(name, EntryKind::Dir);
    e.permissions = Some(Permissions::from_mode(0o755));
    e
}

fn listing(dir: &str, entries: Vec<Entry>) -> Listing {
    Listing {
        dir: p(dir),
        entries,
        fetched_at: Instant::now(),
        raw: None,
    }
}

fn files(dir: &str, names: &[&str]) -> Listing {
    listing(dir, names.iter().map(|n| file(n)).collect())
}

fn policy(enabled: bool, ttl: Option<u64>, max_dirs: usize) -> CachePolicy {
    CachePolicy {
        enabled,
        ttl: ttl.map(Duration::from_secs),
        max_dirs,
    }
}

fn cache_with(policy: CachePolicy) -> (ListingCache, EventReceiver) {
    let (tx, rx) = channel(DebugLevel::Debug);
    (ListingCache::new(policy, tx), rx)
}

fn cache() -> (ListingCache, EventReceiver) {
    cache_with(CachePolicy::default())
}

fn names(l: &Listing) -> Vec<String> {
    l.entries.iter().map(|e| e.name.clone()).collect()
}

fn get(c: &ListingCache, dir: &str) -> Option<(Arc<Listing>, bool)> {
    match c.lookup(&server(), &p(dir)) {
        Lookup::Fresh(l) => Some((l, true)),
        Lookup::Stale(l) => Some((l, false)),
        Lookup::Miss => None,
    }
}

fn drain(rx: &mut EventReceiver) -> Vec<(Option<ServerIdentity>, RemotePath)> {
    let mut out = Vec::new();
    while let Some(ev) = rx.try_recv() {
        if let CoreEvent::ListingUpdated { server, dir } = ev {
            out.push((server, dir));
        }
    }
    out
}

fn updated_dirs(rx: &mut EventReceiver) -> Vec<String> {
    drain(rx)
        .into_iter()
        .map(|(_, d)| d.as_str().to_owned())
        .collect()
}

/// Recomputes the totals from the slots.
fn real_totals(c: &ListingCache) -> (usize, usize, usize) {
    let st = c.state();
    let mut dirs = 0;
    let mut entries = 0;
    let mut raw = 0;
    for map in st.dirs.values() {
        for slot in map.values() {
            dirs += 1;
            entries += slot.listing.entries.len();
            raw += raw_len(&slot.listing);
        }
    }
    (dirs, entries, raw)
}

// ------------------------------------------------------------------ keys and modes

#[test]
fn identity_key_shares_plain_and_tls_sessions() {
    let (c, _rx) = cache();
    let plain = "ftp://host".parse::<ServerAddress>().unwrap().identity();
    let tls = "ftpes://HOST:21"
        .parse::<ServerAddress>()
        .unwrap()
        .identity();
    let sftp = "sftp://host".parse::<ServerAddress>().unwrap().identity();
    c.store(&plain, files("/", &["a"]));
    assert!(matches!(c.lookup(&tls, &p("/")), Lookup::Fresh(_)));
    assert!(matches!(c.lookup(&sftp, &p("/")), Lookup::Miss));
}

#[tokio::test]
async fn prefer_cache_hit_makes_no_backend_call() {
    let (c, _rx) = cache();
    c.store(&server(), files("/d", &["a"]));
    let calls = AtomicUsize::new(0);
    let got = c
        .get_or_fetch(&server(), &p("/d"), ListMode::PreferCache, || {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(files("/d", &["x"])))
        })
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(got.source, ListingSource::Cache);
    assert_eq!(names(&got.listing), ["a"]);
}

#[tokio::test]
async fn refresh_always_fetches_and_replaces() {
    let (c, _rx) = cache();
    c.store(&server(), files("/d", &["a"]));
    let calls = AtomicUsize::new(0);
    for round in 0..3 {
        let got = c
            .get_or_fetch(&server(), &p("/d"), ListMode::Refresh, || {
                calls.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Ok(files("/d", &["b"])))
            })
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), round + 1);
        assert_eq!(got.source, ListingSource::Backend);
    }
    let (l, fresh) = get(&c, "/d").unwrap();
    assert!(fresh);
    assert_eq!(names(&l), ["b"]);
}

#[tokio::test]
async fn fresh_only_refetches_stale_listing() {
    let (c, _rx) = cache();
    c.store(&server(), files("/d", &["a"]));
    // Fresh: served from the cache.
    let got = c
        .get_or_fetch(&server(), &p("/d"), ListMode::FreshOnly, || {
            std::future::ready(Ok(files("/d", &["b"])))
        })
        .await
        .unwrap();
    assert_eq!(got.source, ListingSource::Cache);
    // Unsure after a patch → stale → fetched.
    c.patch(
        &server(),
        CachePatch::Created {
            path: p("/d/new"),
            entry: Entry::new("new", EntryKind::Dir),
        },
    );
    let calls = AtomicUsize::new(0);
    let got = c
        .get_or_fetch(&server(), &p("/d"), ListMode::FreshOnly, || {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(files("/d", &["b"])))
        })
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(got.source, ListingSource::Backend);
    assert_eq!(names(&got.listing), ["b"]);
    // Missing → fetched.
    let got = c
        .get_or_fetch(&server(), &p("/e"), ListMode::FreshOnly, || {
            std::future::ready(Ok(files("/e", &[])))
        })
        .await
        .unwrap();
    assert_eq!(got.source, ListingSource::Backend);
}

#[tokio::test]
async fn prefer_cache_returns_stale_with_source_cachestale() {
    let (c, _rx) = cache();
    c.store(&server(), files("/d", &["a"]));
    c.patch(
        &server(),
        CachePatch::Uploaded {
            path: p("/d/u"),
            size: 3,
            modified: None,
        },
    );
    let calls = AtomicUsize::new(0);
    let got = c
        .get_or_fetch(&server(), &p("/d"), ListMode::PreferCache, || {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(files("/d", &[])))
        })
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(got.source, ListingSource::CacheStale);
    assert_eq!(names(&got.listing), ["a", "u"]);
}

#[tokio::test(start_paused = true)]
async fn ttl_boundary_29s_fresh_30s_stale() {
    let (c, _rx) = cache_with(policy(true, Some(30), 200));
    c.store(&server(), files("/d", &["a"]));
    tokio::time::advance(Duration::from_secs(29)).await;
    assert!(get(&c, "/d").unwrap().1, "fresh at 29 s");
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(!get(&c, "/d").unwrap().1, "stale at 30 s");
}

#[tokio::test(start_paused = true)]
async fn ttl_zero_never_expires() {
    let (c, _rx) = cache_with(CachePolicy::from_settings(&CacheSettings {
        listing_cache: true,
        listing_cache_ttl_secs: 0,
        listing_cache_max_dirs: 200,
    }));
    c.store(&server(), files("/d", &["a"]));
    tokio::time::advance(Duration::from_secs(10 * 86_400)).await;
    assert!(get(&c, "/d").unwrap().1);
}

// ------------------------------------------------------------------ patches

fn seeded() -> (ListingCache, EventReceiver) {
    let (c, mut rx) = cache();
    c.store(
        &server(),
        listing("/a", vec![file("f"), dir_entry("b"), dir_entry("bc")]),
    );
    c.store(&server(), files("/a/b", &["x"]));
    c.store(&server(), files("/a/b/c", &["y"]));
    c.store(&server(), files("/a/bc", &["z"]));
    c.store(&server(), files("/t", &["old"]));
    drain(&mut rx);
    (c, rx)
}

#[test]
fn patch_created_appends_and_replaces_same_name() {
    let (c, mut rx) = seeded();
    c.patch(
        &server(),
        CachePatch::Created {
            path: p("/a/g"),
            entry: file("g"),
        },
    );
    let (l, fresh) = get(&c, "/a").unwrap();
    assert_eq!(names(&l), ["f", "b", "bc", "g"]);
    assert!(
        fresh,
        "an entry with metadata does not make the listing unsure"
    );
    let mut replacement = file("f");
    replacement.size = Some(99);
    c.patch(
        &server(),
        CachePatch::Created {
            path: p("/a/f"),
            entry: replacement,
        },
    );
    let (l, _) = get(&c, "/a").unwrap();
    assert_eq!(names(&l), ["f", "b", "bc", "g"]);
    assert_eq!(l.entries[0].size, Some(99));
    assert_eq!(updated_dirs(&mut rx), ["/a", "/a"]);
    assert_eq!(c.stats().entries, real_totals(&c).1);
}

#[test]
fn patch_mkdir_marks_unsure() {
    let (c, _rx) = seeded();
    c.patch(
        &server(),
        CachePatch::Created {
            path: p("/a/new"),
            entry: Entry::new("new", EntryKind::Dir),
        },
    );
    let (l, fresh) = get(&c, "/a").unwrap();
    assert!(!fresh);
    assert!(l.entries.iter().any(|e| e.name == "new" && e.is_dir()));
}

#[test]
fn patch_removed_file_removes_entry() {
    let (c, mut rx) = seeded();
    c.patch(&server(), CachePatch::RemovedFile { path: p("/a/f") });
    let (l, fresh) = get(&c, "/a").unwrap();
    assert_eq!(names(&l), ["b", "bc"]);
    assert!(fresh);
    assert_eq!(updated_dirs(&mut rx), ["/a"]);
    // Unknown name: no change, no event.
    c.patch(&server(), CachePatch::RemovedFile { path: p("/a/nope") });
    assert!(updated_dirs(&mut rx).is_empty());
}

#[test]
fn patch_removed_dir_drops_subtree() {
    let (c, mut rx) = seeded();
    c.patch(&server(), CachePatch::RemovedDir { path: p("/a/b") });
    assert_eq!(names(&get(&c, "/a").unwrap().0), ["f", "bc"]);
    assert!(get(&c, "/a/b").is_none());
    assert!(get(&c, "/a/b/c").is_none());
    assert!(get(&c, "/a/bc").is_some(), "prefix is per component");
    assert_eq!(updated_dirs(&mut rx), ["/a", "/a/b", "/a/b/c"]);
    assert_eq!(c.stats().dirs, 3);
}

#[test]
fn patch_rename_same_dir() {
    let (c, _rx) = seeded();
    c.patch(
        &server(),
        CachePatch::Renamed {
            from: p("/a/f"),
            to: p("/a/g"),
        },
    );
    let (l, fresh) = get(&c, "/a").unwrap();
    assert_eq!(names(&l), ["b", "bc", "g"]);
    assert_eq!(l.entries[2].size, Some(1), "metadata moves with the entry");
    assert!(fresh);
}

#[test]
fn patch_rename_across_dirs() {
    let (c, mut rx) = seeded();
    c.patch(
        &server(),
        CachePatch::Renamed {
            from: p("/a/f"),
            to: p("/t/old"),
        },
    );
    assert_eq!(names(&get(&c, "/a").unwrap().0), ["b", "bc"]);
    let (t, _) = get(&c, "/t").unwrap();
    assert_eq!(names(&t), ["old"], "same-name entry replaced");
    assert_eq!(t.entries[0].size, Some(1));
    assert_eq!(updated_dirs(&mut rx), ["/a", "/t"]);
    // Target parent not cached: only the source changes.
    c.patch(
        &server(),
        CachePatch::Renamed {
            from: p("/t/old"),
            to: p("/elsewhere/x"),
        },
    );
    assert!(get(&c, "/t").unwrap().0.entries.is_empty());
    assert!(get(&c, "/elsewhere").is_none());
}

#[test]
fn patch_rename_dir_invalidates_old_subtree() {
    let (c, _rx) = seeded();
    c.patch(
        &server(),
        CachePatch::Renamed {
            from: p("/a/b"),
            to: p("/a/renamed"),
        },
    );
    assert_eq!(names(&get(&c, "/a").unwrap().0), ["f", "bc", "renamed"]);
    assert!(get(&c, "/a/b").is_none());
    assert!(get(&c, "/a/b/c").is_none());
    assert!(get(&c, "/a/renamed").is_none(), "children are not re-keyed");
    assert!(get(&c, "/a/bc").is_some());
}

#[test]
fn patch_rename_unknown_source_invalidates_target_parent() {
    let (c, mut rx) = seeded();
    c.patch(
        &server(),
        CachePatch::Renamed {
            from: p("/uncached/x"),
            to: p("/t/x"),
        },
    );
    assert!(get(&c, "/t").is_none());
    assert_eq!(updated_dirs(&mut rx), ["/t"]);
}

#[test]
fn patch_mode_changed_sets_permissions() {
    let (c, mut rx) = seeded();
    let mut raw = file("f");
    raw.permissions = Some(Permissions::from_raw("-rw-r--r--"));
    c.patch(
        &server(),
        CachePatch::Created {
            path: p("/a/f"),
            entry: raw,
        },
    );
    c.patch(
        &server(),
        CachePatch::ModeChanged {
            path: p("/a/f"),
            mode: 0o640,
        },
    );
    let (l, fresh) = get(&c, "/a").unwrap();
    assert_eq!(
        l.entries[0].permissions,
        Some(Permissions::from_mode(0o640))
    );
    assert!(l.entries[0].permissions.as_ref().unwrap().raw.is_none());
    assert!(fresh);
    assert_eq!(updated_dirs(&mut rx), ["/a", "/a"]);
}

#[test]
fn patch_uploaded_upserts_with_size_and_marks_unsure() {
    let (c, _rx) = seeded();
    let ts = Timestamp::new(time::OffsetDateTime::UNIX_EPOCH, Precision::Second);
    // New file.
    c.patch(
        &server(),
        CachePatch::Uploaded {
            path: p("/a/new"),
            size: 42,
            modified: Some(ts),
        },
    );
    let (l, fresh) = get(&c, "/a").unwrap();
    assert!(!fresh);
    let new = l.entries.iter().find(|e| e.name == "new").unwrap();
    assert_eq!(
        (new.size, new.modified, &new.kind),
        (Some(42), Some(ts), &EntryKind::File)
    );
    // Existing file, no mtime: the old one is kept.
    c.patch(
        &server(),
        CachePatch::Uploaded {
            path: p("/a/new"),
            size: 7,
            modified: None,
        },
    );
    let (l, _) = get(&c, "/a").unwrap();
    let new = l.entries.iter().find(|e| e.name == "new").unwrap();
    assert_eq!((new.size, new.modified), (Some(7), Some(ts)));
    // Different kind replaced: nothing kept.
    c.patch(
        &server(),
        CachePatch::Uploaded {
            path: p("/a/bc"),
            size: 5,
            modified: None,
        },
    );
    let (l, _) = get(&c, "/a").unwrap();
    let bc = l.entries.iter().find(|e| e.name == "bc").unwrap();
    assert_eq!(
        (&bc.kind, bc.size, bc.permissions.as_ref()),
        (&EntryKind::File, Some(5), None)
    );
    assert_eq!(l.entries.len(), 4);
    assert_eq!(c.stats().entries, real_totals(&c).1);
}

#[test]
fn patch_on_uncached_parent_is_noop_but_emits_event_when_disabled() {
    let (c, mut rx) = seeded();
    let before = c.stats();
    c.patch(
        &server(),
        CachePatch::Created {
            path: p("/nowhere/x"),
            entry: file("x"),
        },
    );
    c.patch(
        &server(),
        CachePatch::RemovedFile {
            path: p("/nowhere/x"),
        },
    );
    assert_eq!(c.stats().dirs, before.dirs);
    assert!(drain(&mut rx).is_empty());

    let (c, mut rx) = cache_with(policy(false, None, 200));
    c.patch(
        &server(),
        CachePatch::Created {
            path: p("/nowhere/x"),
            entry: file("x"),
        },
    );
    c.patch(
        &server(),
        CachePatch::Renamed {
            from: p("/one/x"),
            to: p("/two/x"),
        },
    );
    let events = drain(&mut rx);
    assert!(events.iter().all(|(s, _)| s.as_ref() == Some(&server())));
    let dirs: Vec<&str> = events.iter().map(|(_, d)| d.as_str()).collect();
    assert_eq!(dirs, ["/nowhere", "/one", "/two"]);
    assert_eq!(c.stats().dirs, 0);
}

// ------------------------------------------------------------------ limits

#[test]
fn lru_evicts_least_recently_used_dir() {
    let (c, _rx) = cache();
    for i in 0..200 {
        c.store(&server(), files(&format!("/d{i}"), &["a"]));
    }
    assert!(get(&c, "/d0").is_some());
    c.store(&server(), files("/d200", &["a"]));
    let st = c.stats();
    assert_eq!(st.dirs, 200);
    assert_eq!(st.evictions, 1);
    assert!(get(&c, "/d0").is_some());
    assert!(get(&c, "/d1").is_none());
    assert!(get(&c, "/d200").is_some());
}

fn big(dir: &str, n: usize) -> Listing {
    listing(
        dir,
        (0..n)
            .map(|i| Entry::new(format!("{i}"), EntryKind::File))
            .collect(),
    )
}

#[test]
fn entry_cap_evicts_until_under_limit() {
    let (c, _rx) = cache();
    c.store(&server(), big("/one", 200_000));
    c.store(&server(), big("/two", 200_000));
    c.store(&server(), big("/three", 200_000));
    let st = c.stats();
    assert_eq!((st.dirs, st.entries), (2, 400_000));
    assert!(get(&c, "/one").is_none());
    assert!(get(&c, "/two").is_some() && get(&c, "/three").is_some());
}

#[test]
fn single_huge_listing_still_served() {
    let (c, _rx) = cache();
    c.store(&server(), files("/small", &["a"]));
    c.store(&server(), big("/huge", 600_000));
    let st = c.stats();
    assert_eq!((st.dirs, st.entries), (1, 600_000));
    assert_eq!(get(&c, "/huge").unwrap().0.entries.len(), 600_000);
}

#[test]
fn raw_text_budget_drops_lru_raw_first() {
    let (c, _rx) = cache();
    for d in ["/r1", "/r2", "/r3"] {
        let mut l = files(d, &["a"]);
        l.raw = Some("x".repeat(30 * 1024 * 1024));
        c.store(&server(), l);
    }
    let (r1, _) = get(&c, "/r1").unwrap();
    assert!(r1.raw.is_none());
    assert_eq!(names(&r1), ["a"]);
    assert!(get(&c, "/r2").unwrap().0.raw.is_some());
    assert!(get(&c, "/r3").unwrap().0.raw.is_some());
    let st = c.stats();
    assert!(st.raw_bytes <= MAX_CACHED_RAW_BYTES);
    assert_eq!(st.raw_bytes, real_totals(&c).2);
    assert_eq!(st.dirs, 3);
}

// ------------------------------------------------------------------ disabled, errors, clear

#[tokio::test]
async fn disabled_cache_always_fetches_and_stores_nothing() {
    let (c, mut rx) = cache_with(policy(false, None, 200));
    let calls = AtomicUsize::new(0);
    for mode in [
        ListMode::PreferCache,
        ListMode::FreshOnly,
        ListMode::Refresh,
        ListMode::PreferCache,
    ] {
        let got = c
            .get_or_fetch(&server(), &p("/d"), mode, || {
                calls.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Ok(files("/d", &["a"])))
            })
            .await
            .unwrap();
        assert_eq!(got.source, ListingSource::Backend);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    c.store(&server(), files("/d", &["a"]));
    assert!(matches!(c.lookup(&server(), &p("/d")), Lookup::Miss));
    assert_eq!(c.stats().dirs, 0);
    assert!(
        drain(&mut rx).is_empty(),
        "nothing stored, nothing announced"
    );

    // Disabling at run time clears everything.
    let (c, _rx) = seeded();
    c.set_policy(policy(false, None, 200));
    assert_eq!(c.stats().dirs, 0);
    c.set_policy(CachePolicy::default());
    c.store(&server(), files("/d", &["a"]));
    assert!(get(&c, "/d").is_some());
}

#[test]
fn set_policy_shrinks_capacity() {
    let (c, _rx) = seeded();
    c.set_policy(policy(true, None, 2));
    assert_eq!(c.stats().dirs, 2);
    assert_eq!(real_totals(&c), (2, c.stats().entries, 0));
}

#[tokio::test]
async fn not_found_invalidates_subtree() {
    let (c, mut rx) = seeded();
    let err = c
        .get_or_fetch(&server(), &p("/a/b"), ListMode::Refresh, || {
            std::future::ready(Err(Error::NotFound(p("/a/b"))))
        })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NotFound(_)));
    assert!(get(&c, "/a/b").is_none());
    assert!(get(&c, "/a/b/c").is_none());
    assert!(get(&c, "/a/bc").is_some());
    assert_eq!(updated_dirs(&mut rx), ["/a/b", "/a/b/c"]);
    // Again: nothing cached any more, so no event (no re-list loop).
    let _ = c
        .get_or_fetch(&server(), &p("/a/b"), ListMode::PreferCache, || {
            std::future::ready(Err(Error::NotFound(p("/a/b"))))
        })
        .await;
    assert!(drain(&mut rx).is_empty());
    // Other errors leave the cache alone.
    let _ = c
        .get_or_fetch(&server(), &p("/a/bc"), ListMode::Refresh, || {
            std::future::ready(Err(Error::Timeout))
        })
        .await;
    assert!(get(&c, "/a/bc").is_some());
}

#[test]
fn clear_all_empties_cache() {
    let (c, _rx) = seeded();
    let other = "ftp://other".parse::<ServerAddress>().unwrap().identity();
    c.store(&other, files("/", &["a"]));
    c.clear_server(&other);
    assert_eq!(c.stats().dirs, 5);
    c.clear_all();
    let st = c.stats();
    assert_eq!((st.dirs, st.entries, st.raw_bytes), (0, 0, 0));
    assert!(get(&c, "/a").is_none());
}

#[test]
fn listing_updated_emitted_once_per_changed_dir() {
    let (c, mut rx) = cache();
    c.store(&server(), files("/a", &["x"]));
    let events = drain(&mut rx);
    assert_eq!(events, [(Some(server()), p("/a"))]);
    // Same parent for both ends of a rename: one event.
    c.patch(
        &server(),
        CachePatch::Renamed {
            from: p("/a/x"),
            to: p("/a/y"),
        },
    );
    assert_eq!(updated_dirs(&mut rx), ["/a"]);
    c.invalidate(&server(), &p("/a"));
    assert_eq!(updated_dirs(&mut rx), ["/a"]);
    c.store(&server(), files("/a", &["x"]));
    c.store(&server(), files("/a/s", &["x"]));
    drain(&mut rx);
    c.invalidate_subtree(&server(), &p("/a"));
    assert_eq!(updated_dirs(&mut rx), ["/a", "/a/s"]);
    // Clearing sends nothing.
    c.store(&server(), files("/a", &["x"]));
    drain(&mut rx);
    c.clear_all();
    assert!(drain(&mut rx).is_empty());
}

#[test]
fn debug_output_has_no_paths() {
    let (c, _rx) = seeded();
    let s = format!("{c:?}");
    assert!(!s.contains("/a") && !s.contains("example.com"), "{s}");
}

#[test]
fn policy_from_settings() {
    let p = CachePolicy::from_settings(&CacheSettings {
        listing_cache: false,
        listing_cache_ttl_secs: 30,
        listing_cache_max_dirs: 0,
    });
    assert_eq!(p, policy(false, Some(30), 1));
    assert_eq!(CachePolicy::default(), policy(true, None, 200));
}

// ------------------------------------------------------------------ single flight (mock backend)

async fn connected(server: &MockServer) -> crate::backend::mock::MockBackend {
    let (ctx, _rx) = test_context();
    let mut b = server.backend(ctx);
    b.connect(CancellationToken::new()).await.unwrap();
    b
}

#[tokio::test(start_paused = true)]
async fn single_flight_coalesces_concurrent_fetches() {
    let mock = MockServer::new();
    mock.add_dir("/d");
    mock.add_file("/d/f", "x");
    let mut backends = Vec::new();
    for _ in 0..10 {
        backends.push(connected(&mock).await);
    }
    mock.set_latency(Duration::from_millis(50));
    let (c, _rx) = cache();
    let mut tasks = Vec::new();
    for mut b in backends {
        let c = c.clone();
        tasks.push(tokio::spawn(async move {
            let dir = p("/d");
            c.get_or_fetch(&server(), &dir, ListMode::PreferCache, || async {
                b.list(&dir, CancellationToken::new()).await
            })
            .await
            .unwrap()
        }));
    }
    let mut backend = 0;
    for t in tasks {
        let got = t.await.unwrap();
        assert_eq!(names(&got.listing), ["f"]);
        if got.source == ListingSource::Backend {
            backend += 1;
        }
    }
    assert_eq!(mock.calls(MockOp::List), 1);
    assert_eq!(backend, 1);
    assert!(c.inner.fetch_locks.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn cancelled_fetch_lets_next_waiter_fetch() {
    let mock = MockServer::new();
    mock.add_dir("/d");
    let mut first = connected(&mock).await;
    let mut second = connected(&mock).await;
    mock.set_latency(Duration::from_millis(50));
    let (c, _rx) = cache();

    let c1 = c.clone();
    let a = tokio::spawn(async move {
        let dir = p("/d");
        c1.get_or_fetch(&server(), &dir, ListMode::Refresh, || async {
            first.list(&dir, CancellationToken::new()).await
        })
        .await
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    let c2 = c.clone();
    let b = tokio::spawn(async move {
        let dir = p("/d");
        c2.get_or_fetch(&server(), &dir, ListMode::PreferCache, || async {
            second.list(&dir, CancellationToken::new()).await
        })
        .await
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    a.abort();
    assert!(a.await.unwrap_err().is_cancelled());
    let got = b.await.unwrap().unwrap();
    assert_eq!(got.source, ListingSource::Backend);
    assert_eq!(mock.calls(MockOp::List), 2);
    assert!(get(&c, "/d").is_some());
    assert!(c.inner.fetch_locks.lock().unwrap().is_empty());
}

// ------------------------------------------------------------------ properties

const DIRS: [&str; 6] = ["/", "/a", "/a/b", "/a/b/c", "/b", "/ab"];
const NAMES: [&str; 4] = ["a", "b", "c", "ab"];

#[derive(Debug, Clone)]
enum Op {
    Store(usize, Vec<(usize, bool)>),
    Lookup(usize),
    Patch(PatchOp),
    Invalidate(usize),
    InvalidateSubtree(usize),
}

#[derive(Debug, Clone)]
enum PatchOp {
    Created(usize, usize, bool),
    RemovedFile(usize, usize),
    RemovedDir(usize, usize),
    Renamed(usize, usize, usize, usize),
    ModeChanged(usize, usize),
    Uploaded(usize, usize),
}

fn path_of(d: usize, n: usize) -> RemotePath {
    p(DIRS[d]).join(NAMES[n]).unwrap()
}

impl PatchOp {
    fn to_patch(&self) -> CachePatch {
        match *self {
            Self::Created(d, n, is_dir) => CachePatch::Created {
                path: path_of(d, n),
                entry: if is_dir {
                    Entry::new(NAMES[n], EntryKind::Dir)
                } else {
                    file(NAMES[n])
                },
            },
            Self::RemovedFile(d, n) => CachePatch::RemovedFile {
                path: path_of(d, n),
            },
            Self::RemovedDir(d, n) => CachePatch::RemovedDir {
                path: path_of(d, n),
            },
            Self::Renamed(d1, n1, d2, n2) => CachePatch::Renamed {
                from: path_of(d1, n1),
                to: path_of(d2, n2),
            },
            Self::ModeChanged(d, n) => CachePatch::ModeChanged {
                path: path_of(d, n),
                mode: 0o600,
            },
            Self::Uploaded(d, n) => CachePatch::Uploaded {
                path: path_of(d, n),
                size: 1,
                modified: None,
            },
        }
    }
}

fn idx(n: usize) -> impl Strategy<Value = usize> {
    0..n
}

fn patch_op() -> impl Strategy<Value = PatchOp> {
    let d = || idx(DIRS.len());
    let n = || idx(NAMES.len());
    prop_oneof![
        (d(), n(), any::<bool>()).prop_map(|(d, n, b)| PatchOp::Created(d, n, b)),
        (d(), n()).prop_map(|(d, n)| PatchOp::RemovedFile(d, n)),
        (d(), n()).prop_map(|(d, n)| PatchOp::RemovedDir(d, n)),
        (d(), n(), d(), n()).prop_map(|(a, b, c, e)| PatchOp::Renamed(a, b, c, e)),
        (d(), n()).prop_map(|(d, n)| PatchOp::ModeChanged(d, n)),
        (d(), n()).prop_map(|(d, n)| PatchOp::Uploaded(d, n)),
    ]
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (idx(DIRS.len()), prop::collection::vec((idx(NAMES.len()), any::<bool>()), 0..5))
            .prop_map(|(d, e)| Op::Store(d, e)),
        1 => idx(DIRS.len()).prop_map(Op::Lookup),
        4 => patch_op().prop_map(Op::Patch),
        1 => idx(DIRS.len()).prop_map(Op::Invalidate),
        1 => idx(DIRS.len()).prop_map(Op::InvalidateSubtree),
    ]
}

fn store_listing(d: usize, entries: &[(usize, bool)]) -> Listing {
    let entries = entries
        .iter()
        .map(|&(n, is_dir)| {
            if is_dir {
                dir_entry(NAMES[n])
            } else {
                file(NAMES[n])
            }
        })
        .collect();
    let (entries, _) = Listing::clean_entries(entries);
    listing(DIRS[d], entries)
}

/// Reference model: cached directory → name → is a regular file.
type Model = BTreeMap<RemotePath, BTreeMap<String, bool>>;

fn model_drop_subtree(m: &mut Model, dir: &RemotePath) {
    m.retain(|d, _| !d.starts_with(dir));
}

fn model_apply(m: &mut Model, patch: &CachePatch) {
    let split = |path: &RemotePath| (path.parent().unwrap(), path.file_name().unwrap().to_owned());
    match patch {
        CachePatch::Created { path, entry } => {
            let (parent, name) = split(path);
            let is_file = matches!(entry.kind, EntryKind::File);
            if let Some(d) = m.get_mut(&parent) {
                d.insert(name, is_file);
            }
            if !is_file {
                model_drop_subtree(m, path);
            }
        }
        CachePatch::RemovedFile { path } => {
            let (parent, name) = split(path);
            if let Some(d) = m.get_mut(&parent) {
                d.remove(&name);
            }
        }
        CachePatch::RemovedDir { path } => {
            let (parent, name) = split(path);
            if let Some(d) = m.get_mut(&parent) {
                d.remove(&name);
            }
            model_drop_subtree(m, path);
        }
        CachePatch::Renamed { from, to } => {
            let (fp, fname) = split(from);
            let (tp, tname) = split(to);
            match m.get_mut(&fp).and_then(|d| d.remove(&fname)) {
                Some(is_file) => {
                    if let Some(d) = m.get_mut(&tp) {
                        d.insert(tname, is_file);
                    }
                    if !is_file {
                        model_drop_subtree(m, from);
                    }
                }
                None => {
                    m.remove(&tp);
                }
            }
            model_drop_subtree(m, to);
        }
        CachePatch::ModeChanged { .. } => {}
        CachePatch::Uploaded { path, .. } => {
            let (parent, name) = split(path);
            if let Some(d) = m.get_mut(&parent) {
                d.insert(name, true);
            }
        }
    }
}

fn cache_view(c: &ListingCache) -> Model {
    let st = c.state();
    let mut out = Model::new();
    for map in st.dirs.values() {
        for (dir, slot) in map {
            out.insert(
                dir.clone(),
                slot.listing
                    .entries
                    .iter()
                    .map(|e| (e.name.clone(), matches!(e.kind, EntryKind::File)))
                    .collect(),
            );
        }
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_cache_never_exceeds_limits(
        max_dirs in 10usize..=300,
        ops in prop::collection::vec(
            (op(), idx(400), prop::collection::vec(idx(NAMES.len()), 0..40)),
            0..200,
        ),
    ) {
        let (c, _rx) = cache_with(policy(true, None, max_dirs));
        for (op, wide, extra) in ops {
            match op {
                // Spread stores over many directories so the LRU limit is reached.
                Op::Store(d, e) => {
                    let dir = p(DIRS[d]).join(&format!("w{wide}")).unwrap();
                    let mut l = store_listing(d, &e);
                    l.dir = dir;
                    l.entries.extend(extra.iter().enumerate().map(|(i, n)| file(&format!("{}{i}", NAMES[*n]))));
                    let (entries, _) = Listing::clean_entries(l.entries);
                    l.entries = entries;
                    c.store(&server(), l);
                }
                Op::Lookup(d) => { let _ = c.lookup(&server(), &p(DIRS[d])); }
                Op::Patch(po) => c.patch(&server(), po.to_patch()),
                Op::Invalidate(d) => c.invalidate(&server(), &p(DIRS[d])),
                Op::InvalidateSubtree(d) => c.invalidate_subtree(&server(), &p(DIRS[d])),
            }
            let st = c.stats();
            prop_assert!(st.dirs <= max_dirs);
            prop_assert!(st.entries <= MAX_CACHED_ENTRIES || st.dirs == 1);
            prop_assert_eq!((st.dirs, st.entries, st.raw_bytes), real_totals(&c));
        }
    }

    #[test]
    fn prop_patches_match_reference_model(
        ops in prop::collection::vec(op(), 0..60),
    ) {
        let (c, _rx) = cache_with(policy(true, None, 10_000));
        let mut model = Model::new();
        for op in ops {
            match op {
                Op::Store(d, e) => {
                    let l = store_listing(d, &e);
                    model.insert(
                        l.dir.clone(),
                        l.entries.iter().map(|e| (e.name.clone(), matches!(e.kind, EntryKind::File))).collect(),
                    );
                    c.store(&server(), l);
                }
                Op::Lookup(d) => { let _ = c.lookup(&server(), &p(DIRS[d])); }
                Op::Patch(po) => {
                    let patch = po.to_patch();
                    model_apply(&mut model, &patch);
                    c.patch(&server(), patch);
                }
                Op::Invalidate(d) => {
                    model.remove(&p(DIRS[d]));
                    c.invalidate(&server(), &p(DIRS[d]));
                }
                Op::InvalidateSubtree(d) => {
                    model_drop_subtree(&mut model, &p(DIRS[d]));
                    c.invalidate_subtree(&server(), &p(DIRS[d]));
                }
            }
            prop_assert_eq!(&cache_view(&c), &model);
            let names: BTreeSet<RemotePath> = model.keys().cloned().collect();
            prop_assert_eq!(c.stats().dirs, names.len());
        }
    }
}
