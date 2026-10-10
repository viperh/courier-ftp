//! Listing cache patch speed (T46, AC10: patching a 100 000-entry cached directory
//! takes < 5 ms).
#![allow(missing_docs, clippy::unwrap_used)]

use std::hint::black_box;

use courier_ftp_core::backend::Listing;
use courier_ftp_core::cache::{CachePatch, CachePolicy, ListingCache};
use courier_ftp_core::events::channel;
use courier_ftp_core::model::{Entry, EntryKind, Permissions, RemotePath, ServerAddress};
use courier_ftp_core::settings::DebugLevel;
use criterion::{Criterion, criterion_group, criterion_main};

fn bench(c: &mut Criterion) {
    // The receiver is dropped: events are discarded instead of queueing up.
    let (events, _) = channel(DebugLevel::None);
    let cache = ListingCache::new(CachePolicy::default(), events);
    let server = "sftp://bench@example.com"
        .parse::<ServerAddress>()
        .unwrap()
        .identity();
    let dir = RemotePath::parse("/big").unwrap();
    let entries = (0..100_000)
        .map(|i| {
            let mut e = Entry::new(format!("file-{i:06}.dat"), EntryKind::File);
            e.size = Some(i * 31);
            e.permissions = Some(Permissions::from_mode(0o644));
            e
        })
        .collect();
    cache.store(
        &server,
        Listing {
            dir: dir.clone(),
            entries,
            fetched_at: tokio::time::Instant::now(),
            raw: None,
        },
    );
    // Worst case: the renamed entry is first (removal shifts every entry) and the new
    // name is looked up over the whole directory.
    let a = dir.join("file-000000.dat").unwrap();
    let b = dir.join("renamed.dat").unwrap();
    let mut flip = false;
    let mut g = c.benchmark_group("cache");
    g.bench_function("cache_patch_100k", |bench| {
        bench.iter(|| {
            let (from, to) = if flip { (&b, &a) } else { (&a, &b) };
            flip = !flip;
            cache.patch(
                black_box(&server),
                CachePatch::Renamed {
                    from: from.clone(),
                    to: to.clone(),
                },
            );
        });
    });
    g.finish();
    assert_eq!(cache.stats().entries, 100_000);
}

criterion_group!(benches, bench);
criterion_main!(benches);
