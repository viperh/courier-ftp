//! File list view build (T53, AC7): filter + natural sort of a 100 000-entry listing
//! (≤ 80 ms). The render target (AC6, `file_list_render_100k`) needs the theme and
//! the rest of the UI, so it is the ignored timing test of the same name in
//! `src/components/file_list/snapshot_tests.rs`.
//!
//! `courier-ftp` is a binary crate, so the bench includes the view pipeline sources
//! directly; they depend only on `courier-ftp-core`.
#![allow(
    missing_docs,
    dead_code,
    unreachable_pub,
    unfulfilled_lint_expectations,
    unused_imports,
    reason = "the included modules are written for the binary; the bench uses a part"
)]

use std::hint::black_box;

use courier_ftp_core::{
    backend::Listing,
    filters::{FilterEngine, Side},
    model::{Entry, EntryKind, Precision, RemotePath, Timestamp},
    settings::SortSpec,
};
use criterion::{Criterion, criterion_group, criterion_main};

// An inline module with a `path` takes its files from that directory.
#[path = "../src/components/file_list"]
mod file_list {
    pub(crate) mod format;
    pub(crate) mod natural;
    pub(crate) mod view;
}

use file_list::view::{ViewParams, build};

fn listing(n: usize) -> Listing {
    let t = Timestamp::new(time::OffsetDateTime::UNIX_EPOCH, Precision::Second);
    let entries = (0..n)
        .map(|i| {
            let mut e = Entry::new(
                format!("File-{}-{i}.txt", (i * 7919) % 1000),
                if i % 10 == 0 {
                    EntryKind::Dir
                } else {
                    EntryKind::File
                },
            );
            e.size = Some(u64::try_from(i).unwrap_or(0));
            e.modified = Some(t);
            e
        })
        .collect();
    Listing {
        dir: RemotePath::root(),
        entries,
        fetched_at: tokio::time::Instant::now(),
        raw: None,
    }
}

fn bench(c: &mut Criterion) {
    let l = listing(100_000);
    let filters = FilterEngine::empty(Side::Remote);
    let params = ViewParams {
        show_hidden: true,
        quick: String::new(),
        sort: SortSpec::default(),
        natural: true,
        case_sensitive: false,
        dirs_first: true,
    };
    let mut g = c.benchmark_group("file_list");
    g.sample_size(10);
    g.bench_function("file_list_view_build_100k", |b| {
        b.iter(|| black_box(build(black_box(&l), &params, &filters, "/")));
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
