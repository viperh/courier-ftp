//! Filter evaluation speed (T47, AC8: 10 000 entries × 10 regex filters in < 10 ms).
#![allow(missing_docs, clippy::unwrap_used)]

use std::hint::black_box;

use courier_ftp_core::filters::{
    AppliesTo, Condition, Filter, FilterEngine, FilterScope, FilterSet, FilterSettings, MatchMode,
    Side, StringOp,
};
use courier_ftp_core::model::{Entry, EntryKind, Permissions};
use criterion::{Criterion, criterion_group, criterion_main};
use time::UtcOffset;

const PATTERNS: [&str; 10] = [
    r"\.log$",
    r"^tmp",
    r"backup-\d+",
    r"\.(bak|old|orig)$",
    r"^\.#",
    r"~$",
    r"thumbs\.db",
    r"^core\.\d+$",
    r"\.swp$",
    r"node_modules|__pycache__",
];

fn settings() -> FilterSettings {
    let filters: Vec<Filter> = PATTERNS
        .iter()
        .enumerate()
        .map(|(i, p)| Filter {
            name: format!("regex {i}"),
            applies_to: AppliesTo::Both,
            match_mode: MatchMode::Any,
            case_sensitive: i % 2 == 0,
            scope: FilterScope::Both,
            conditions: vec![Condition::Name {
                op: StringOp::Regex,
                value: (*p).to_owned(),
            }],
            builtin: false,
        })
        .collect();
    let names: Vec<String> = filters.iter().map(|f| f.name.clone()).collect();
    FilterSettings {
        filters,
        sets: vec![FilterSet {
            name: "bench".to_owned(),
            local: names.clone(),
            remote: names,
        }],
        active_set: "bench".to_owned(),
        apply_to_transfers: true,
    }
}

fn entries(n: usize) -> Vec<Entry> {
    const EXT: [&str; 8] = ["txt", "rs", "log", "bak", "jpeg", "tar.gz", "swp", "md"];
    (0..n)
        .map(|i| {
            let kind = if i % 10 == 0 {
                EntryKind::Dir
            } else {
                EntryKind::File
            };
            let mut e = Entry::new(format!("Document-{i:05}.{}", EXT[i % EXT.len()]), kind);
            e.size = Some(i as u64 * 37);
            e.permissions = Some(Permissions::from_mode(0o644));
            e
        })
        .collect()
}

fn bench(c: &mut Criterion) {
    let (engine, errors) = FilterEngine::new(&settings(), Side::Remote, UtcOffset::UTC);
    assert!(errors.is_empty() && engine.filters().len() == 10);
    let mut g = c.benchmark_group("filters");
    let list = entries(10_000);
    g.bench_function("filters_10k_10_regex", |b| {
        b.iter(|| black_box(engine.visible_indices(black_box(&list), "/var/www")));
    });
    let list = entries(100_000);
    g.sample_size(20);
    g.bench_function("filters_100k_10_regex", |b| {
        b.iter(|| black_box(engine.visible_indices(black_box(&list), "/var/www")));
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
