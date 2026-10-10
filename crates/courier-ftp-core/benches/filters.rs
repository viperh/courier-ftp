//! T47: 10 000 entries filtered with 10 regex filters in < 10 ms
//! (gate in scripts/bench-gates.toml).

use std::hint::black_box;

use courier_ftp_core::{
    filters::{AppliesTo, Condition, Filter, FilterEngine, FilterScope, MatchMode, StringOp},
    model::Entry,
};
use criterion::{Criterion, criterion_group, criterion_main};

fn bench_filters(c: &mut Criterion) {
    let filters: Vec<Filter> = (0..10)
        .map(|i| Filter {
            name: format!("regex {i}"),
            applies_to: AppliesTo::Both,
            match_mode: MatchMode::Any,
            case_sensitive: false,
            conditions: vec![Condition::Name {
                op: StringOp::Matches,
                value: format!(r"^tmp{i}_.*\.(bak|swp)$"),
            }],
            scope: FilterScope::Both,
        })
        .collect();
    let (engine, warnings) = FilterEngine::new(&filters);
    assert!(warnings.is_empty());
    let entries: Vec<(Entry, String)> = (0..10_000)
        .map(|i| {
            let name = format!("file_{i:05}_{}.txt", i % 7);
            let path = format!("/srv/data/{name}");
            (Entry::file(name, i), path)
        })
        .collect();

    let mut group = c.benchmark_group("filter");
    group.bench_function("10k_entries_10_regex", |b| {
        b.iter(|| {
            entries
                .iter()
                .filter(|(e, p)| !engine.excluded(black_box(e), p))
                .count()
        })
    });
    group.finish();
}

criterion_group!(benches, bench_filters);
criterion_main!(benches);
