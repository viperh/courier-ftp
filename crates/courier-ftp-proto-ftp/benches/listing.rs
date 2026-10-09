//! Listing parser throughput (T13, AC10: a 100 000-line Unix listing in < 150 ms).
#![allow(missing_docs, clippy::unwrap_used)]

use std::fmt::Write as _;
use std::hint::black_box;

use courier_ftp_proto_ftp::listing::{
    ListingContext, ParseOptions, TextDecoder, parse_list, parse_mlsd,
};
use criterion::{Criterion, criterion_group, criterion_main};
use time::macros::datetime;

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn unix_listing(lines: usize) -> Vec<u8> {
    let mut s = String::from("total 123456\n");
    for i in 0..lines {
        let month = MONTHS[i % 12];
        let day = i % 28 + 1;
        if i % 3 == 0 {
            let _ = writeln!(
                s,
                "-rw-r--r--    1 alice    staff    {:>10} {month} {day:>2}  2023 file-{i}.txt",
                i * 37
            );
        } else {
            let _ = writeln!(
                s,
                "drwxr-xr-x    2 alice    staff    {:>10} {month} {day:>2} {:02}:{:02} dir {i}",
                4096,
                i % 24,
                i % 60
            );
        }
    }
    s.into_bytes()
}

fn mlsd_listing(lines: usize) -> Vec<u8> {
    let mut s = String::new();
    for i in 0..lines {
        let _ = writeln!(
            s,
            "type=file;size={};modify=20240131120000;perm=adfrw;unix.mode=0644;unix.owner=1000; file {i}.txt\r",
            i * 37
        );
    }
    s.into_bytes()
}

fn bench_listing(c: &mut Criterion) {
    let opts = ParseOptions {
        ctx: ListingContext::new(datetime!(2024-06-15 12:00 UTC), 0),
        decoder: TextDecoder::Utf8,
        hint: None,
    };
    let unix_100k = unix_listing(100_000);
    let unix_10k = unix_listing(10_000);
    let mlsd_10k = mlsd_listing(10_000);

    let mut g = c.benchmark_group("listing_parse");
    g.sample_size(20);
    g.bench_function("listing_unix_100k", |b| {
        b.iter(|| parse_list(black_box(&unix_100k), &opts));
    });
    g.bench_function("unix_10k_lines", |b| {
        b.iter(|| parse_list(black_box(&unix_10k), &opts));
    });
    g.bench_function("mlsd_10k_lines", |b| {
        b.iter(|| parse_mlsd(black_box(&mlsd_10k), &opts));
    });
    g.finish();
}

criterion_group!(benches, bench_listing);
criterion_main!(benches);
