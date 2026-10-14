#![allow(clippy::unwrap_used)]

//! T44: cost of one `RateLimiter::acquire` per 128 KiB chunk when the
//! limiter doesn't have to wait (informational, no gate).

use std::hint::black_box;

use courier_ftp_core::{
    model::Direction,
    settings::TransferSettings,
    transfer::{BUFFER_SIZE, RateLimiter, SpeedLimiter},
};
use criterion::{Criterion, criterion_group, criterion_main};

fn bench_ratelimit(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let off = SpeedLimiter::new(&TransferSettings::default());
    // 1 TiB/s: enabled, but never waits.
    let fast = SpeedLimiter::new(&TransferSettings {
        speed_limit_enabled: true,
        download_limit_kib: 1 << 30,
        ..TransferSettings::default()
    });

    let mut group = c.benchmark_group("ratelimit");
    group.bench_function("acquire_disabled", |b| {
        b.iter(|| rt.block_on(off.acquire(Direction::Download, black_box(BUFFER_SIZE))))
    });
    group.bench_function("acquire_enabled_no_wait", |b| {
        b.iter(|| rt.block_on(fast.acquire(Direction::Download, black_box(BUFFER_SIZE))))
    });
    group.finish();
}

criterion_group!(benches, bench_ratelimit);
criterion_main!(benches);
