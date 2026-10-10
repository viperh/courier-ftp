//! Vault unlock speed (T30, AC15: unlocking a vault with 10 000 items, Argon2
//! excluded, takes < 500 ms). Keyring unlock runs no Argon2; the rest (vault and device
//! keys, decrypting every item into the cache) is what a password unlock does after
//! Argon2.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use courier_ftp_core::model::item::{FieldWriter, HlcClock, ItemBody, ItemId, ItemKind};
use courier_ftp_core::secret::SecretString;
use courier_ftp_core::trust::{MemoryHostKeyStore, SwitchableHostKeyStore};
use courier_ftp_core::vault::{
    Argon2Cost, BodyEdit, BodyWrite, LockReason, MemKeyring, VaultEngine, VaultOptions,
};
use courier_ftp_store::Store;
use criterion::{Criterion, criterion_group, criterion_main};

fn site_body(i: usize, w: &mut FieldWriter<'_>) -> ItemBody {
    let mut b = ItemBody::new(ItemKind::Site, 1);
    let mut put = |k: &str, v: String| {
        w.put(&mut b, k, ciborium::Value::Text(v), false);
    };
    put("name", format!("Site {i:05}"));
    put("host", format!("host{i:05}.example.org"));
    put("user", format!("user{i}"));
    put("password", format!("pw-{i:08}"));
    put("remote_dir", format!("/srv/www/site{i}"));
    put("comments", "x".repeat(200));
    b
}

fn bench(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("courier-ftp.db");
    let engine = rt.block_on(async {
        let store = Store::open(&path).unwrap();
        let e = VaultEngine::new(
            store,
            Arc::new(MemKeyring::new()),
            VaultOptions {
                cost: Argon2Cost::TEST,
                ..VaultOptions::default()
            },
            Arc::new(SwitchableHostKeyStore::new(Arc::new(
                MemoryHostKeyStore::new(),
            ))),
        );
        e.initialize(
            SecretString::from("correct horse battery staple violin"),
            true,
        )
        .await
        .unwrap();
        let vault = e.personal_vault().unwrap();
        let mut clock = HlcClock::default();
        let dev = e.device_id().unwrap();
        let mut w = FieldWriter::new(&mut clock, dev);
        let writes = (0..10_000)
            .map(|i| BodyWrite {
                vault,
                id: ItemId::new(),
                body: BodyEdit::Replace(site_body(i, &mut w)),
            })
            .collect();
        assert_eq!(e.put_many(writes).await.unwrap(), 10_000);
        e.lock(LockReason::Manual).await;
        e
    });
    let mut g = c.benchmark_group("vault");
    g.sample_size(10);
    g.bench_function("vault_unlock_10k", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                rt.block_on(async {
                    let start = Instant::now();
                    let r = engine.unlock_with_keyring().await.unwrap();
                    total += start.elapsed();
                    assert_eq!(r.items, 10_000);
                    engine.lock(LockReason::Manual).await;
                });
            }
            total
        });
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
