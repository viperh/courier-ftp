//! Canary test (T30 AC9): a full vault cycle at TRACE level leaks the master password
//! and a stored secret into no log line, no `Debug` output and no database file.
//! Own test binary: the subscriber is process-global, so events from blocking threads
//! are captured too.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::*;
use courier_ftp_core::model::item::ItemId;
use courier_ftp_core::vault::{DeviceBlobStore, KdfParams, LockReason, MemKeyring};
use zeroize::Zeroizing;

const CANARY_PW: &str = "CANARY-master-5c2e quiet violin harbor";
const CANARY_SECRET: &str = "CANARY-site-secret-9b4f";
const CANARY_BLOB: &str = "CANARY-blob-31aa";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vault_cycle_leaks_nothing() {
    let buf = LogBuf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    tracing::callsite::rebuild_interest_cache();

    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let kr = MemKeyring::new();
    let e = engine(&path, kr.clone()).await;
    let mut debug = Vec::new();
    e.initialize(pw(CANARY_PW), true).await.unwrap();
    let vault = e.personal_vault().unwrap();
    let id = ItemId::new();
    e.put(vault, id, site("canary.example", CANARY_SECRET))
        .await
        .unwrap();
    e.put_blob("tabs", Zeroizing::new(CANARY_BLOB.as_bytes().to_vec()))
        .await
        .unwrap();
    let got = e.get::<TestSite>(id).await.unwrap().unwrap();
    assert_eq!(
        got.view.password.value().map(|s| s.expose().to_owned()),
        Some(CANARY_SECRET.to_owned())
    );
    debug.push(format!("{got:?}"));
    debug.push(format!("{:?}", e.get_body(id).await.unwrap()));
    debug.push(format!("{:?}", e.list::<TestSite>().unwrap()));
    debug.push(format!("{e:?}"));
    debug.push(format!("{:?}", e.crypto().unwrap()));
    debug.push(format!("{kr:?}"));
    debug.push(format!("{:?}", e.status().await.unwrap()));
    debug.push(format!("{:?}", pw(CANARY_PW)));
    e.lock(LockReason::Manual).await;
    let _ = e.unlock(pw("wrong horse battery staple violin")).await;
    let report = e.unlock(pw(CANARY_PW)).await.unwrap();
    debug.push(format!("{report:?}"));
    e.change_password(Some(pw(CANARY_PW)), pw(CANARY_PW))
        .await
        .unwrap();
    let store = e_store(&path).await;
    let kdf = store
        .get_meta(courier_ftp_store::meta::keys::KDF)
        .await
        .unwrap()
        .unwrap();
    debug.push(format!("{:?}", KdfParams::from_cbor(&kdf).unwrap()));
    e.lock(LockReason::Shutdown).await;
    drop(store);
    drop(e);

    let logs = buf.text();
    assert!(logs.contains("vault unlocked"), "logging works: {logs}");
    for canary in ["CANARY"] {
        for line in logs.lines() {
            assert!(!line.contains(canary), "log line leaks: {line}");
        }
        for d in &debug {
            assert!(!d.contains(canary), "Debug leaks: {d}");
        }
    }
    let mut files = 0;
    for name in ["courier-ftp.db", "courier-ftp.db-wal", "courier-ftp.db-shm"] {
        let p = dir.path().join(name);
        let Ok(bytes) = std::fs::read(&p) else {
            continue;
        };
        files += 1;
        for canary in [CANARY_PW, CANARY_SECRET, CANARY_BLOB, "CANARY"] {
            assert!(
                !bytes.windows(canary.len()).any(|w| w == canary.as_bytes()),
                "{name} contains {canary}"
            );
        }
    }
    assert!(files >= 1);
}
