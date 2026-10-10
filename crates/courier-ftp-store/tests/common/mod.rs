//! Shared helpers for the store integration tests.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use courier_ftp_crypto::Key32;
use courier_ftp_crypto::envelope::seal_item;
use courier_ftp_crypto::random::os_rng;
use courier_ftp_store::{Id16, ManualClock, PutItem, Store, VaultKind};

pub(crate) const KV: u32 = 1;
pub(crate) const DB: &str = "courier-ftp.db";

/// A fresh random-ish id (unique within the test process).
pub(crate) fn new_id() -> Id16 {
    static N: AtomicU64 = AtomicU64::new(1);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&std::process::id().to_be_bytes().repeat(2));
    id[8..].copy_from_slice(&n.to_be_bytes());
    id
}

pub(crate) fn seal(vault: Id16, item: Id16, body: &[u8]) -> Vec<u8> {
    seal_item(
        &Key32::from_bytes([7; 32]),
        &vault,
        &item,
        KV,
        body,
        &mut os_rng(),
    )
    .unwrap()
}

pub(crate) fn open(dir: &Path) -> (Store, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(1_000));
    let store = Store::open_with_clock(dir.join(DB), clock.clone()).unwrap();
    (store, clock)
}

pub(crate) async fn with_vault(store: &Store) -> Id16 {
    let vault = new_id();
    store
        .create_vault(vault, VaultKind::Personal, None, KV, vec![9; 72])
        .await
        .unwrap();
    vault
}

/// `put_item` of a freshly sealed body.
pub(crate) async fn put(store: &Store, vault: Id16, id: Id16, body: &[u8], mark_dirty: bool) {
    let env = seal(vault, id, body);
    store
        .put_item(PutItem {
            vault_id: vault,
            id,
            key_version: KV,
            envelope: &env,
            deleted: false,
            mark_dirty,
        })
        .await
        .unwrap();
}

pub(crate) fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}
