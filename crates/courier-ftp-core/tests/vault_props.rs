//! Property test (T30 AC1): random put/delete/restore sequences survive lock + unlock;
//! the visible items always equal a model map.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::sync::OnceLock;

use common::*;
use courier_ftp_core::model::item::ItemId;
use courier_ftp_core::vault::{LockReason, MemKeyring, VaultEngine, VaultError};
use proptest::prelude::*;

#[derive(Debug, Clone)]
enum Op {
    Put(usize, String),
    Delete(usize),
    Restore(usize),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0..5usize, "[a-z]{1,8}").prop_map(|(s, h)| Op::Put(s, h)),
        1 => (0..5usize).prop_map(Op::Delete),
        1 => (0..5usize).prop_map(Op::Restore),
    ]
}

struct Fixture {
    rt: tokio::runtime::Runtime,
    engine: VaultEngine,
    _dir: tempfile::TempDir,
}

/// One vault for every case; each case uses fresh item ids. Cases unlock with the
/// (memory) keyring, so no case runs Argon2.
fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let engine = rt.block_on(async {
            let e = engine(&db(&dir), MemKeyring::new()).await;
            e.initialize(pw(PASSWORD), true).await.unwrap();
            e
        });
        Fixture {
            rt,
            engine,
            _dir: dir,
        }
    })
}

/// Model: slot → (host, deleted).
type Model = BTreeMap<usize, (String, bool)>;

async fn run(e: &VaultEngine, ops: Vec<Op>) {
    let vault = e.personal_vault().unwrap();
    let ids: Vec<ItemId> = (0..5).map(|_| ItemId::new()).collect();
    let mut model = Model::new();
    for op in ops {
        match op {
            Op::Put(s, host) => {
                e.put(vault, ids[s], site(&host, "p")).await.unwrap();
                model.insert(s, (host, false));
            }
            Op::Delete(s) => {
                let r = e.delete(ids[s]).await;
                match model.get_mut(&s) {
                    Some(entry) => {
                        r.unwrap();
                        entry.1 = true;
                    }
                    None => assert_eq!(r, Err(VaultError::NotFound(ids[s]))),
                }
            }
            Op::Restore(s) => {
                let r = e.restore(ids[s]).await;
                match model.get_mut(&s) {
                    Some(entry) => {
                        r.unwrap();
                        entry.1 = false;
                    }
                    None => assert_eq!(r, Err(VaultError::NotFound(ids[s]))),
                }
            }
        }
    }
    let check = |label: &str| {
        let visible: BTreeMap<ItemId, String> = e
            .list::<TestSite>()
            .unwrap()
            .into_iter()
            .filter(|l| ids.contains(&l.id))
            .map(|l| (l.id, l.view.host))
            .collect();
        let expected: BTreeMap<ItemId, String> = model
            .iter()
            .filter(|(_, (_, deleted))| !deleted)
            .map(|(s, (h, _))| (ids[*s], h.clone()))
            .collect();
        assert_eq!(visible, expected, "{label}");
    };
    check("before lock");
    e.lock(LockReason::Manual).await;
    e.unlock_with_keyring().await.unwrap();
    check("after unlock");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn random_put_delete_restore_survives_relock(ops in prop::collection::vec(op(), 1..12)) {
        let f = fixture();
        f.rt.block_on(run(&f.engine, ops));
    }
}
