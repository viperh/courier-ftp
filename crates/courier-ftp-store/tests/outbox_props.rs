//! Property test of the dirty/outbox bookkeeping (AC4).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::HashMap;

use common::{KV, open, seal, with_vault};
use courier_ftp_store::{PutItem, RemoteItem, Store};
use proptest::prelude::*;

const ITEMS: u8 = 3;

#[derive(Debug, Clone)]
enum Op {
    Put {
        item: u8,
        dirty: bool,
    },
    MarkPushed {
        item: u8,
        revision: i64,
        stale: bool,
    },
    ApplyRemote {
        item: u8,
        revision: i64,
        local_pending: bool,
    },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0..ITEMS, any::<bool>()).prop_map(|(item, dirty)| Op::Put { item, dirty }),
        2 => (0..ITEMS, 1..100_i64, any::<bool>())
            .prop_map(|(item, revision, stale)| Op::MarkPushed { item, revision, stale }),
        2 => (0..ITEMS, 1..100_i64, any::<bool>()).prop_map(|(item, revision, local_pending)| {
            Op::ApplyRemote { item, revision, local_pending }
        }),
    ]
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Model {
    revision: i64,
    dirty: bool,
    base: Option<i64>,
}

fn id(item: u8) -> [u8; 16] {
    [item + 1; 16]
}

async fn run(ops: Vec<Op>) {
    let dir = tempfile::tempdir().unwrap();
    let (store, clock) = open(dir.path());
    let vault = with_vault(&store).await;
    let mut model: HashMap<u8, Model> = HashMap::new();

    for op in ops {
        clock.advance(7);
        match op {
            Op::Put { item, dirty } => {
                let env = seal(vault, id(item), b"local edit");
                store
                    .put_item(PutItem {
                        vault_id: vault,
                        id: id(item),
                        key_version: KV,
                        envelope: &env,
                        deleted: false,
                        mark_dirty: dirty,
                    })
                    .await
                    .unwrap();
                let m = model.entry(item).or_default();
                if dirty {
                    m.dirty = true;
                    m.base.get_or_insert(m.revision);
                }
            }
            Op::MarkPushed {
                item,
                revision,
                stale,
            } => {
                let Some(m) = model.get_mut(&item) else {
                    continue;
                };
                let queued = store
                    .list_outbox(vault)
                    .await
                    .unwrap()
                    .into_iter()
                    .find(|r| r.item_id == id(item))
                    .map_or(0, |r| r.queued_at);
                let pushed = if stale { queued - 1 } else { queued };
                store.mark_pushed(id(item), revision, pushed).await.unwrap();
                m.revision = revision;
                if m.base.is_some() && stale {
                    m.base = Some(revision);
                } else {
                    m.dirty = false;
                    m.base = None;
                }
            }
            Op::ApplyRemote {
                item,
                revision,
                local_pending,
            } => {
                store
                    .apply_remote(
                        vault,
                        vec![RemoteItem {
                            id: id(item),
                            revision,
                            key_version: KV,
                            envelope: seal(vault, id(item), b"remote"),
                            deleted: false,
                            local_pending,
                        }],
                        revision,
                    )
                    .await
                    .unwrap();
                model.insert(
                    item,
                    Model {
                        revision,
                        dirty: local_pending,
                        base: local_pending.then_some(revision),
                    },
                );
            }
        }
        check(&store, vault, &model).await;
    }
}

async fn check(store: &Store, vault: [u8; 16], model: &HashMap<u8, Model>) {
    let outbox = store.list_outbox(vault).await.unwrap();
    let items = store.list_items(vault).await.unwrap();
    assert_eq!(items.len(), model.len());
    for row in &items {
        let queued = outbox.iter().find(|o| o.item_id == row.id);
        // The invariant: dirty = 1 <=> an outbox row exists.
        assert_eq!(row.dirty, queued.is_some(), "{row:?} {queued:?}");
        let m = model[&(row.id[0] - 1)];
        assert_eq!(
            Model {
                revision: row.revision,
                dirty: row.dirty,
                base: queued.map(|o| o.base_revision),
            },
            m
        );
    }
    assert_eq!(outbox.len(), items.iter().filter(|r| r.dirty).count());
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    #[test]
    fn coalescing_keeps_first_base(ops in proptest::collection::vec(op(), 1..25)) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(run(ops));
    }
}
