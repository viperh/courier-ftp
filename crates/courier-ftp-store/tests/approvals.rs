//! The `local_approvals` repository (ported from sverb `tests/approvals.rs`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{new_id, open, put, with_vault};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upsert_get_list_revoke() {
    let dir = tempfile::tempdir().unwrap();
    let (store, clock) = open(dir.path());
    let item = new_id();
    assert!(
        store
            .get_local_approval(item, "proxy.command")
            .await
            .unwrap()
            .is_none()
    );
    store
        .put_local_approval(item, "proxy.command", [1; 32])
        .await
        .unwrap();
    let row = store
        .get_local_approval(item, "proxy.command")
        .await
        .unwrap()
        .unwrap();
    assert_eq!((row.value_sha256, row.approved_at), ([1; 32], 1_000));

    // Upsert: a new value replaces the row.
    clock.set(2_000);
    store
        .put_local_approval(item, "proxy.command", [2; 32])
        .await
        .unwrap();
    store
        .put_local_approval(item, "agent_forwarding", [3; 32])
        .await
        .unwrap();
    let rows = store.list_local_approvals().await.unwrap();
    assert_eq!(rows.len(), 2);
    let cmd = rows.iter().find(|r| r.field == "proxy.command").unwrap();
    assert_eq!((cmd.value_sha256, cmd.approved_at), ([2; 32], 2_000));

    assert!(
        store
            .delete_local_approval(item, "proxy.command")
            .await
            .unwrap()
    );
    assert!(
        !store
            .delete_local_approval(item, "proxy.command")
            .await
            .unwrap()
    );
    assert_eq!(store.delete_local_approvals_of(item).await.unwrap(), 1);
    assert!(store.list_local_approvals().await.unwrap().is_empty());
}

// Approvals are never items, envelopes or outbox rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t09_approvals_never_in_outbox() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let vault = with_vault(&store).await;
    let item = new_id();
    put(&store, vault, item, b"body", true).await;
    let before = store.list_outbox(vault).await.unwrap();
    let items_before = store.list_all_items().await.unwrap().len();

    store
        .put_local_approval(item, "proxy.command", [5; 32])
        .await
        .unwrap();
    store
        .put_local_approval(new_id(), "bind_addr", [6; 32])
        .await
        .unwrap();

    assert_eq!(store.list_outbox(vault).await.unwrap(), before);
    assert_eq!(store.list_all_items().await.unwrap().len(), items_before);
    assert_eq!(store.pending_count().await.unwrap(), 1);
    // The table holds no envelope column: only ids, field names and hashes.
    let cols: Vec<String> = store
        .read(|r| {
            let mut stmt = r.conn().prepare("PRAGMA table_info(local_approvals)")?;
            let names = stmt
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(names)
        })
        .await
        .unwrap();
    assert_eq!(
        cols,
        ["item_id", "field", "value_sha256", "approved_at"].map(String::from)
    );
}

// The 32-byte CHECK keeps a malformed hash out of the table.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hash_length_is_checked() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let err = store
        .write(|w| {
            w.conn().execute(
                "INSERT INTO local_approvals VALUES (x'00', 'f', x'0102', 0)",
                [],
            )?;
            Ok(())
        })
        .await;
    assert!(err.is_err());
}
