//! Store integration tests (ported from sverb `crates/sverb-store/tests/store.rs`,
//! names kept).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;
use std::sync::Arc;

use common::{DB, KV, new_id, open, put, seal, sibling, with_vault};
use courier_ftp_store::{
    BUSY_TIMEOUT_MS, Clock, MAX_DEVICE_BLOB_LEN, ManualClock, PutItem, READER_POOL_SIZE,
    RemoteItem, SCHEMA_VERSION, Store, StoreError, SyncState, TABLES,
};

async fn table_names(store: &Store) -> Vec<String> {
    store
        .read(|r| {
            let mut stmt = r.conn().prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table' \
                 AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )?;
            let names = stmt
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(names)
        })
        .await
        .unwrap()
}

async fn user_version(store: &Store) -> i64 {
    store
        .read(|r| {
            Ok(r.conn()
                .query_row("PRAGMA user_version", [], |row| row.get(0))?)
        })
        .await
        .unwrap()
}

// A fresh file: every table of TABLES, user_version = SCHEMA_VERSION (AC1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t01_fresh_db() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join(DB)).unwrap();
    assert_eq!(store.path(), dir.path().join(DB));

    let mut expected: Vec<String> = TABLES.iter().map(|s| (*s).to_owned()).collect();
    expected.sort();
    assert_eq!(table_names(&store).await, expected);
    assert_eq!(user_version(&store).await, SCHEMA_VERSION);
    assert_eq!(SCHEMA_VERSION, 1);
}

// PRAGMAs on the writer and on every reader (AC1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t02_pragmas() {
    fn pragmas(conn: &rusqlite::Connection) -> (String, i64, i64, i64, i64) {
        let q = |p: &str| -> i64 {
            conn.query_row(&format!("PRAGMA {p}"), [], |r| r.get(0))
                .unwrap()
        };
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        (
            mode,
            q("foreign_keys"),
            q("temp_store"),
            q("synchronous"),
            q("busy_timeout"),
        )
    }

    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let busy = i64::try_from(BUSY_TIMEOUT_MS).unwrap();
    let expected = ("wal".to_owned(), 1, 2, 1, busy);

    let w = store.write(|w| Ok(pragmas(w.conn()))).await.unwrap();
    assert_eq!(w, expected);

    // Hold READER_POOL_SIZE reads open at once so each runs on a distinct
    // pooled connection.
    let barrier = Arc::new(std::sync::Barrier::new(READER_POOL_SIZE));
    let mut handles = Vec::new();
    for _ in 0..READER_POOL_SIZE {
        let store = store.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(store.read(move |r| {
                barrier.wait();
                Ok(pragmas(r.conn()))
            }))
            .unwrap()
        }));
    }
    for h in handles {
        assert_eq!(h.join().unwrap(), expected);
    }
}

// A newer schema refuses to open; the file is byte-for-byte unchanged and no
// -wal/-shm appear (AC2).
#[test]
fn t03_newer_schema_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(DB);
    let newer = SCHEMA_VERSION + 1;
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(&format!(
            "CREATE TABLE future (x); PRAGMA user_version = {newer};"
        ))
        .unwrap();
    }
    let before = std::fs::read(&path).unwrap();
    let err = Store::open_with_clock(&path, Arc::new(ManualClock::new(0))).unwrap_err();
    match &err {
        StoreError::NewerSchema { found, supported } => {
            assert_eq!((*found, *supported), (newer, SCHEMA_VERSION));
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(
        err.to_string().contains(&format!(
            "This database was created by a newer courier-ftp (schema {newer}). Please update \
             courier-ftp."
        )),
        "{err}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(!sibling(&path, "-wal").exists());
    assert!(!sibling(&path, "-shm").exists());
}

// A failing extra migration leaves user_version and the schema intact (AC3).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t04_migration_atomicity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(DB);
    drop(Store::open_with_clock(&path, Arc::new(ManualClock::new(0))).unwrap());

    let err = Store::open_with_migrations(
        &path,
        Arc::new(ManualClock::new(0)),
        &["CREATE TABLE half_done (x); THIS IS NOT SQL;"],
    )
    .unwrap_err();
    assert!(matches!(err, StoreError::Sqlite(_)), "{err:?}");

    let (store, _) = open(dir.path());
    assert_eq!(user_version(&store).await, SCHEMA_VERSION);
    assert!(!table_names(&store).await.contains(&"half_done".to_owned()));
}

// Ten dirty edits leave one outbox row with the first base (AC4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t05_outbox_coalescing() {
    let dir = tempfile::tempdir().unwrap();
    let (store, clock) = open(dir.path());
    let vault = with_vault(&store).await;
    let item = new_id();

    // The item is at server revision 7.
    store
        .apply_remote(
            vault,
            vec![RemoteItem {
                id: item,
                revision: 7,
                key_version: KV,
                envelope: seal(vault, item, b"v0"),
                deleted: false,
                local_pending: false,
            }],
            7,
        )
        .await
        .unwrap();

    for i in 0..10 {
        clock.advance(10);
        put(&store, vault, item, format!("edit {i}").as_bytes(), true).await;
    }
    // The revision moves to 9 underneath, then another edit and enqueue.
    store
        .write(move |w| {
            w.conn()
                .execute("UPDATE items SET revision = 9 WHERE id = ?1", [&item[..]])?;
            Ok(())
        })
        .await
        .unwrap();
    clock.advance(10);
    put(&store, vault, item, b"edit 10", true).await;
    store.enqueue(item, vault, 9).await.unwrap();

    let rows = store.list_outbox(vault).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].base_revision, 7);
    assert_eq!(rows[0].queued_at, clock.now_millis());
    assert_eq!(store.pending_count().await.unwrap(), 1);
    assert_eq!(store.pending_by_vault().await.unwrap(), [(vault, 1)]);
    let dirty = store.list_dirty(vault).await.unwrap();
    assert_eq!(dirty.len(), 1);
    assert!(dirty[0].dirty);

    // A clean write never clears the dirty flag.
    put(&store, vault, item, b"clean", false).await;
    assert!(store.get_item(item).await.unwrap().unwrap().dirty);
    assert_eq!(store.pending_count().await.unwrap(), 1);
}

// The item row and the outbox row commit together: an error after put_item
// leaves neither (AC4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t05b_put_item_atomic_with_outbox() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let vault = with_vault(&store).await;
    let item = new_id();
    let env = seal(vault, item, b"body");
    let err = store
        .write(move |w| {
            w.put_item(PutItem {
                vault_id: vault,
                id: item,
                key_version: KV,
                envelope: &env,
                deleted: false,
                mark_dirty: true,
            })?;
            assert_eq!(w.as_read().pending_count()?, 1);
            Err::<(), _>(StoreError::Task("injected".into()))
        })
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::Task(_)));
    assert!(store.get_item(item).await.unwrap().is_none());
    assert_eq!(store.pending_count().await.unwrap(), 0);
    assert_eq!(store.item_count().await.unwrap(), 0);
}

// Rebase updates the base; later enqueues keep it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t06_rebase() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let vault = with_vault(&store).await;
    let item = new_id();
    // Queuing a local change wakes outbox listeners (the sync engine).
    let mut changes = store.outbox_changes();
    assert!(!changes.has_changed().unwrap());
    put(&store, vault, item, b"a", true).await;
    assert!(changes.has_changed().unwrap());
    changes.mark_unchanged();
    assert_eq!(store.list_outbox(vault).await.unwrap()[0].base_revision, 0);
    store.set_meta("x", vec![1]).await.unwrap();
    assert!(!changes.has_changed().unwrap(), "no outbox row, no wake-up");

    store.rebase(item, 12).await.unwrap();
    put(&store, vault, item, b"b", true).await;
    store.enqueue(item, vault, 3).await.unwrap();
    assert_eq!(store.list_outbox(vault).await.unwrap()[0].base_revision, 12);

    assert!(matches!(
        store.rebase(new_id(), 1).await,
        Err(StoreError::NotFound)
    ));
    assert_eq!(store.bump_attempts(item).await.unwrap(), 1);
    assert_eq!(store.bump_attempts(item).await.unwrap(), 2);
    store.dequeue(item).await.unwrap();
    assert_eq!(store.pending_count().await.unwrap(), 0);
    assert!(store.pending_by_vault().await.unwrap().is_empty());
}

// An invalid envelope in the middle of a page rolls back the page and the
// cursor (AC5).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t07_apply_remote_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let vault = with_vault(&store).await;

    let mut page: Vec<RemoteItem> = (1..=5)
        .map(|rev| {
            let id = new_id();
            RemoteItem {
                id,
                revision: rev,
                key_version: KV,
                envelope: seal(vault, id, b"remote"),
                deleted: false,
                local_pending: false,
            }
        })
        .collect();
    page[2].envelope = b"plaintext body".to_vec(); // the 3rd item fails

    let err = store
        .apply_remote(vault, page.clone(), 5)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::InvalidEnvelope(_)), "{err:?}");
    assert!(store.list_items(vault).await.unwrap().is_empty());
    assert_eq!(
        store.get_vault(vault).await.unwrap().unwrap().sync_cursor,
        0
    );

    // The fixed page applies fully.
    let id = page[2].id;
    page[2].envelope = seal(vault, id, b"remote");
    store.apply_remote(vault, page, 5).await.unwrap();
    assert_eq!(store.list_items(vault).await.unwrap().len(), 5);
    assert_eq!(
        store.get_vault(vault).await.unwrap().unwrap().sync_cursor,
        5
    );
    assert_eq!(store.item_markers().await.unwrap().len(), 5);
}

// apply_remote of a merged dirty item keeps it dirty and rebases; mark_pushed
// cleans only when no newer edit happened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apply_remote_rebases_and_mark_pushed() {
    let dir = tempfile::tempdir().unwrap();
    let (store, clock) = open(dir.path());
    let vault = with_vault(&store).await;
    let item = new_id();
    put(&store, vault, item, b"local", true).await;

    let merged = RemoteItem {
        id: item,
        revision: 4,
        key_version: KV,
        envelope: seal(vault, item, b"merged"),
        deleted: false,
        local_pending: true,
    };
    store.apply_remote(vault, vec![merged], 4).await.unwrap();
    let row = store.get_item(item).await.unwrap().unwrap();
    assert!(row.dirty);
    assert_eq!(row.revision, 4);
    let ob = store.list_outbox(vault).await.unwrap();
    assert_eq!(ob[0].base_revision, 4);

    // The push of that state succeeds, but the user edited meanwhile: stays
    // dirty, rebased (t06 in sverb's numbering).
    let pushed_at = ob[0].queued_at;
    clock.advance(5);
    put(&store, vault, item, b"newer", true).await;
    store.mark_pushed(item, 5, pushed_at).await.unwrap();
    let row = store.get_item(item).await.unwrap().unwrap();
    assert!(row.dirty);
    let ob = store.list_outbox(vault).await.unwrap();
    assert_eq!(ob[0].base_revision, 5);

    // Pushing the latest state cleans it.
    store.mark_pushed(item, 6, ob[0].queued_at).await.unwrap();
    let row = store.get_item(item).await.unwrap().unwrap();
    assert!(!row.dirty);
    assert_eq!(row.revision, 6);
    assert_eq!(store.pending_count().await.unwrap(), 0);

    // Reseal replaces only key version and envelope.
    let before = store.get_item(item).await.unwrap().unwrap();
    let mut env2 = seal(vault, item, b"newer");
    env2[1..5].copy_from_slice(&2u32.to_be_bytes());
    store.reseal_item(item, 2, env2.clone()).await.unwrap();
    let after = store.get_item(item).await.unwrap().unwrap();
    assert_eq!((after.key_version, &after.envelope), (2, &env2));
    assert_eq!(
        (after.revision, after.dirty, after.updated_at),
        (before.revision, before.dirty, before.updated_at)
    );
    assert!(matches!(
        store.reseal_item(item, 3, env2).await,
        Err(StoreError::InvalidEnvelope(_))
    ));

    // reset_sync: everything back to revision 0, dirty, queued at base 0.
    let other = new_id();
    put(&store, vault, other, b"other", false).await;
    assert_eq!(store.reset_sync(vault).await.unwrap(), 2);
    let ob = store.list_outbox(vault).await.unwrap();
    assert_eq!(ob.len(), 2);
    assert!(ob.iter().all(|r| r.base_revision == 0));
    assert!(
        store
            .list_items(vault)
            .await
            .unwrap()
            .iter()
            .all(|r| r.dirty && r.revision == 0)
    );
    assert_eq!(
        store.get_vault(vault).await.unwrap().unwrap().sync_cursor,
        0
    );
}

// delete_vault removes its items, outbox rows, device_local rows and approvals
// in one transaction.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t08_delete_vault_cascade() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let a = with_vault(&store).await;
    let b = with_vault(&store).await;
    for vault in [a, b] {
        for _ in 0..3 {
            let id = new_id();
            put(&store, vault, id, b"x", true).await;
            store.touch_connected(id, 1).await.unwrap();
            store
                .put_local_approval(id, "proxy.command", [1; 32])
                .await
                .unwrap();
        }
    }
    store.delete_vault(a).await.unwrap();

    assert!(store.list_items(a).await.unwrap().is_empty());
    assert!(store.list_outbox(a).await.unwrap().is_empty());
    assert_eq!(store.list_items(b).await.unwrap().len(), 3);
    assert_eq!(store.list_outbox(b).await.unwrap().len(), 3);
    assert_eq!(store.list_device_local().await.unwrap().len(), 3);
    assert_eq!(store.list_local_approvals().await.unwrap().len(), 3);
    let raw_local: i64 = store
        .read(|r| {
            Ok(r.conn()
                .query_row("SELECT COUNT(*) FROM device_local", [], |row| row.get(0))?)
        })
        .await
        .unwrap();
    assert_eq!(raw_local, 3);
    assert_eq!(store.list_vaults().await.unwrap().len(), 1);
    assert!(matches!(
        store.delete_vault(a).await,
        Err(StoreError::NotFound)
    ));

    // Atomicity: a failing step after delete_vault inside the same
    // transaction leaves everything in place.
    let err = store
        .write(move |w| {
            w.delete_vault(b)?;
            Err::<(), _>(StoreError::Busy)
        })
        .await;
    assert!(err.is_err());
    assert_eq!(store.list_items(b).await.unwrap().len(), 3);
    assert_eq!(store.list_outbox(b).await.unwrap().len(), 3);

    // purge_item removes one item with its rows.
    let victim = store.list_items(b).await.unwrap()[0].id;
    store.purge_item(victim).await.unwrap();
    assert_eq!(store.list_items(b).await.unwrap().len(), 2);
    assert_eq!(store.list_outbox(b).await.unwrap().len(), 2);
    assert!(store.get_device_local(victim).await.unwrap().is_none());
    assert_eq!(store.list_local_approvals().await.unwrap().len(), 2);
    assert!(matches!(
        store.purge_item(victim).await,
        Err(StoreError::NotFound)
    ));
}

// Two Store instances on one file (two processes) each commit 500 writes
// concurrently: all 1 000 commits land, no Busy, integrity ok (AC6).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t09_concurrency() {
    const PER_STORE: usize = 500;
    let dir = tempfile::tempdir().unwrap();
    let (first, _) = open(dir.path());
    let vault = with_vault(&first).await;
    let (second, _) = open(dir.path());

    let mut tasks = Vec::new();
    for store in [first.clone(), second.clone()] {
        tasks.push(tokio::spawn(async move {
            for i in 0..PER_STORE {
                let id = new_id();
                let env = seal(vault, id, b"payload");
                store
                    .write(move |w| {
                        w.put_item(PutItem {
                            vault_id: vault,
                            id,
                            key_version: KV,
                            envelope: &env,
                            deleted: false,
                            mark_dirty: i % 2 == 0,
                        })
                    })
                    .await
                    .unwrap();
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(first.item_count().await.unwrap(), 2 * PER_STORE as u64);
    assert_eq!(second.item_count().await.unwrap(), 2 * PER_STORE as u64);
    assert_eq!(first.pending_count().await.unwrap(), PER_STORE as u64);
    let check: String = first
        .write(|w| {
            Ok(w.conn()
                .query_row("PRAGMA integrity_check", [], |r| r.get(0))?)
        })
        .await
        .unwrap();
    assert_eq!(check, "ok");
}

// data_version changes after another instance's commit, not after our own
// (AC10).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t10_data_version_cross_instance() {
    let dir = tempfile::tempdir().unwrap();
    let (a, _) = open(dir.path());
    let (b, _) = open(dir.path());
    let v0 = a.data_version().await.unwrap();
    a.set_meta("k", vec![1]).await.unwrap();
    let vault = with_vault(&a).await;
    put(&a, vault, new_id(), b"own", true).await;
    assert_eq!(a.data_version().await.unwrap(), v0);

    b.set_meta("k", vec![2]).await.unwrap();
    let v1 = a.data_version().await.unwrap();
    assert_ne!(v1, v0);
    assert_eq!(a.get_meta("k").await.unwrap(), Some(vec![2]));
    assert_eq!(a.data_version().await.unwrap(), v1);
}

fn assert_no_canary(path: &Path, canary: &[u8]) {
    for p in [
        path.to_path_buf(),
        sibling(path, "-wal"),
        sibling(path, "-shm"),
        sibling(path, "-journal"),
    ] {
        if let Ok(bytes) = std::fs::read(&p) {
            assert!(
                !bytes.windows(canary.len()).any(|w| w == canary),
                "canary found in {}",
                p.display()
            );
        }
    }
}

// No plaintext on disk (DB, WAL, SHM); plaintext is refused (AC7).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t12_no_plaintext_on_disk() {
    const CANARY: &str = "CANARY-SITE-9d2e";
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let vault = with_vault(&store).await;

    for i in 0..50 {
        let body = format!("label={CANARY} host {i};address={CANARY}.example.com");
        put(&store, vault, new_id(), body.as_bytes(), true).await;
    }
    // Plaintext is refused outright, padded to envelope size or not.
    for plain in [
        CANARY.as_bytes().to_vec(),
        format!("{CANARY}{}", " ".repeat(64)).into_bytes(),
    ] {
        let err = store
            .put_item(PutItem {
                vault_id: vault,
                id: new_id(),
                key_version: KV,
                envelope: &plain,
                deleted: false,
                mark_dirty: true,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::InvalidEnvelope(_)), "{err:?}");
    }
    assert_no_canary(store.path(), CANARY.as_bytes());

    {
        // Checkpoint from a separate connection so the main file is rewritten.
        let conn = rusqlite::Connection::open(store.path()).unwrap();
        conn.query_row("PRAGMA wal_checkpoint(FULL)", [], |_| Ok(()))
            .unwrap();
    }
    assert_no_canary(store.path(), CANARY.as_bytes());
    let path = store.path().to_path_buf();
    drop(store);
    assert_no_canary(&path, CANARY.as_bytes());
}

// Random bytes: Corrupt with the path in the message, no panic, file intact
// (AC9).
#[test]
fn t13_corrupt_db() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(DB);
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let bytes: Vec<u8> = (0..8192)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect();
    std::fs::write(&path, &bytes).unwrap();
    let err = Store::open_with_clock(&path, Arc::new(ManualClock::new(0))).unwrap_err();
    assert!(matches!(err, StoreError::Corrupt(_)), "{err:?}");
    let msg = err.to_string();
    assert!(msg.contains("backup"), "{msg}");
    assert!(msg.contains(&path.display().to_string()), "{msg}");
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

// sync_state is a singleton; the API only touches row 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t14_sync_state_singleton() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    assert_eq!(store.get_sync_state().await.unwrap(), None);

    let state = SyncState {
        server_url: "https://sync.example".into(),
        device_id: new_id(),
        tokens_enc: vec![1; 72],
    };
    store.set_sync_state(state.clone()).await.unwrap();
    let state2 = SyncState {
        tokens_enc: vec![4; 80],
        ..state.clone()
    };
    store.set_sync_state(state2.clone()).await.unwrap();
    assert_eq!(store.get_sync_state().await.unwrap(), Some(state2.clone()));

    // Unwrapped tokens are refused.
    let short = SyncState {
        tokens_enc: b"plain-token".to_vec(),
        ..state
    };
    assert!(matches!(
        store.set_sync_state(short).await,
        Err(StoreError::InvalidEnvelope(_))
    ));

    let err = store
        .write(|w| {
            w.conn().execute(
                "INSERT INTO sync_state (id, server_url, device_id, tokens_enc)
                 VALUES (2, 'x', x'00', x'00')",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap_err();
    match err {
        StoreError::Sqlite(e) => {
            assert_eq!(
                e.sqlite_error_code(),
                Some(rusqlite::ErrorCode::ConstraintViolation)
            );
        }
        other => panic!("unexpected {other:?}"),
    }
    let n: i64 = store
        .read(|r| {
            Ok(r.conn()
                .query_row("SELECT COUNT(*) FROM sync_state", [], |row| row.get(0))?)
        })
        .await
        .unwrap();
    assert_eq!(n, 1);
    store.clear_sync_state().await.unwrap();
    assert_eq!(store.get_sync_state().await.unwrap(), None);
}

// Database, -wal and -shm are 0600, the directory 0700 (AC8).
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t15_file_modes() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let db = data.join(DB);
    let store = Store::open(&db).unwrap();
    // Force -wal/-shm to exist.
    let vault = with_vault(&store).await;
    put(&store, vault, new_id(), b"x", true).await;
    for p in [db.clone(), sibling(&db, "-wal"), sibling(&db, "-shm")] {
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{}", p.display());
    }
    let mode = std::fs::metadata(&data).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);

    // A loose existing file is tightened on open.
    drop(store);
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).unwrap();
    drop(Store::open(&db).unwrap());
    let mode = std::fs::metadata(&db).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

// meta and device_local round trips.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn meta_and_device_local() {
    use courier_ftp_store::meta::keys;
    const DAY: i64 = 86_400_000;
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    assert_eq!(store.get_meta(keys::KDF).await.unwrap(), None);
    store.set_meta(keys::KDF, vec![1, 2]).await.unwrap();
    store.set_meta(keys::KDF, vec![3]).await.unwrap();
    assert_eq!(store.get_meta(keys::KDF).await.unwrap(), Some(vec![3]));
    store.delete_meta(keys::KDF).await.unwrap();
    assert_eq!(store.get_meta(keys::KDF).await.unwrap(), None);

    let vault = with_vault(&store).await;
    let item = new_id();
    // A device-local row may precede its item.
    assert!((store.touch_connected(item, 0).await.unwrap() - 1.0).abs() < 1e-9);
    assert!(store.list_device_local().await.unwrap().is_empty());
    put(&store, vault, item, b"site", true).await;
    assert!((store.touch_connected(item, 14 * DAY).await.unwrap() - 1.5).abs() < 1e-9);
    store
        .set_local_dir_override(item, Some("/home/me/site".into()))
        .await
        .unwrap();
    store.set_tree_expanded(item, Some(true)).await.unwrap();
    let dl = store.get_device_local(item).await.unwrap().unwrap();
    assert_eq!(dl.last_connected_at, Some(14 * DAY));
    assert_eq!(dl.local_dir_override.as_deref(), Some("/home/me/site"));
    assert_eq!(dl.tree_expanded, Some(true));
    assert!((dl.score_at(28 * DAY) - 0.75).abs() < 1e-9);
    assert_eq!(
        store.list_device_local().await.unwrap(),
        std::slice::from_ref(&dl)
    );
    // Device-local writes never touch the outbox.
    assert_eq!(store.pending_count().await.unwrap(), 1);

    // Move to a re-created item.
    let moved = new_id();
    store.move_device_local(item, moved).await.unwrap();
    assert!(store.get_device_local(item).await.unwrap().is_none());
    let got = store.get_device_local(moved).await.unwrap().unwrap();
    assert_eq!(got.local_dir_override.as_deref(), Some("/home/me/site"));

    // Data survives a reopen.
    drop(store);
    let (store, _) = open(dir.path());
    assert!(store.get_device_local(moved).await.unwrap().is_some());
    store.delete_device_local(moved).await.unwrap();
    assert!(store.get_device_local(moved).await.unwrap().is_none());
}

// Device blobs: shape checks, upsert, delete, the size limit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_blobs_roundtrip_and_size_limit() {
    use courier_ftp_crypto::Key32;
    use courier_ftp_crypto::device_blob::seal_device_blob;
    use courier_ftp_crypto::random::os_rng;

    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let key = Key32::from_bytes([3; 32]);
    let blob = seal_device_blob(&key, "transfer-queue", b"[queue]", &mut os_rng()).unwrap();
    assert_eq!(store.get_device_blob("transfer-queue").await.unwrap(), None);
    store
        .put_device_blob("transfer-queue", blob.clone())
        .await
        .unwrap();
    assert_eq!(
        store.get_device_blob("transfer-queue").await.unwrap(),
        Some(blob)
    );
    let tabs = seal_device_blob(&key, "tabs", b"[tabs]", &mut os_rng()).unwrap();
    store
        .put_device_blob("transfer-queue", tabs.clone())
        .await
        .unwrap();
    assert_eq!(
        store.get_device_blob("transfer-queue").await.unwrap(),
        Some(tabs)
    );

    // Not a sealed blob.
    for bad in [b"queue".to_vec(), vec![0x02; 64], vec![0x01; 40]] {
        assert!(matches!(
            store.put_device_blob("tabs", bad).await,
            Err(StoreError::InvalidEnvelope(_))
        ));
    }
    // Too large (zero pages: allocating does not touch the memory).
    let mut huge = vec![0u8; MAX_DEVICE_BLOB_LEN + 1];
    huge[0] = 0x01;
    assert!(matches!(
        store.put_device_blob("tabs", huge).await,
        Err(StoreError::TooLarge)
    ));

    assert!(store.delete_device_blob("transfer-queue").await.unwrap());
    assert!(!store.delete_device_blob("transfer-queue").await.unwrap());
    assert_eq!(store.get_device_blob("transfer-queue").await.unwrap(), None);
    // Device blobs never reach the outbox.
    assert_eq!(store.pending_count().await.unwrap(), 0);
}

// Vault rows: wrapped-key guard, updates, untrusted values read as Corrupt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vaults_roundtrip_and_corrupt_rows() {
    use courier_ftp_store::VaultKind;
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let org = new_id();
    let vault = new_id();
    assert!(matches!(
        store
            .create_vault(vault, VaultKind::Shared, Some(org), 1, vec![0; 32])
            .await,
        Err(StoreError::InvalidEnvelope(_))
    ));
    store
        .create_vault(vault, VaultKind::Shared, Some(org), 1, vec![5; 72])
        .await
        .unwrap();
    store
        .update_wrapped_key(vault, 2, vec![6; 72])
        .await
        .unwrap();
    store.set_sync_cursor(vault, 42).await.unwrap();
    let row = store.get_vault(vault).await.unwrap().unwrap();
    assert_eq!(row.kind, VaultKind::Shared);
    assert_eq!(row.org_id, Some(org));
    assert_eq!((row.key_version, row.sync_cursor), (2, 42));
    assert_eq!(row.wrapped_key, vec![6; 72]);
    assert!(matches!(
        store.set_sync_cursor(new_id(), 1).await,
        Err(StoreError::NotFound)
    ));

    // A hostile file: an out-of-range key_version reads as Corrupt.
    store
        .write(move |w| {
            w.conn().execute(
                "UPDATE vaults SET key_version = -1 WHERE id = ?1",
                [&vault[..]],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(matches!(
        store.list_vaults().await,
        Err(StoreError::Corrupt(_))
    ));
}
