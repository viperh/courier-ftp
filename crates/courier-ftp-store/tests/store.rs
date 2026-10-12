//! The store: schema, PRAGMAs, migrations, outbox bookkeeping, concurrency,
//! permissions and the no-plaintext guarantee.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use courier_ftp_core::model::Protocol;
use courier_ftp_core::model::item::{
    DeviceId, Hlc, HlcClock, ItemId, ItemKind, ItemView, Site, VaultId,
};
use courier_ftp_crypto::Key32;
use courier_ftp_crypto::envelope::seal_item;
use courier_ftp_crypto::keys::os_rng;
use courier_ftp_store::{
    Clock, IndexRow, ManualClock, RemoteItem, SCHEMA_VERSION, Store, StoreError, SyncState,
    VaultKind,
};
use secrecy::SecretString;

const KV: u32 = 1;

fn vk() -> Key32 {
    Key32::from_bytes([7; 32])
}

fn seal(vault: VaultId, item: ItemId, body: &[u8]) -> Vec<u8> {
    seal_item(
        &vk(),
        vault.as_bytes(),
        item.as_bytes(),
        KV,
        body,
        &mut os_rng(),
    )
    .unwrap()
}

fn open(dir: &Path) -> (Store, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(1_000));
    let store = Store::open_at(dir.join("courier-ftp.db"), clock.clone()).unwrap();
    (store, clock)
}

async fn with_vault(store: &Store) -> VaultId {
    let vault = VaultId::new();
    store
        .vaults()
        .create(vault, VaultKind::Personal, None, KV, vec![9; 72])
        .await
        .unwrap();
    vault
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

async fn table_names(store: &Store) -> Vec<String> {
    store
        .read(|r| {
            let mut stmt = r
                .conn()
                .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")?;
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

// Fresh DB in a new data dir: every table, user_version = SCHEMA_VERSION, modes 0700 / 0600.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fresh_db_schema_and_permissions() {
    let home = tempfile::tempdir().unwrap();
    let data_dir = home.path().join("data").join("courier-ftp");
    let store = Store::open_in_dir(&data_dir).unwrap();
    assert_eq!(store.path(), data_dir.join(courier_ftp_store::DB_FILE_NAME));

    let mut tables = table_names(&store).await;
    tables.retain(|t| !t.starts_with("sqlite_"));
    let mut expected: Vec<String> = courier_ftp_store::schema::TABLES
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    expected.sort();
    assert_eq!(tables, expected);
    assert_eq!(user_version(&store).await, SCHEMA_VERSION);
    assert_eq!(SCHEMA_VERSION, 2);

    // Force WAL/SHM to exist, then check modes.
    with_vault(&store).await;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&data_dir), 0o700);
        assert_eq!(mode(data_dir.parent().unwrap()), 0o700);
        let db = store.path().to_path_buf();
        for p in [db.clone(), sibling(&db, "-wal"), sibling(&db, "-shm")] {
            assert_eq!(mode(&p), 0o600, "{}", p.display());
        }
    }
}

// PRAGMAs on the writer and on every reader.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pragmas_on_every_connection() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());

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

    let w = store.write(|w| Ok(pragmas(w.conn()))).await.unwrap();
    assert_eq!(w, ("wal".to_owned(), 1, 2, 1, 5000));

    // Hold every read open at once so each runs on a distinct pooled connection.
    let n = courier_ftp_store::READER_POOL_SIZE;
    let barrier = Arc::new(std::sync::Barrier::new(n));
    let mut handles = Vec::new();
    for _ in 0..n {
        let store = store.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            store
                .read(move |r| {
                    barrier.wait();
                    Ok(pragmas(r.conn()))
                })
                .await
                .unwrap()
        }));
    }
    for h in handles {
        assert_eq!(h.await.unwrap(), ("wal".to_owned(), 1, 2, 1, 5000));
    }
}

// A newer schema refuses to open and the file is byte-for-byte unchanged.
#[test]
fn newer_schema_is_refused_and_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("courier-ftp.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE future (x); PRAGMA user_version = 99;")
            .unwrap();
    }
    let before = std::fs::read(&path).unwrap();
    let err = Store::open_at(&path, Arc::new(ManualClock::new(0))).unwrap_err();
    match &err {
        StoreError::NewerSchema { found, supported } => {
            assert_eq!((*found, *supported), (99, SCHEMA_VERSION));
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(err.to_string().contains(
        "This database was created by a newer courier-ftp (schema 99). Please update courier-ftp."
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(!sibling(&path, "-wal").exists());
}

// A failing migration leaves the database at its previous version.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn migrations_are_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("courier-ftp.db");
    drop(Store::open_at(&path, Arc::new(ManualClock::new(0))).unwrap());

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

    // A later migration applies on top (the upgrade path).
    drop(store);
    let store = Store::open_with_migrations(
        &path,
        Arc::new(ManualClock::new(0)),
        &["CREATE TABLE added_later (x);"],
    )
    .unwrap();
    assert_eq!(user_version(&store).await, SCHEMA_VERSION + 1);
    drop(store);
    // ...after which this build refuses the file.
    assert!(matches!(
        Store::open_at(&path, Arc::new(ManualClock::new(0))),
        Err(StoreError::NewerSchema { found, supported })
            if found == SCHEMA_VERSION + 1 && supported == SCHEMA_VERSION
    ));
}

// Every local write is dirty and queued in the same transaction; edits coalesce
// and keep the oldest base revision.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outbox_coalescing() {
    let dir = tempfile::tempdir().unwrap();
    let (store, clock) = open(dir.path());
    let vault = with_vault(&store).await;
    let item = ItemId::new();

    // The item is at server revision 7.
    let env = seal(vault, item, b"v0");
    store
        .items()
        .apply_remote(
            vault,
            vec![RemoteItem {
                id: item,
                revision: 7,
                key_version: KV,
                envelope: env,
                deleted: false,
                local_pending: false,
            }],
            7,
        )
        .await
        .unwrap();
    assert!(!store.items().get(item).await.unwrap().unwrap().dirty);
    assert_eq!(store.outbox().pending_count().await.unwrap(), 0);

    for i in 0..10 {
        clock.advance(10);
        let env = seal(vault, item, format!("edit {i}").as_bytes());
        store
            .items()
            .put(vault, item, KV, env, false)
            .await
            .unwrap();
    }
    // The revision moves to 9 underneath, then another edit.
    store
        .write(move |w| {
            w.conn().execute(
                "UPDATE items SET revision = 9 WHERE id = ?1",
                [item.as_bytes()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    clock.advance(10);
    store
        .items()
        .put(vault, item, KV, seal(vault, item, b"edit 10"), false)
        .await
        .unwrap();
    store.outbox().enqueue(item, vault, 9).await.unwrap();

    let rows = store.outbox().list(vault).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].base_revision, 7);
    assert_eq!(rows[0].queued_at, clock.now_millis());
    assert_eq!(store.outbox().pending_count().await.unwrap(), 1);
    assert_eq!(
        store.outbox().pending_by_vault().await.unwrap(),
        [(vault, 1)]
    );
    let dirty = store.items().list_dirty(vault).await.unwrap();
    assert_eq!(dirty.len(), 1);
    assert!(dirty[0].dirty);
}

// Item write and outbox row are atomic: a failure after the write in the same
// transaction leaves neither, and a failing outbox insert fails the write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn item_write_and_outbox_are_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let vault = with_vault(&store).await;
    let item = ItemId::new();

    let env = seal(vault, item, b"body");
    let err = store
        .write(move |w| {
            w.put_item(vault, item, KV, &env, false)?;
            // Both rows are visible inside the transaction...
            assert!(w.as_read().get_item(item)?.is_some());
            assert_eq!(w.as_read().pending_count()?, 1);
            Err::<(), _>(StoreError::Busy)
        })
        .await;
    assert!(err.is_err());
    // ...and gone after the rollback.
    assert!(store.items().get(item).await.unwrap().is_none());
    assert_eq!(store.outbox().pending_count().await.unwrap(), 0);

    // Make the outbox insert fail: the item write is rolled back with it.
    store
        .write(|w| {
            w.conn().execute_batch(
                "CREATE TRIGGER no_outbox BEFORE INSERT ON outbox
                 BEGIN SELECT RAISE(ABORT, 'outbox broken'); END;",
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let env = seal(vault, item, b"body");
    assert!(
        store
            .items()
            .put(vault, item, KV, env, false)
            .await
            .is_err()
    );
    assert!(store.items().get(item).await.unwrap().is_none());

    // An unknown vault is refused (foreign key).
    store
        .write(|w| {
            w.conn().execute_batch("DROP TRIGGER no_outbox;")?;
            Ok(())
        })
        .await
        .unwrap();
    let other = VaultId::new();
    let env = seal(other, item, b"body");
    assert!(
        store
            .items()
            .put(other, item, KV, env, false)
            .await
            .is_err()
    );
    assert_eq!(store.outbox().pending_count().await.unwrap(), 0);
}

// Rebase updates the base; later enqueues keep it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebase_and_attempts() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let vault = with_vault(&store).await;
    let item = ItemId::new();
    // Queuing a local change wakes outbox listeners (the sync engine).
    let mut changes = store.outbox_changes();
    assert!(!changes.has_changed().unwrap());
    store
        .items()
        .put(vault, item, KV, seal(vault, item, b"a"), false)
        .await
        .unwrap();
    assert!(changes.has_changed().unwrap());
    changes.mark_unchanged();
    assert_eq!(
        store.outbox().list(vault).await.unwrap()[0].base_revision,
        0
    );
    store.meta().set("x", vec![1]).await.unwrap();
    assert!(!changes.has_changed().unwrap(), "no outbox row, no wake-up");

    store.outbox().rebase(item, 12).await.unwrap();
    store
        .items()
        .put(vault, item, KV, seal(vault, item, b"b"), false)
        .await
        .unwrap();
    store.outbox().enqueue(item, vault, 3).await.unwrap();
    assert_eq!(
        store.outbox().list(vault).await.unwrap()[0].base_revision,
        12
    );

    assert!(matches!(
        store.outbox().rebase(ItemId::new(), 1).await,
        Err(StoreError::NotFound)
    ));
    assert_eq!(store.outbox().bump_attempts(item).await.unwrap(), 1);
    assert_eq!(store.outbox().bump_attempts(item).await.unwrap(), 2);
    store.outbox().dequeue(item).await.unwrap();
    assert_eq!(store.outbox().pending_count().await.unwrap(), 0);
}

// An error in the 3rd item of 5 rolls back the whole page and the cursor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apply_remote_is_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let vault = with_vault(&store).await;

    let mut page: Vec<RemoteItem> = (1..=5)
        .map(|rev| {
            let id = ItemId::new();
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
    page[2].envelope = Vec::new();

    let err = store
        .items()
        .apply_remote(vault, page.clone(), 5)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::InvalidEnvelope(_)), "{err:?}");
    assert!(store.items().list(vault).await.unwrap().is_empty());
    let cursor = |s: &Store| {
        let s = s.clone();
        async move { s.vaults().get(vault).await.unwrap().unwrap().sync_cursor }
    };
    assert_eq!(cursor(&store).await, 0);

    let id = page[2].id;
    page[2].envelope = seal(vault, id, b"remote");
    store.items().apply_remote(vault, page, 5).await.unwrap();
    assert_eq!(store.items().list(vault).await.unwrap().len(), 5);
    assert_eq!(cursor(&store).await, 5);
}

// A merged dirty item stays dirty and is rebased; mark_pushed cleans only when no
// newer edit happened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apply_remote_rebases_and_mark_pushed() {
    let dir = tempfile::tempdir().unwrap();
    let (store, clock) = open(dir.path());
    let vault = with_vault(&store).await;
    let item = ItemId::new();
    store
        .items()
        .put(vault, item, KV, seal(vault, item, b"local"), false)
        .await
        .unwrap();

    let merged = RemoteItem {
        id: item,
        revision: 4,
        key_version: KV,
        envelope: seal(vault, item, b"merged"),
        deleted: false,
        local_pending: true,
    };
    store
        .items()
        .apply_remote(vault, vec![merged], 4)
        .await
        .unwrap();
    let row = store.items().get(item).await.unwrap().unwrap();
    assert!(row.dirty);
    assert_eq!(row.revision, 4);
    let ob = store.outbox().list(vault).await.unwrap();
    assert_eq!(ob[0].base_revision, 4);

    let pushed_at = ob[0].queued_at;
    clock.advance(5);
    store
        .items()
        .put(vault, item, KV, seal(vault, item, b"newer"), false)
        .await
        .unwrap();
    store.items().mark_pushed(item, 5, pushed_at).await.unwrap();
    assert!(store.items().get(item).await.unwrap().unwrap().dirty);
    let ob = store.outbox().list(vault).await.unwrap();
    assert_eq!(ob[0].base_revision, 5);

    store
        .items()
        .mark_pushed(item, 6, ob[0].queued_at)
        .await
        .unwrap();
    let row = store.items().get(item).await.unwrap().unwrap();
    assert!(!row.dirty);
    assert_eq!(row.revision, 6);
    assert_eq!(store.outbox().pending_count().await.unwrap(), 0);
}

// delete_vault removes its items, outbox and device-local rows in one transaction.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_vault_cascades() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let a = with_vault(&store).await;
    let b = with_vault(&store).await;
    for vault in [a, b] {
        for _ in 0..3 {
            let id = ItemId::new();
            store
                .items()
                .put(vault, id, KV, seal(vault, id, b"x"), false)
                .await
                .unwrap();
            store.device_local().touch_connected(id, 1).await.unwrap();
        }
    }
    store.vaults().delete(a).await.unwrap();

    assert!(store.items().list(a).await.unwrap().is_empty());
    assert!(store.outbox().list(a).await.unwrap().is_empty());
    assert_eq!(store.items().list(b).await.unwrap().len(), 3);
    assert_eq!(store.outbox().list(b).await.unwrap().len(), 3);
    assert_eq!(store.device_local().list().await.unwrap().len(), 3);
    assert_eq!(store.vaults().list().await.unwrap().len(), 1);
    assert!(matches!(
        store.vaults().delete(a).await,
        Err(StoreError::NotFound)
    ));

    let err = store
        .write(move |w| {
            w.delete_vault(b)?;
            Err::<(), _>(StoreError::Busy)
        })
        .await;
    assert!(err.is_err());
    assert_eq!(store.items().list(b).await.unwrap().len(), 3);
    assert_eq!(store.outbox().list(b).await.unwrap().len(), 3);
}

// 8 concurrent readers + 1 writer for 1 s; consistent snapshots.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_readers_and_writer() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let vault = with_vault(&store).await;
    let deadline = Instant::now() + Duration::from_secs(1);

    let writer = {
        let store = store.clone();
        tokio::spawn(async move {
            let mut written = 0_u64;
            while Instant::now() < deadline {
                let id = ItemId::new();
                let env = seal(vault, id, b"payload");
                store.items().put(vault, id, KV, env, false).await.unwrap();
                written += 1;
            }
            written
        })
    };
    let mut readers = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        readers.push(tokio::spawn(async move {
            let mut last = 0_u64;
            let mut reads = 0_u64;
            while Instant::now() < deadline {
                let (items, outbox) = store
                    .read(move |r| Ok((r.list_items(vault)?.len() as u64, r.pending_count()?)))
                    .await
                    .unwrap();
                // One snapshot: every item is dirty and queued exactly once.
                assert_eq!(items, outbox);
                assert!(items >= last);
                last = items;
                reads += 1;
            }
            reads
        }));
    }
    let written = writer.await.unwrap();
    for r in readers {
        assert!(r.await.unwrap() > 0);
    }
    assert!(written > 0);
    assert_eq!(
        store.items().list(vault).await.unwrap().len() as u64,
        written
    );
}

/// Writes `n` items to the store at `path` from its own `Store` instance.
async fn write_items(path: PathBuf, vault: VaultId, n: u64) -> Vec<ItemId> {
    let store = Store::open_at(&path, Arc::new(courier_ftp_store::SystemClock)).unwrap();
    let mut ids = Vec::new();
    for i in 0..n {
        let id = ItemId::new();
        let env = seal(vault, id, format!("item {i}").as_bytes());
        // A multi-statement transaction, to widen the window for interleaving.
        store
            .write(move |w| {
                w.put_item(vault, id, KV, &env, false)?;
                w.set_hlc_last(Hlc::from_u64(i))?;
                Ok(())
            })
            .await
            .unwrap();
        ids.push(id);
    }
    ids
}

fn integrity_ok(path: &Path) {
    let conn = rusqlite::Connection::open(path).unwrap();
    let res: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(res, "ok");
}

// Two store instances on one file write concurrently: no corruption, no
// deadlock, every write lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_store_instances_write_concurrently() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let vault = with_vault(&store).await;
    let path = store.path().to_path_buf();

    let a = tokio::spawn(write_items(path.clone(), vault, 200));
    let b = tokio::spawn(write_items(path.clone(), vault, 200));
    let (a, b) = tokio::time::timeout(Duration::from_secs(60), async {
        (a.await.unwrap(), b.await.unwrap())
    })
    .await
    .expect("writers deadlocked");

    let items = store.items().list(vault).await.unwrap();
    assert_eq!(items.len(), a.len() + b.len());
    assert_eq!(
        store.outbox().pending_count().await.unwrap(),
        items.len() as u64
    );
    assert_eq!(
        store.meta().hlc_last().await.unwrap(),
        Some(Hlc::from_u64(199))
    );
    drop(store);
    integrity_ok(&path);
}

const CHILD_DB: &str = "COURIER_FTP_STORE_CHILD_DB";
const CHILD_VAULT: &str = "COURIER_FTP_STORE_CHILD_VAULT";

// Helper run as a separate process by `two_processes_write_concurrently`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "child process helper"]
async fn child_writer() {
    let (Ok(path), Ok(vault)) = (std::env::var(CHILD_DB), std::env::var(CHILD_VAULT)) else {
        return;
    };
    write_items(PathBuf::from(path), vault.parse().unwrap(), 150).await;
}

// Two real processes write to the same database at the same time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_processes_write_concurrently() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let vault = with_vault(&store).await;
    let path = store.path().to_path_buf();

    let exe = std::env::current_exe().unwrap();
    let child = std::process::Command::new(exe)
        .args(["--ignored", "--exact", "child_writer", "--test-threads=1"])
        .env(CHILD_DB, &path)
        .env(CHILD_VAULT, vault.to_string())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mine = write_items(path.clone(), vault, 150).await;
    let status = tokio::task::spawn_blocking(move || {
        let mut child = child;
        child.wait().unwrap()
    })
    .await
    .unwrap();
    assert!(status.success(), "child writer failed: {status}");

    let items = store.items().list(vault).await.unwrap();
    assert_eq!(mine.len(), 150);
    assert_eq!(items.len(), 300);
    assert_eq!(store.outbox().pending_count().await.unwrap(), 300);
    drop(store);
    integrity_ok(&path);
}

// Read-only items reject writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_only_items_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let vault = with_vault(&store).await;
    let item = ItemId::new();
    store
        .items()
        .put(vault, item, KV, seal(vault, item, b"v1"), false)
        .await
        .unwrap();
    store.outbox().dequeue(item).await.unwrap();

    store.set_read_only(item, true);
    assert!(store.is_read_only(item));
    let err = store
        .items()
        .put(vault, item, KV, seal(vault, item, b"v2"), false)
        .await
        .unwrap_err();
    assert!(
        matches!(err, StoreError::ReadOnlyItem(id) if id == item),
        "{err:?}"
    );
    assert_eq!(store.outbox().pending_count().await.unwrap(), 0);

    store.set_read_only(item, false);
    store
        .items()
        .put(vault, item, KV, seal(vault, item, b"v2"), false)
        .await
        .unwrap();
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

// No plaintext on disk (DB, WAL, SHM): real site items with a canary name and
// password, the search labels in the TEMP index, and a refused plaintext write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_plaintext_item_data_on_disk() {
    const CANARY: &str = "PLAINTEXT-CANARY-SITE-42";
    const PW: &str = "PLAINTEXT-CANARY-PASSWORD";
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let vault = with_vault(&store).await;
    let device = DeviceId::new();
    let mut clock = HlcClock::default();

    let mut rows = Vec::new();
    for i in 0..50 {
        let id = ItemId::new();
        let mut site = Site::new(
            format!("{CANARY} {i}"),
            Protocol::Sftp,
            format!("{CANARY}.example.com"),
        );
        site.password = Some(SecretString::from(PW.to_owned()));
        let body = site.to_body(&mut clock, device).to_cbor().unwrap();
        assert!(body.windows(CANARY.len()).any(|w| w == CANARY.as_bytes()));
        store
            .items()
            .put(vault, id, KV, seal(vault, id, &body), false)
            .await
            .unwrap();
        rows.push(IndexRow {
            item_id: id,
            vault_id: vault,
            kind: ItemKind::Site,
            label: site.name.clone(),
            search: site.host.clone(),
        });
    }
    store.meta().set_hlc_last(clock.last()).await.unwrap();

    // Plaintext is refused outright, for items and device blobs.
    let id = ItemId::new();
    let err = store
        .items()
        .put(vault, id, KV, CANARY.repeat(4).into_bytes(), false)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::InvalidEnvelope(_)));
    // So is an unsealed CBOR body handed over by mistake.
    let plain = Site::new(CANARY, Protocol::Ftp, "h")
        .to_body(&mut clock, device)
        .to_cbor()
        .unwrap();
    let err = store
        .items()
        .put(vault, id, KV, plain, false)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::InvalidEnvelope(_)));
    let err = store
        .device_blobs()
        .put("queue", CANARY.as_bytes().to_vec())
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::InvalidEnvelope(_)));
    assert_no_canary(store.path(), CANARY.as_bytes());
    assert_no_canary(store.path(), PW.as_bytes());

    store.rebuild_temp_index(rows).await.unwrap();
    let hits = store
        .query_temp_index("canary-site-42 7".to_owned())
        .await
        .unwrap();
    assert_eq!(hits.len(), 1);
    // More writes while the index exists, then a checkpoint.
    let id = ItemId::new();
    store
        .items()
        .put(vault, id, KV, seal(vault, id, CANARY.as_bytes()), false)
        .await
        .unwrap();
    {
        let conn = rusqlite::Connection::open(store.path()).unwrap();
        conn.query_row("PRAGMA wal_checkpoint(FULL)", [], |_| Ok(()))
            .unwrap();
    }
    assert_no_canary(store.path(), CANARY.as_bytes());
    assert_no_canary(store.path(), PW.as_bytes());

    let tables = table_names(&store).await;
    assert!(!tables.contains(&"item_index".to_owned()));

    store.drop_temp_index().await.unwrap();
    assert!(
        store
            .query_temp_index(CANARY.to_owned())
            .await
            .unwrap()
            .is_empty()
    );
    let path = store.path().to_path_buf();
    drop(store);
    assert_no_canary(&path, CANARY.as_bytes());
    assert_no_canary(&path, PW.as_bytes());
}

// Random bytes → Corrupt with a helpful message, no panic, file untouched.
#[test]
fn corrupt_db_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("courier-ftp.db");
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
    let err = Store::open_at(&path, Arc::new(ManualClock::new(0))).unwrap_err();
    assert!(matches!(err, StoreError::Corrupt(_)), "{err:?}");
    let msg = err.to_string();
    assert!(msg.contains("backup"), "{msg}");
    assert!(msg.contains("courier-ftp.db"), "{msg}");
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

// sync_state is a singleton; the API only touches row 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_state_singleton() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let repo = store.sync_state();
    assert_eq!(repo.get().await.unwrap(), None);

    let state = SyncState {
        server_url: Some("https://sync.example".into()),
        device_id: Some(DeviceId::new()),
        tokens_enc: Some(vec![1, 2, 3]),
    };
    repo.set(state.clone()).await.unwrap();
    let state2 = SyncState {
        tokens_enc: Some(vec![4]),
        ..state.clone()
    };
    repo.set(state2.clone()).await.unwrap();
    assert_eq!(repo.get().await.unwrap(), Some(state2));

    let err = store
        .write(|w| {
            w.conn().execute(
                "INSERT INTO sync_state (id, server_url) VALUES (2, 'x')",
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
    repo.clear().await.unwrap();
    assert_eq!(repo.get().await.unwrap(), None);
}

// meta, device_local, device_blobs and local_approvals round trips.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn meta_device_local_blobs_and_approvals() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    use courier_ftp_store::meta::keys;
    let meta = store.meta();
    assert_eq!(meta.get(keys::KDF).await.unwrap(), None);
    meta.set(keys::KDF, vec![1, 2]).await.unwrap();
    meta.set(keys::KDF, vec![3]).await.unwrap();
    assert_eq!(meta.get(keys::KDF).await.unwrap(), Some(vec![3]));
    meta.delete(keys::KDF).await.unwrap();
    assert_eq!(meta.get(keys::KDF).await.unwrap(), None);

    // hlc_last never goes backwards.
    assert_eq!(meta.hlc_last().await.unwrap(), None);
    meta.set_hlc_last(Hlc::from_u64(50)).await.unwrap();
    meta.set_hlc_last(Hlc::from_u64(40)).await.unwrap();
    assert_eq!(meta.hlc_last().await.unwrap(), Some(Hlc::from_u64(50)));
    let device = DeviceId::new();
    meta.set_device_id(device).await.unwrap();
    assert_eq!(meta.device_id().await.unwrap(), Some(device));

    let item = ItemId::new();
    const DAY: i64 = 86_400_000;
    let dl = store.device_local();
    assert!((dl.touch_connected(item, 0).await.unwrap() - 1.0).abs() < 1e-9);
    assert!((dl.touch_connected(item, 14 * DAY).await.unwrap() - 1.5).abs() < 1e-9);
    dl.set_local_dir_override(item, Some("/home/me/site".into()))
        .await
        .unwrap();
    let row = dl.get(item).await.unwrap().unwrap();
    assert_eq!(row.last_connected_at, Some(14 * DAY));
    assert_eq!(row.local_dir_override.as_deref(), Some("/home/me/site"));
    assert_eq!(row.key_path_override, None);
    assert!((row.score_at(28 * DAY) - 0.75).abs() < 1e-9);
    dl.set_key_path_override(item, Some("/home/me/.ssh/id".into()))
        .await
        .unwrap();
    let row = dl.get(item).await.unwrap().unwrap();
    assert_eq!(row.key_path_override.as_deref(), Some("/home/me/.ssh/id"));
    assert_eq!(row.local_dir_override.as_deref(), Some("/home/me/site"));
    // A moved row keeps the key path; a deleted one is gone.
    let moved = ItemId::new();
    store
        .write(move |w| w.move_device_local(item, moved))
        .await
        .unwrap();
    let row = dl.get(moved).await.unwrap().unwrap();
    assert_eq!(row.key_path_override.as_deref(), Some("/home/me/.ssh/id"));
    store
        .write(move |w| w.move_device_local(moved, item))
        .await
        .unwrap();
    let gone = ItemId::new();
    dl.set_key_path_override(gone, Some("/k".into()))
        .await
        .unwrap();
    dl.delete(gone).await.unwrap();
    assert!(dl.get(gone).await.unwrap().is_none());
    assert!(dl.get(item).await.unwrap().is_some());
    // Device-local data is never queued for sync.
    assert_eq!(store.outbox().pending_count().await.unwrap(), 0);

    let blobs = store.device_blobs();
    let vault = VaultId::from_bytes([0; 16]);
    let blob_id = ItemId::from_bytes([1; 16]);
    let queue = seal(vault, blob_id, b"queued transfers");
    blobs
        .put(
            courier_ftp_store::device_blobs::names::TRANSFER_QUEUE,
            queue.clone(),
        )
        .await
        .unwrap();
    assert_eq!(
        blobs
            .get(courier_ftp_store::device_blobs::names::TRANSFER_QUEUE)
            .await
            .unwrap(),
        Some(queue)
    );
    assert_eq!(blobs.list().await.unwrap(), ["transfer_queue"]);
    assert!(blobs.delete("transfer_queue").await.unwrap());
    assert!(!blobs.delete("transfer_queue").await.unwrap());

    let approvals = store.approvals();
    approvals.put(item, "proxy.command", [5; 32]).await.unwrap();
    approvals.put(item, "proxy.command", [6; 32]).await.unwrap();
    let a = approvals.get(item, "proxy.command").await.unwrap().unwrap();
    assert_eq!(a.value_sha256, [6; 32]);
    assert_eq!(approvals.list().await.unwrap().len(), 1);
    assert!(approvals.delete(item, "proxy.command").await.unwrap());
    assert_eq!(store.outbox().pending_count().await.unwrap(), 0);

    // Data survives a reopen.
    drop(store);
    let (store, _) = open(dir.path());
    assert!(store.device_local().get(item).await.unwrap().is_some());
    assert_eq!(
        store.meta().hlc_last().await.unwrap(),
        Some(Hlc::from_u64(50))
    );
}
