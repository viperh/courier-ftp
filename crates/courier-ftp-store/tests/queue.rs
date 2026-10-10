//! The persisted transfer queue (T40) over the real vault engine: device blobs
//! sealed under the LMK-wrapped device key, round trip across a restart,
//! nothing written while locked, no plaintext on disk.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};

use courier_ftp_core::events::TransferId;
use courier_ftp_core::model::{Direction, LocalPath, Protocol, RemotePath, ServerAddress};
use courier_ftp_core::queue::{
    ItemState, LossReason, NewItem, PersistError, QUEUE_BLOB, Queue, QueueList, QueuePersister,
    QueueServer, QuitCheck, SaveOutcome, lock_queue,
};
use courier_ftp_core::vault::{DeviceBlobVault, MemKeyring, VaultError};
use courier_ftp_crypto::kdf::Argon2Cost;
use courier_ftp_store::device_blobs::names;
use courier_ftp_store::meta::keys;
use courier_ftp_store::vault::VaultEngine;
use courier_ftp_store::{ManualClock, Store};
use pretty_assertions::assert_eq;
use secrecy::SecretString;
use time::macros::datetime;

const PW: &str = "correct horse battery staple violin";
const HOST: &str = "canary-host-5d1e.example.com";
const QUICK_PW: &str = "canary-quick-pw-91c4";
const REMOTE: &str = "/canary-remote-path-77ab/file.bin";
const NOW: time::OffsetDateTime = datetime!(2026-10-10 12:00 UTC);

struct Fixture {
    dir: tempfile::TempDir,
    clock: Arc<ManualClock>,
    keyring: MemKeyring,
}

impl Fixture {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            clock: Arc::new(ManualClock::new(1_800_000_000_000)),
            keyring: MemKeyring::new(),
        }
    }

    fn engine(&self) -> VaultEngine {
        let store =
            Store::open_at(self.dir.path().join("courier-ftp.db"), self.clock.clone()).unwrap();
        VaultEngine::new(store, Arc::new(self.keyring.clone()), Argon2Cost::TEST)
    }

    /// Every byte of every file in the data directory.
    fn disk(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(self.dir.path()).unwrap() {
            let p = e.unwrap().path();
            if p.is_file() {
                out.extend(std::fs::read(p).unwrap());
            }
        }
        out
    }
}

fn pw(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

fn items() -> Vec<NewItem> {
    let quick = QueueServer::Quick {
        address: ServerAddress::new(Protocol::Sftp, HOST),
        password: Some(pw(QUICK_PW)),
    };
    vec![
        NewItem::file(
            quick,
            Direction::Download,
            LocalPath::new("/tmp/file.bin"),
            RemotePath::new(REMOTE),
            Some(1000),
        ),
        NewItem::file(
            QueueServer::Site(courier_ftp_core::model::item::ItemId::new()),
            Direction::Upload,
            LocalPath::new("/tmp/up.txt"),
            RemotePath::new("/up.txt"),
            None,
        ),
    ]
}

fn sample() -> Queue {
    let mut q = Queue::default();
    let ids = q.add_batch(items(), NOW);
    q.start(ids[0]).unwrap();
    q.set_progress(ids[0], 500).unwrap();
    q
}

fn persister(engine: &VaultEngine, queue: Queue) -> Arc<QueuePersister> {
    QueuePersister::new(
        Arc::new(Mutex::new(queue)),
        Arc::new(engine.clone()) as Arc<dyn DeviceBlobVault>,
        true,
    )
}

#[test]
fn blob_names_match() {
    assert_eq!(names::TRANSFER_QUEUE, QUEUE_BLOB);
}

#[tokio::test]
async fn queue_survives_restart_and_active_items_come_back_queued() {
    let fx = Fixture::new();
    let engine = fx.engine();
    engine.initialize(&pw(PW), false).await.unwrap();
    let p = persister(&engine, sample());
    assert_eq!(p.restore().await.unwrap(), 0);
    assert_eq!(p.save_now().await.unwrap(), SaveOutcome::Saved);
    // The device key was created and wrapped under the LMK.
    assert!(
        engine
            .store()
            .meta()
            .get(keys::DEVICE_KEY_WRAPPED)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(engine.live_keys(), 3);
    engine.lock().await;
    assert_eq!(engine.live_keys(), 0);

    // Restart: a new engine over the same database.
    let engine = fx.engine();
    engine.unlock(&pw(PW)).await.unwrap();
    let p = persister(&engine, Queue::default());
    assert_eq!(p.restore().await.unwrap(), 2);
    let q = lock_queue(p.queue());
    assert!(!q.is_processing());
    let first = q.get(TransferId(1)).unwrap();
    assert_eq!(first.state, ItemState::Queued);
    assert_eq!(first.remote, RemotePath::new(REMOTE));
    assert_eq!(
        first.server,
        QueueServer::Quick {
            address: ServerAddress::new(Protocol::Sftp, HOST),
            password: Some(pw(QUICK_PW)),
        }
    );
    assert_eq!(q.count(QueueList::Queued), 2);
}

#[tokio::test]
async fn nothing_is_written_while_locked_and_nothing_in_plaintext() {
    let fx = Fixture::new();
    let engine = fx.engine();
    engine.initialize(&pw(PW), false).await.unwrap();
    engine.lock().await;

    // Locked (or skipped) vault: no write, no device key, a quit warning.
    let p = persister(&engine, Queue::default());
    assert!(matches!(
        p.restore().await,
        Err(PersistError::Vault(VaultError::Locked))
    ));
    lock_queue(p.queue()).add_batch(items().into_iter().take(1), NOW);
    assert_eq!(p.save_now().await.unwrap(), SaveOutcome::Locked);
    assert_eq!(
        p.quit_check().await,
        QuitCheck::WouldLose {
            items: 1,
            reason: LossReason::VaultLocked
        }
    );
    assert!(
        engine
            .store()
            .device_blobs()
            .get(QUEUE_BLOB)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        engine
            .store()
            .meta()
            .get(keys::DEVICE_KEY_WRAPPED)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        DeviceBlobVault::save_blob(&engine, QUEUE_BLOB, b"x").await,
        Err(VaultError::Locked)
    );

    // After unlocking: restore (none saved), save, and the bytes on disk are
    // an envelope without the host, path or password.
    engine.unlock(&pw(PW)).await.unwrap();
    assert_eq!(p.restore().await.unwrap(), 0);
    assert_eq!(p.save_now().await.unwrap(), SaveOutcome::Saved);
    let env = engine
        .store()
        .device_blobs()
        .get(QUEUE_BLOB)
        .await
        .unwrap()
        .unwrap();
    for canary in [HOST, QUICK_PW, REMOTE] {
        assert!(!contains(&env, canary), "{canary} in the envelope");
    }
    engine.lock().await;
    drop(p);
    drop(engine);
    let disk = fx.disk();
    for canary in [HOST, QUICK_PW, REMOTE] {
        assert!(!contains(&disk, canary), "{canary} on disk");
    }
}

#[tokio::test]
async fn blobs_are_bound_to_their_name_and_key() {
    let fx = Fixture::new();
    let engine = fx.engine();
    engine.initialize(&pw(PW), false).await.unwrap();
    engine.save_blob("a", b"hello").await.unwrap();
    assert_eq!(
        engine.load_blob("a").await.unwrap().unwrap().as_slice(),
        b"hello"
    );
    assert_eq!(engine.load_blob("missing").await.unwrap(), None);
    // Moving the envelope to another name is detected.
    let env = engine
        .store()
        .device_blobs()
        .get("a")
        .await
        .unwrap()
        .unwrap();
    engine.store().device_blobs().put("b", env).await.unwrap();
    assert!(matches!(
        engine.load_blob("b").await,
        Err(VaultError::Corrupt(_))
    ));
    assert!(engine.delete_blob("b").await.unwrap());
    // A second engine (another process) reuses the stored device key.
    let other = fx.engine();
    other.unlock(&pw(PW)).await.unwrap();
    assert_eq!(
        other.load_blob("a").await.unwrap().unwrap().as_slice(),
        b"hello"
    );
    // Deleting works while locked.
    other.lock().await;
    assert!(other.delete_blob("a").await.unwrap());
}
