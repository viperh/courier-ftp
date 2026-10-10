//! The Site Manager's storage (T31) over the real vault engine and the
//! store's `device_local` table: save, lock, restart, unlock, connect.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use courier_ftp_core::model::item::ItemKind;
use courier_ftp_core::model::{LocalPath, LogonType, Protocol};
use courier_ftp_core::sites::{Site, SiteKey, SiteLocalStore, SiteLogon, SiteManager};
use courier_ftp_core::vault::{ItemVault, MemKeyring};
use courier_ftp_crypto::kdf::Argon2Cost;
use courier_ftp_store::vault::VaultEngine;
use courier_ftp_store::{ManualClock, Store};
use pretty_assertions::assert_eq;
use secrecy::{ExposeSecret, SecretString};

const PW: &str = "correct horse battery staple violin";

fn pw(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

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

    /// A fresh store and engine (a restart).
    fn engine(&self) -> (Arc<VaultEngine>, Store) {
        let store =
            Store::open_at(self.dir.path().join("courier-ftp.db"), self.clock.clone()).unwrap();
        let engine = VaultEngine::new(
            store.clone(),
            Arc::new(self.keyring.clone()),
            Argon2Cost::TEST,
        );
        (Arc::new(engine), store)
    }
}

async fn manager(engine: &Arc<VaultEngine>, store: &Store) -> SiteManager {
    SiteManager::load(engine.clone(), Arc::new(store.clone()))
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saved_sites_connect_after_a_restart_without_asking() {
    let fx = Fixture::new();
    let (engine, store) = fx.engine();
    engine.initialize(&pw(PW), false).await.unwrap();
    let mut m = manager(&engine, &store).await;
    let work = m.add_folder(None, "Work").await.unwrap();
    let prod = m.add_folder(Some(work), "Prödüction").await.unwrap();

    let mut web = Site::new("web01", Protocol::Sftp, "web01.example.com");
    web.parent = Some(prod);
    web.logon = SiteLogon::Normal {
        user: "deploy".into(),
        password: Some(pw("site-password")),
    };
    web.default_local_dir = Some(LocalPath::new("/srv/www"));
    let web_id = web.id;
    m.save_site(web).await.unwrap();

    let mut keyed = Site::new("keyed", Protocol::Sftp, "k.example.com");
    keyed.parent = Some(work);
    keyed.logon = SiteLogon::KeyFile {
        user: "deploy".into(),
        key: Some(SiteKey::File(LocalPath::new("/home/me/.ssh/id_ed25519"))),
        passphrase: Some(pw("key-passphrase")),
    };
    let keyed_id = keyed.id;
    m.save_site(keyed).await.unwrap();
    m.record_connected(web_id).await.unwrap();
    let before = m.tree().clone();
    engine.lock().await;
    drop((m, engine, store));

    // Restart and unlock.
    let (engine, store) = fx.engine();
    engine.unlock(&pw(PW)).await.unwrap();
    let m = manager(&engine, &store).await;
    assert_eq!(m.tree(), &before);
    let web = m.find_site("Work/Prödüction/web01").unwrap();
    assert_eq!(web.id, web_id);
    assert_eq!(web.default_local_dir, Some(LocalPath::new("/srv/www")));
    assert!(web.last_connected_at.is_some());

    let connect = m.connect(web_id).await.unwrap();
    assert!(!connect.info.logon.needs_prompt());
    assert_eq!(
        connect.info.logon.password().unwrap().expose_secret(),
        "site-password"
    );

    // The key path came from this device's table, not the synced item.
    let connect = m.connect(keyed_id).await.unwrap();
    assert_eq!(
        connect.info.logon,
        LogonType::KeyFile {
            user: "deploy".into(),
            path: LocalPath::new("/home/me/.ssh/id_ed25519"),
        }
    );
    let item = engine.get(keyed_id).await.unwrap().unwrap();
    assert!(item.body.get("logon.key_path").is_none());
    assert!(item.body.get("logon.passphrase").is_some());
    let local = store.get(keyed_id).await.unwrap();
    assert_eq!(
        local.key_path,
        Some(LocalPath::new("/home/me/.ssh/id_ed25519"))
    );

    // Deleting removes the items and the device-local rows.
    let mut m = m;
    assert_eq!(m.delete(work).await.unwrap(), 4);
    assert!(engine.list(ItemKind::Site).await.unwrap().is_empty());
    assert!(engine.list(ItemKind::SiteFolder).await.unwrap().is_empty());
    assert!(store.device_local().get(web_id).await.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn store_passwords_off_keeps_site_passwords_out_of_the_vault() {
    let fx = Fixture::new();
    let (engine, store) = fx.engine();
    engine.initialize(&pw(PW), false).await.unwrap();
    engine.set_store_passwords(false);
    let mut m = manager(&engine, &store).await;
    let mut s = Site::new("web", Protocol::Sftp, "h");
    s.logon = SiteLogon::Normal {
        user: "u".into(),
        password: Some(pw("never-stored")),
    };
    let id = s.id;
    m.save_site(s).await.unwrap();
    let connect = m.connect(id).await.unwrap();
    assert_eq!(
        connect.info.logon,
        LogonType::AskForPassword { user: "u".into() }
    );
    let item = engine.get(id).await.unwrap().unwrap();
    assert!(item.body.get("logon.password").is_none());
}
