//! T73 archives over the real vault engine: a full backup restored into a
//! fresh vault on "another machine", T30's `export_backup` files read as
//! archives, and a wrong passphrase.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use courier_ftp_core::archive::{self, Archive, ExportChoice, ImportChoice, Section};
use courier_ftp_core::model::Protocol;
use courier_ftp_core::model::item::{ItemKind, UnixMillis};
use courier_ftp_core::sites::{Bookmark, Bookmarks, History, Site, SiteLogon, SiteManager};
use courier_ftp_core::vault::backup::BackupError;
use courier_ftp_core::vault::{ItemVault, MemKeyring};
use courier_ftp_crypto::kdf::Argon2Cost;
use courier_ftp_crypto::keys::os_rng;
use courier_ftp_store::vault::VaultEngine;
use courier_ftp_store::{ManualClock, Store};
use pretty_assertions::assert_eq;
use secrecy::{ExposeSecret, SecretString};

const PW: &str = "correct horse battery staple violin";

fn pw(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

async fn engine(dir: &std::path::Path) -> (Arc<VaultEngine>, Store) {
    let store = Store::open_at(
        dir.join("courier-ftp.db"),
        Arc::new(ManualClock::new(1_800_000_000_000)),
    )
    .unwrap();
    let engine = VaultEngine::new(store.clone(), Arc::new(MemKeyring::new()), Argon2Cost::TEST);
    engine.initialize(&pw(PW), false).await.unwrap();
    (Arc::new(engine), store)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_backup_restores_into_a_fresh_vault() {
    let a = tempfile::tempdir().unwrap();
    let (src, src_store) = engine(a.path()).await;
    let mut sites = SiteManager::load(src.clone(), Arc::new(src_store.clone()))
        .await
        .unwrap();
    let work = sites.add_folder(None, "Work").await.unwrap();
    let mut web = Site::new("web01", Protocol::Sftp, "web01.example.com");
    web.parent = Some(work);
    web.logon = SiteLogon::Normal {
        user: "deploy".into(),
        password: Some(pw("site-password")),
    };
    let web_id = web.id;
    sites.save_site(web).await.unwrap();
    let mut bookmarks = Bookmarks::load(src.clone(), Arc::new(src_store.clone()))
        .await
        .unwrap();
    bookmarks
        .add(Bookmark::for_site(
            web_id,
            "logs",
            courier_ftp_core::model::RemotePath::new("/var/log"),
        ))
        .await
        .unwrap();
    let history = History::new(src.clone(), Arc::new(src_store.clone()));
    history
        .record(&courier_ftp_core::backend::ConnectInfo::new(
            courier_ftp_core::model::ServerAddress::new(Protocol::Ftp, "old.example.com"),
            courier_ftp_core::model::LogonType::Anonymous,
        ))
        .await
        .unwrap();

    let mut archive = Archive::new(UnixMillis::now().0);
    archive.items = archive::collect_items(&*src, &ExportChoice::ALL)
        .await
        .unwrap();
    archive.passwords = true;
    let file = archive::seal(&archive, &pw("backup"), src.cost(), &mut os_rng()).unwrap();
    assert!(matches!(
        archive::open(&file, &pw("nope")),
        Err(BackupError::Decrypt)
    ));
    let opened = archive::open(&file, &pw("backup")).unwrap();
    assert_eq!(
        opened.sections(),
        vec![Section::Sites, Section::History, Section::Trust]
    );

    // Another machine: a new vault with another master password.
    let b = tempfile::tempdir().unwrap();
    let (dst, dst_store) = engine(b.path()).await;
    let report = archive::restore_items(&*dst, &opened, &ImportChoice::everything(&opened))
        .await
        .unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert_eq!(report.added, 4);

    // Restart the new machine's vault: everything is stored.
    dst.lock().await;
    dst.unlock(&pw(PW)).await.unwrap();
    let restored = SiteManager::load(dst.clone(), Arc::new(dst_store.clone()))
        .await
        .unwrap();
    // Same tree and ids (in this machine's personal vault).
    assert_eq!(restored.find_site("Work/web01").unwrap().id, web_id);
    assert_eq!(
        restored.tree().get(work).map(|n| n.name().to_owned()),
        Some("Work".to_owned())
    );
    let connect = restored.connect(web_id).await.unwrap();
    assert_eq!(
        connect.info.logon.password().unwrap().expose_secret(),
        "site-password"
    );
    for kind in [ItemKind::Bookmark, ItemKind::HistoryEntry] {
        assert_eq!(dst.list(kind).await.unwrap().len(), 1, "{kind}");
    }

    // T30's `export_backup` (a plain item list) reads as an archive too.
    let t30 = src.export_backup(&pw("backup")).await.unwrap();
    let old = archive::open(&t30, &pw("backup")).unwrap();
    assert_eq!(old.count(ItemKind::Site), 1);
    assert_eq!(old.count(ItemKind::HistoryEntry), 1);
}
