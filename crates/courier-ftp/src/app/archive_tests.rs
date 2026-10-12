//! T73: settings and vault backups through the app with the real vault
//! engine (`Argon2Cost::TEST`): export from the settings screen, import on
//! "another machine" (full restore and a partial import into a new folder),
//! a wrong passphrase, and the first-run "Restore from a .cftp-backup"
//! (T60), including the "Forgot password?" path.

use std::path::{Path, PathBuf};

use courier_ftp_core::{
    model::{
        Direction, LocalPath, Protocol,
        item::{self, ItemId, ItemKind},
    },
    queue::{NewItem, QueueServer, lock_queue},
    vault::{ItemVault, ItemVaultExt, MemKeyring},
};
use crossterm::event::KeyCode;
use pretty_assertions::assert_eq;
use secrecy::{ExposeSecret, SecretString};

use super::vault_tests::{Rig, STRONG, config, initialised, start};
use super::*;
use crate::ui::{VaultPage, VaultView};

const PASS: &str = "backup passphrase";
const CANARY: &str = "CANARY-T73-APP-4b1e";

fn config_in(dir: &Path) -> Config {
    let mut config = config();
    config.config.config_dir = dir.join("config");
    config
}

/// A started app with a new vault in `dir/vault` and its config in
/// `dir/config`, sites loaded.
async fn machine(dir: &Path, keyring: &MemKeyring) -> Rig {
    let mut rig = start(&dir.join("vault"), keyring, config_in(dir)).await;
    rig.create(STRONG, false).await;
    rig.until("sites loaded", |a| a.site_snapshot.is_some())
        .await;
    rig
}

fn message(app: &App) -> String {
    app.screen
        .settings_view()
        .and_then(|v| v.message().cloned())
        .map(|(m, _)| m)
        .unwrap_or_default()
}

fn page(rig: &Rig) -> Option<VaultPage> {
    rig.app.screen.vault_view().map(VaultView::page)
}

/// The source machine: a site with a password, a site bookmark, a history
/// entry, a trusted host key, a queued download, a changed setting and a
/// keybinding in `config.json`. Returns the site id.
async fn fill(rig: &mut Rig, dir: &Path) -> ItemId {
    let engine = rig.engine();
    let site = ItemId::new();
    let mut view = item::Site::new("web", Protocol::Sftp, "web.example.com");
    view.user = "deploy".into();
    view.password = Some(SecretString::from(CANARY));
    engine.put_view(site, None, view).await.unwrap();
    engine
        .put_view(
            ItemId::new(),
            None,
            item::Bookmark {
                name: "logs".into(),
                site_id: Some(site),
                remote_dir: Some("/var/log".into()),
                ..item::Bookmark::default()
            },
        )
        .await
        .unwrap();
    engine
        .put_view(
            ItemId::new(),
            None,
            item::HistoryEntry::new(Protocol::Ftp, "old.example.com"),
        )
        .await
        .unwrap();
    engine
        .put_view(
            ItemId::new(),
            None,
            item::KnownHost {
                host: "web.example.com".into(),
                port: 22,
                key_type: "ssh-ed25519".into(),
                public_key: "AAAAC3".into(),
                ..item::KnownHost::default()
            },
        )
        .await
        .unwrap();
    lock_queue(&rig.app.transfers.queue).add_batch(
        [NewItem::file(
            QueueServer::Site(site),
            Direction::Download,
            LocalPath::new("/tmp/a.txt"),
            courier_ftp_core::model::RemotePath::new("/pub/a.txt"),
            Some(3),
        )],
        time::OffsetDateTime::now_utc(),
    );
    let config_dir = dir.join("config");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.json"),
        r#"{"keybindings": {"Normal": {"<F12>": "Quit"}}}"#,
    )
    .unwrap();
    let mut settings = rig.app.settings.clone();
    settings.connection.timeout_secs = 45;
    rig.app.apply_settings(settings);
    site
}

/// Export everything from the settings screen to `path`.
async fn export_all(rig: &mut Rig, path: &Path) {
    rig.app.dispatch(Action::Settings).unwrap();
    rig.alt('e');
    // settings, sites, passwords, history, trust, queue, format, file
    for _ in 0..7 {
        rig.key(KeyCode::Tab);
    }
    rig.replace_text(&path.display().to_string());
    rig.key(KeyCode::Tab);
    rig.typed(PASS);
    rig.key(KeyCode::Tab);
    rig.typed(PASS);
    rig.alt('e');
    rig.until("exported", |a| message(a).starts_with("Exported"))
        .await;
}

/// Open `path` in the settings screen's Import with `pass`.
async fn open_import(rig: &mut Rig, path: &Path, pass: &str) {
    rig.app.dispatch(Action::Settings).unwrap();
    rig.alt('i');
    rig.replace_text(&path.display().to_string());
    rig.key(KeyCode::Tab);
    rig.typed(pass);
    rig.alt('o');
}

async fn source(dir: &Path) -> (Rig, ItemId, PathBuf) {
    let mut rig = machine(dir, &MemKeyring::new()).await;
    let site = fill(&mut rig, dir).await;
    let file = dir.join("setup.cftp-backup");
    export_all(&mut rig, &file).await;
    (rig, site, file)
}

#[tokio::test]
async fn export_then_full_restore_on_another_machine() {
    let a = tempfile::tempdir().unwrap();
    let (_src, site, file) = source(a.path()).await;
    let bytes = std::fs::read(&file).unwrap();
    assert!(!bytes.windows(CANARY.len()).any(|w| w == CANARY.as_bytes()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let b = tempfile::tempdir().unwrap();
    let mut dst = machine(b.path(), &MemKeyring::new()).await;
    open_import(&mut dst, &file, PASS).await;
    dst.until("import choices", |a| a.import_archive.is_some())
        .await;
    // Settings: replace; sites: restore in place.
    dst.key(KeyCode::Tab);
    dst.key(KeyCode::Right);
    for _ in 0..2 {
        dst.key(KeyCode::Tab);
    }
    dst.key(KeyCode::Right);
    // Off the select (it takes letters, Alt or not, as a jump).
    dst.key(KeyCode::Tab);
    dst.alt('i');
    dst.until("imported", |a| message(a).starts_with("Settings replaced"))
        .await;
    dst.until("sites reloaded", |a| {
        a.site_snapshot
            .as_ref()
            .is_some_and(|s| s.tree.site(site).is_some())
    })
    .await;

    assert_eq!(dst.app.settings.connection.timeout_secs, 45);
    let config: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(b.path().join("config/config.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(config["keybindings"]["Normal"]["<F12>"], "Quit");
    assert_eq!(config["settings"]["connection"]["timeout_secs"], 45);

    let engine = dst.engine();
    let (_, web) = engine
        .list_views::<item::Site>()
        .await
        .unwrap()
        .into_iter()
        .find(|(i, _)| i.id == site)
        .unwrap();
    assert_eq!(web.password.unwrap().expose_secret(), CANARY);
    for kind in [
        ItemKind::Bookmark,
        ItemKind::HistoryEntry,
        ItemKind::KnownHost,
    ] {
        assert_eq!(engine.list(kind).await.unwrap().len(), 1, "{kind}");
    }
    let queue = lock_queue(&dst.app.transfers.queue);
    assert_eq!(queue.len(), 1);
}

#[tokio::test]
async fn partial_import_into_a_new_folder_and_a_wrong_passphrase() {
    let a = tempfile::tempdir().unwrap();
    let (_src, site, file) = source(a.path()).await;

    let b = tempfile::tempdir().unwrap();
    let mut dst = machine(b.path(), &MemKeyring::new()).await;
    open_import(&mut dst, &file, "not the passphrase").await;
    dst.until("refused", |a| message(a).starts_with("Wrong passphrase"))
        .await;
    assert!(dst.app.import_archive.is_none());

    // Again with the right one.
    open_import(&mut dst, &file, PASS).await;
    dst.until("import choices", |a| a.import_archive.is_some())
        .await;
    // Untick settings and history; sites go into a new folder.
    dst.key(KeyCode::Char(' '));
    for _ in 0..4 {
        dst.key(KeyCode::Tab);
    }
    dst.key(KeyCode::Char(' '));
    dst.alt('i');
    dst.until("imported", |a| message(a).starts_with("Vault items"))
        .await;
    dst.until("sites reloaded", |a| {
        a.site_snapshot
            .as_ref()
            .is_some_and(|s| s.tree.roots().len() == 1)
    })
    .await;

    // Settings untouched.
    assert_ne!(dst.app.settings.connection.timeout_secs, 45);
    assert!(!b.path().join("config/config.json").exists());
    let engine = dst.engine();
    assert!(
        engine
            .list(ItemKind::HistoryEntry)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(engine.list(ItemKind::KnownHost).await.unwrap().len(), 1);
    // The site is a new item inside "Imported <date>".
    let snapshot = dst.app.site_snapshot.clone().unwrap();
    let folder = &snapshot.tree.roots()[0];
    assert!(folder.name().starts_with("Imported "), "{}", folder.name());
    let path = format!("{}/web", folder.name());
    let web = snapshot.tree.find_site(&path).unwrap();
    assert_ne!(web.id, site);
    // Its queue item follows it.
    let queue = lock_queue(&dst.app.transfers.queue);
    let servers: Vec<_> = queue
        .items(courier_ftp_core::queue::QueueList::Queued)
        .map(|i| i.server.clone())
        .collect();
    assert_eq!(servers, [QueueServer::Site(web.id)]);
}

#[tokio::test]
async fn first_run_restores_a_backup() {
    let a = tempfile::tempdir().unwrap();
    let (_src, site, file) = source(a.path()).await;

    let b = tempfile::tempdir().unwrap();
    let mut rig = start(
        &b.path().join("vault"),
        &MemKeyring::new(),
        config_in(b.path()),
    )
    .await;
    assert_eq!(page(&rig), Some(VaultPage::Create));
    assert!(rig.screen(100, 30).contains("Restore backup…"));
    rig.alt('r');
    assert_eq!(page(&rig), Some(VaultPage::Restore));
    rig.typed(&file.display().to_string());
    rig.key(KeyCode::Tab);
    rig.typed("wrong");
    rig.key(KeyCode::Enter);
    rig.until("refused", |a| {
        a.screen
            .vault_view()
            .is_some_and(|v| !v.is_busy() && !v.has_backup())
    })
    .await;
    assert!(rig.screen(100, 30).contains("Wrong passphrase"));
    rig.typed(PASS);
    rig.key(KeyCode::Enter);
    rig.until("backup opened", |a| {
        a.screen.vault_view().is_some_and(VaultView::has_backup)
    })
    .await;
    assert_eq!(page(&rig), Some(VaultPage::Create));
    let text = rig.screen(100, 34);
    assert!(text.contains("Backup opened"), "{text}");
    assert!(text.contains("Sites and bookmarks: 1 site"), "{text}");

    rig.create(STRONG, false).await;
    rig.until("restored", |a| {
        a.site_snapshot
            .as_ref()
            .is_some_and(|s| s.tree.site(site).is_some())
    })
    .await;
    assert_eq!(rig.app.settings.connection.timeout_secs, 45);
    assert_eq!(lock_queue(&rig.app.transfers.queue).len(), 1);
    assert!(rig.app.screen.has_modal(), "summary shown");
}

#[tokio::test]
async fn forgot_password_can_restore_a_backup() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    initialised(dir.path(), &keyring, false).await;
    let mut rig = start(dir.path(), &keyring, config()).await;
    rig.alt('f');
    rig.key(KeyCode::Enter); // Restore from a .cftp-backup file
    assert_eq!(page(&rig), Some(VaultPage::NewVault));
    assert!(rig.screen(80, 24).contains("Restore from a backup?"));
    rig.alt('m');
    rig.settle().await;
    assert_eq!(page(&rig), Some(VaultPage::Restore));
    // Back leads to the first-run form.
    rig.key(KeyCode::Esc);
    assert_eq!(page(&rig), Some(VaultPage::Create));
}
