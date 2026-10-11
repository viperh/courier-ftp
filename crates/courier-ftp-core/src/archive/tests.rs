#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use courier_ftp_crypto::kdf::Argon2Cost;
use courier_ftp_crypto::keys::os_rng;
use pretty_assertions::assert_eq;
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;

use super::*;
use crate::model::item::{
    Bookmark, HistoryEntry, ItemId, KnownHost, ProxyCredential, Site, SiteFolder, SshKey,
    TrustedCert,
};
use crate::model::{Direction, Protocol};
use crate::queue::{NewItem, Queue, QueueServer};
use crate::settings::{GenericProxy, ProxyServer};
use crate::vault::{ItemVaultExt, MemItemVault};

const CANARY: &str = "CANARY-T73-PW-7f3a";

fn pw(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

/// A vault with a folder, two sites (one in the folder, using a vault SSH
/// key), bookmarks, history, a host key, a certificate and a proxy
/// password. Returns the ids `(folder, site_in_folder, proxy)`.
async fn filled() -> (Arc<MemItemVault>, ItemId, ItemId, ItemId) {
    let v = Arc::new(MemItemVault::unlocked());
    let folder = ItemId::new();
    v.put_view(
        folder,
        None,
        SiteFolder {
            name: "Work".into(),
            ..SiteFolder::default()
        },
    )
    .await
    .unwrap();
    let key = ItemId::new();
    v.put_view(
        key,
        None,
        SshKey {
            label: "deploy key".into(),
            algorithm: "ssh-ed25519".into(),
            public_key: "ssh-ed25519 AAAA".into(),
            private_key: pw(CANARY),
            passphrase: None,
            read_only: false,
        },
    )
    .await
    .unwrap();
    let web = ItemId::new();
    let mut site = Site::new("web01", Protocol::Sftp, "web01.example.com");
    site.parent = Some(folder);
    site.user = "deploy".into();
    site.password = Some(pw(CANARY));
    site.key_id = Some(key);
    v.put_view(web, None, site).await.unwrap();
    let mut top = Site::new("ftp", Protocol::Ftp, "ftp.example.com");
    top.password = Some(pw(CANARY));
    v.put_view(ItemId::new(), None, top).await.unwrap();
    v.put_view(
        ItemId::new(),
        None,
        Bookmark {
            name: "logs".into(),
            site_id: Some(web),
            remote_dir: Some("/var/log".into()),
            ..Bookmark::default()
        },
    )
    .await
    .unwrap();
    v.put_view(
        ItemId::new(),
        None,
        Bookmark {
            name: "Home".into(),
            local_dir: Some("/home/me".into()),
            ..Bookmark::default()
        },
    )
    .await
    .unwrap();
    v.put_view(
        ItemId::new(),
        None,
        HistoryEntry::new(Protocol::Sftp, "old.example.com"),
    )
    .await
    .unwrap();
    v.put_view(
        ItemId::new(),
        None,
        KnownHost {
            host: "web01.example.com".into(),
            port: 22,
            key_type: "ssh-ed25519".into(),
            public_key: "AAAAkey1".into(),
            ..KnownHost::default()
        },
    )
    .await
    .unwrap();
    v.put_view(
        ItemId::new(),
        None,
        TrustedCert {
            host: "ftp.example.com".into(),
            port: 21,
            sha256: vec![1; 32],
            der: vec![1, 2, 3],
            subject: "CN=ftp".into(),
            ..TrustedCert::default()
        },
    )
    .await
    .unwrap();
    let proxy = ItemId::new();
    v.put_view(
        proxy,
        None,
        ProxyCredential {
            label: "Generic proxy".into(),
            user: "proxyuser".into(),
            password: Some(pw(CANARY)),
            read_only: false,
        },
    )
    .await
    .unwrap();
    (v, folder, web, proxy)
}

fn settings_with_proxy(proxy: ItemId) -> Settings {
    let mut s = Settings::default();
    s.connection.timeout_secs = 45;
    s.proxy.generic = GenericProxy::Socks5(ProxyServer {
        host: "proxy.example.com".into(),
        port: 1080,
        user: Some("proxyuser".into()),
        password_ref: Some(proxy.to_string()),
    });
    s
}

fn queue_json(site: ItemId) -> String {
    let mut q = Queue::new(10);
    q.add_batch(
        [
            NewItem::file(
                QueueServer::Site(site),
                Direction::Download,
                crate::model::LocalPath::new("/tmp/a.txt"),
                "/pub/a.txt",
                Some(12),
            ),
            NewItem::file(
                QueueServer::Site(ItemId::new()),
                Direction::Download,
                crate::model::LocalPath::new("/tmp/b.txt"),
                "/pub/b.txt",
                None,
            ),
        ],
        time::OffsetDateTime::now_utc(),
    );
    q.export_json()
}

async fn full_archive(v: &MemItemVault, settings: &Settings, web: ItemId) -> Archive {
    let mut a = Archive::new(1_760_000_000_000);
    a.items = collect_items(v, &ExportChoice::ALL).await.unwrap();
    a.passwords = true;
    a.settings = Some(SettingsDoc {
        keybindings: Some(json!({"Normal": {"<F12>": "Quit"}})),
        ..SettingsDoc::from_config(settings, None).unwrap()
    });
    a.queue = Some(queue_json(web));
    a
}

/// Every live item as `(kind, sorted field values without stamps)`.
async fn contents(v: &MemItemVault) -> Vec<(ItemKind, ItemId, Vec<(String, ciborium::Value)>)> {
    let mut out = Vec::new();
    for kind in ItemKind::ALL {
        for item in v.list(kind).await.unwrap() {
            let fields = item
                .body
                .fields
                .iter()
                .map(|(k, s)| (k.clone(), s.value.clone()))
                .collect();
            out.push((kind, item.id, fields));
        }
    }
    out.sort_by_key(|a| a.1);
    out
}

#[tokio::test]
async fn full_backup_round_trips_into_a_fresh_vault() {
    let (v, _, web, proxy) = filled().await;
    let settings = settings_with_proxy(proxy);
    let archive = full_archive(&v, &settings, web).await;
    assert_eq!(archive.sections(), Section::ALL.to_vec());
    assert_eq!(
        archive.describe(Section::Sites),
        "2 sites, 1 folder, 2 bookmarks, 1 SSH key, with passwords"
    );

    let file = seal(
        &archive,
        &pw("backup pass"),
        Argon2Cost::TEST,
        &mut os_rng(),
    )
    .unwrap();
    assert!(is_backup(&file));
    assert!(
        !file.windows(CANARY.len()).any(|w| w == CANARY.as_bytes()),
        "no plaintext secret"
    );
    let opened = open(&file, &pw("backup pass")).unwrap();
    assert_eq!(opened, archive);

    // A fresh vault gets every item back, secrets included.
    let fresh = MemItemVault::unlocked();
    let choice = ImportChoice::everything(&opened);
    let report = restore_items(&fresh, &opened, &choice).await.unwrap();
    assert_eq!(report.conflicts, Vec::<String>::new());
    assert_eq!(report.added, 10);
    assert_eq!(contents(&fresh).await, contents(&v).await);
    let (_, site) = fresh
        .list_views::<Site>()
        .await
        .unwrap()
        .into_iter()
        .find(|(i, _)| i.id == web)
        .unwrap();
    assert_eq!(site.password.unwrap().expose_secret(), CANARY);

    // Restoring again changes nothing.
    let again = restore_items(&fresh, &opened, &choice).await.unwrap();
    assert_eq!((again.added, again.updated, again.unchanged), (0, 0, 10));

    // Settings come back as they were.
    let (restored, report) = apply_settings(
        opened.settings.as_ref().unwrap(),
        SettingsMode::Replace,
        &Settings::default(),
        None,
    )
    .unwrap();
    assert!(report.warnings.is_empty(), "{report:?}");
    assert_eq!(restored, settings);

    // Queue items of existing sites come back; the other is dropped.
    let queue = queue_items(&opened, &report_default(), |id| id == web)
        .unwrap()
        .unwrap();
    assert_eq!(queue.items.len(), 1);
    assert_eq!(queue.missing_sites, 1);
}

fn report_default() -> RestoreReport {
    RestoreReport::default()
}

#[tokio::test]
async fn wrong_passphrase_and_tampering_are_refused() {
    let (v, _, web, proxy) = filled().await;
    let archive = full_archive(&v, &settings_with_proxy(proxy), web).await;
    let file = seal(&archive, &pw("right"), Argon2Cost::TEST, &mut os_rng()).unwrap();
    assert_eq!(open(&file, &pw("wrong")).unwrap_err(), BackupError::Decrypt);
    let mut bad = file.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x40;
    assert_eq!(open(&bad, &pw("right")).unwrap_err(), BackupError::Decrypt);
    // A different header (e.g. the item count) breaks authentication.
    let text = String::from_utf8_lossy(&file).into_owned();
    let header = text.split('\n').next().unwrap();
    let edited = header.replacen("\"created_at\":1760000000000", "\"created_at\":1", 1);
    assert_ne!(edited, header);
    let mut h = edited.into_bytes();
    let nl = file.iter().position(|b| *b == b'\n').unwrap();
    h.extend_from_slice(&file[nl..]);
    assert_eq!(open(&h, &pw("right")).unwrap_err(), BackupError::Decrypt);
    assert!(matches!(
        open(b"{\"format\":\"something else\"}\nxx", &pw("right")),
        Err(BackupError::Format(_))
    ));
}

#[tokio::test]
async fn a_t30_item_list_reads_as_sections() {
    let (v, ..) = filled().await;
    let mut all = Vec::new();
    for kind in ItemKind::ALL {
        for item in v.list(kind).await.unwrap() {
            all.push(BackupItem {
                id: item.id,
                vault_id: item.vault_id,
                body: item.body,
            });
        }
    }
    let file = backup::seal(&all, &pw("p"), Argon2Cost::TEST, 7, &mut os_rng()).unwrap();
    let archive = open(&file, &pw("p")).unwrap();
    // No config in a plain item list: the proxy credential sits in the
    // settings section without settings.
    assert_eq!(
        archive.sections(),
        vec![Section::Sites, Section::History, Section::Trust]
    );
    assert_eq!(archive.items_of(Section::Settings).len(), 1);
    assert!(archive.passwords);
    assert_eq!(archive.created_at, 7);
}

#[test]
fn unknown_sections_are_skipped_with_a_warning() {
    let payload = Value::Map(vec![
        (text("version"), Value::from(2u32)),
        (
            text("sections"),
            Value::Map(vec![
                (
                    text("history"),
                    Value::Map(vec![(text("items"), Value::Array(vec![]))]),
                ),
                (text("macros"), Value::Map(vec![])),
            ]),
        ),
    ]);
    let mut cbor = Vec::new();
    ciborium::into_writer(&payload, &mut cbor).unwrap();
    let file = backup::seal_payload(
        backup::FORMAT,
        backup::AAD_LABEL,
        &cbor,
        0,
        &pw("p"),
        Argon2Cost::TEST,
        1,
        &mut os_rng(),
    )
    .unwrap();
    let archive = open(&file, &pw("p")).unwrap();
    assert_eq!(archive.sections(), vec![Section::History]);
    assert_eq!(archive.version, 2);
    assert_eq!(archive.warnings.len(), 2, "{:?}", archive.warnings);
    assert!(archive.warnings[1].contains("macros"));
}

#[tokio::test]
async fn without_passwords_no_secret_is_exported() {
    let (v, ..) = filled().await;
    let choice = ExportChoice {
        sites: true,
        ..ExportChoice::default()
    };
    let items = collect_items(&*v, &choice).await.unwrap();
    assert_eq!(items.keys().copied().collect::<Vec<_>>(), [Section::Sites]);
    let sites = &items[&Section::Sites];
    assert!(sites.iter().all(|i| i.body.kind != ItemKind::SshKey));
    let mut cbor = Vec::new();
    for item in sites {
        cbor.extend(item.body.to_cbor().unwrap());
    }
    assert!(!cbor.windows(CANARY.len()).any(|w| w == CANARY.as_bytes()));
}

#[test]
fn plain_settings_export_has_no_secrets_and_reads_back() {
    let proxy = ItemId::new();
    let settings = settings_with_proxy(proxy);
    let doc = SettingsDoc {
        styles: Some(json!({"Normal": {"title": "bold"}})),
        ..SettingsDoc::from_config(&settings, None).unwrap()
    };
    let text = settings_to_json(&doc, UnixMillis(5));
    assert!(!text.contains(&proxy.to_string()), "{text}");
    assert!(!text.contains("password"), "{text}");
    assert!(is_settings_json(text.as_bytes()));
    assert!(!is_backup(text.as_bytes()));
    let archive = parse_settings_json(text.as_bytes()).unwrap();
    assert_eq!(archive.sections(), vec![Section::Settings]);
    let (back, report) = apply_settings(
        archive.settings.as_ref().unwrap(),
        SettingsMode::Replace,
        &Settings::default(),
        None,
    )
    .unwrap();
    assert!(report.warnings.is_empty());
    let mut expected = settings.clone();
    if let GenericProxy::Socks5(p) = &mut expected.proxy.generic {
        p.password_ref = None;
    }
    assert_eq!(back, expected);
    assert!(matches!(
        parse_settings_json(br#"{"format":"courier-ftp-queue"}"#),
        Err(BackupError::Format(_))
    ));
}

#[test]
fn settings_merge_and_replace() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config.json"),
        r#"{"keybindings": {"Normal": {"<F11>": "Help"}}, "other": 1,
            "settings": {"interface": {"natural_sort": false}}}"#,
    )
    .unwrap();
    let mut current = Settings::default();
    current.interface.natural_sort = false;
    let mut imported = Settings::default();
    imported.connection.timeout_secs = 45;
    let doc = SettingsDoc {
        keybindings: Some(json!({"Normal": {"<F12>": "Quit"}})),
        ..SettingsDoc::from_config(&imported, None).unwrap()
    };

    let (merged, _) =
        apply_settings(&doc, SettingsMode::Merge, &current, Some(dir.path())).unwrap();
    assert_eq!(merged.connection.timeout_secs, 45);
    assert!(!merged.interface.natural_sort, "kept");
    let file: Json =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join("config.json")).unwrap())
            .unwrap();
    assert_eq!(
        file["keybindings"],
        json!({"Normal": {"<F11>": "Help", "<F12>": "Quit"}})
    );
    assert_eq!(file["other"], json!(1));
    assert_eq!(
        file["settings"],
        json!({"connection": {"timeout_secs": 45}, "interface": {"natural_sort": false}})
    );

    let (replaced, _) =
        apply_settings(&doc, SettingsMode::Replace, &merged, Some(dir.path())).unwrap();
    assert_eq!(replaced, imported);
    let file: Json =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join("config.json")).unwrap())
            .unwrap();
    assert_eq!(file["keybindings"], json!({"Normal": {"<F12>": "Quit"}}));
    assert_eq!(
        file["settings"],
        json!({"connection": {"timeout_secs": 45}})
    );
    // Replace without styles in the import drops them.
    assert!(file.get("styles").is_none());
}

#[tokio::test]
async fn partial_import_into_a_new_folder() {
    let (v, folder, web, proxy) = filled().await;
    let archive = full_archive(&v, &settings_with_proxy(proxy), web).await;

    // The target already has a "Restored" folder, a global "home" bookmark
    // and a different key for web01.
    let target = MemItemVault::unlocked();
    target
        .put_view(
            ItemId::new(),
            None,
            SiteFolder {
                name: "Restored".into(),
                ..SiteFolder::default()
            },
        )
        .await
        .unwrap();
    target
        .put_view(
            ItemId::new(),
            None,
            Bookmark {
                name: "home".into(),
                ..Bookmark::default()
            },
        )
        .await
        .unwrap();
    target
        .put_view(
            ItemId::new(),
            None,
            KnownHost {
                host: "web01.example.com".into(),
                port: 22,
                key_type: "ssh-ed25519".into(),
                public_key: "AAAAother".into(),
                ..KnownHost::default()
            },
        )
        .await
        .unwrap();

    let choice = ImportChoice {
        sites: Some(SitesMode::NewFolder("Restored".into())),
        trust: true,
        queue: true,
        ..ImportChoice::default()
    };
    let report = restore_items(&target, &archive, &choice).await.unwrap();
    assert_eq!(report.conflicts.len(), 2, "{:?}", report.conflicts);
    assert!(report.conflicts[0].contains("Home"));
    assert!(report.conflicts[1].contains("web01.example.com:22"));

    // Nothing of the settings or history sections came in.
    assert!(
        target
            .list(ItemKind::ProxyCredential)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        target
            .list(ItemKind::HistoryEntry)
            .await
            .unwrap()
            .is_empty()
    );

    let new_folder = report.folder.unwrap();
    let folders = target.list_views::<SiteFolder>().await.unwrap();
    let names: Vec<&str> = folders.iter().map(|(_, f)| f.name.as_str()).collect();
    assert!(names.contains(&"Restored (2)"), "{names:?}");
    let (work_item, work) = folders.iter().find(|(_, f)| f.name == "Work").unwrap();
    assert_eq!(work.parent, Some(new_folder));
    assert_ne!(work_item.id, folder, "new ids");
    let sites = target.list_views::<Site>().await.unwrap();
    let (web_item, web_view) = sites.iter().find(|(_, s)| s.name == "web01").unwrap();
    assert_eq!(web_view.parent, Some(work_item.id));
    assert_eq!(report.new_ids[&web], web_item.id);
    assert_eq!(web_view.password.as_ref().unwrap().expose_secret(), CANARY);
    let (_, ftp) = sites.iter().find(|(_, s)| s.name == "ftp").unwrap();
    assert_eq!(ftp.parent, Some(new_folder));
    // The SSH key keeps its id, so the site still finds it.
    assert!(
        target
            .get(web_view.key_id.unwrap())
            .await
            .unwrap()
            .is_some()
    );
    // The site bookmark follows its site.
    let bookmarks = target.list_views::<Bookmark>().await.unwrap();
    let (_, logs) = bookmarks.iter().find(|(_, b)| b.name == "logs").unwrap();
    assert_eq!(logs.site_id, Some(web_item.id));
    // The certificate (no conflict) came in; the host key kept the old one.
    assert_eq!(target.list(ItemKind::TrustedCert).await.unwrap().len(), 1);
    let keys = target.list_views::<KnownHost>().await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].1.public_key, "AAAAother");

    // Queue items point at the new site id.
    let queue = queue_items(&archive, &report, |id| id == web_item.id)
        .unwrap()
        .unwrap();
    assert_eq!(queue.items.len(), 1);
    assert_eq!(queue.items[0].server, QueueServer::Site(web_item.id));
}

#[tokio::test]
async fn restoring_into_a_vault_with_newer_edits_keeps_them_and_renames_clashes() {
    let (v, _, web, proxy) = filled().await;
    let archive = full_archive(&v, &settings_with_proxy(proxy), web).await;
    // The source edits web01 after the backup; a different site named "ftp"
    // exists at the top level.
    let mut site = v
        .list_views::<Site>()
        .await
        .unwrap()
        .into_iter()
        .find(|(i, _)| i.id == web)
        .unwrap()
        .1;
    site.host = "web01-new.example.com".into();
    v.put_view(web, None, site).await.unwrap();

    let choice = ImportChoice {
        sites: Some(SitesMode::Merge),
        ..ImportChoice::default()
    };
    let report = restore_items(&*v, &archive, &choice).await.unwrap();
    assert_eq!(report.conflicts, Vec::<String>::new());
    assert_eq!(report.added, 0);
    let sites = v.list_views::<Site>().await.unwrap();
    let (_, web_view) = sites.iter().find(|(i, _)| i.id == web).unwrap();
    assert_eq!(web_view.host, "web01-new.example.com", "newer edit kept");

    // Another vault has a different site called "ftp" at the top level.
    let other = MemItemVault::unlocked();
    other
        .put_view(
            ItemId::new(),
            None,
            Site::new("ftp", Protocol::Sftp, "other.example.com"),
        )
        .await
        .unwrap();
    let report = restore_items(&other, &archive, &choice).await.unwrap();
    assert_eq!(report.conflicts.len(), 1, "{:?}", report.conflicts);
    assert!(report.conflicts[0].contains("ftp (2)"));
    let sites = other.list_views::<Site>().await.unwrap();
    let mut names: Vec<&str> = sites.iter().map(|(_, s)| s.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["ftp", "ftp (2)", "web01"]);
}
