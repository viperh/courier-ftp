#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use pretty_assertions::assert_eq;
use secrecy::{ExposeSecret, SecretString};
use time::Duration;

use super::*;
use crate::backend::{KeySource, ProxyChoice};
use crate::model::item::{
    self, ItemId, ItemView, LogonKind, ServerType, SiteColor, SiteTransferMode, SshKey, UnixMillis,
};
use crate::model::{Charset, FtpEncryption, LocalPath, LogonType, PathStyle, Protocol, RemotePath};
use crate::settings::FtpTransferMode;
use crate::vault::{ItemVault, ItemVaultExt, MemItemVault, VaultError};

fn secret(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

fn sftp(name: &str) -> Site {
    let mut s = Site::new(name, Protocol::Sftp, format!("{name}.example.com"));
    s.logon = SiteLogon::Normal {
        user: "deploy".into(),
        password: Some(secret("hunter2")),
    };
    s
}

fn site_node(s: Site) -> SiteNode {
    SiteNode::Site(Box::new(s))
}

fn folder_node(name: &str) -> (ItemId, SiteNode) {
    let f = Folder::new(name);
    (f.id, SiteNode::Folder(f))
}

/// Work/Production/web01, Work/db01, Personal, top-level "home".
fn sample_tree() -> (SiteTree, [ItemId; 6]) {
    let mut t = SiteTree::new();
    let (work, n) = folder_node("Work");
    t.insert(None, n).unwrap();
    let (prod, n) = folder_node("Production");
    t.insert(Some(work), n).unwrap();
    let (personal, n) = folder_node("Personal");
    t.insert(None, n).unwrap();
    let web = sftp("web01");
    let web_id = web.id;
    t.insert(Some(prod), site_node(web)).unwrap();
    let db = sftp("db01");
    let db_id = db.id;
    t.insert(Some(work), site_node(db)).unwrap();
    let home = sftp("home");
    let home_id = home.id;
    t.insert(None, site_node(home)).unwrap();
    (t, [work, prod, personal, web_id, db_id, home_id])
}

fn names(nodes: &[SiteNode]) -> Vec<&str> {
    nodes.iter().map(SiteNode::name).collect()
}

// ------------------------------------------------------------------ names

#[test]
fn names_are_validated() {
    assert_eq!(validate_name("  web01 ").unwrap(), "web01");
    assert_eq!(validate_name("Ünïcødé 服务器").unwrap(), "Ünïcødé 服务器");
    assert_eq!(validate_name(""), Err(NameError::Empty));
    assert_eq!(validate_name("   "), Err(NameError::Empty));
    assert_eq!(validate_name("a/b"), Err(NameError::Slash));
    assert_eq!(validate_name("a\nb"), Err(NameError::Control));

    let mut t = SiteTree::new();
    assert!(matches!(
        t.insert(None, site_node(sftp("a/b"))),
        Err(SiteError::InvalidName(NameError::Slash))
    ));
    t.insert(None, site_node(sftp("web"))).unwrap();
    assert!(matches!(
        t.insert(None, site_node(sftp("web"))),
        Err(SiteError::NameTaken(_))
    ));
    // Same name in another folder is fine; a folder and a site can't share
    // one either (paths must be unique).
    let (f, n) = folder_node("Work");
    t.insert(None, n).unwrap();
    t.insert(Some(f), site_node(sftp("web"))).unwrap();
    assert!(matches!(
        t.insert(None, folder_node("web").1),
        Err(SiteError::NameTaken(_))
    ));
}

// ------------------------------------------------------------------ tree

#[test]
fn children_are_sorted_folders_first_then_name() {
    let mut t = SiteTree::new();
    for name in ["beta", "Alpha", "gamma"] {
        t.insert(None, site_node(sftp(name))).unwrap();
    }
    t.insert(None, folder_node("zeta").1).unwrap();
    t.insert(None, folder_node("Eta").1).unwrap();
    assert_eq!(names(t.roots()), ["Eta", "zeta", "Alpha", "beta", "gamma"]);
}

#[test]
fn insert_into_missing_or_site_parent_fails() {
    let (mut t, [.., web, _, _]) = sample_tree();
    assert!(matches!(
        t.insert(Some(ItemId::new()), site_node(sftp("x"))),
        Err(SiteError::NotFound(_))
    ));
    assert!(matches!(
        t.insert(Some(web), site_node(sftp("x"))),
        Err(SiteError::NotAFolder(_))
    ));
}

#[test]
fn rename_checks_name_and_resorts() {
    let (mut t, [work, _, personal, _, db, _]) = sample_tree();
    t.rename(db, "aaa").unwrap();
    assert_eq!(t.site(db).unwrap().name, "aaa");
    assert_eq!(
        names(t.children(Some(work)).unwrap()),
        ["Production", "aaa"]
    );
    assert!(matches!(
        t.rename(personal, "Work"),
        Err(SiteError::NameTaken(_))
    ));
    // Renaming to its own name is fine.
    t.rename(personal, "Personal").unwrap();
    assert!(matches!(
        t.rename(db, "x/y"),
        Err(SiteError::InvalidName(_))
    ));
    assert!(matches!(
        t.rename(ItemId::new(), "x"),
        Err(SiteError::NotFound(_))
    ));
}

#[test]
fn move_into_own_descendant_is_rejected() {
    let (mut t, [work, prod, personal, web, _, home]) = sample_tree();
    assert!(matches!(
        t.move_node(work, Some(prod)),
        Err(SiteError::IntoOwnDescendant)
    ));
    assert!(matches!(
        t.move_node(work, Some(work)),
        Err(SiteError::IntoOwnDescendant)
    ));
    assert!(matches!(
        t.move_node(work, Some(home)),
        Err(SiteError::NotAFolder(_))
    ));
    // Folder into a sibling folder, site to the top level.
    t.move_node(prod, Some(personal)).unwrap();
    assert_eq!(t.path_of(web).unwrap(), "Personal/Production/web01");
    assert_eq!(t.folder(prod).unwrap().parent, Some(personal));
    t.move_node(web, None).unwrap();
    assert_eq!(t.path_of(web).unwrap(), "web01");
    assert_eq!(t.site(web).unwrap().parent, None);
    // Name clash in the target.
    let clash = sftp("home");
    t.insert(Some(personal), site_node(clash)).unwrap();
    assert!(matches!(
        t.move_node(home, Some(personal)),
        Err(SiteError::NameTaken(_))
    ));
    // Moving to where it already is changes nothing.
    t.move_node(home, None).unwrap();
}

#[test]
fn duplicate_deep_copies_with_new_ids() {
    let (mut t, [work, prod, _, web, db, _]) = sample_tree();
    let now = UnixMillis(42);
    let copy = t.duplicate(work, now).unwrap();
    assert_ne!(copy, work);
    let c = t.folder(copy).unwrap();
    assert_eq!(c.name, "Work (copy)");
    assert_eq!(c.parent, None);
    let ids: Vec<ItemId> = t.get(copy).unwrap().walk().iter().map(|n| n.id()).collect();
    assert_eq!(ids.len(), 4);
    for id in [work, prod, web, db] {
        assert!(!ids.contains(&id));
    }
    // The children keep their names and get parents inside the copy.
    let copied_web = t.find_site("Work (copy)/Production/web01").unwrap();
    assert_eq!(copied_web.created_at, Some(now));
    assert_eq!(
        copied_web.logon.password().unwrap().expose_secret(),
        "hunter2",
        "passwords are copied"
    );
    assert_eq!(t.ancestors(copied_web.id).len(), 2);
    // A second copy gets a numbered name.
    let again = t.duplicate(work, now).unwrap();
    assert_eq!(t.get(again).unwrap().name(), "Work (copy) (2)");
    // A site.
    let site_copy = t.duplicate(web, now).unwrap();
    assert_eq!(
        t.path_of(site_copy).unwrap(),
        "Work/Production/web01 (copy)"
    );
}

#[test]
fn remove_takes_the_subtree() {
    let (mut t, [work, _, _, web, db, home]) = sample_tree();
    let (folders, sites) = t.get(work).unwrap().count();
    assert_eq!((folders, sites), (2, 2));
    let removed = t.remove(work).unwrap();
    assert_eq!(removed.walk().len(), 4);
    assert!(t.get(web).is_none());
    assert!(t.get(db).is_none());
    assert!(t.get(home).is_some());
    assert!(t.remove(work).is_none());
}

#[test]
fn lookup_by_path_with_nesting_and_unicode() {
    let (mut t, [work, prod, ..]) = sample_tree();
    let (deep, n) = folder_node("Ünïcødé 服务器");
    t.insert(Some(prod), n).unwrap();
    let s = sftp("сервер 🚀");
    let sid = s.id;
    t.insert(Some(deep), site_node(s)).unwrap();

    let path = "Work/Production/Ünïcødé 服务器/сервер 🚀";
    assert_eq!(t.path_of(sid).unwrap(), path);
    assert_eq!(t.find_site(path).unwrap().id, sid);
    assert_eq!(t.find_path(&format!("/{path}/")).unwrap().id(), sid);
    assert_eq!(t.find_path("Work/Production").unwrap().id(), prod);
    assert_eq!(t.find_path("Work").unwrap().id(), work);
    assert_eq!(t.find_site("Work/db01").unwrap().name, "db01");
    assert_eq!(t.find_site("home").unwrap().name, "home");
    // A folder is not a site; nothing below a site; exact names.
    assert!(t.find_site("Work").is_none());
    assert!(t.find_path("home/x").is_none());
    assert!(t.find_path("work/db01").is_none());
    assert!(t.find_path("").is_none());
    assert!(t.find_path("/").is_none());
    assert!(t.find_path("Nope/web01").is_none());
}

#[test]
fn visible_rows_follow_expansion() {
    let (mut t, [work, prod, ..]) = sample_tree();
    let rows = |t: &SiteTree| -> Vec<(usize, String)> {
        t.visible_rows()
            .iter()
            .map(|r| (r.depth, r.node.name().to_owned()))
            .collect()
    };
    assert_eq!(rows(&t).len(), 3);
    t.set_expanded(work, true);
    assert_eq!(
        rows(&t),
        [
            (0, "Personal".into()),
            (0, "Work".into()),
            (1, "Production".into()),
            (1, "db01".into()),
            (0, "home".into()),
        ]
    );
    t.set_expanded(work, false);
    let web = t.find_site("Work/Production/web01").unwrap().id;
    t.reveal(web);
    assert_eq!(t.expanded().into_iter().collect::<Vec<_>>().len(), 2);
    assert!(t.folder(prod).unwrap().expanded);
}

#[test]
fn rebuild_repairs_orphans_and_cycles() {
    let mut a = Folder::new("A");
    let mut b = Folder::new("B");
    let mut c = Folder::new("C");
    let mut d = Folder::new("D");
    // A → B → C → A is a cycle; D hangs below C; E's parent is missing.
    a.parent = Some(c.id);
    b.parent = Some(a.id);
    c.parent = Some(b.id);
    d.parent = Some(c.id);
    let mut e = Folder::new("E");
    e.parent = Some(ItemId::new());
    let mut s = sftp("orphan");
    s.parent = Some(ItemId::new());
    let mut inside = sftp("inside");
    inside.parent = Some(d.id);
    let ids = [a.id, b.id, c.id];
    let lowest = *ids.iter().min().unwrap();
    let inside_id = inside.id;

    let t = SiteTree::from_items(vec![a, b, c, d, e], vec![s, inside]);
    // Everything is still there.
    assert_eq!(t.walk().len(), 7);
    // The cycle is broken at its lowest id, which is now top level.
    assert_eq!(t.get(lowest).unwrap().parent(), None);
    let top = names(t.roots());
    assert!(top.contains(&"E") && top.contains(&"orphan"), "{top:?}");
    assert_eq!(t.site(inside_id).unwrap().parent.is_some(), true);
    assert!(t.path_of(inside_id).unwrap().ends_with("D/inside"));
}

// ------------------------------------------------------------------ site <-> item

fn full_site() -> Site {
    let mut s = Site::new("full", Protocol::FtpsExplicit, "ftp.example.com");
    s.encryption = Some(FtpEncryption::RequireExplicit);
    s.port = Some(2121);
    s.logon = SiteLogon::Account {
        user: "bob".into(),
        password: Some(secret("pw")),
        account: "acct".into(),
    };
    s.color = SiteColor::Magenta;
    s.comments = "notes\nline 2".into();
    s.server_type = ServerType::Vms;
    s.bypass_proxy = true;
    s.default_local_dir = Some(LocalPath::new("/home/me/www"));
    s.default_remote_dir = Some(RemotePath::new("/var/www"));
    s.sync_browsing = true;
    s.directory_comparison = true;
    s.timezone_offset_minutes = -90;
    s.transfer_mode = SiteTransferMode::Active;
    s.limit_connections = Some(3);
    s.charset = Charset::Utf8;
    s.try_agent_first = true;
    s.created_at = Some(UnixMillis(1_700_000_000_000));
    s.last_connected_at = Some(UnixMillis(1_700_000_100_000));
    s
}

#[test]
fn every_field_round_trips_through_the_item() {
    let s = full_site();
    let mut clock = item::HlcClock::default();
    let dev = item::DeviceId::new();
    let body = s.to_item().to_body(&mut clock, dev);
    let cbor = body.to_cbor().unwrap();
    let back_body = item::ItemBody::from_cbor(&cbor).unwrap();
    let view = item::Site::from_body(&back_body).unwrap();
    let back = Site::from_item(s.id, None, &view, &s.local());
    assert_eq!(back, s);
    // Device-local fields are not in the item.
    assert!(!back_body.contains("default_local_dir"));
    let without_local = Site::from_item(s.id, None, &view, &SiteLocal::default());
    assert_eq!(without_local.default_local_dir, None);
    assert_eq!(without_local.last_connected_at, None);
}

#[test]
fn key_paths_are_device_local_and_vault_keys_sync() {
    let mut s = sftp("k");
    s.logon = SiteLogon::KeyFile {
        user: "deploy".into(),
        key: Some(SiteKey::File(LocalPath::new("/home/me/.ssh/id_ed25519"))),
        passphrase: Some(secret("pp")),
    };
    let view = s.to_item();
    assert_eq!(view.key_path, None);
    assert_eq!(view.key_id, None);
    assert_eq!(
        s.local().key_path,
        Some(LocalPath::new("/home/me/.ssh/id_ed25519"))
    );
    assert_eq!(Site::from_item(s.id, None, &view, &s.local()), s);
    // Another device without a local path: no key yet.
    let other = Site::from_item(s.id, None, &view, &SiteLocal::default());
    assert!(matches!(other.logon, SiteLogon::KeyFile { key: None, .. }));
    // A path synced by an older build is still used.
    let mut legacy = view.clone();
    legacy.key_path = Some("/old/key".into());
    let read = Site::from_item(s.id, None, &legacy, &SiteLocal::default());
    assert!(
        matches!(read.logon, SiteLogon::KeyFile { key: Some(SiteKey::File(p)), .. } if p == LocalPath::new("/old/key"))
    );

    let key_id = ItemId::new();
    s.logon = SiteLogon::KeyFile {
        user: "deploy".into(),
        key: Some(SiteKey::Vault(key_id)),
        passphrase: None,
    };
    assert_eq!(s.to_item().key_id, Some(key_id));
    assert_eq!(s.local().key_path, None);
    assert_eq!(s.vault_key_id(), Some(key_id));
}

#[test]
fn changing_the_logon_type_drops_secrets() {
    let normal = SiteLogon::Normal {
        user: "bob".into(),
        password: Some(secret("pw")),
    };
    let account = normal.clone().with_kind(LogonKind::Account);
    assert_eq!(account.password().unwrap().expose_secret(), "pw");
    let ask = account.with_kind(LogonKind::AskForPassword);
    assert_eq!(ask, SiteLogon::AskForPassword { user: "bob".into() });
    assert!(
        ask.clone()
            .with_kind(LogonKind::Normal)
            .password()
            .is_none()
    );
    let key = normal.clone().with_kind(LogonKind::KeyFile);
    assert_eq!(key.user(), "bob");
    assert_eq!(normal.clone().with_kind(LogonKind::Normal), normal);
    assert_eq!(normal.with_kind(LogonKind::Anonymous).user(), "");

    // Writing the new type erases the stored password (explicit null).
    let mut s = sftp("x");
    let mut clock = item::HlcClock::default();
    let dev = item::DeviceId::new();
    let mut body = s.to_item().to_body(&mut clock, dev);
    assert!(body.get("logon.password").is_some());
    s.logon = s.logon.clone().with_kind(LogonKind::Agent);
    s.to_item().apply_to(&mut body, &mut clock, dev);
    assert!(body.get("logon.password").is_none());
    assert!(body.contains("logon.password"));
}

#[test]
fn site_debug_hides_secrets() {
    let mut s = full_site();
    s.logon = SiteLogon::Normal {
        user: "bob".into(),
        password: Some(secret("CANARY-site-pw")),
    };
    let shown = format!("{s:?}");
    assert!(!shown.contains("CANARY"), "{shown}");
    let info = s.to_connect_info(None).unwrap();
    assert!(!format!("{info:?}").contains("CANARY"));
}

// ------------------------------------------------------------------ validation

fn errors(s: &Site) -> Vec<SiteField> {
    s.validate()
        .into_iter()
        .filter(SiteIssue::is_error)
        .map(|i| i.field)
        .collect()
}

#[test]
fn validation_rules() {
    assert!(sftp("ok").validate().is_empty());

    let mut s = sftp("ok");
    s.host = "  ".into();
    assert_eq!(errors(&s), [SiteField::Host]);
    s.host = "a b".into();
    assert_eq!(errors(&s), [SiteField::Host]);

    let mut s = sftp("ok");
    s.port = Some(0);
    assert_eq!(errors(&s), [SiteField::Port]);
    s.port = Some(65535);
    assert!(errors(&s).is_empty());

    let mut s = sftp("ok");
    s.timezone_offset_minutes = 24 * 60;
    assert!(errors(&s).is_empty());
    s.timezone_offset_minutes = -(24 * 60 + 1);
    assert_eq!(errors(&s), [SiteField::TimezoneOffset]);

    let mut s = sftp("ok");
    s.limit_connections = Some(0);
    assert_eq!(errors(&s), [SiteField::ConnectionLimit]);
    s.limit_connections = Some(11);
    assert_eq!(errors(&s), [SiteField::ConnectionLimit]);
    s.limit_connections = Some(10);
    assert!(errors(&s).is_empty());

    let mut s = sftp("ok");
    s.name = "a/b".into();
    assert_eq!(errors(&s), [SiteField::Name]);

    // Logon types per protocol, and a user.
    let mut s = sftp("ok");
    s.logon = SiteLogon::Anonymous;
    assert_eq!(errors(&s), [SiteField::Logon]);
    s.protocol = Protocol::Ftp;
    assert!(errors(&s).is_empty());
    s.logon = SiteLogon::Agent { user: "x".into() };
    assert_eq!(errors(&s), [SiteField::Logon]);
    s.logon = SiteLogon::AskForPassword { user: " ".into() };
    assert_eq!(errors(&s), [SiteField::User]);
    assert!(logon_kinds(Protocol::Sftp).contains(&LogonKind::KeyFile));
    assert!(!logon_kinds(Protocol::FtpsImplicit).contains(&LogonKind::KeyFile));

    // Key logins: no key is an error, a missing file only a warning.
    let mut s = sftp("ok");
    s.logon = SiteLogon::KeyFile {
        user: "x".into(),
        key: None,
        passphrase: None,
    };
    assert_eq!(errors(&s), [SiteField::KeyFile]);
    s.logon = SiteLogon::KeyFile {
        user: "x".into(),
        key: Some(SiteKey::File(LocalPath::new(
            "/definitely/not/here/id_ed25519",
        ))),
        passphrase: None,
    };
    let issues = s.validate();
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].severity, Severity::Warning);
    assert_eq!(issues[0].field, SiteField::KeyFile);
}

// ------------------------------------------------------------------ connect info

fn ssh_key(label: &str, passphrase: Option<&str>) -> SshKey {
    SshKey {
        label: label.into(),
        algorithm: "ssh-ed25519".into(),
        public_key: "ssh-ed25519 AAAA".into(),
        private_key: secret("-----BEGIN OPENSSH PRIVATE KEY-----"),
        passphrase: passphrase.map(secret),
        read_only: false,
    }
}

#[test]
fn connect_info_maps_every_setting() {
    let s = full_site();
    let info = s.to_connect_info(None).unwrap();
    assert_eq!(info.address.protocol, Protocol::FtpsExplicit);
    assert_eq!(info.address.host, "ftp.example.com");
    assert_eq!(info.address.port, 2121);
    assert_eq!(info.address.user.as_deref(), Some("bob"));
    assert_eq!(
        info.logon,
        LogonType::Account {
            user: "bob".into(),
            password: secret("pw"),
            account: "acct".into()
        }
    );
    assert_eq!(info.encryption, Some(FtpEncryption::RequireExplicit));
    assert_eq!(info.charset, Charset::Utf8);
    assert_eq!(info.server_type, Some(PathStyle::Vms));
    assert_eq!(info.timezone_offset, Duration::minutes(-90));
    assert_eq!(info.transfer_mode, Some(FtpTransferMode::Active));
    assert_eq!(info.proxy, ProxyChoice::Bypass);
    assert_eq!(info.connection_limit, Some(3));
    assert!(info.try_agent_first);
    assert_eq!(info.key, None);

    let connect = s.to_connect(None).unwrap();
    assert_eq!(connect.remote_dir, Some(RemotePath::new("/var/www")));
    assert_eq!(connect.local_dir, Some(LocalPath::new("/home/me/www")));
    assert!(connect.sync_browsing && connect.directory_comparison);
    assert_eq!(connect.site_id, s.id);
}

#[test]
fn connect_info_defaults_use_the_global_settings() {
    let mut s = Site::new("d", Protocol::Sftp, " host ");
    s.logon = SiteLogon::Normal {
        user: "u".into(),
        password: Some(secret("p")),
    };
    s.encryption = Some(FtpEncryption::RequireImplicit);
    let info = s.to_connect_info(None).unwrap();
    assert_eq!(info.address.host, "host");
    assert_eq!(info.address.port, 22);
    assert_eq!(info.encryption, None, "no FTP encryption for SFTP");
    assert_eq!(info.transfer_mode, None);
    assert_eq!(info.connection_limit, None);
    assert_eq!(info.server_type, None);
    assert_eq!(info.proxy, ProxyChoice::UseSettings);
    assert_eq!(info.timezone_offset, Duration::ZERO);
    assert!(!info.logon.needs_prompt());
    assert_eq!(path_style(ServerType::NetWare), Some(PathStyle::Unix));
}

#[test]
fn missing_passwords_are_asked() {
    let mut s = sftp("x");
    s.logon = SiteLogon::Normal {
        user: "u".into(),
        password: None,
    };
    let info = s.to_connect_info(None).unwrap();
    assert_eq!(info.logon, LogonType::AskForPassword { user: "u".into() });
    s.protocol = Protocol::Ftp;
    s.logon = SiteLogon::Account {
        user: "u".into(),
        password: None,
        account: "a".into(),
    };
    assert!(s.to_connect_info(None).unwrap().logon.needs_prompt());
    s.logon = SiteLogon::Anonymous;
    let info = s.to_connect_info(None).unwrap();
    assert_eq!(info.logon, LogonType::Anonymous);
    assert_eq!(info.address.user, None);
}

#[test]
fn connect_info_with_keys() {
    let mut s = sftp("k");
    s.logon = SiteLogon::KeyFile {
        user: "deploy".into(),
        key: Some(SiteKey::File(LocalPath::new("/k/id"))),
        passphrase: Some(secret("pp")),
    };
    let info = s.to_connect_info(None).unwrap();
    assert_eq!(
        info.logon,
        LogonType::KeyFile {
            user: "deploy".into(),
            path: LocalPath::new("/k/id")
        }
    );
    assert_eq!(info.key_passphrase.unwrap().secret().expose_secret(), "pp");

    // A vault key: its text and saved passphrase go along.
    let key_id = ItemId::new();
    s.logon = SiteLogon::KeyFile {
        user: "deploy".into(),
        key: Some(SiteKey::Vault(key_id)),
        passphrase: None,
    };
    assert!(matches!(
        s.to_connect_info(None),
        Err(SiteError::KeyMissing(id)) if id == key_id
    ));
    let key = ssh_key("laptop key", Some("vault-pp"));
    let info = s.to_connect_info(Some(&key)).unwrap();
    let Some(KeySource::Vault(vk)) = &info.key else {
        panic!("{:?}", info.key)
    };
    assert_eq!(vk.id, key_id);
    assert_eq!(vk.label, "laptop key");
    assert!(
        vk.private_key
            .secret()
            .expose_secret()
            .starts_with("-----BEGIN")
    );
    assert_eq!(
        info.key_passphrase
            .as_ref()
            .unwrap()
            .secret()
            .expose_secret(),
        "vault-pp"
    );
    assert_eq!(info.logon.user(), "deploy");

    // The site's own passphrase wins over the key's.
    s.logon = SiteLogon::KeyFile {
        user: "deploy".into(),
        key: Some(SiteKey::Vault(key_id)),
        passphrase: Some(secret("site-pp")),
    };
    let info = s.to_connect_info(Some(&key)).unwrap();
    assert_eq!(
        info.key_passphrase.unwrap().secret().expose_secret(),
        "site-pp"
    );

    s.logon = SiteLogon::KeyFile {
        user: "deploy".into(),
        key: None,
        passphrase: None,
    };
    assert!(matches!(
        s.to_connect_info(None),
        Err(SiteError::Invalid(_))
    ));
}

// ------------------------------------------------------------------ manager

struct Env {
    vault: Arc<MemItemVault>,
    local: Arc<MemSiteLocalStore>,
}

impl Env {
    fn new() -> Self {
        Self {
            vault: Arc::new(MemItemVault::unlocked()),
            local: Arc::new(MemSiteLocalStore::new()),
        }
    }

    async fn open(&self) -> SiteManager {
        SiteManager::load(self.vault.clone(), self.local.clone())
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn sites_round_trip_through_the_vault() {
    let env = Env::new();
    let mut m = env.open().await;
    let work = m.add_folder(None, "Work").await.unwrap();
    let prod = m.add_folder(Some(work), "Production").await.unwrap();
    let mut s = full_site();
    s.parent = Some(prod);
    s.created_at = None;
    let id = s.id;
    let warnings = m.save_site(s.clone()).await.unwrap();
    assert!(warnings.is_empty());
    let saved = m.site(id).unwrap().clone();
    assert!(saved.created_at.is_some());
    assert!(saved.vault.is_some());

    // "Restart": a new manager over the same vault and device store.
    let m2 = env.open().await;
    assert_eq!(m2.tree(), m.tree());
    let back = m2.find_site("Work/Production/full").unwrap();
    assert_eq!(back, &saved);
    assert_eq!(back.default_local_dir, s.default_local_dir);
    assert_eq!(back.last_connected_at, None, "only connects set it");

    // Connecting doesn't ask for the saved password.
    let connect = m2.connect(id).await.unwrap();
    assert!(!connect.info.logon.needs_prompt());
    assert_eq!(connect.info.logon.password().unwrap().expose_secret(), "pw");
}

#[tokio::test]
async fn store_passwords_off_asks_on_connect() {
    let env = Env::new();
    env.vault.set_store_passwords(false);
    let mut m = env.open().await;
    let s = sftp("web");
    let id = s.id;
    m.save_site(s).await.unwrap();
    assert!(m.site(id).unwrap().logon.password().is_none());
    let connect = m.connect(id).await.unwrap();
    assert_eq!(
        connect.info.logon,
        LogonType::AskForPassword {
            user: "deploy".into()
        }
    );
    for (_, body) in env.vault.raw_bodies() {
        assert!(body.get("logon.password").is_none());
    }
}

#[tokio::test]
async fn saving_updates_in_place_and_erases_dropped_secrets() {
    let env = Env::new();
    let mut m = env.open().await;
    let f = m.add_folder(None, "F").await.unwrap();
    let mut s = sftp("web");
    s.parent = Some(f);
    let id = s.id;
    m.save_site(s).await.unwrap();

    let mut edit = m.site(id).unwrap().clone();
    edit.logon = edit.logon.with_kind(LogonKind::Agent);
    edit.name = "web2".into();
    edit.parent = None; // ignored: save doesn't move
    m.save_site(edit).await.unwrap();
    let s = m.site(id).unwrap();
    assert_eq!(s.name, "web2");
    assert_eq!(s.parent, Some(f));
    assert_eq!(m.tree().path_of(id).unwrap(), "F/web2");
    let body = env.vault.get(id).await.unwrap().unwrap().body;
    assert!(body.get("logon.password").is_none());

    // Invalid sites are refused and nothing changes.
    let mut bad = m.site(id).unwrap().clone();
    bad.host = String::new();
    assert!(matches!(
        m.save_site(bad).await,
        Err(SiteError::Invalid(issues)) if issues[0].field == SiteField::Host
    ));
    assert_eq!(m.site(id).unwrap().host, "web.example.com");

    // Name clash with a sibling.
    let mut other = sftp("other");
    other.parent = Some(f);
    m.save_site(other.clone()).await.unwrap();
    other.name = "web2".into();
    assert!(matches!(
        m.save_site(other).await,
        Err(SiteError::NameTaken(_))
    ));
}

#[tokio::test]
async fn tree_operations_persist() {
    let env = Env::new();
    let mut m = env.open().await;
    let work = m.add_folder(None, "Work").await.unwrap();
    let prod = m.add_folder(Some(work), "Production").await.unwrap();
    let personal = m.add_folder(None, "Personal").await.unwrap();
    let mut web = sftp("web01");
    web.parent = Some(prod);
    web.default_local_dir = Some(LocalPath::new("/srv/www"));
    let web_id = web.id;
    m.save_site(web).await.unwrap();

    assert!(matches!(
        m.move_node(work, Some(prod)).await,
        Err(SiteError::IntoOwnDescendant)
    ));
    m.move_node(prod, Some(personal)).await.unwrap();
    m.rename(personal, "Home").await.unwrap();
    let copy = m.duplicate(prod).await.unwrap();
    m.set_expanded(work, true);

    let mut m2 = env.open().await;
    assert_eq!(m2.tree().path_of(web_id).unwrap(), "Home/Production/web01");
    let copied = m2.find_site("Home/Production (copy)/web01").unwrap();
    assert_ne!(copied.id, web_id);
    assert_eq!(copied.logon.password().unwrap().expose_secret(), "hunter2");
    assert_eq!(copied.default_local_dir, Some(LocalPath::new("/srv/www")));
    assert_eq!(m2.tree().get(copy).unwrap().name(), "Production (copy)");

    // Reload keeps folders expanded.
    m2.set_expanded(work, true);
    m2.reload().await.unwrap();
    assert!(m2.tree().folder(work).unwrap().expanded);

    // Deleting a folder deletes everything below it, device-local rows too.
    m2.record_connected(web_id).await.unwrap();
    assert!(m2.site(web_id).unwrap().last_connected_at.is_some());
    assert!(
        env.local
            .get(web_id)
            .await
            .unwrap()
            .last_connected_at
            .is_some()
    );
    let deleted = m2.delete(personal).await.unwrap();
    assert_eq!(deleted, 5);
    assert!(m2.tree().get(web_id).is_none());
    assert_eq!(env.local.get(web_id).await.unwrap(), SiteLocal::default());
    let m3 = env.open().await;
    assert_eq!(names(m3.tree().roots()), ["Work"]);
    assert!(
        env.vault
            .list(item::ItemKind::Site)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn vault_keys_are_read_on_connect() {
    let env = Env::new();
    let key_id = ItemId::new();
    env.vault
        .put_view(key_id, None, ssh_key("work key", None))
        .await
        .unwrap();
    let mut m = env.open().await;
    assert_eq!(m.ssh_keys().await.unwrap().len(), 1);
    let mut s = sftp("k");
    s.logon = SiteLogon::KeyFile {
        user: "deploy".into(),
        key: Some(SiteKey::Vault(key_id)),
        passphrase: None,
    };
    let id = s.id;
    m.save_site(s).await.unwrap();
    let connect = m.connect(id).await.unwrap();
    assert!(matches!(&connect.info.key, Some(KeySource::Vault(k)) if k.label == "work key"));

    env.vault.delete(key_id).await.unwrap();
    assert!(matches!(m.connect(id).await, Err(SiteError::KeyMissing(_))));
}

#[tokio::test]
async fn a_locked_vault_is_an_error() {
    let env = Env::new();
    env.vault.set_unlocked(false);
    let err = SiteManager::load(env.vault.clone(), env.local.clone())
        .await
        .unwrap_err();
    assert!(matches!(err, SiteError::Vault(VaultError::Locked)));

    env.vault.set_unlocked(true);
    let mut m = env.open().await;
    env.vault.set_unlocked(false);
    assert!(m.add_folder(None, "x").await.is_err());
    assert!(m.tree().is_empty(), "a failed write changes nothing");
}

#[tokio::test]
async fn new_items_go_into_their_folders_vault() {
    let env = Env::new();
    let mut m = env.open().await;
    let f = m.add_folder(None, "F").await.unwrap();
    let folder_vault = m.tree().folder(f).unwrap().vault;
    let mut s = sftp("s");
    s.parent = Some(f);
    let id = s.id;
    m.save_site(s).await.unwrap();
    assert_eq!(m.site(id).unwrap().vault, folder_vault);
}
