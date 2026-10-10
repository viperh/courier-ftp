//! Tests for bookmarks, the quickconnect history and recent servers (T33).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use pretty_assertions::assert_eq;
use secrecy::{ExposeSecret, SecretString};

use super::*;
use crate::backend::ConnectInfo;
use crate::model::item;
use crate::model::item::{ItemId, LogonKind, UnixMillis};
use crate::model::{LocalPath, LogonType, Protocol, RemotePath, ServerAddress};
use crate::vault::{ItemVault, ItemVaultExt, MemItemVault, VaultError};

struct Fixture {
    vault: Arc<MemItemVault>,
    local: Arc<MemSiteLocalStore>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            vault: Arc::new(MemItemVault::unlocked()),
            local: Arc::new(MemSiteLocalStore::new()),
        }
    }

    fn history(&self) -> History {
        History::new(self.vault.clone(), self.local.clone())
    }

    async fn sites(&self) -> SiteManager {
        SiteManager::load(self.vault.clone(), self.local.clone())
            .await
            .unwrap()
    }

    async fn bookmarks(&self) -> Bookmarks {
        Bookmarks::load(self.vault.clone(), self.local.clone())
            .await
            .unwrap()
    }
}

fn login(protocol: Protocol, host: &str, port: u16, user: &str, pw: Option<&str>) -> ConnectInfo {
    let logon = match (user, pw) {
        ("", _) => LogonType::Anonymous,
        (u, Some(p)) => LogonType::Normal {
            user: u.into(),
            password: SecretString::from(p.to_owned()),
        },
        (u, None) => LogonType::AskForPassword { user: u.into() },
    };
    let address = ServerAddress {
        protocol,
        host: host.into(),
        port,
        user: (!user.is_empty()).then(|| user.to_owned()),
    };
    ConnectInfo::new(address, logon)
}

fn site_named(name: &str) -> Site {
    let mut s = Site::new(name, Protocol::Sftp, format!("{name}.example.com"));
    s.logon = SiteLogon::AskForPassword { user: "u".into() };
    s
}

fn hosts(entries: &[HistoryEntry]) -> Vec<String> {
    entries
        .iter()
        .map(|e| format!("{}@{}:{}", e.user, e.host, e.port))
        .collect()
}

// ------------------------------------------------------------------ history

#[tokio::test]
async fn history_is_deduplicated_most_recent_first() {
    let f = Fixture::new();
    let h = f.history();
    h.record(&login(Protocol::Sftp, "a.example.com", 22, "u", Some("1")))
        .await
        .unwrap();
    h.record(&login(Protocol::Sftp, "b.example.com", 22, "u", None))
        .await
        .unwrap();
    // Same protocol, host (other case), port and user: updates the first.
    let again = h
        .record(&login(Protocol::Sftp, "A.Example.com", 22, "u", Some("2")))
        .await
        .unwrap();
    // Other user, port or protocol: separate entries.
    h.record(&login(Protocol::Sftp, "a.example.com", 22, "v", None))
        .await
        .unwrap();
    h.record(&login(Protocol::Sftp, "a.example.com", 2222, "u", None))
        .await
        .unwrap();
    h.record(&login(Protocol::Ftp, "a.example.com", 22, "u", None))
        .await
        .unwrap();

    let list = h.list().await.unwrap();
    assert_eq!(
        hosts(&list),
        [
            "u@a.example.com:22",
            "u@a.example.com:2222",
            "v@a.example.com:22",
            "u@A.Example.com:22",
            "u@b.example.com:22",
        ]
    );
    assert_eq!(list[0].protocol, Protocol::Ftp);
    assert_eq!(list[3].id, again.id);
    assert_eq!(list[3].password.as_ref().unwrap().expose_secret(), "2");
    assert_eq!(
        f.vault
            .list(item::ItemKind::HistoryEntry)
            .await
            .unwrap()
            .len(),
        5
    );
}

#[tokio::test]
async fn history_is_capped_at_ten() {
    let f = Fixture::new();
    let h = f.history();
    let mut ids = Vec::new();
    for i in 0..15 {
        let e = h
            .record(&login(Protocol::Sftp, &format!("h{i}"), 22, "u", None))
            .await
            .unwrap();
        ids.push(e.id);
    }
    let list = h.list().await.unwrap();
    assert_eq!(list.len(), HISTORY_LIMIT);
    assert_eq!(list[0].host, "h14");
    assert_eq!(list[9].host, "h5");
    // The overflow is deleted, with its device-local row.
    let stored = f.vault.list(item::ItemKind::HistoryEntry).await.unwrap();
    assert_eq!(stored.len(), HISTORY_LIMIT);
    let locals = f.local.all().await.unwrap();
    for old in &ids[..5] {
        assert!(!locals.contains_key(old));
    }
}

#[tokio::test]
async fn history_list_hides_extra_entries_synced_in() {
    let f = Fixture::new();
    // Another device added duplicates and more than ten entries.
    for i in 0..12 {
        let mut v = item::HistoryEntry::new(Protocol::Sftp, format!("h{}", i % 11));
        v.used_at = Some(UnixMillis(1000 + i64::from(i)));
        f.vault.put_view(ItemId::new(), None, v).await.unwrap();
    }
    let list = f.history().list().await.unwrap();
    assert_eq!(list.len(), 10);
    assert_eq!(list[0].host, "h0", "the newest duplicate wins");
    let keys: std::collections::HashSet<_> = list.iter().map(|e| e.host.clone()).collect();
    assert_eq!(keys.len(), 10);
}

#[tokio::test]
async fn ask_for_password_keeps_a_stored_password() {
    let f = Fixture::new();
    let h = f.history();
    h.record(&login(Protocol::Sftp, "a", 22, "u", Some("pw")))
        .await
        .unwrap();
    let e = h
        .record(&login(Protocol::Sftp, "a", 22, "u", None))
        .await
        .unwrap();
    assert_eq!(e.logon, LogonKind::Normal);
    assert_eq!(e.password.unwrap().expose_secret(), "pw");
}

#[tokio::test]
async fn passwords_follow_store_passwords() {
    let f = Fixture::new();
    f.vault.set_store_passwords(false);
    let e = f
        .history()
        .record(&login(Protocol::Sftp, "a", 22, "u", Some("pw")))
        .await
        .unwrap();
    assert!(e.password.is_none());
    assert_eq!(
        e.to_connect_info().logon,
        LogonType::AskForPassword { user: "u".into() }
    );
    let raw = format!("{:?}", f.vault.raw_bodies());
    assert!(!raw.contains("\"pw\""), "{raw}");
}

#[tokio::test]
async fn locked_vault_neither_shows_nor_saves() {
    let f = Fixture::new();
    f.vault.set_unlocked(false);
    let h = f.history();
    assert!(matches!(
        h.record(&login(Protocol::Sftp, "a", 22, "u", None)).await,
        Err(SiteError::Vault(VaultError::Locked))
    ));
    assert!(matches!(
        h.list().await,
        Err(SiteError::Vault(VaultError::Locked))
    ));
    f.vault.set_unlocked(true);
    assert!(h.list().await.unwrap().is_empty());
    assert!(f.local.all().await.unwrap().is_empty());
}

#[tokio::test]
async fn clear_history_removes_everything() {
    let f = Fixture::new();
    let h = f.history();
    for host in ["a", "b", "c"] {
        h.record(&login(Protocol::Sftp, host, 22, "u", None))
            .await
            .unwrap();
    }
    assert_eq!(h.clear().await.unwrap(), 3);
    assert!(h.list().await.unwrap().is_empty());
    let sites = f.sites().await;
    assert!(
        load_recent_servers(sites.tree(), &h)
            .await
            .unwrap()
            .is_empty()
    );
}

#[test]
fn entries_convert_to_connect_info_and_back() {
    let info = login(Protocol::Sftp, " host ", 2222, "alice", Some("pw"));
    let e = HistoryEntry::from_connect_info(&info);
    assert_eq!(e.host, "host");
    let back = e.to_connect_info();
    assert_eq!(back.address.host, "host");
    assert_eq!(back.address.port, 2222);
    assert_eq!(back.address.user.as_deref(), Some("alice"));
    assert_eq!(back.logon, info.logon);

    let anon = HistoryEntry::from_connect_info(&login(Protocol::Ftp, "h", 21, "", None));
    assert_eq!(anon.to_connect_info().logon, LogonType::Anonymous);
    assert_eq!(anon.to_connect_info().address.user, None);

    // A key file isn't kept: asks next time.
    let mut key = login(Protocol::Sftp, "h", 22, "k", None);
    key.logon = LogonType::KeyFile {
        user: "k".into(),
        path: LocalPath::new("/home/k/.ssh/id"),
    };
    let e = HistoryEntry::from_connect_info(&key);
    assert_eq!(e.logon, LogonKind::AskForPassword);
    assert!(!format!("{e:?}").contains(".ssh"));
}

#[test]
fn debug_hides_the_password() {
    let e = HistoryEntry::from_connect_info(&login(Protocol::Sftp, "h", 22, "u", Some("s3cret")));
    assert!(!format!("{e:?}").contains("s3cret"));
}

// ------------------------------------------------------------------ conversion

#[tokio::test]
async fn quickconnect_entry_converts_to_site() {
    let f = Fixture::new();
    let h = f.history();
    let e = h
        .record(&login(
            Protocol::Sftp,
            "web.example.com",
            2222,
            "deploy",
            Some("pw"),
        ))
        .await
        .unwrap();
    let mut sites = f.sites().await;
    let id = sites.add_from_history(&e).await.unwrap();
    let site = sites.site(id).unwrap();
    assert_eq!(site.parent, None);
    assert_eq!(site.name, "web.example.com");
    assert_eq!(site.host, "web.example.com");
    assert_eq!(site.port, Some(2222));
    assert_eq!(
        site.logon,
        SiteLogon::Normal {
            user: "deploy".into(),
            password: Some(SecretString::from("pw".to_owned())),
        }
    );
    // A second conversion picks a free name.
    let id2 = sites.add_from_history(&e).await.unwrap();
    assert_eq!(sites.site(id2).unwrap().name, "web.example.com (2)");

    let anon =
        HistoryEntry::from_connect_info(&login(Protocol::Ftp, "ftp.example.org", 21, "", None));
    let s = anon.to_site();
    assert_eq!(s.logon, SiteLogon::Anonymous);
    assert_eq!(s.port, None);
    assert!(s.validate().iter().all(|i| !i.is_error()));
}

// ------------------------------------------------------------------ recent servers

#[tokio::test]
async fn recent_servers_mix_sites_and_quickconnect() {
    let f = Fixture::new();
    let mut sites = f.sites().await;
    let s = site_named("web01");
    let site = s.id;
    sites.save_site(s).await.unwrap();
    let h = f.history();
    let q = h
        .record(&login(Protocol::Ftp, "ftp.example.org", 21, "", None))
        .await
        .unwrap();
    f.local
        .touch_connected(site, UnixMillis(q.used_at.0 + 10))
        .await
        .unwrap();

    let recent = load_recent_servers(sites.tree(), &h).await.unwrap();
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0].id, site, "reconnect uses item 0");
    assert!(matches!(recent[0].target, RecentTarget::Site(_)));
    assert_eq!(recent[0].label(sites.tree()), "web01");
    assert_eq!(recent[1].label(sites.tree()), "ftp://ftp.example.org:21");

    // Deleting the site removes it from the recent servers.
    sites.delete(site).await.unwrap();
    let recent = load_recent_servers(sites.tree(), &h).await.unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].id, q.id);
}

#[tokio::test]
async fn record_connected_puts_a_site_first() {
    let f = Fixture::new();
    let mut sites = f.sites().await;
    let s = site_named("db");
    let id = s.id;
    sites.save_site(s).await.unwrap();
    let h = f.history();
    let q = h
        .record(&login(Protocol::Sftp, "x", 22, "u", None))
        .await
        .unwrap();
    // Recorded later than the quickconnect entry.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    sites.record_connected(id).await.unwrap();
    let recent = load_recent_servers(sites.tree(), &h).await.unwrap();
    assert_eq!(recent.iter().map(|r| r.id).collect::<Vec<_>>(), [id, q.id]);
}

#[test]
fn recent_servers_ignore_missing_items_and_cap() {
    let tree = SiteTree::new();
    let mut history = Vec::new();
    let mut locals = std::collections::HashMap::new();
    for i in 0..12 {
        let mut e = HistoryEntry::from_connect_info(&login(
            Protocol::Sftp,
            &format!("h{i}"),
            22,
            "u",
            None,
        ));
        e.used_at = UnixMillis(i);
        locals.insert(
            e.id,
            SiteLocal {
                last_connected_at: Some(UnixMillis(i)),
                ..SiteLocal::default()
            },
        );
        history.push(e);
    }
    // A row of a deleted item and one never connected.
    locals.insert(
        ItemId::new(),
        SiteLocal {
            last_connected_at: Some(UnixMillis(99)),
            ..SiteLocal::default()
        },
    );
    locals.insert(history[0].id, SiteLocal::default());
    let recent = recent_servers(&tree, &history, &locals);
    assert_eq!(recent.len(), RECENT_LIMIT);
    assert_eq!(recent[0].connected_at, UnixMillis(11));
    assert_eq!(recent[9].connected_at, UnixMillis(2));
}

// ------------------------------------------------------------------ bookmarks

#[tokio::test]
async fn bookmarks_round_trip_through_the_vault() {
    let f = Fixture::new();
    let mut sites = f.sites().await;
    let s = site_named("web01");
    let site = s.id;
    sites.save_site(s).await.unwrap();

    let mut b = f.bookmarks().await;
    let mut g = Bookmark::global("Projects");
    g.local_dir = Some(LocalPath::new("/home/me/projects"));
    g.remote_dir = Some(RemotePath::new("/srv/projects"));
    g.sync_browsing = true;
    g.comparison = true;
    let g_id = b.add(g.clone()).await.unwrap();

    let mut sb = Bookmark::for_site(site, "Logs", RemotePath::new("/var/log"));
    sb.local_dir_override = Some(LocalPath::new("/tmp/logs"));
    let sb_id = b.add(sb.clone()).await.unwrap();

    let fresh = f.bookmarks().await;
    let got = fresh.get(g_id).unwrap();
    assert_eq!(got.name, "Projects");
    assert_eq!(got.local_dir, g.local_dir);
    assert_eq!(got.remote_dir, g.remote_dir);
    assert!(got.sync_browsing && got.comparison && got.is_global());
    assert!(got.vault.is_some());

    let got = fresh.get(sb_id).unwrap();
    assert_eq!(got.site_id, Some(site));
    assert_eq!(got.local_dir, None, "the override is not synced");
    assert_eq!(got.local_dir_override, sb.local_dir_override);
    assert_eq!(
        got.target(),
        BookmarkTarget {
            local_dir: Some(LocalPath::new("/tmp/logs")),
            remote_dir: Some(RemotePath::new("/var/log")),
            sync_browsing: false,
            comparison: false,
        }
    );
    assert_eq!(fresh.global().len(), 1);
    assert_eq!(fresh.for_site(site).len(), 1);
    // The device-local path stays out of the synced item.
    let raw = format!("{:?}", f.vault.raw_bodies());
    assert!(!raw.contains("/tmp/logs"));
}

#[tokio::test]
async fn bookmarks_rename_edit_delete() {
    let f = Fixture::new();
    let mut b = f.bookmarks().await;
    let mut a = Bookmark::global("A");
    a.local_dir = Some(LocalPath::new("/a"));
    let a_id = b.add(a).await.unwrap();
    let mut c = Bookmark::global("C");
    c.remote_dir = Some(RemotePath::new("/c"));
    let c_id = b.add(c).await.unwrap();

    assert!(matches!(
        b.rename(c_id, "a").await,
        Err(SiteError::NameTaken(_))
    ));
    b.rename(c_id, " B ").await.unwrap();
    assert_eq!(b.get(c_id).unwrap().name, "B");

    let mut edit = b.get(a_id).unwrap().clone();
    edit.remote_dir = Some(RemotePath::new("/remote"));
    edit.position = 99; // ignored
    b.edit(edit).await.unwrap();
    let fresh = f.bookmarks().await;
    assert_eq!(
        fresh.get(a_id).unwrap().remote_dir,
        Some(RemotePath::new("/remote"))
    );
    assert_eq!(fresh.get(a_id).unwrap().position, 0);

    b.delete(a_id).await.unwrap();
    assert!(b.get(a_id).is_none());
    assert!(f.bookmarks().await.get(a_id).is_none());
    assert!(matches!(b.delete(a_id).await, Err(SiteError::NotFound(_))));
}

#[tokio::test]
async fn bookmarks_reorder() {
    let f = Fixture::new();
    let mut b = f.bookmarks().await;
    let mut ids = Vec::new();
    for name in ["one", "two", "three", "four"] {
        let mut x = Bookmark::global(name);
        x.local_dir = Some(LocalPath::new(format!("/{name}")));
        ids.push(b.add(x).await.unwrap());
    }
    let names =
        |b: &Bookmarks| -> Vec<String> { b.global().iter().map(|x| x.name.clone()).collect() };
    assert_eq!(names(&b), ["one", "two", "three", "four"]);
    b.reorder(ids[3], 0).await.unwrap();
    assert_eq!(names(&b), ["four", "one", "two", "three"]);
    b.reorder(ids[3], 100).await.unwrap();
    assert_eq!(names(&b), ["one", "two", "three", "four"]);
    b.reorder(ids[0], 2).await.unwrap();
    assert_eq!(names(&f.bookmarks().await), ["two", "three", "one", "four"]);
}

#[tokio::test]
async fn bookmarks_are_validated() {
    let f = Fixture::new();
    let mut b = f.bookmarks().await;
    let site = ItemId::new();
    let empty = Bookmark::global("nothing");
    assert!(matches!(
        b.add(empty).await,
        Err(SiteError::InvalidBookmark(_))
    ));
    let mut no_remote = Bookmark::for_site(site, "x", RemotePath::root());
    no_remote.remote_dir = None;
    no_remote.local_dir = Some(LocalPath::new("/x"));
    assert!(matches!(
        b.add(no_remote).await,
        Err(SiteError::InvalidBookmark(_))
    ));
    let mut sync_one_side = Bookmark::global("s");
    sync_one_side.local_dir = Some(LocalPath::new("/x"));
    sync_one_side.sync_browsing = true;
    assert!(sync_one_side.validate().is_err());
    let mut blank = Bookmark::global("  ");
    blank.local_dir = Some(LocalPath::new("/x"));
    assert!(blank.validate().is_err());
    // Names are unique per scope, not across scopes.
    let mut g = Bookmark::global("logs");
    g.remote_dir = Some(RemotePath::new("/var/log"));
    b.add(g).await.unwrap();
    b.add(Bookmark::for_site(
        site,
        "logs",
        RemotePath::new("/var/log"),
    ))
    .await
    .unwrap();
}

#[tokio::test]
async fn deleting_a_site_deletes_its_bookmarks() {
    let f = Fixture::new();
    let mut sites = f.sites().await;
    let folder = sites.add_folder(None, "Work").await.unwrap();
    let mut s = site_named("web01");
    s.parent = Some(folder);
    let site = s.id;
    sites.save_site(s).await.unwrap();
    let mut b = f.bookmarks().await;
    b.add(Bookmark::for_site(
        site,
        "logs",
        RemotePath::new("/var/log"),
    ))
    .await
    .unwrap();
    let mut g = Bookmark::global("g");
    g.remote_dir = Some(RemotePath::new("/"));
    b.add(g).await.unwrap();

    sites.delete(folder).await.unwrap();
    let b = f.bookmarks().await;
    assert!(b.for_site(site).is_empty());
    assert_eq!(b.global().len(), 1);
}
