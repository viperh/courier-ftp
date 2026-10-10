//! T64: the bookmarks menu through the app, with the real vault engine
//! (cheap Argon2) and the core's `MockServer`: add a site bookmark from the
//! directories shown and apply it with synchronized browsing, global
//! bookmarks (local only, local + remote with comparison) with reorder and
//! delete persisted across a restart, and the locked vault.

use std::path::Path;

use courier_ftp_core::{
    model::RemotePath,
    sites::{Bookmark, Bookmarks},
    vault::MemKeyring,
};
use crossterm::event::KeyCode;
use pretty_assertions::assert_eq;

use super::site_tests::{server, start_with};
use super::vault_tests::{Rig, STRONG};
use super::*;
use crate::ui::bookmarks::{NOT_CONNECTED_NOTE, QUICKCONNECT_NOTE};

fn local(path: &Path) -> RemotePath {
    courier_ftp_core::local::local_to_remote(path).unwrap()
}

impl Rig {
    fn menu_open(&self) -> bool {
        self.app.screen.bookmarks().is_some()
    }

    /// Show `dir` in `side`'s file list.
    async fn go(&mut self, side: Side, dir: RemotePath) {
        self.app
            .dispatch(Action::ListDir {
                side,
                dir: dir.clone(),
                force: false,
            })
            .unwrap();
        self.until("directory shown", |app| {
            let pane = match side {
                Side::Local => &app.screen.local,
                Side::Remote => &app.screen.remote,
            };
            pane.dir.as_ref() == Some(&dir)
        })
        .await;
    }

    /// `<Ctrl-b>`, waiting for the bookmarks.
    async fn bookmarks_menu(&mut self) {
        self.ctrl(KeyCode::Char('b'));
        self.settle().await;
        assert!(self.menu_open());
    }

    /// Every bookmark, read from the vault.
    async fn stored(&self) -> Vec<Bookmark> {
        let engine = self.engine();
        let store = engine.store().clone();
        Bookmarks::load(Arc::new(engine), Arc::new(store))
            .await
            .unwrap()
            .all()
            .to_vec()
    }
}

fn names(list: &[Bookmark]) -> Vec<&str> {
    list.iter().map(|b| b.name.as_str()).collect()
}

#[tokio::test]
async fn add_site_bookmark_from_the_current_dirs_and_apply_it_with_sync_browsing() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    let server = server();
    let disk = tempfile::tempdir().unwrap();
    let www = disk.path().join("projects").join("www");
    std::fs::create_dir_all(&www).unwrap();

    let mut rig = start_with(dir.path(), &keyring, &server).await;
    rig.create(STRONG, false).await;
    rig.until("sites loaded", |a| a.site_snapshot.is_some())
        .await;
    rig.create_mock_site().await;
    let site = rig.snapshot().tree.find_site("mock").unwrap().id;
    rig.alt('c');
    rig.until("connected", Rig::connected).await;

    // The directories to bookmark.
    rig.go(Side::Local, local(&www)).await;
    rig.go(Side::Remote, RemotePath::new("/srv/www")).await;
    rig.bookmarks_menu().await;
    let text = rig.screen(120, 40);
    assert!(text.contains("Bookmarks of site mock"), "{text}");

    // a: name and directories prefilled, site-specific by default; tick
    // "Use synchronized browsing" and save.
    rig.key(KeyCode::Char('a'));
    let text = rig.screen(120, 40);
    assert!(text.contains("Add bookmark"), "{text}");
    assert!(text.contains("(•) Site-specific"), "{text}");
    assert!(text.contains("/srv/www"), "{text}");
    assert!(text.contains(&www.display().to_string()), "{text}");
    // Down moves on (Tab completes the local path).
    rig.key(KeyCode::Down); // type
    rig.key(KeyCode::Tab); // local
    rig.key(KeyCode::Down); // remote
    rig.key(KeyCode::Down); // sync
    rig.key(KeyCode::Char(' '));
    rig.key(KeyCode::Enter);
    rig.settle().await;
    assert!(rig.screen(120, 40).contains("Saved"));

    // Persisted in the vault as the site's bookmark.
    let stored = rig.stored().await;
    assert_eq!(names(&stored), ["www"]);
    let b = &stored[0];
    assert_eq!(b.site_id, Some(site));
    assert_eq!(b.effective_local_dir().unwrap().as_path(), www.as_path());
    assert_eq!(b.remote_dir, Some(RemotePath::new("/srv/www")));
    assert!(b.sync_browsing && !b.comparison);
    // The Site Manager's Bookmarks tab sees it.
    assert_eq!(rig.snapshot().bookmarks.get(&site).unwrap(), &["www"]);

    // Somewhere else, then apply it: both panes move, sync browsing is on.
    rig.key(KeyCode::Esc);
    assert!(!rig.menu_open());
    rig.go(Side::Local, local(disk.path())).await;
    rig.go(Side::Remote, RemotePath::new("/srv")).await;
    assert!(!rig.app.screen.sync_on());
    rig.bookmarks_menu().await;
    rig.key(KeyCode::Char('G'));
    rig.key(KeyCode::Enter);
    assert!(!rig.menu_open());
    let (want_local, want_remote) = (local(&www), RemotePath::new("/srv/www"));
    rig.until("bookmark applied", |app| {
        app.screen.local.dir.as_ref() == Some(&want_local)
            && app.screen.remote.dir.as_ref() == Some(&want_remote)
            && app.screen.sync_on()
    })
    .await;
    assert!(!rig.app.screen.compare_on());
    let text = rig.screen(120, 40);
    assert!(text.contains("index.html"), "{text}");
}

#[tokio::test]
async fn global_bookmarks_apply_reorder_delete_and_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    let server = server();
    let disk = tempfile::tempdir().unwrap();
    let alpha = disk.path().join("alpha");
    let beta = disk.path().join("beta");
    std::fs::create_dir_all(&alpha).unwrap();
    std::fs::create_dir_all(&beta).unwrap();

    let mut rig = start_with(dir.path(), &keyring, &server).await;
    rig.create(STRONG, false).await;
    rig.until("sites loaded", |a| a.site_snapshot.is_some())
        .await;

    // Not connected: local-only global bookmarks; site bookmarks explained.
    rig.go(Side::Local, local(&alpha)).await;
    rig.bookmarks_menu().await;
    let text = rig.screen(120, 40);
    assert!(text.contains(NOT_CONNECTED_NOTE), "{text}");
    rig.key(KeyCode::Char('a'));
    assert!(!rig.screen(120, 40).contains("Site-specific"));
    rig.key(KeyCode::Enter);
    rig.settle().await;
    rig.key(KeyCode::Esc);
    rig.go(Side::Local, local(&beta)).await;
    rig.bookmarks_menu().await;
    rig.key(KeyCode::Char('a'));
    rig.key(KeyCode::Enter);
    rig.settle().await;
    assert_eq!(names(&rig.stored().await), ["alpha", "beta"]);

    // K moves "beta" (just added, selected) up.
    rig.key(KeyCode::Char('K'));
    rig.settle().await;
    assert_eq!(names(&rig.stored().await), ["beta", "alpha"]);

    // Apply "alpha": the local pane goes there.
    rig.key(KeyCode::Char('j'));
    rig.key(KeyCode::Enter);
    let want = local(&alpha);
    rig.until("local bookmark applied", |app| {
        app.screen.local.dir.as_ref() == Some(&want)
    })
    .await;

    // A quickconnect session: no site bookmarks, said why.
    rig.quickconnect("sftp://alice:pw@mock.invalid/srv").await;
    rig.until("connected", Rig::connected).await;
    rig.bookmarks_menu().await;
    let text = rig.screen(120, 40);
    assert!(text.contains(QUICKCONNECT_NOTE), "{text}");
    // A global bookmark of both directories with comparison.
    rig.key(KeyCode::Char('a'));
    for _ in 0..4 {
        rig.key(KeyCode::Down); // local, remote, sync, comparison
    }
    rig.key(KeyCode::Char(' '));
    rig.key(KeyCode::Enter);
    rig.settle().await;
    let stored = rig.stored().await;
    assert_eq!(names(&stored), ["beta", "alpha", "srv"]);
    assert!(stored[2].comparison && stored[2].site_id.is_none());

    // Elsewhere, then apply it: both panes move, comparison (and sync
    // browsing with it) is on.
    rig.key(KeyCode::Esc);
    rig.go(Side::Local, local(&beta)).await;
    rig.go(Side::Remote, RemotePath::new("/srv/www")).await;
    rig.bookmarks_menu().await;
    rig.key(KeyCode::Char('G'));
    rig.key(KeyCode::Enter);
    let want_local = local(&alpha);
    rig.until("compare bookmark applied", |app| {
        app.screen.local.dir.as_ref() == Some(&want_local)
            && app.screen.remote.dir.as_ref() == Some(&RemotePath::new("/srv"))
            && app.screen.compare_on()
            && app.screen.sync_on()
    })
    .await;

    // Delete "beta" (first), confirmed.
    rig.bookmarks_menu().await;
    rig.key(KeyCode::Char('g'));
    rig.key(KeyCode::Char('x'));
    rig.key(KeyCode::Char('y'));
    rig.settle().await;
    assert_eq!(names(&rig.stored().await), ["alpha", "srv"]);

    // Restart: the bookmarks are still there, in order.
    drop(rig);
    let mut rig = start_with(dir.path(), &keyring, &server).await;
    rig.unlock(STRONG).await;
    rig.until("sites loaded", |a| a.site_snapshot.is_some())
        .await;
    rig.bookmarks_menu().await;
    let text = rig.screen(120, 40);
    let (a, s) = (text.find("alpha").unwrap(), text.find("srv").unwrap());
    assert!(a < s, "{text}");
    assert!(!text.contains("beta"), "{text}");
}

#[tokio::test]
async fn locked_vault_hides_bookmarks_and_offers_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    let mut rig = Rig::fresh(dir.path(), &keyring).await;
    rig.bookmarks_menu().await;
    // Locking closes the menu.
    rig.app.dispatch(Action::LockVault).unwrap();
    rig.settle().await;
    assert!(!rig.menu_open());

    // Continue without the vault, Ctrl-b: asked to unlock; "No" leaves the
    // menu with the bookmarks hidden.
    rig.alt('c');
    rig.settle().await;
    rig.ctrl(KeyCode::Char('b'));
    rig.settle().await;
    let text = rig.screen(120, 40);
    assert!(
        text.contains("The vault is locked. Unlock it to use bookmarks?"),
        "{text}"
    );
    rig.key(KeyCode::Char('n'));
    rig.settle().await;
    let text = rig.screen(120, 40);
    assert!(text.contains("Bookmarks are kept in the vault."), "{text}");
    // Enter there unlocks; then the bookmarks load.
    rig.key(KeyCode::Enter);
    rig.settle().await;
    rig.unlock(STRONG).await;
    rig.until("bookmarks loaded", |app| {
        app.screen
            .bookmarks()
            .is_some_and(|m| !m.is_locked() && !m.is_busy())
    })
    .await;
    let text = rig.screen(120, 40);
    assert!(text.contains("None yet: a adds"), "{text}");
}
