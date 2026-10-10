//! T64: the bookmarks menu on its own: rendering (sections, quickconnect
//! note, locked vault, the add form) and the keyboard flows (the requests
//! it sends). The flows against a real vault and the mock server are in
//! `app/bookmark_tests.rs`.

use courier_ftp_core::{
    model::{LocalPath, RemotePath, item::ItemId},
    sites::Bookmark,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};

use super::*;
use crate::bookmarks::{BookmarkOp, BookmarkOutcome, BookmarksReply};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn typed(menu: &mut BookmarksMenu, text: &str) {
    for c in text.chars() {
        menu.handle_key(key(KeyCode::Char(c)));
    }
}

/// The one request the menu sent.
fn one(menu: &mut BookmarksMenu) -> BookmarkOp {
    let mut requests = menu.take_requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    requests.remove(0)
}

fn render(menu: &mut BookmarksMenu, w: u16, h: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
    terminal
        .draw(|f| menu.draw(f, f.area(), &Theme::default()))
        .unwrap();
    terminal.backend().to_string()
}

struct Fixture {
    site: ItemId,
    docs: Bookmark,
    www: Bookmark,
    logs: Bookmark,
    conf: Bookmark,
}

fn fixture() -> Fixture {
    let site = ItemId::new();
    let mut docs = Bookmark::global("Docs");
    docs.local_dir = Some(LocalPath::new("/home/me/docs"));
    docs.position = 0;
    let mut www = Bookmark::global("Website");
    www.local_dir = Some(LocalPath::new("/home/me/www"));
    www.remote_dir = Some(RemotePath::new("/var/www"));
    www.sync_browsing = true;
    www.comparison = true;
    www.position = 1;
    let mut logs = Bookmark::for_site(site, "Logs", RemotePath::new("/var/log"));
    logs.position = 0;
    let mut conf = Bookmark::for_site(site, "Config", RemotePath::new("/etc/nginx"));
    conf.position = 1;
    conf.read_only = true;
    Fixture {
        site,
        docs,
        www,
        logs,
        conf,
    }
}

fn reply(list: Vec<Bookmark>, outcome: BookmarkOutcome) -> BookmarksReply {
    BookmarksReply {
        bookmarks: Some(list),
        sites: None,
        outcome,
    }
}

/// A menu connected to the fixture's site, loaded.
fn loaded(fx: &Fixture) -> BookmarksMenu {
    let mut menu = BookmarksMenu::new(MenuContext {
        site: Some((fx.site, "web01".into())),
        quickconnect: false,
        local_dir: Some("/home/me/projects/site".into()),
        remote_dir: Some("/srv/site/public".into()),
    });
    assert!(matches!(
        menu.take_requests().as_slice(),
        [BookmarkOp::Load]
    ));
    assert!(menu.is_busy());
    menu.apply_reply(&reply(
        vec![
            fx.docs.clone(),
            fx.www.clone(),
            fx.logs.clone(),
            fx.conf.clone(),
        ],
        BookmarkOutcome::Loaded,
    ));
    menu
}

#[test]
fn sections_snapshot() {
    let fx = fixture();
    let mut menu = loaded(&fx);
    assert_eq!(menu.selected(), Some(fx.docs.id));
    menu.handle_key(key(KeyCode::Down));
    insta::assert_snapshot!("bookmarks_menu_90x20", render(&mut menu, 90, 20));
}

#[test]
fn quickconnect_and_not_connected_explain_site_bookmarks() {
    let fx = fixture();
    let mut menu = BookmarksMenu::new(MenuContext {
        quickconnect: true,
        local_dir: Some("/home/me".into()),
        remote_dir: Some("/".into()),
        ..MenuContext::default()
    });
    menu.apply_reply(&reply(vec![fx.logs.clone()], BookmarkOutcome::Loaded));
    let text = render(&mut menu, 90, 20);
    insta::assert_snapshot!("bookmarks_menu_quickconnect_90x20", text);
    // The other site's bookmark isn't listed.
    assert!(!text.contains("Logs"), "{text}");

    let mut menu = BookmarksMenu::new(MenuContext::default());
    menu.apply_reply(&reply(Vec::new(), BookmarkOutcome::Loaded));
    let text = render(&mut menu, 90, 20);
    assert!(text.contains(NOT_CONNECTED_NOTE), "{text}");
    assert!(text.contains("None yet: a adds"), "{text}");
    // Nothing to apply.
    menu.handle_key(key(KeyCode::Enter));
    assert!(!menu.is_closed());
    assert!(render(&mut menu, 90, 20).contains("No bookmark selected"));
}

#[test]
fn locked_menu_hides_bookmarks_and_offers_unlock() {
    let mut menu = BookmarksMenu::locked(MenuContext::default());
    assert!(menu.take_requests().is_empty());
    insta::assert_snapshot!("bookmarks_menu_locked_70x12", render(&mut menu, 70, 12));
    menu.handle_key(key(KeyCode::Enter));
    assert!(menu.take_unlock_request());
    menu.unlocked();
    assert!(menu.take_requests().is_empty());
    assert!(render(&mut menu, 70, 12).contains("Loading bookmarks"));
    menu.sites_ready();
    assert!(matches!(
        menu.take_requests().as_slice(),
        [BookmarkOp::Load]
    ));
    assert!(render(&mut menu, 70, 12).contains("Loading bookmarks"));
}

#[test]
fn enter_applies_the_selected_bookmark() {
    let fx = fixture();
    let mut menu = loaded(&fx);
    menu.handle_key(key(KeyCode::Char('j')));
    menu.handle_key(key(KeyCode::Enter));
    assert!(menu.is_closed());
    let target = menu.take_apply().unwrap();
    assert_eq!(target, fx.www.target());
    assert!(target.sync_browsing && target.comparison);
}

#[test]
fn search_is_fuzzy_and_enter_applies_the_best_match() {
    let fx = fixture();
    let mut menu = loaded(&fx);
    menu.handle_key(key(KeyCode::Char('/')));
    typed(&mut menu, "lg");
    let text = render(&mut menu, 90, 20);
    assert!(text.contains("Search: lg"), "{text}");
    assert!(!text.contains("Website"), "{text}");
    assert_eq!(menu.selected(), Some(fx.logs.id));
    // Plain letters are search text, not commands.
    assert!(!menu.has_overlay());
    menu.handle_key(key(KeyCode::Enter));
    assert_eq!(menu.take_apply(), Some(fx.logs.target()));

    // Esc clears the search; Esc again closes.
    let mut menu = loaded(&fx);
    menu.handle_key(key(KeyCode::Char('/')));
    typed(&mut menu, "zzz");
    assert!(render(&mut menu, 90, 20).contains("No match"));
    menu.handle_key(key(KeyCode::Esc));
    assert!(render(&mut menu, 90, 20).contains("Website"));
    menu.handle_key(key(KeyCode::Esc));
    assert!(menu.is_closed());
    assert!(menu.take_apply().is_none());
}

#[test]
fn add_prefills_the_current_directories_as_a_site_bookmark() {
    let fx = fixture();
    let mut menu = loaded(&fx);
    menu.handle_key(key(KeyCode::Char('a')));
    assert!(menu.has_overlay());
    insta::assert_snapshot!("bookmarks_add_90x20", render(&mut menu, 90, 20));
    menu.handle_key(key(KeyCode::Enter));
    let BookmarkOp::Add(b) = one(&mut menu) else {
        panic!("add expected");
    };
    assert_eq!(b.name, "public");
    assert_eq!(b.site_id, Some(fx.site));
    assert_eq!(
        b.local_dir.as_ref().map(LocalPath::to_display),
        Some("/home/me/projects/site".to_owned())
    );
    assert_eq!(b.remote_dir, Some(RemotePath::new("/srv/site/public")));
    assert!(!b.sync_browsing && !b.comparison);
    assert!(menu.is_busy());

    // The saved bookmark is selected.
    let mut saved = (*b).clone();
    saved.position = 2;
    menu.apply_reply(&reply(
        vec![
            fx.docs.clone(),
            fx.www.clone(),
            fx.logs.clone(),
            fx.conf.clone(),
            saved.clone(),
        ],
        BookmarkOutcome::Saved(saved.id),
    ));
    assert_eq!(menu.selected(), Some(saved.id));
    assert!(render(&mut menu, 90, 20).contains("Saved"));
}

#[test]
fn add_global_with_sync_and_compare() {
    let fx = fixture();
    let mut menu = loaded(&fx);
    menu.handle_key(key(KeyCode::Char('a')));
    menu.handle_paste("x"); // name: "publicx"
    menu.handle_key(key(KeyCode::Tab));
    menu.handle_key(key(KeyCode::Left)); // Type: Global
    for _ in 0..3 {
        menu.handle_key(key(KeyCode::Tab));
    }
    menu.handle_key(key(KeyCode::Char(' '))); // sync
    menu.handle_key(key(KeyCode::Tab));
    menu.handle_key(key(KeyCode::Char(' '))); // compare
    menu.handle_key(key(KeyCode::Enter));
    let BookmarkOp::Add(b) = one(&mut menu) else {
        panic!("add expected");
    };
    assert_eq!(b.name, "publicx");
    assert_eq!(b.site_id, None);
    assert!(b.sync_browsing && b.comparison);
}

#[test]
fn add_refuses_sync_without_both_directories() {
    let mut menu = BookmarksMenu::new(MenuContext {
        local_dir: Some("/home/me".into()),
        ..MenuContext::default()
    });
    menu.apply_reply(&reply(Vec::new(), BookmarkOutcome::Loaded));
    menu.take_requests();
    menu.handle_key(key(KeyCode::Char('a')));
    // No site: no type field. Name, local, remote, sync.
    for _ in 0..3 {
        menu.handle_key(key(KeyCode::Tab));
    }
    menu.handle_key(key(KeyCode::Char(' ')));
    menu.handle_key(key(KeyCode::Enter));
    assert!(menu.has_overlay());
    assert!(menu.take_requests().is_empty());
    let text = render(&mut menu, 90, 20);
    assert!(
        text.contains("Synchronized browsing needs both a local and a remote directory"),
        "{text}"
    );
    // Esc cancels the form, then closes the menu.
    menu.handle_key(key(KeyCode::Esc));
    assert!(!menu.has_overlay());
    assert!(menu.take_requests().is_empty());
}

#[test]
fn edit_keeps_the_scope_and_refuses_read_only() {
    let fx = fixture();
    let mut menu = loaded(&fx);
    menu.handle_key(key(KeyCode::Char('G'))); // Config (read-only)
    assert_eq!(menu.selected(), Some(fx.conf.id));
    menu.handle_key(key(KeyCode::Char('e')));
    assert!(!menu.has_overlay());
    assert!(render(&mut menu, 90, 20).contains("can't be edited"));

    menu.handle_key(key(KeyCode::Char('k'))); // Logs
    menu.handle_key(key(KeyCode::Char('e')));
    let text = render(&mut menu, 90, 20);
    assert!(text.contains("Edit bookmark"), "{text}");
    assert!(!text.contains("Site-specific"), "{text}");
    // Name: replace "Logs" with "Nginx logs".
    for _ in 0..4 {
        menu.handle_key(key(KeyCode::Backspace));
    }
    typed(&mut menu, "Nginx logs");
    menu.handle_key(key(KeyCode::Enter));
    let BookmarkOp::Edit(b) = one(&mut menu) else {
        panic!("edit expected");
    };
    assert_eq!(b.id, fx.logs.id);
    assert_eq!(b.name, "Nginx logs");
    assert_eq!(b.site_id, Some(fx.site));
    assert_eq!(b.remote_dir, Some(RemotePath::new("/var/log")));

    // A refused save shows the reason.
    menu.apply_reply(&reply(
        vec![fx.docs.clone(), fx.logs.clone()],
        BookmarkOutcome::Failed("the name “Docs” is already used".into()),
    ));
    assert!(render(&mut menu, 90, 20).contains("already used"));
}

#[test]
fn edit_writes_this_devices_override_when_there_is_one() {
    let fx = fixture();
    let mut docs = fx.docs.clone();
    docs.local_dir_override = Some(LocalPath::new("/mnt/docs"));
    let mut menu = BookmarksMenu::new(MenuContext::default());
    menu.apply_reply(&reply(vec![docs.clone()], BookmarkOutcome::Loaded));
    menu.take_requests();
    menu.handle_key(key(KeyCode::Char('e')));
    let text = render(&mut menu, 90, 20);
    assert!(text.contains("/mnt/docs"), "{text}");
    menu.handle_key(key(KeyCode::Tab));
    menu.handle_paste("2");
    menu.handle_key(key(KeyCode::Enter));
    let BookmarkOp::Edit(b) = one(&mut menu) else {
        panic!("edit expected");
    };
    assert_eq!(b.local_dir_override, Some(LocalPath::new("/mnt/docs2")));
    assert_eq!(b.local_dir, Some(LocalPath::new("/home/me/docs")));
}

#[test]
fn delete_asks_first() {
    let fx = fixture();
    let mut menu = loaded(&fx);
    menu.handle_key(key(KeyCode::Char('x')));
    let text = render(&mut menu, 90, 20);
    assert!(text.contains("Delete the bookmark “Docs”?"), "{text}");
    menu.handle_key(key(KeyCode::Char('n')));
    assert!(menu.take_requests().is_empty());
    menu.handle_key(key(KeyCode::Delete));
    menu.handle_key(key(KeyCode::Char('y')));
    let BookmarkOp::Delete(id) = one(&mut menu) else {
        panic!("delete expected");
    };
    assert_eq!(id, fx.docs.id);
    menu.apply_reply(&reply(
        vec![fx.www.clone(), fx.logs.clone()],
        BookmarkOutcome::Deleted,
    ));
    // The selection moves to a bookmark still there.
    assert_eq!(menu.selected(), Some(fx.www.id));
}

#[test]
fn shift_j_k_reorder_within_the_section() {
    let fx = fixture();
    let mut menu = loaded(&fx);
    // First global: K does nothing, J moves it down.
    menu.handle_key(key(KeyCode::Char('K')));
    assert!(menu.take_requests().is_empty());
    menu.handle_key(KeyEvent::new(KeyCode::Char('J'), KeyModifiers::SHIFT));
    let BookmarkOp::Reorder { id, index } = one(&mut menu) else {
        panic!("reorder expected");
    };
    assert_eq!((id, index), (fx.docs.id, 1));
    let mut docs = fx.docs.clone();
    docs.position = 1;
    let mut www = fx.www.clone();
    www.position = 0;
    menu.apply_reply(&reply(
        vec![www, docs, fx.logs.clone(), fx.conf.clone()],
        BookmarkOutcome::Moved(fx.docs.id),
    ));
    assert_eq!(menu.selected(), Some(fx.docs.id));
    // Last global: J doesn't cross into the site section.
    menu.handle_key(key(KeyCode::Char('J')));
    assert!(menu.take_requests().is_empty());
    // Site bookmarks reorder within their section.
    menu.handle_key(key(KeyCode::Char('G')));
    menu.handle_key(key(KeyCode::Char('K')));
    let BookmarkOp::Reorder { id, index } = one(&mut menu) else {
        panic!("reorder expected");
    };
    assert_eq!((id, index), (fx.conf.id, 0));
    menu.apply_reply(&reply(Vec::new(), BookmarkOutcome::Loaded));

    // Not while searching.
    let mut menu = loaded(&fx);
    menu.handle_key(key(KeyCode::Char('/')));
    typed(&mut menu, "do");
    menu.handle_key(key(KeyCode::Tab));
    menu.handle_key(key(KeyCode::Char('J')));
    assert!(menu.take_requests().is_empty());
    assert!(render(&mut menu, 90, 20).contains("Clear the search"));
}

#[test]
fn default_name_is_the_last_directory() {
    let ctx = |local: Option<&str>, remote: Option<&str>| MenuContext {
        local_dir: local.map(Into::into),
        remote_dir: remote.map(Into::into),
        ..MenuContext::default()
    };
    assert_eq!(default_name(&ctx(Some("/a/b"), Some("/srv/www/"))), "www");
    assert_eq!(default_name(&ctx(Some("C:\\Users\\me"), Some("/"))), "me");
    assert_eq!(default_name(&ctx(None, None)), "");
}
