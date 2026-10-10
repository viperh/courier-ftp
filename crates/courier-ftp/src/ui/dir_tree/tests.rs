//! T54: tree states as snapshots, lazy loading, sync with the file list,
//! keys.

use std::time::Instant;

use courier_ftp_core::{
    backend::Listing,
    model::{Entry, RemotePath},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};

use super::{DirTree, TreeEffect};
use crate::{
    action::Action,
    ui::{Side, theme::Theme},
};

fn p(s: &str) -> RemotePath {
    RemotePath::new(s)
}

fn listing(dir: &str, dirs: &[&str]) -> Listing {
    let mut entries: Vec<Entry> = dirs.iter().map(|d| Entry::dir(*d)).collect();
    entries.push(Entry::file("notes.txt", 10));
    for e in &mut entries {
        e.hidden = e.name.starts_with('.');
    }
    Listing {
        dir: p(dir),
        entries,
        fetched_at: Instant::now(),
        raw: None,
    }
}

fn tree(side: Side) -> DirTree {
    DirTree::with_shortcuts(side, true, false, false)
}

fn render(t: &mut DirTree, focused: bool) -> Terminal<TestBackend> {
    let mut terminal = Terminal::new(TestBackend::new(32, 10)).unwrap();
    terminal
        .draw(|f| t.draw(f, f.area(), focused, 0, &Theme::new(None, true)))
        .unwrap();
    terminal
}

fn text(t: &mut DirTree) -> String {
    render(t, true).backend().to_string()
}

/// `/` → home → alice, the way a local tree starts in `/home/alice`.
fn synced() -> DirTree {
    let mut t = tree(Side::Local);
    t.listing(&listing("/home/alice", &["Documents", "Music", ".config"]));
    t.sync_to(&p("/home/alice"));
    assert_eq!(t.take_requests(), vec![p("/"), p("/home")]);
    t.loaded(&p("/"), &Ok(listing("/", &["etc", "home", "usr"])));
    t.loaded(&p("/home"), &Ok(listing("/home", &["alice", "bob"])));
    t
}

#[test]
fn snapshot_loading() {
    let mut t = tree(Side::Remote);
    t.set_active(true);
    t.sync_to(&p("/srv/www"));
    let wanted = t.take_requests();
    assert_eq!(wanted, vec![p("/"), p("/srv")]);
    t.loaded(&p("/"), &Ok(listing("/", &["home", "srv"])));
    insta::assert_snapshot!("tree_loading", render(&mut t, true).backend());
}

#[test]
fn snapshot_expanded() {
    let mut t = synced();
    assert_eq!(t.cursor_path(), Some(&p("/home/alice")));
    insta::assert_snapshot!("tree_expanded", render(&mut t, true).backend());
}

#[test]
fn snapshot_collapsed() {
    let mut t = synced();
    t.update(&Action::Top);
    t.update(&Action::CursorDown);
    t.update(&Action::CursorDown);
    t.update(&Action::ParentDir);
    insta::assert_snapshot!("tree_collapsed", render(&mut t, false).backend());
}

#[test]
fn snapshot_ascii() {
    let mut t = DirTree::with_shortcuts(Side::Local, false, false, false);
    t.listing(&listing("/home/alice", &["Documents"]));
    t.sync_to(&p("/home/alice"));
    t.take_requests();
    t.loaded(&p("/"), &Ok(listing("/", &["etc", "home"])));
    t.loaded(&p("/home"), &Err("permission denied".into()));
    insta::assert_snapshot!("tree_ascii", render(&mut t, true).backend());
}

#[test]
fn remote_tree_waits_for_a_connection() {
    let mut t = tree(Side::Remote);
    t.sync_to(&p("/srv"));
    assert!(t.take_requests().is_empty());
    assert!(text(&mut t).contains("Not connected."));
    t.set_active(true);
    assert_eq!(t.take_requests(), vec![p("/")]);
    // Asked for once only, until it arrives.
    assert!(t.take_requests().is_empty());
    t.reset();
    assert_eq!(t.current(), None);
    assert!(t.take_requests().is_empty());
}

#[test]
fn sync_expands_the_path_and_reveals_it() {
    let mut t = synced();
    let s = text(&mut t);
    for name in ["home", "alice", "bob", "Documents", "etc", "usr"] {
        assert!(s.contains(name), "{name} missing:\n{s}");
    }
    // Hidden directories stay hidden unless shown, or on the way.
    assert!(!s.contains(".config"), "{s}");
    t.set_show_hidden(true);
    assert!(text(&mut t).contains(".config"));
    t.set_show_hidden(false);
    t.listing(&listing("/home/alice/.config", &["courier"]));
    t.sync_to(&p("/home/alice/.config"));
    assert_eq!(t.cursor_path(), Some(&p("/home/alice/.config")));
    assert!(text(&mut t).contains(".config"));
    // A directory far below the visible rows is scrolled into view.
    let mut t = tree(Side::Local);
    let many: Vec<String> = (0..50).map(|i| format!("d{i:02}")).collect();
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();
    t.listing(&listing("/", &refs));
    t.listing(&listing("/d40", &[]));
    t.sync_to(&p("/d40"));
    let s = text(&mut t);
    assert!(s.contains("d40"), "{s}");
    assert!(!s.contains("d01"), "{s}");
}

#[test]
fn keys_move_expand_collapse_and_navigate() {
    let mut t = synced();
    // Rows: / , etc, home, alice, Documents, Music, bob, usr.
    t.update(&Action::Top);
    t.update(&Action::CursorDown);
    t.update(&Action::CursorDown);
    assert_eq!(t.cursor_path(), Some(&p("/home")));
    // `h` collapses an expanded node, then goes to the parent.
    t.update(&Action::ParentDir);
    assert!(!text(&mut t).contains("alice"));
    t.update(&Action::ParentDir);
    assert_eq!(t.cursor_path(), Some(&p("/")));
    // `l` expands, then steps into the first child.
    t.update(&Action::CursorDown);
    t.update(&Action::CursorDown);
    t.update(&Action::Open);
    assert!(text(&mut t).contains("alice"));
    t.update(&Action::Open);
    assert_eq!(t.cursor_path(), Some(&p("/home/alice")));
    // Expanding an unlisted directory asks for it (lazily).
    t.update(&Action::Bottom);
    assert_eq!(t.cursor_path(), Some(&p("/usr")));
    t.update(&Action::Open);
    assert_eq!(t.take_requests(), vec![p("/usr")]);
    assert!(text(&mut t).contains("? usr"));
    // Enter shows the directory in the file list.
    let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
    assert_eq!(
        t.handle_key(enter),
        Some(Some(TreeEffect::Navigate(p("/usr"))))
    );
    let j = KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE);
    assert_eq!(t.handle_key(j), None);
}

#[test]
fn cache_changes_reload_shown_directories() {
    let mut t = synced();
    t.invalidate(&p("/home"));
    // Never listed: nothing to refresh.
    t.invalidate(&p("/usr"));
    assert_eq!(t.take_requests(), vec![p("/home")]);
    t.loaded(&p("/home"), &Ok(listing("/home", &["alice", "carol"])));
    let s = text(&mut t);
    assert!(s.contains("carol") && !s.contains("bob"), "{s}");
}

#[test]
fn failed_listings_can_be_retried() {
    let mut t = synced();
    t.update(&Action::Bottom);
    t.update(&Action::Open);
    t.take_requests();
    t.loaded(&p("/usr"), &Err("denied".into()));
    assert!(text(&mut t).contains("! usr"));
    t.update(&Action::ParentDir);
    t.update(&Action::Open);
    assert_eq!(t.take_requests(), vec![p("/usr")]);
}

#[test]
fn windows_shortcuts_come_first() {
    let mut t = DirTree::with_shortcuts(Side::Local, true, false, true);
    t.set_home(&p("/C:/Users/me"));
    t.listing(&listing("/", &["C:", "D:"]));
    t.listing(&listing("/C:/Users/me", &["Desktop", "Documents"]));
    t.sync_to(&p("/C:/Users/me/Documents"));
    let s = text(&mut t);
    let home = s.find("Home").unwrap();
    let desktop = s.find("Desktop").unwrap();
    let computer = s.find("Computer").unwrap();
    assert!(home < desktop && desktop < computer, "{s}");
    // The Home shortcut holds the cursor, not the drive list.
    assert_eq!(t.cursor_path(), Some(&p("/C:/Users/me/Documents")));
    // `h` collapses the current directory first, then goes up.
    t.update(&Action::ParentDir);
    t.update(&Action::ParentDir);
    assert_eq!(t.cursor_path(), Some(&p("/C:/Users/me")));
}
