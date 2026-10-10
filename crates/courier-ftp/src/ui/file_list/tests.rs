//! T53: snapshots of every state, navigation, selection, sorting, filtering.

use std::time::Instant;

use courier_ftp_core::{
    backend::Listing,
    filters::{Condition, FilterEngine, MatchMode, StringOp},
    model::{Entry, EntryKind, Permissions, Precision, RemotePath, Timestamp},
    settings::{Column, Settings},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};
use time::{UtcOffset, macros::datetime};

use super::{Effect, FileList};
use crate::{
    action::Action,
    ui::{Side, theme::Theme},
};

fn entry(name: &str, size: u64, dir: bool) -> Entry {
    let mut e = if dir {
        Entry::dir(name)
    } else {
        Entry::file(name, size)
    };
    e.modified = Some(Timestamp::new(
        datetime!(2026-10-08 18:22:10 UTC),
        Precision::Second,
    ));
    e.permissions = Some(Permissions::from_mode(if dir {
        0o040_755
    } else {
        0o100_644
    }));
    e.owner = Some("alice".into());
    e.group = Some("www".into());
    e
}

fn site_entries() -> Vec<Entry> {
    let mut link = entry("current", 0, false);
    link.kind = EntryKind::Symlink {
        target: Some("releases/42".into()),
        target_kind: Some(Box::new(EntryKind::Dir)),
    };
    let mut old = entry("notes.txt", 120, false);
    old.modified = Some(Timestamp::new(
        datetime!(2021-01-05 0:00 UTC),
        Precision::Day,
    ));
    vec![
        entry("index.html", 4096, false),
        entry("assets", 0, true),
        entry("style.css", 900, false),
        entry(".htaccess", 64, false),
        entry("file10.log", 10, false),
        entry("file2.log", 2, false),
        link,
        old,
    ]
}

fn listing(dir: &str, entries: Vec<Entry>) -> Result<Listing, String> {
    Ok(Listing {
        dir: RemotePath::new(dir),
        entries,
        fetched_at: Instant::now(),
        raw: None,
    })
}

fn list(side: Side) -> FileList {
    let mut l = FileList::new(side, &Settings::default(), FilterEngine::default());
    l.set_offset(UtcOffset::UTC);
    l
}

fn loaded(side: Side, dir: &str) -> FileList {
    let mut l = list(side);
    assert!(l.listing_loaded(&listing(dir, site_entries())).is_none());
    l
}

fn render(l: &mut FileList, w: u16, h: u16) -> Terminal<TestBackend> {
    let theme = Theme::new(None, true);
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    t.draw(|f| l.draw(f, f.area(), true, 0, &theme)).unwrap();
    t
}

fn text(t: &Terminal<TestBackend>) -> String {
    t.backend().to_string()
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn list_dir(effect: Option<Effect>) -> (RemotePath, bool) {
    match effect {
        Some(Effect::Action(Action::ListDir { dir, force, .. })) => (dir, force),
        Some(Effect::Action(other)) => panic!("expected ListDir, got {other:?}"),
        Some(Effect::Modal(_)) => panic!("expected ListDir, got a modal"),
        None => panic!("expected ListDir, got nothing"),
    }
}

fn current(l: &FileList) -> String {
    l.current()
        .map_or_else(|| "..".to_owned(), |e| e.name.clone())
}

// --- snapshots ---

#[cfg(unix)]
#[test]
fn snapshot_local_listing() {
    let mut l = loaded(Side::Local, "/home/me/site");
    insta::assert_snapshot!("local_listing", render(&mut l, 100, 14).backend());
}

#[test]
fn snapshot_remote_listing() {
    let mut l = loaded(Side::Remote, "/var/www");
    l.update(&Action::CursorDown, None);
    insta::assert_snapshot!("remote_listing", render(&mut l, 120, 14).backend());
}

#[test]
fn snapshot_filtered() {
    let mut l = loaded(Side::Remote, "/var/www");
    l.update(&Action::QuickFilter, None);
    for c in "*.log".chars() {
        l.handle_key(key(KeyCode::Char(c)));
    }
    l.handle_key(key(KeyCode::Enter));
    let t = render(&mut l, 100, 10);
    insta::assert_snapshot!("filtered", t.backend());
    assert!(text(&t).contains("(filtered)"));
}

#[test]
fn snapshot_selection() {
    let mut l = loaded(Side::Remote, "/var/www");
    l.update(&Action::CursorDown, None); // assets
    l.update(&Action::CursorDown, None); // current
    l.update(&Action::ToggleSelect, None);
    l.update(&Action::ToggleSelect, None);
    let t = render(&mut l, 100, 14);
    insta::assert_snapshot!("selection", t.backend());
    assert!(
        text(&t).contains("Selected 1 file and 1 directory."),
        "{}",
        text(&t)
    );
}

#[test]
fn snapshot_empty_dir() {
    let mut l = list(Side::Remote);
    l.listing_loaded(&listing("/var/www/empty", vec![]));
    let t = render(&mut l, 80, 8);
    insta::assert_snapshot!("empty_dir", t.backend());
    assert!(text(&t).contains("(empty)") && text(&t).contains(".."));
}

#[test]
fn snapshot_error_keeps_the_old_directory() {
    let mut l = loaded(Side::Remote, "/var/www");
    l.update(&Action::CursorDown, None);
    let (target, _) = list_dir(l.update(&Action::Open, None));
    assert_eq!(target, RemotePath::new("/var/www/assets"));
    let logged = l.listing_loaded(&Err("permission denied".into()));
    assert!(
        matches!(logged, Some(Action::Error(m)) if m.contains("/var/www/assets") && m.contains("permission denied"))
    );
    assert_eq!(l.dir, Some(RemotePath::new("/var/www")));
    let t = render(&mut l, 100, 10);
    insta::assert_snapshot!("error", t.backend());
}

#[test]
fn snapshot_not_connected() {
    let mut l = list(Side::Remote);
    let t = render(&mut l, 60, 6);
    insta::assert_snapshot!("not_connected", t.backend());
    assert!(text(&t).contains("Not connected to any server."));
}

#[test]
fn snapshot_narrow_terminal_drops_columns() {
    let mut l = loaded(Side::Remote, "/var/www");
    let t = render(&mut l, 44, 10);
    insta::assert_snapshot!("narrow", t.backend());
    let s = text(&t);
    assert!(
        s.contains("Size") && !s.contains("Owner") && !s.contains("Type"),
        "{s}"
    );
}

// --- behaviour ---

#[test]
fn rows_are_sorted_dirs_first_and_naturally() {
    let l = loaded(Side::Remote, "/var/www");
    let names: Vec<&str> = l.view.iter().map(|&i| l.entries[i].name.as_str()).collect();
    assert_eq!(
        names,
        [
            "assets",
            "current",
            ".htaccess",
            "file2.log",
            "file10.log",
            "index.html",
            "notes.txt",
            "style.css"
        ]
    );
    assert_eq!(current(&l), "..", "the cursor starts on ..");
}

#[test]
fn sorting_actions_reverse_on_repeat() {
    let mut l = loaded(Side::Remote, "/var/www");
    l.update(&Action::SortSize, None);
    let first_file = l
        .view
        .iter()
        .map(|&i| &l.entries[i])
        .find(|e| !e.is_dir_like())
        .unwrap();
    assert_eq!(first_file.name, "file2.log");
    l.update(&Action::SortSize, None);
    let first_file = l
        .view
        .iter()
        .map(|&i| &l.entries[i])
        .find(|e| !e.is_dir_like())
        .unwrap();
    assert_eq!(first_file.name, "index.html");
    assert!(text(&render(&mut l, 100, 6)).contains("Size▼"));
}

#[test]
fn enter_parent_restores_the_cursor() {
    let mut l = loaded(Side::Remote, "/var/www");
    l.update(&Action::CursorDown, None);
    assert_eq!(current(&l), "assets");
    let (dir, force) = list_dir(l.update(&Action::Open, None));
    assert_eq!((dir.as_str(), force), ("/var/www/assets", false));
    l.listing_loaded(&listing(
        "/var/www/assets",
        vec![entry("logo.png", 1, false)],
    ));
    assert_eq!(l.dir, Some(RemotePath::new("/var/www/assets")));
    assert_eq!(current(&l), "..");

    let (dir, _) = list_dir(l.update(&Action::ParentDir, None));
    assert_eq!(dir.as_str(), "/var/www");
    l.listing_loaded(&listing("/var/www", site_entries()));
    assert_eq!(current(&l), "assets", "back on the directory we came from");

    // `..` with Open goes up too.
    l.update(&Action::Top, None);
    let (dir, _) = list_dir(l.update(&Action::Open, None));
    assert_eq!(dir.as_str(), "/var");
}

#[test]
fn history_back_and_forward() {
    let mut l = loaded(Side::Remote, "/var/www");
    l.update(&Action::CursorDown, None);
    list_dir(l.update(&Action::Open, None));
    l.listing_loaded(&listing("/var/www/assets", vec![]));
    let (dir, _) = list_dir(l.update(&Action::HistoryBack, None));
    assert_eq!(dir.as_str(), "/var/www");
    l.listing_loaded(&listing("/var/www", site_entries()));
    assert_eq!(
        current(&l),
        "assets",
        "the cursor is remembered per directory"
    );
    let (dir, _) = list_dir(l.update(&Action::HistoryForward, None));
    assert_eq!(dir.as_str(), "/var/www/assets");
    l.listing_loaded(&listing("/var/www/assets", vec![]));
    assert!(
        l.update(&Action::HistoryForward, None).is_none(),
        "nothing ahead"
    );
}

#[test]
fn refresh_forces_and_keeps_the_cursor() {
    let mut l = loaded(Side::Remote, "/var/www");
    l.update(&Action::Bottom, None);
    let name = current(&l);
    let (dir, force) = list_dir(l.update(&Action::Refresh, None));
    assert_eq!((dir.as_str(), force), ("/var/www", true));
    l.listing_loaded(&listing("/var/www", site_entries()));
    assert_eq!(current(&l), name);
}

#[test]
fn opening_a_file_transfers_it() {
    let mut l = loaded(Side::Remote, "/var/www");
    l.update(&Action::Bottom, None);
    assert!(matches!(
        l.update(&Action::Open, None),
        Some(Effect::Action(Action::Copy))
    ));
}

#[test]
fn selection_operations() {
    let mut l = loaded(Side::Remote, "/var/www");
    l.update(&Action::CursorDown, None);
    l.update(&Action::ToggleSelect, None);
    assert_eq!(current(&l), "current", "space moves down");
    assert_eq!(l.targets(), ["assets"]);
    l.update(&Action::ToggleSelect, None); // current
    l.update(&Action::CursorUp, None);
    l.update(&Action::ToggleSelect, None); // unselect current
    assert_eq!(l.targets(), ["assets"]);

    l.update(&Action::SelectAll, None);
    assert_eq!(l.targets().len(), 8);
    l.update(&Action::InvertSelection, None);
    assert!(
        l.targets() == vec![current(&l)],
        "nothing selected: the cursor entry"
    );

    l.update(
        &Action::ApplyPattern {
            side: Side::Remote,
            pattern: "*.log".into(),
            select: true,
        },
        None,
    );
    assert_eq!(l.targets(), ["file10.log", "file2.log"]);
    l.update(
        &Action::ApplyPattern {
            side: Side::Remote,
            pattern: "file1*".into(),
            select: false,
        },
        None,
    );
    assert_eq!(l.targets(), ["file2.log"]);
}

#[test]
fn visual_range_selection() {
    let mut l = loaded(Side::Remote, "/var/www");
    l.update(&Action::CursorDown, None);
    l.update(&Action::VisualSelect, None);
    l.update(&Action::CursorDown, None);
    l.update(&Action::CursorDown, None);
    assert_eq!(l.targets(), [".htaccess", "assets", "current"]);
    assert!(text(&render(&mut l, 100, 14)).contains("-- VISUAL --"));
    l.update(&Action::VisualSelect, None);
    l.update(&Action::CursorDown, None);
    assert_eq!(
        l.targets().len(),
        3,
        "leaving visual mode keeps the selection"
    );
}

#[test]
fn pattern_actions_open_a_dialog() {
    let mut l = loaded(Side::Remote, "/var/www");
    assert!(matches!(
        l.update(&Action::SelectPattern, None),
        Some(Effect::Modal(_))
    ));
}

#[test]
fn hidden_files_toggle() {
    let mut local = loaded(Side::Local, "/home/me/site");
    assert!(
        local.view.iter().all(|&i| !local.entries[i].hidden),
        "local hides dotfiles by default"
    );
    local.update(&Action::ToggleHidden, None);
    assert!(
        local
            .view
            .iter()
            .any(|&i| local.entries[i].name == ".htaccess")
    );
}

#[test]
fn quick_filter_typing_enter_and_escape() {
    let mut l = loaded(Side::Remote, "/var/www");
    l.update(&Action::QuickFilter, None);
    assert!(l.is_typing());
    for c in "STYLE".chars() {
        assert!(l.handle_key(key(KeyCode::Char(c))).is_some());
    }
    assert_eq!(l.view.len(), 1, "case-insensitive substring");
    assert_eq!(
        current(&l),
        "style.css",
        "the cursor lands on the match, not on .."
    );
    assert!(text(&render(&mut l, 80, 8)).contains("/STYLE▏"));
    l.handle_key(key(KeyCode::Enter));
    assert!(!l.is_typing() && l.is_filtered());
    assert!(
        l.handle_key(key(KeyCode::Char('x'))).is_none(),
        "keys go back to navigation"
    );
    l.update(&Action::QuickFilter, None);
    l.handle_key(key(KeyCode::Esc));
    assert!(!l.is_filtered());
    assert_eq!(l.view.len(), 8);
}

#[test]
fn filters_hide_entries() {
    let filter = courier_ftp_core::filters::Filter {
        name: "logs".into(),
        applies_to: courier_ftp_core::filters::AppliesTo::Files,
        match_mode: MatchMode::All,
        case_sensitive: false,
        conditions: vec![Condition::Name {
            op: StringOp::EndsWith,
            value: ".log".into(),
        }],
        scope: courier_ftp_core::filters::FilterScope::Both,
    };
    let (engine, _) = FilterEngine::new([&filter]);
    let mut l = FileList::new(Side::Remote, &Settings::default(), engine);
    l.listing_loaded(&listing("/var/www", site_entries()));
    assert!(l.is_filtered());
    assert!(l.view.iter().all(|&i| !l.entries[i].name.ends_with(".log")));
}

#[test]
fn remote_address_bar_navigates_relative_and_absolute() {
    let mut l = loaded(Side::Remote, "/var/www");
    l.update(&Action::EditAddress, None);
    assert!(l.is_editing_address());
    // Pre-filled with "/var/www/"; complete a name with Tab.
    for c in "as".chars() {
        l.handle_key(key(KeyCode::Char(c)));
    }
    l.handle_key(key(KeyCode::Tab));
    let effect = l.handle_key(key(KeyCode::Enter)).unwrap();
    assert_eq!(list_dir(effect).0.as_str(), "/var/www/assets");
    assert!(!l.is_editing_address());

    l.update(&Action::EditAddress, None);
    l.handle_key(key(KeyCode::Esc));
    assert!(!l.is_editing_address());
}

#[cfg(unix)]
#[test]
fn local_address_bar_takes_native_paths() {
    let mut l = loaded(Side::Local, "/home/me/site");
    l.update(&Action::EditAddress, None);
    for _ in 0.."/home/me/site/".len() {
        l.handle_key(key(KeyCode::Backspace));
    }
    l.handle_paste("/tmp");
    let effect = l.handle_key(key(KeyCode::Enter)).unwrap();
    assert_eq!(list_dir(effect).0.as_str(), "/tmp");
}

#[test]
fn column_menu_and_set_columns() {
    let mut l = loaded(Side::Remote, "/var/www");
    assert!(matches!(
        l.update(&Action::ColumnMenu, None),
        Some(Effect::Modal(_))
    ));
    l.update(
        &Action::SetColumns {
            side: Side::Remote,
            columns: vec![Column::Name, Column::Size],
        },
        None,
    );
    assert_eq!(l.columns(), [Column::Name, Column::Size]);
    let s = text(&render(&mut l, 100, 6));
    assert!(s.contains("Size") && !s.contains("Modified"), "{s}");
}

#[test]
fn footer_counts_files_and_directories() {
    let mut l = loaded(Side::Remote, "/var/www");
    let s = text(&render(&mut l, 100, 14));
    assert!(
        s.contains("6 files and 2 directories. Total size: 5.1 KiB"),
        "{s}"
    );
}

#[test]
fn day_precision_dates_omit_the_time() {
    let mut l = loaded(Side::Remote, "/var/www");
    let s = text(&render(&mut l, 120, 14));
    assert!(s.contains("2021-01-05      "), "{s}");
    assert!(s.contains("2026-10-08 18:22"), "{s}");
}

/// T53: 100 000 entries render in under 5 ms per frame. Timing is only
/// meaningful with optimisations: run `cargo test --release -p courier-ftp
/// hundred_thousand`.
#[test]
#[cfg_attr(debug_assertions, ignore = "timing needs --release")]
fn hundred_thousand_entries_render_fast() {
    let entries: Vec<Entry> = (0..100_000)
        .map(|i| entry(&format!("file_{i:06}.dat"), i, i % 50 == 0))
        .collect();
    let mut l = list(Side::Remote);
    l.listing_loaded(&listing("/big", entries));
    l.update(&Action::PageDown, None);
    let theme = Theme::default();
    let mut t = Terminal::new(TestBackend::new(200, 60)).unwrap();
    t.draw(|f| l.draw(f, f.area(), true, 0, &theme)).unwrap();
    let frames = 50;
    let start = Instant::now();
    for _ in 0..frames {
        l.update(&Action::CursorDown, None);
        t.draw(|f| l.draw(f, f.area(), true, 0, &theme)).unwrap();
    }
    let per_frame = start.elapsed() / frames;
    assert!(per_frame.as_millis() < 5, "{per_frame:?} per frame");
}
