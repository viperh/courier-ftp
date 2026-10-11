//! T65: the search view on its own — snapshots of the form and the results,
//! the query the form builds, and the requests the result keys send. The
//! flows against `MockServer` and a temporary directory are in
//! `app/search_tests.rs`.

use std::time::Duration;

use courier_ftp_core::{
    filters::{AppliesTo, Condition, MatchMode, StringOp},
    model::{Entry, Permissions, Precision, RemotePath, Timestamp},
    search::{SearchHit, SearchProgress, SearchQuery, SearchRoot, SearchSummary},
    settings::Settings,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};
use time::macros::datetime;

use super::*;

/// An absolute local directory on this OS.
const LOCAL: &str = if cfg!(windows) {
    r"C:\Users\me"
} else {
    "/home/me"
};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn press(view: &mut SearchView, code: KeyCode) {
    view.handle_key(key(code));
}

fn ctrl(view: &mut SearchView, c: char) {
    view.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL));
}

fn typed(view: &mut SearchView, text: &str) {
    for c in text.chars() {
        press(view, KeyCode::Char(c));
    }
}

fn opts(side: Side) -> SearchOpts {
    SearchOpts {
        side,
        dirs: [LOCAL.into(), "/srv".into()],
        unicode: true,
        fmt: Fmt::new(&Settings::default(), time::UtcOffset::UTC),
    }
}

fn render(view: &mut SearchView, w: u16, h: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
    terminal
        .draw(|f| view.draw(f, f.area(), 0, &Theme::default()))
        .unwrap();
    terminal.backend().to_string()
}

fn file(path: &str, size: u64, mode: u32) -> SearchHit {
    let path = RemotePath::new(path);
    let mut entry = Entry::file(path.file_name().unwrap(), size);
    entry.modified = Some(Timestamp::new(
        datetime!(2024-03-10 14:05:00 UTC),
        Precision::Minute,
    ));
    entry.permissions = Some(Permissions::from_mode(mode));
    SearchHit { path, entry }
}

fn dir(path: &str) -> SearchHit {
    let path = RemotePath::new(path);
    let entry = Entry::dir(path.file_name().unwrap());
    SearchHit { path, entry }
}

fn hits() -> Vec<SearchHit> {
    vec![
        file("/srv/www/index.html", 2048, 0o644),
        dir("/srv/www/img"),
        file("/srv/www/img/logo.png", 1_500_000, 0o644),
        file("/srv/backup/index.html.bak", 99, 0o600),
    ]
}

/// A view that searched the remote `/srv` for "index" and got `hits()`.
fn searched() -> SearchView {
    let mut view = SearchView::new(opts(Side::Remote));
    typed(&mut view, "index");
    press(&mut view, KeyCode::Enter);
    let requests = view.take_requests();
    assert!(matches!(requests.as_slice(), [SearchRequest::Start(_)]));
    view.apply_update(&SearchUpdate::Found(hits()));
    view
}

fn names(view: &mut SearchView) -> Vec<String> {
    view.results_mut()
        .unwrap()
        .visible()
        .iter()
        .map(|h| h.path.to_string())
        .collect()
}

#[test]
fn form_snapshot() {
    let mut view = SearchView::new(opts(Side::Remote));
    typed(&mut view, "index");
    insta::assert_snapshot!("search_form_80x24", render(&mut view, 80, 24));
}

#[test]
fn form_builds_the_query() {
    let mut view = SearchView::new(opts(Side::Remote));
    assert_eq!(view.form().focus(), form::Slot::Cond(0, 2));
    typed(&mut view, "index");
    // A second condition: size greater than 100.
    ctrl(&mut view, 'n');
    press(&mut view, KeyCode::BackTab);
    press(&mut view, KeyCode::BackTab);
    press(&mut view, KeyCode::Char('s')); // type: Size
    press(&mut view, KeyCode::Tab);
    press(&mut view, KeyCode::Tab);
    typed(&mut view, "100");
    // Match: Any; case-sensitive; files only.
    for _ in 0..20 {
        if view.form().focus() == form::Slot::Match {
            break;
        }
        press(&mut view, KeyCode::BackTab);
    }
    press(&mut view, KeyCode::Right);
    press(&mut view, KeyCode::Tab);
    press(&mut view, KeyCode::Char(' '));
    press(&mut view, KeyCode::Tab);
    press(&mut view, KeyCode::Char('f'));
    view.handle_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::ALT));
    let requests = view.take_requests();
    let [SearchRequest::Start(query)] = requests.as_slice() else {
        panic!("{requests:?}");
    };
    assert_eq!(
        *query,
        SearchQuery {
            root: SearchRoot::Remote(RemotePath::new("/srv")),
            conditions: vec![
                Condition::Name {
                    op: StringOp::Contains,
                    value: "index".into()
                },
                Condition::Size {
                    op: courier_ftp_core::filters::NumOp::Greater,
                    value: 100
                },
            ],
            match_mode: MatchMode::Any,
            case_sensitive: true,
            search_type: AppliesTo::Files,
        }
    );
    assert_eq!(view.page(), Page::Results);
    assert!(view.is_running());
}

#[test]
fn form_reports_problems() {
    let mut view = SearchView::new(opts(Side::Remote));
    // An empty filename condition.
    press(&mut view, KeyCode::Enter);
    assert!(view.take_requests().is_empty());
    assert_eq!(view.form().error(), Some("Condition 1: enter a value."));
    // Without conditions everything matches.
    ctrl(&mut view, 'd');
    press(&mut view, KeyCode::Tab); // Search button
    press(&mut view, KeyCode::Enter);
    let requests = view.take_requests();
    let [SearchRequest::Start(query)] = requests.as_slice() else {
        panic!("{requests:?}");
    };
    assert!(query.conditions.is_empty());
    // A relative local directory is refused.
    let mut view = SearchView::new(opts(Side::Local));
    assert_eq!(view.form().dir_text(), LOCAL);
    ctrl(&mut view, 'd');
    for _ in 0..10 {
        if view.form().focus() == form::Slot::Dir {
            break;
        }
        press(&mut view, KeyCode::BackTab);
    }
    view.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    view.handle_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::CONTROL));
    view.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    typed(&mut view, "relative/dir");
    press(&mut view, KeyCode::Enter);
    assert!(view.take_requests().is_empty());
    assert_eq!(
        view.form().error(),
        Some("Enter the full path of a local directory.")
    );
}

#[test]
fn switching_side_switches_the_directory() {
    let mut view = SearchView::new(opts(Side::Local));
    for _ in 0..10 {
        if view.form().focus() == form::Slot::Side {
            break;
        }
        press(&mut view, KeyCode::BackTab);
    }
    press(&mut view, KeyCode::Right);
    assert_eq!(view.form().side(), Side::Remote);
    assert_eq!(view.form().dir_text(), "/srv");
}

#[test]
fn results_snapshots() {
    let mut view = searched();
    view.apply_update(&SearchUpdate::Progress(SearchProgress {
        dirs_scanned: 3,
        entries_scanned: 12,
        matches: 4,
        current: RemotePath::new("/srv/www"),
    }));
    insta::assert_snapshot!("search_results_running_80x24", render(&mut view, 80, 24));
    press(&mut view, KeyCode::Char(' '));
    view.apply_update(&SearchUpdate::Done(SearchSummary {
        dirs_scanned: 4,
        entries_scanned: 12,
        matches: 4,
        elapsed: Duration::from_millis(1200),
        ..SearchSummary::default()
    }));
    insta::assert_snapshot!("search_results_done_120x30", render(&mut view, 120, 30));
}

#[test]
fn esc_and_ctrl_c_stop_a_running_search() {
    let mut view = searched();
    press(&mut view, KeyCode::Esc);
    assert!(matches!(
        view.take_requests().as_slice(),
        [SearchRequest::Cancel]
    ));
    // Asked once; the view waits for the end.
    press(&mut view, KeyCode::Esc);
    assert!(view.take_requests().is_empty());
    assert!(render(&mut view, 80, 24).contains("stopping…"));
    view.apply_update(&SearchUpdate::Done(SearchSummary {
        cancelled: true,
        matches: 4,
        ..SearchSummary::default()
    }));
    assert!(!view.is_running());
    assert!(render(&mut view, 80, 24).contains("· stopped"));
    // Not running: Esc goes back to the form, which keeps the query.
    press(&mut view, KeyCode::Esc);
    assert_eq!(view.page(), Page::Form);

    let mut view = searched();
    ctrl(&mut view, 'c');
    assert!(matches!(
        view.take_requests().as_slice(),
        [SearchRequest::Cancel]
    ));
}

#[test]
fn results_sort_and_filter() {
    let mut view = searched();
    assert_eq!(
        names(&mut view),
        [
            "/srv/www/index.html",
            "/srv/www/img",
            "/srv/www/img/logo.png",
            "/srv/backup/index.html.bak"
        ]
    );
    press(&mut view, KeyCode::Char('s')); // name
    assert_eq!(
        names(&mut view),
        [
            "/srv/www/img",
            "/srv/www/index.html",
            "/srv/backup/index.html.bak",
            "/srv/www/img/logo.png"
        ]
    );
    press(&mut view, KeyCode::Char('s')); // path
    press(&mut view, KeyCode::Char('s')); // size
    press(&mut view, KeyCode::Char('S'));
    assert_eq!(names(&mut view)[0], "/srv/www/img/logo.png");
    press(&mut view, KeyCode::Char('/'));
    typed(&mut view, "WWW/I");
    press(&mut view, KeyCode::Enter);
    assert_eq!(
        names(&mut view),
        [
            "/srv/www/img/logo.png",
            "/srv/www/index.html",
            "/srv/www/img"
        ]
    );
    // Esc clears the filter, then goes back to the form.
    view.apply_update(&SearchUpdate::Done(SearchSummary::default()));
    press(&mut view, KeyCode::Esc);
    assert_eq!(names(&mut view).len(), 4);
    assert_eq!(view.page(), Page::Results);
}

#[test]
fn result_actions_send_requests() {
    let mut view = searched();
    // Nothing selected: the hit under the cursor.
    press(&mut view, KeyCode::F(5));
    let requests = view.take_requests();
    let [SearchRequest::AskTransfer(h)] = requests.as_slice() else {
        panic!("{requests:?}");
    };
    assert_eq!(h, &hits()[..1]);
    // Two selected.
    press(&mut view, KeyCode::Char(' '));
    press(&mut view, KeyCode::Char(' '));
    press(&mut view, KeyCode::F(8));
    let requests = view.take_requests();
    let [SearchRequest::AskDelete(h)] = requests.as_slice() else {
        panic!("{requests:?}");
    };
    assert_eq!(h, &hits()[..2]);
    // Select all / none.
    press(&mut view, KeyCode::Char('a'));
    assert_eq!(view.results_mut().unwrap().selected_count(), 4);
    press(&mut view, KeyCode::Char('a'));
    assert_eq!(view.results_mut().unwrap().selected_count(), 0);
    // Enter: go to the hit under the cursor (the third).
    press(&mut view, KeyCode::Enter);
    let requests = view.take_requests();
    let [SearchRequest::GoTo(h)] = requests.as_slice() else {
        panic!("{requests:?}");
    };
    assert_eq!(*h, hits()[2]);
    // q hides; reopening shows the results again.
    press(&mut view, KeyCode::Char('q'));
    assert!(view.is_hidden());
    view.reopen(opts(Side::Local));
    assert!(!view.is_hidden());
    assert_eq!(view.page(), Page::Results);
}

#[test]
fn deleted_hits_leave_the_results() {
    let mut view = searched();
    view.apply_update(&SearchUpdate::Deleted(vec![RemotePath::new(
        "/srv/www/img",
    )]));
    assert_eq!(
        names(&mut view),
        ["/srv/www/index.html", "/srv/backup/index.html.bak"]
    );
}

#[test]
fn the_last_query_is_kept() {
    let mut view = searched();
    view.apply_update(&SearchUpdate::Done(SearchSummary::default()));
    press(&mut view, KeyCode::Char('n'));
    assert_eq!(view.page(), Page::Form);
    press(&mut view, KeyCode::Esc);
    assert!(view.is_hidden());
    // Opened again from the local pane: the conditions stay, the
    // directory follows the pane.
    view.reopen(opts(Side::Local));
    assert_eq!(view.form().side(), Side::Local);
    assert_eq!(view.form().dir_text(), LOCAL);
    press(&mut view, KeyCode::Enter);
    let requests = view.take_requests();
    let [SearchRequest::Start(query)] = requests.as_slice() else {
        panic!("{requests:?}");
    };
    assert_eq!(
        query.conditions,
        [Condition::Name {
            op: StringOp::Contains,
            value: "index".into()
        }]
    );
}
