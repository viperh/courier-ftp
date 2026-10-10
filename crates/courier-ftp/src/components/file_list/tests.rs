//! Unit, property and integration tests of the file list pane.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::sync::Arc;

use courier_ftp_core::{
    Error,
    backend::Listing,
    filters::FilterEngine,
    model::{Entry, EntryKind, LocalPath, Protocol, RemotePath, ServerIdentity},
    settings::Settings,
};
use tokio::time::Instant;

use super::state::{
    FileListState, FileOp, InterfaceEdit, PaneCommand, PaneCtx, PaneDir, PaneId, PaneInput,
    PaneRequest, PaneStatus, RequestId, Side, error_message, expand_local,
};
use crate::tabs::TabId;

pub(super) fn remote_id() -> PaneId {
    PaneId {
        tab: TabId::FIRST,
        side: Side::Remote,
    }
}

pub(super) fn local_id() -> PaneId {
    PaneId {
        tab: TabId::FIRST,
        side: Side::Local,
    }
}

pub(super) fn server() -> ServerIdentity {
    ServerIdentity {
        protocol: Protocol::Sftp,
        host: "web01.example".into(),
        port: 22,
        user: "deploy".into(),
    }
}

pub(super) fn file(name: &str, size: u64) -> Entry {
    let mut e = Entry::new(name, EntryKind::File);
    e.size = Some(size);
    e
}

pub(super) fn dir(name: &str) -> Entry {
    Entry::new(name, EntryKind::Dir)
}

pub(super) fn rdir(p: &str) -> PaneDir {
    PaneDir::Remote(RemotePath::parse(p).unwrap())
}

pub(super) fn listing(dir: &str, entries: Vec<Entry>) -> Arc<Listing> {
    Arc::new(Listing {
        dir: RemotePath::parse(dir).unwrap(),
        entries,
        fetched_at: Instant::now(),
        raw: None,
    })
}

/// Reducer context with default settings and no filters.
pub(super) struct Ctx {
    pub settings: Settings,
    pub filters: Arc<FilterEngine>,
}

impl Ctx {
    pub(super) fn new() -> Self {
        Self {
            settings: Settings::default(),
            filters: Arc::new(FilterEngine::empty(courier_ftp_core::filters::Side::Remote)),
        }
    }

    pub(super) fn get(&self) -> PaneCtx<'_> {
        PaneCtx {
            settings: &self.settings,
            filters: &self.filters,
            now: Instant::now(),
        }
    }
}

/// A connected remote pane.
pub(super) fn remote_pane(ctx: &Ctx) -> FileListState {
    let mut s = FileListState::new(remote_id(), &ctx.settings);
    s.reduce(
        PaneInput::Connected {
            server: server(),
            label: "web01".into(),
        },
        &ctx.get(),
    );
    s.reduce(PaneInput::Resize { body_rows: 10 }, &ctx.get());
    s
}

fn list_request(reqs: &[PaneRequest]) -> (RequestId, PaneDir) {
    reqs.iter()
        .find_map(|r| match r {
            PaneRequest::List { request, dir, .. } => Some((*request, dir.clone())),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no List request in {reqs:?}"))
}

/// Answers the pending `List` in `reqs` with `entries`.
pub(super) fn answer(
    s: &mut FileListState,
    ctx: &Ctx,
    reqs: &[PaneRequest],
    entries: Vec<Entry>,
) -> Vec<PaneRequest> {
    let (request, d) = list_request(reqs);
    let path = match &d {
        PaneDir::Remote(p) => p.as_str().to_owned(),
        PaneDir::Local(_) => "/".to_owned(),
    };
    s.reduce(
        PaneInput::ListingLoaded {
            request,
            dir: d,
            result: Ok(listing(&path, entries)),
        },
        &ctx.get(),
    )
}

/// Navigates to `dir` and loads `entries`.
pub(super) fn load(s: &mut FileListState, ctx: &Ctx, dir: &str, entries: Vec<Entry>) {
    let reqs = s.reduce(PaneInput::Navigate(rdir(dir)), &ctx.get());
    answer(s, ctx, &reqs, entries);
}

fn key(s: &mut FileListState, ctx: &Ctx, cmd: PaneCommand) -> Vec<PaneRequest> {
    s.reduce(PaneInput::Key(cmd), &ctx.get())
}

fn cursor_name(s: &FileListState) -> Option<String> {
    s.cursor_entry().map(|e| e.name.clone())
}

fn abc() -> Vec<Entry> {
    vec![
        dir("a"),
        dir("b"),
        dir("c"),
        file("x.txt", 10),
        file("y.html", 20),
    ]
}

#[test]
fn cursor_returns_to_previous_dir_on_parent() {
    let ctx = Ctx::new();
    let mut s = remote_pane(&ctx);
    load(&mut s, &ctx, "/srv", abc());
    // Rows: .., a, b, c, x.txt, y.html.
    key(&mut s, &ctx, PaneCommand::CursorDown);
    key(&mut s, &ctx, PaneCommand::CursorDown);
    key(&mut s, &ctx, PaneCommand::CursorDown);
    assert_eq!(cursor_name(&s).as_deref(), Some("c"));
    let reqs = key(&mut s, &ctx, PaneCommand::Open);
    assert_eq!(list_request(&reqs).1, rdir("/srv/c"));
    answer(&mut s, &ctx, &reqs, vec![file("inner", 1)]);
    assert_eq!(s.cursor, 0, "a new directory starts on row 0");
    let reqs = key(&mut s, &ctx, PaneCommand::Parent);
    assert_eq!(list_request(&reqs).1, rdir("/srv"));
    answer(&mut s, &ctx, &reqs, abc());
    assert_eq!(cursor_name(&s).as_deref(), Some("c"));
    // `Open` on `..` is Parent.
    key(&mut s, &ctx, PaneCommand::Top);
    let reqs = key(&mut s, &ctx, PaneCommand::Open);
    assert_eq!(list_request(&reqs).1, rdir("/"));
    answer(&mut s, &ctx, &reqs, vec![dir("srv"), dir("etc")]);
    assert!(!s.has_parent_row(), "no `..` at the root");
    assert_eq!(cursor_name(&s).as_deref(), Some("srv"));
}

#[test]
fn back_forward_restores_cursor_memory() {
    let ctx = Ctx::new();
    let mut s = remote_pane(&ctx);
    load(&mut s, &ctx, "/srv", abc());
    key(&mut s, &ctx, PaneCommand::Bottom);
    assert_eq!(cursor_name(&s).as_deref(), Some("y.html"));
    load(
        &mut s,
        &ctx,
        "/etc",
        vec![file("hosts", 1), file("passwd", 2)],
    );
    key(&mut s, &ctx, PaneCommand::CursorDown);
    assert_eq!(cursor_name(&s).as_deref(), Some("hosts"));
    let reqs = key(&mut s, &ctx, PaneCommand::Back);
    assert_eq!(list_request(&reqs).1, rdir("/srv"));
    answer(&mut s, &ctx, &reqs, abc());
    assert_eq!(cursor_name(&s).as_deref(), Some("y.html"));
    let reqs = key(&mut s, &ctx, PaneCommand::Forward);
    assert_eq!(list_request(&reqs).1, rdir("/etc"));
    answer(
        &mut s,
        &ctx,
        &reqs,
        vec![file("hosts", 1), file("passwd", 2)],
    );
    assert_eq!(cursor_name(&s).as_deref(), Some("hosts"));
    // Nothing further forward.
    assert!(key(&mut s, &ctx, PaneCommand::Forward).is_empty());
}

#[test]
fn stale_listing_result_is_dropped() {
    let ctx = Ctx::new();
    let mut s = remote_pane(&ctx);
    load(&mut s, &ctx, "/srv", abc());
    let first = s.reduce(PaneInput::Navigate(rdir("/one")), &ctx.get());
    let second = s.reduce(PaneInput::Navigate(rdir("/two")), &ctx.get());
    // The second navigation cancels the first.
    let (r1, _) = list_request(&first);
    assert!(
        second
            .iter()
            .any(|r| matches!(r, PaneRequest::CancelList { request, .. } if *request == r1))
    );
    answer(&mut s, &ctx, &first, vec![file("stale", 1)]);
    assert_eq!(s.dir, Some(rdir("/srv")), "stale result ignored");
    assert!(matches!(s.status, PaneStatus::Loading { .. }));
    answer(&mut s, &ctx, &second, vec![file("fresh", 1)]);
    assert_eq!(s.dir, Some(rdir("/two")));
    assert_eq!(cursor_name(&s).as_deref(), None, "row 0 is `..`");
    key(&mut s, &ctx, PaneCommand::CursorDown);
    assert_eq!(cursor_name(&s).as_deref(), Some("fresh"));
}

#[test]
fn listing_error_keeps_previous_dir() {
    let cases: Vec<(Error, &str)> = vec![
        (
            Error::PermissionDenied("x".into()),
            "Permission denied: /srv/secret",
        ),
        (
            Error::NotFound(RemotePath::parse("/srv/secret").unwrap()),
            "Directory not found: /srv/secret",
        ),
        (Error::Timeout, "Timed out listing /srv/secret"),
        (Error::Connection("reset".into()), "Connection lost"),
        (
            Error::Protocol {
                code: Some(550),
                message: "No such directory".into(),
            },
            "550 No such directory",
        ),
        (Error::InvalidInput("bad path".into()), "bad path"),
    ];
    for (err, text) in cases {
        let ctx = Ctx::new();
        let mut s = remote_pane(&ctx);
        load(&mut s, &ctx, "/srv", abc());
        let reqs = s.reduce(PaneInput::Navigate(rdir("/srv/secret")), &ctx.get());
        let (request, d) = list_request(&reqs);
        s.reduce(
            PaneInput::ListingLoaded {
                request,
                dir: d,
                result: Err(Arc::new(err)),
            },
            &ctx.get(),
        );
        assert_eq!(s.dir, Some(rdir("/srv")));
        assert_eq!(s.listing.as_ref().map(|l| l.entries.len()), Some(5));
        assert_eq!(s.notice.as_ref().map(|n| n.0.as_str()), Some(text));
        assert!(matches!(&s.status, PaneStatus::Error { message, .. } if message == text));
        // The next key clears the footer error.
        key(&mut s, &ctx, PaneCommand::CursorDown);
        assert!(s.notice.is_none());
        assert_eq!(s.status, PaneStatus::Ready);
    }
    // Cancelled: nothing shown.
    let ctx = Ctx::new();
    let mut s = remote_pane(&ctx);
    load(&mut s, &ctx, "/srv", abc());
    let reqs = s.reduce(PaneInput::Navigate(rdir("/x")), &ctx.get());
    let (request, d) = list_request(&reqs);
    s.reduce(
        PaneInput::ListingLoaded {
            request,
            dir: d,
            result: Err(Arc::new(Error::Cancelled)),
        },
        &ctx.get(),
    );
    assert!(s.notice.is_none());
    assert_eq!(s.status, PaneStatus::Ready);
    assert_eq!(error_message(&Error::Timeout, "/a"), "Timed out listing /a");
}

#[test]
fn filter_hiding_marked_entries_unmarks_them() {
    let ctx = Ctx::new();
    let mut s = remote_pane(&ctx);
    load(&mut s, &ctx, "/srv", abc());
    key(&mut s, &ctx, PaneCommand::MarkAll);
    assert_eq!(s.marked_count(), 5);
    key(&mut s, &ctx, PaneCommand::QuickFilter);
    for c in "html".chars() {
        key(&mut s, &ctx, PaneCommand::FilterInsert(c));
    }
    assert_eq!(s.view().len(), 1);
    assert_eq!(s.marked_count(), 1, "hidden entries are unmarked");
    assert!(s.is_filtered());
    let f = s.footer();
    assert_eq!((f.files, f.dirs, f.selected), (1, 0, true));
    // Clearing the filter does not bring the marks back.
    key(&mut s, &ctx, PaneCommand::FilterClear);
    assert_eq!(s.marked_count(), 1);
    assert!(!s.is_filtered());
}

#[test]
fn footer_counts_selected_files_and_dirs() {
    let ctx = Ctx::new();
    let mut s = remote_pane(&ctx);
    let mut unknown = file("zz", 0);
    unknown.size = None;
    let mut entries = abc();
    entries.push(unknown);
    load(&mut s, &ctx, "/srv", entries);
    let f = s.footer();
    assert_eq!(
        (f.files, f.dirs, f.bytes, f.unknown_size, f.selected),
        (3, 3, 30, true, false)
    );
    // Mark `a` and `x.txt`.
    key(&mut s, &ctx, PaneCommand::CursorDown);
    key(&mut s, &ctx, PaneCommand::ToggleMark);
    key(&mut s, &ctx, PaneCommand::CursorDown);
    key(&mut s, &ctx, PaneCommand::CursorDown);
    key(&mut s, &ctx, PaneCommand::ToggleMark);
    let f = s.footer();
    assert_eq!(
        (f.files, f.dirs, f.bytes, f.unknown_size, f.selected),
        (1, 1, 10, false, true)
    );
    let sel = s.selection().unwrap();
    let names: Vec<&str> = sel.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["a", "x.txt"]);
    let fmt = super::render::RowFormat {
        size: courier_ftp_core::settings::SizeFormat::Iec,
        thousands: true,
        dates: snapshot_dates(),
    };
    assert_eq!(
        super::render::summary_text(&f, false, &fmt),
        "Selected 1 file and 1 directory. Total size: 10 B"
    );
}

pub(super) fn snapshot_dates() -> super::format::DateFormats {
    super::format::DateFormats {
        date: "%Y-%m-%d".into(),
        time: "%H:%M".into(),
        offset: time::UtcOffset::UTC,
        current_year: 2026,
    }
}

#[test]
fn visual_mode_marks_range_both_directions() {
    let ctx = Ctx::new();
    let mut s = remote_pane(&ctx);
    load(&mut s, &ctx, "/srv", abc());
    // Down: rows 1..=3 (a, b, c).
    key(&mut s, &ctx, PaneCommand::CursorDown);
    key(&mut s, &ctx, PaneCommand::VisualMode);
    key(&mut s, &ctx, PaneCommand::CursorDown);
    key(&mut s, &ctx, PaneCommand::CursorDown);
    assert_eq!(s.visual_range(), Some((1, 3)));
    key(&mut s, &ctx, PaneCommand::VisualMode);
    assert_eq!(s.marked_count(), 3);
    assert!(s.visual_range().is_none());
    // Up from y.html to x.txt, marked with Space; `..` (row 0) is never marked.
    key(&mut s, &ctx, PaneCommand::Bottom);
    key(&mut s, &ctx, PaneCommand::VisualMode);
    for _ in 0..10 {
        key(&mut s, &ctx, PaneCommand::CursorUp);
    }
    key(&mut s, &ctx, PaneCommand::ToggleMark);
    assert_eq!(s.marked_count(), 5);
    // Esc cancels without marking.
    key(&mut s, &ctx, PaneCommand::VisualMode);
    key(&mut s, &ctx, PaneCommand::Escape);
    assert!(s.visual_range().is_none());
}

#[test]
fn mark_pattern_glob_case_insensitive() {
    let ctx = Ctx::new();
    let mut s = remote_pane(&ctx);
    load(
        &mut s,
        &ctx,
        "/srv",
        vec![file("INDEX.HTML", 1), file("a.html", 1), file("a.css", 1)],
    );
    let reqs = key(&mut s, &ctx, PaneCommand::MarkPattern);
    assert!(matches!(
        reqs[..],
        [PaneRequest::PromptPattern { mark: true, .. }]
    ));
    s.reduce(
        PaneInput::Pattern {
            glob: "*.html".into(),
            mark: true,
        },
        &ctx.get(),
    );
    assert_eq!(s.marked_count(), 2);
    s.reduce(
        PaneInput::Pattern {
            glob: "index.*".into(),
            mark: false,
        },
        &ctx.get(),
    );
    assert_eq!(s.marked_count(), 1);
    s.reduce(
        PaneInput::Pattern {
            glob: "A.CSS".into(),
            mark: true,
        },
        &ctx.get(),
    );
    assert_eq!(s.marked_count(), 2);
}

#[test]
fn invert_marks_skips_parent_row() {
    let ctx = Ctx::new();
    let mut s = remote_pane(&ctx);
    load(&mut s, &ctx, "/srv", abc());
    key(&mut s, &ctx, PaneCommand::ToggleMark); // on `..`: nothing, cursor down
    assert_eq!(s.marked_count(), 0);
    assert_eq!(s.cursor, 1);
    key(&mut s, &ctx, PaneCommand::ToggleMark); // a
    key(&mut s, &ctx, PaneCommand::InvertMarks);
    assert_eq!(s.marked_count(), 4);
    assert!(!s.is_marked(0), "a was unmarked");
    let sel = s.selection().unwrap();
    assert!(sel.entries.iter().all(|e| e.name != ".."));
}

#[test]
fn quick_filter_esc_clears_enter_keeps() {
    let ctx = Ctx::new();
    let mut s = remote_pane(&ctx);
    load(&mut s, &ctx, "/srv", abc());
    key(&mut s, &ctx, PaneCommand::QuickFilter);
    key(&mut s, &ctx, PaneCommand::FilterInsert('x'));
    assert_eq!(s.view().len(), 1);
    key(&mut s, &ctx, PaneCommand::FilterAccept);
    let q = s.quick_filter.clone().unwrap();
    assert_eq!((q.text.as_str(), q.editing), ("x", false));
    assert_eq!(s.view().len(), 1);
    // `/` again resumes editing; Esc (FilterClear) clears.
    key(&mut s, &ctx, PaneCommand::QuickFilter);
    key(&mut s, &ctx, PaneCommand::FilterClear);
    assert!(s.quick_filter.is_none());
    assert_eq!(s.view().len(), 5);
    // Backspace on empty text leaves the mode.
    key(&mut s, &ctx, PaneCommand::QuickFilter);
    key(&mut s, &ctx, PaneCommand::FilterBackspace);
    assert!(s.quick_filter.is_none());
    // Escape in the list clears a kept filter.
    key(&mut s, &ctx, PaneCommand::QuickFilter);
    key(&mut s, &ctx, PaneCommand::FilterInsert('y'));
    key(&mut s, &ctx, PaneCommand::FilterAccept);
    key(&mut s, &ctx, PaneCommand::Escape);
    assert!(s.quick_filter.is_none());
    // Input is bounded.
    key(&mut s, &ctx, PaneCommand::QuickFilter);
    for _ in 0..300 {
        key(&mut s, &ctx, PaneCommand::FilterInsert('z'));
    }
    assert_eq!(s.quick_filter.as_ref().unwrap().text.len(), 256);
}

#[test]
fn listing_updated_keeps_cursor_and_marks_by_name() {
    let ctx = Ctx::new();
    let mut s = remote_pane(&ctx);
    load(&mut s, &ctx, "/srv", abc());
    key(&mut s, &ctx, PaneCommand::Bottom); // y.html
    key(&mut s, &ctx, PaneCommand::CursorUp); // x.txt
    key(&mut s, &ctx, PaneCommand::ToggleMark); // marks x.txt, cursor → y.html
    // A patch adds `0first` and removes `b`.
    let new = vec![
        file("0first", 1),
        dir("a"),
        dir("c"),
        file("x.txt", 10),
        file("y.html", 20),
    ];
    s.reduce(
        PaneInput::ListingUpdated {
            dir: rdir("/srv"),
            listing: listing("/srv", new),
        },
        &ctx.get(),
    );
    assert_eq!(cursor_name(&s).as_deref(), Some("y.html"));
    let sel = s.selection().unwrap();
    let names: Vec<&str> = sel.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["x.txt"]);
    // The cursor entry disappeared: nearest row index.
    let new = vec![dir("a"), dir("c"), file("x.txt", 10)];
    s.reduce(
        PaneInput::ListingUpdated {
            dir: rdir("/srv"),
            listing: listing("/srv", new),
        },
        &ctx.get(),
    );
    assert_eq!(cursor_name(&s).as_deref(), Some("x.txt"));
    // Another directory: ignored.
    s.reduce(
        PaneInput::ListingUpdated {
            dir: rdir("/other"),
            listing: listing("/other", vec![]),
        },
        &ctx.get(),
    );
    assert_eq!(s.view().len(), 3);
}

#[test]
fn listing_updated_matches_server_identity() {
    use courier_ftp_core::events::CoreEvent;

    use crate::components::{Component, file_list::FileListPane};

    let settings = Arc::new(Settings::default());
    let mut remote = FileListPane::new(remote_id(), Arc::clone(&settings));
    remote.input(PaneInput::Connected {
        server: server(),
        label: "web01".into(),
    });
    remote.input(PaneInput::Navigate(rdir("/srv")));
    let (request, d) = list_request(&remote.sent);
    remote.input(PaneInput::ListingLoaded {
        request,
        dir: d,
        result: Ok(listing("/srv", abc())),
    });
    remote.sent.clear();
    let srv = RemotePath::parse("/srv").unwrap();
    let mut other = server();
    other.host = "other.example".into();
    for (server, dir, relists) in [
        (Some(other), srv.clone(), false),
        (None, srv.clone(), false),
        (Some(server()), RemotePath::parse("/etc").unwrap(), false),
        (Some(server()), srv.clone(), true),
    ] {
        remote
            .on_core_event(&CoreEvent::ListingUpdated { server, dir })
            .unwrap();
        let listed = remote
            .sent
            .iter()
            .any(|r| matches!(r, PaneRequest::List { force: false, .. }));
        assert_eq!(listed, relists);
        remote.sent.clear();
    }

    // Local panes react to `server: None` for the directory they show.
    let tmp = tempfile::tempdir().unwrap();
    let mut local = FileListPane::new(local_id(), settings);
    let path = LocalPath::new(tmp.path());
    local.input(PaneInput::Navigate(PaneDir::Local(path.clone())));
    let (request, d) = list_request(&local.sent);
    local.input(PaneInput::ListingLoaded {
        request,
        dir: d.clone(),
        result: Ok(listing("/", vec![])),
    });
    local.sent.clear();
    let backend = d.backend_path().unwrap();
    local
        .on_core_event(&CoreEvent::ListingUpdated {
            server: Some(server()),
            dir: backend.clone(),
        })
        .unwrap();
    assert!(local.sent.is_empty());
    local
        .on_core_event(&CoreEvent::ListingUpdated {
            server: None,
            dir: backend,
        })
        .unwrap();
    assert!(matches!(local.sent[..], [PaneRequest::List { .. }]));
}

#[test]
fn address_bar_expands_tilde_and_relative_paths() {
    let home = std::path::absolute("home-of-user").unwrap();
    let cur = PaneDir::Local(LocalPath::new(std::path::absolute("cur").unwrap()));
    assert_eq!(expand_local("~", Some(&home), None).unwrap(), home);
    assert_eq!(
        expand_local("~/x", Some(&home), None).unwrap(),
        home.join("x")
    );
    assert_eq!(
        expand_local("sub", Some(&home), Some(&cur)).unwrap(),
        std::path::absolute("cur").unwrap().join("sub")
    );
    assert!(expand_local("~", None, None).is_err());
    assert!(expand_local("rel", None, None).is_err());

    // Remote: relative to the current dir, `..` normalised.
    let ctx = Ctx::new();
    let mut s = remote_pane(&ctx);
    load(&mut s, &ctx, "/srv/www", abc());
    key(&mut s, &ctx, PaneCommand::EditAddress);
    assert!(s.address_editing);
    let reqs = key(
        &mut s,
        &ctx,
        PaneCommand::AddressSubmit("../logs/./x".into()),
    );
    assert!(!s.address_editing);
    assert_eq!(list_request(&reqs).1, rdir("/srv/logs/x"));

    // Local: `~` and relative paths through the reducer.
    let mut l = FileListState::new(local_id(), &ctx.settings);
    let tmp = tempfile::tempdir().unwrap();
    let reqs = l.reduce(
        PaneInput::Navigate(PaneDir::Local(LocalPath::new(tmp.path()))),
        &ctx.get(),
    );
    let (request, d) = list_request(&reqs);
    l.reduce(
        PaneInput::ListingLoaded {
            request,
            dir: d,
            result: Ok(listing("/", vec![])),
        },
        &ctx.get(),
    );
    let reqs = key(
        &mut l,
        &ctx,
        PaneCommand::AddressSubmit("child/../other".into()),
    );
    assert_eq!(
        list_request(&reqs).1,
        PaneDir::Local(LocalPath::new(tmp.path().join("other")))
    );
}

#[test]
fn address_bar_error_reverts() {
    let ctx = Ctx::new();
    let mut s = remote_pane(&ctx);
    load(&mut s, &ctx, "/srv", abc());
    key(&mut s, &ctx, PaneCommand::EditAddress);
    let reqs = key(&mut s, &ctx, PaneCommand::AddressSubmit("/a\0b".into()));
    assert!(reqs.is_empty());
    assert!(!s.address_editing, "the address bar reverts");
    assert_eq!(s.dir, Some(rdir("/srv")));
    let notice = s.notice.clone().unwrap();
    assert!(notice.1, "an error");
    assert!(notice.0.contains("NUL"), "{}", notice.0);
}

#[test]
fn sort_toggle_hidden_and_columns_request_settings() {
    let ctx = Ctx::new();
    let mut s = remote_pane(&ctx);
    load(&mut s, &ctx, "/srv", abc());
    let reqs = key(
        &mut s,
        &ctx,
        PaneCommand::SortBy(courier_ftp_core::settings::Column::Name),
    );
    assert!(s.sort.descending, "same column again reverses");
    assert!(reqs.iter().any(|r| matches!(
        r,
        PaneRequest::Settings(InterfaceEdit::Sort(Side::Remote, _))
    )));
    // Remote `.` relists bypassing the cache.
    let reqs = key(&mut s, &ctx, PaneCommand::ToggleHidden);
    assert!(reqs.iter().any(|r| matches!(
        r,
        PaneRequest::Settings(InterfaceEdit::ForceShowHiddenRemote(true))
    )));
    assert!(
        reqs.iter()
            .any(|r| matches!(r, PaneRequest::List { force: true, .. }))
    );
    let reqs = key(&mut s, &ctx, PaneCommand::FileOp(FileOp::Refresh));
    assert!(
        reqs.iter()
            .any(|r| matches!(r, PaneRequest::List { force: true, .. }))
    );
}

#[test]
fn file_ops_carry_the_selection() {
    let ctx = Ctx::new();
    let mut s = remote_pane(&ctx);
    load(&mut s, &ctx, "/srv", abc());
    // On `..`: no selection, nothing requested; Mkdir needs none.
    assert!(key(&mut s, &ctx, PaneCommand::FileOp(FileOp::Delete)).is_empty());
    let reqs = key(&mut s, &ctx, PaneCommand::FileOp(FileOp::Mkdir));
    assert!(
        matches!(&reqs[..], [PaneRequest::FileOp { op: FileOp::Mkdir, selection, .. }] if selection.entries.is_empty())
    );
    key(&mut s, &ctx, PaneCommand::Bottom);
    // Open on a file follows `interface.enter_on_file` (transfer).
    let reqs = key(&mut s, &ctx, PaneCommand::Open);
    assert!(
        matches!(&reqs[..], [PaneRequest::FileOp { op: FileOp::Transfer, selection, .. }] if selection.entries[0].name == "y.html")
    );
}

/// AC13: the default keymap reaches the pane.
#[test]
fn filelist_default_keys() {
    use crate::{
        action::Action, components::main_screen::layout::Region, config::Config,
        testing::AppHarness,
    };

    let mut h = AppHarness::new(Config::default());
    assert_eq!(h.focus(), Region::LocalList);
    let pane = local_id();
    let entries: Vec<Entry> = (0..40).map(|i| file(&format!("f{i:02}"), 1)).collect();
    let mut hidden = file(".hidden", 1);
    hidden.hidden = true;
    let mut all = entries;
    all.push(hidden);
    let tmp = tempfile::tempdir().unwrap();
    let d = PaneDir::Local(LocalPath::new(tmp.path()));
    h.action(Action::PaneInput(pane, PaneInput::Navigate(d.clone())));
    // Answer the request with a fake listing (request ids start at 1).
    h.action(Action::PaneInput(
        pane,
        PaneInput::ListingLoaded {
            request: RequestId(1),
            dir: d,
            result: Ok(listing("/", all)),
        },
    ));
    let screen = h.render(80, 24);
    assert!(screen.contains("f00"), "{screen}");
    assert!(!screen.contains(".hidden"), "{screen}");
    // `.` toggles hidden files.
    h.keys(".");
    let screen = h.render(80, 24);
    assert!(screen.contains(".hidden"), "{screen}");
    // `ctrl-d` moves half a page.
    let cursor_row = |h: &mut AppHarness| {
        let buf = h.buffer(80, 24);
        (0..24u16).find(|y| {
            buf[(3, *y)]
                .style()
                .add_modifier
                .contains(ratatui::style::Modifier::REVERSED)
        })
    };
    let before = cursor_row(&mut h).unwrap();
    h.keys("ctrl-d");
    let after = cursor_row(&mut h).unwrap();
    assert!(after > before + 1, "{before} -> {after}");
    // `Q` and `M` request QueueOnly / MkdirEnter (not available until T62).
    h.keys("Q");
    let status = h.render(80, 24);
    assert!(
        status.contains("Add selection to the queue only is not available yet"),
        "{status}"
    );
    h.keys("M");
    let status = h.render(80, 24);
    assert!(
        status.contains("Make directory and enter it is not available yet"),
        "{status}"
    );
    // `ctrl-h` changes nothing.
    let before = h.render(80, 24);
    h.keys("ctrl-h");
    assert_eq!(h.render(80, 24), before);
}
