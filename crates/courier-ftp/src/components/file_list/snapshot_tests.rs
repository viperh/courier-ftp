//! Snapshot, style, rendering-property, integration and performance tests.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use courier_ftp_core::{
    Error,
    backend::{Backend, Listing},
    cache::{CachePolicy, ListingCache},
    filters::FilterEngine,
    model::{
        Entry, EntryKind, LocalPath, Permissions, Precision, RemotePath, SymlinkTarget, Timestamp,
    },
    settings::SizeFormat,
};
use proptest::prelude::*;
use ratatui::{Frame, style::Modifier};
use time::macros::datetime;
use tokio::time::Instant;

use super::{
    render::{self, RenderCx, RowFormat},
    state::{FileListState, PaneCommand, PaneDir, PaneInput, PaneRequest, RequestId},
    tests::{
        Ctx, answer, dir, file, listing, load, local_id, rdir, remote_id, remote_pane,
        snapshot_dates,
    },
    view::{self, INLINE_LIMIT},
};
use crate::{
    components::DrawCx,
    testing::{assert_view_snapshots, buffer_to_string},
    ui::{
        symbols::Symbols,
        theme::{Theme, ThemePreset},
    },
};

fn ts(t: time::OffsetDateTime, p: Precision) -> Option<Timestamp> {
    Some(Timestamp::new(t, p))
}

fn meta(mut e: Entry, mode: u32, t: Option<Timestamp>, owner: &str, group: &str) -> Entry {
    e.permissions = Some(Permissions::from_mode(mode));
    e.modified = t;
    e.owner = Some(owner.into());
    e.group = Some(group.into());
    e
}

/// The listing of the T53 mock-ups.
fn web_entries() -> Vec<Entry> {
    let m = Precision::Minute;
    let mut htaccess = file(".htaccess", 412);
    htaccess.hidden = true;
    let mut logo = Entry::new(
        "logo.png",
        EntryKind::Symlink {
            target: Some("static/logo.png".into()),
            target_kind: Some(SymlinkTarget::File),
        },
    );
    logo.size = None;
    vec![
        meta(
            dir("assets"),
            0o755,
            ts(datetime!(2026-10-01 12:00 UTC), m),
            "deploy",
            "www-data",
        ),
        meta(
            dir("css"),
            0o755,
            ts(datetime!(2026-09-30 09:12 UTC), m),
            "deploy",
            "www-data",
        ),
        meta(
            dir("js"),
            0o755,
            ts(datetime!(2026-09-30 09:12 UTC), m),
            "deploy",
            "www-data",
        ),
        meta(
            dir("uploads"),
            0o775,
            ts(datetime!(2026-10-07 23:59 UTC), m),
            "www-data",
            "www-data",
        ),
        meta(
            htaccess,
            0o644,
            ts(datetime!(2026-03-14 08:00 UTC), m),
            "deploy",
            "www-data",
        ),
        meta(
            file("backup-2026-10-01.tar.gz", 1_300_000_000),
            0o600,
            ts(datetime!(2026-10-01 03:00 UTC), m),
            "deploy",
            "deploy",
        ),
        meta(
            file("favicon.ico", 15_360),
            0o644,
            ts(datetime!(2025-01-05 00:00 UTC), Precision::Day),
            "deploy",
            "www-data",
        ),
        meta(
            file("index.html", 4198),
            0o644,
            ts(datetime!(2026-10-08 18:22 UTC), m),
            "deploy",
            "www-data",
        ),
        meta(
            logo,
            0o777,
            ts(datetime!(2026-06-02 10:41 UTC), m),
            "deploy",
            "www-data",
        ),
        meta(
            file("README.md", 2365),
            0o644,
            ts(datetime!(2026-09-12 16:05 UTC), m),
            "deploy",
            "www-data",
        ),
        meta(
            file("robots.txt", 68),
            0o644,
            ts(datetime!(2024-11-30 00:00 UTC), Precision::Day),
            "deploy",
            "www-data",
        ),
        meta(
            file("sitemap.xml", 12_698),
            0o644,
            ts(datetime!(2026-10-08 02:00 UTC), m),
            "deploy",
            "www-data",
        ),
        meta(
            file("style.min.css", 49_869),
            0o644,
            ts(datetime!(2026-10-08 18:20 UTC), m),
            "deploy",
            "www-data",
        ),
        meta(
            file(
                "very-long-file-name-that-gets-truncated-in-the-pane.txt",
                1024,
            ),
            0o644,
            ts(datetime!(2026-10-02 07:30 UTC), m),
            "deploy",
            "www-data",
        ),
    ]
}

fn web_pane(ctx: &Ctx) -> FileListState {
    let mut s = remote_pane(ctx);
    load(&mut s, ctx, "/var/www/html", web_entries());
    s
}

fn format() -> RowFormat {
    RowFormat {
        size: SizeFormat::Iec,
        thousands: true,
        dates: snapshot_dates(),
    }
}

struct Look {
    theme: Theme,
    symbols: Symbols,
}

fn look(mono_ascii: bool) -> Look {
    let (theme, _) = Theme::load(ThemePreset::Default, &BTreeMap::new(), mono_ascii);
    Look {
        theme,
        symbols: if mono_ascii {
            Symbols::ascii()
        } else {
            Symbols::unicode()
        },
    }
}

fn draw_with<'a>(
    state: &'a mut FileListState,
    look: &'a Look,
    spinner: Option<&'static str>,
) -> impl FnMut(&mut Frame) + 'a {
    let fmt = format();
    move |f: &mut Frame| {
        let area = f.area();
        let ctx = Ctx::new();
        state.reduce(
            PaneInput::Resize {
                body_rows: area.height.saturating_sub(5),
            },
            &ctx.get(),
        );
        let cx = DrawCx {
            theme: &look.theme,
            symbols: &look.symbols,
            focused: true,
            now: Instant::now(),
            spinner,
        };
        let rcx = RenderCx {
            draw: &cx,
            format: &fmt,
            address: None,
            not_connected_hint: "Ctrl-s Site Manager · Ctrl-k Quickconnect",
        };
        render::draw(state, f, area, &rcx);
    }
}

/// Snapshots `make()` at both sizes, colour + Unicode and `NO_COLOR` + ASCII.
fn snap(name: &str, make: impl Fn() -> FileListState, spinner: Option<&'static str>) {
    for mono in [false, true] {
        let l = look(mono);
        let mut s = make();
        let full = if mono {
            format!("{name}_mono_ascii")
        } else {
            name.to_owned()
        };
        assert_view_snapshots!(full.clone(), draw_with(&mut s, &l, spinner));
        if mono {
            for (w, h) in crate::testing::SIZES {
                let text = crate::testing::render(w, h, draw_with(&mut s, &l, spinner));
                let screen = text.split("--- styles ---").next().unwrap_or("");
                assert!(screen.is_ascii(), "{full}: non-ASCII cell\n{screen}");
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn snap_local_listing() {
    snap(
        "local_listing",
        || {
            let ctx = Ctx::new();
            let mut s = FileListState::new(local_id(), &ctx.settings);
            let reqs = s.reduce(
                PaneInput::Navigate(PaneDir::Local(LocalPath::new("/srv/data"))),
                &ctx.get(),
            );
            answer(&mut s, &ctx, &reqs, web_entries());
            s
        },
        None,
    );
}

#[test]
fn snap_remote_listing() {
    snap("remote_listing", || web_pane(&Ctx::new()), None);
}

fn marked() -> FileListState {
    let ctx = Ctx::new();
    let mut s = web_pane(&ctx);
    // Rows: 0 `..`, 1–4 dirs, 5 .htaccess, 6 backup, 7 favicon, 8 index, …, 13 style.
    for _ in 0..13 {
        s.reduce(PaneInput::Key(PaneCommand::CursorDown), &ctx.get());
    }
    s.reduce(PaneInput::Key(PaneCommand::ToggleMark), &ctx.get());
    for _ in 0..6 {
        s.reduce(PaneInput::Key(PaneCommand::CursorUp), &ctx.get());
    }
    s.reduce(PaneInput::Key(PaneCommand::ToggleMark), &ctx.get());
    s.reduce(PaneInput::Key(PaneCommand::CursorUp), &ctx.get());
    s
}

#[test]
fn snap_marked_rows() {
    snap("marked_rows", marked, None);
}

#[test]
fn snap_quick_filter_editing() {
    snap(
        "quick_filter_editing",
        || {
            let ctx = Ctx::new();
            let mut s = web_pane(&ctx);
            s.reduce(PaneInput::Key(PaneCommand::QuickFilter), &ctx.get());
            for c in "s".chars() {
                s.reduce(PaneInput::Key(PaneCommand::FilterInsert(c)), &ctx.get());
            }
            s
        },
        None,
    );
}

#[test]
fn snap_filtered_view() {
    snap(
        "filtered_view",
        || {
            let ctx = Ctx::new();
            let mut s = web_pane(&ctx);
            s.reduce(PaneInput::Key(PaneCommand::QuickFilter), &ctx.get());
            for c in "*.html".chars() {
                s.reduce(PaneInput::Key(PaneCommand::FilterInsert(c)), &ctx.get());
            }
            s.reduce(PaneInput::Key(PaneCommand::FilterAccept), &ctx.get());
            s
        },
        None,
    );
}

#[test]
fn snap_all_entries_hidden_by_filters() {
    snap(
        "all_hidden",
        || {
            let ctx = Ctx::new();
            let mut s = remote_pane(&ctx);
            load(&mut s, &ctx, "/", vec![file("a", 1), file("b", 2)]);
            s.reduce(PaneInput::Key(PaneCommand::QuickFilter), &ctx.get());
            s.reduce(PaneInput::Key(PaneCommand::FilterInsert('z')), &ctx.get());
            s.reduce(PaneInput::Key(PaneCommand::FilterAccept), &ctx.get());
            s
        },
        None,
    );
}

#[test]
fn snap_empty_dir() {
    snap(
        "empty_dir",
        || {
            let ctx = Ctx::new();
            let mut s = remote_pane(&ctx);
            load(&mut s, &ctx, "/var/empty", Vec::new());
            s
        },
        None,
    );
}

fn fail(s: &mut FileListState, ctx: &Ctx, to: &str, err: Error) {
    let reqs = s.reduce(PaneInput::Navigate(rdir(to)), &ctx.get());
    let (request, d) = reqs
        .iter()
        .find_map(|r| match r {
            PaneRequest::List { request, dir, .. } => Some((*request, dir.clone())),
            _ => None,
        })
        .unwrap();
    s.reduce(
        PaneInput::ListingLoaded {
            request,
            dir: d,
            result: Err(Arc::new(err)),
        },
        &ctx.get(),
    );
}

#[test]
fn snap_error_with_previous() {
    snap(
        "error_with_previous",
        || {
            let ctx = Ctx::new();
            let mut s = web_pane(&ctx);
            fail(
                &mut s,
                &ctx,
                "/var/www/private",
                Error::PermissionDenied("x".into()),
            );
            s
        },
        None,
    );
}

#[test]
fn snap_error_first_listing() {
    snap(
        "error_first_listing",
        || {
            let ctx = Ctx::new();
            let mut s = remote_pane(&ctx);
            fail(
                &mut s,
                &ctx,
                "/missing",
                Error::NotFound(RemotePath::parse("/missing").unwrap()),
            );
            s
        },
        None,
    );
}

#[test]
fn snap_not_connected() {
    snap(
        "not_connected",
        || FileListState::new(remote_id(), &Ctx::new().settings),
        None,
    );
}

#[test]
fn snap_loading() {
    snap(
        "loading",
        || {
            let ctx = Ctx::new();
            let mut s = remote_pane(&ctx);
            s.reduce(PaneInput::Navigate(rdir("/var/www")), &ctx.get());
            s
        },
        Some("⠋"),
    );
}

fn hostile_entries() -> Vec<Entry> {
    let mut link = Entry::new(
        "link\u{1b}]0;x\u{7}",
        EntryKind::Symlink {
            target: Some("/etc/\u{202e}dwssap".into()),
            target_kind: Some(SymlinkTarget::Dir),
        },
    );
    link.owner = Some("ro\u{1b}[2Jot".into());
    vec![
        file("esc\u{1b}[31mred", 1),
        file("bidi\u{202e}txt.exe", 2),
        file("tab\tcr\rdel\u{7f}c1\u{85}", 3),
        file("wide-日本語-😀", 4),
        link,
    ]
}

#[test]
fn snap_hostile_names() {
    snap(
        "hostile_names",
        || {
            let ctx = Ctx::new();
            let mut s = remote_pane(&ctx);
            load(&mut s, &ctx, "/srv", hostile_entries());
            s
        },
        None,
    );
}

#[test]
fn snap_narrow_pane_40x12() {
    for mono in [false, true] {
        let l = look(mono);
        let mut s = web_pane(&Ctx::new());
        let text = crate::testing::render(40, 12, draw_with(&mut s, &l, None));
        let name = if mono {
            "narrow_pane_40x12_mono_ascii"
        } else {
            "narrow_pane_40x12"
        };
        insta::assert_snapshot!(name, text);
    }
}

/// Style assertions: the cursor row is reversed, directories are bold, marks are
/// bold in both themes.
#[test]
fn cursor_reversed_and_dirs_bold() {
    for mono in [false, true] {
        let l = look(mono);
        let mut s = marked();
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        terminal.draw(draw_with(&mut s, &l, None)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let text = buffer_to_string(&buf);
        let row_of = |needle: &str| {
            u16::try_from(text.lines().position(|l| l.contains(needle)).unwrap()).unwrap()
        };
        let reversed = |y: u16| buf[(5, y)].style().add_modifier.contains(Modifier::REVERSED);
        // Cursor on index.html (marked too).
        assert!(reversed(row_of("*index.html")));
        assert!(!reversed(row_of("favicon.ico")));
        let y = row_of("assets/");
        assert!(buf[(3, y)].style().add_modifier.contains(Modifier::BOLD));
        assert!(
            !buf[(3, y)]
                .style()
                .add_modifier
                .contains(Modifier::REVERSED)
        );
        let y = row_of("*style.min.css");
        assert!(buf[(3, y)].style().add_modifier.contains(Modifier::BOLD));
    }
}

fn many(n: usize) -> Vec<Entry> {
    (0..n)
        .map(|i| {
            let mut e = file(&format!("file-{i}.txt"), u64::try_from(i).unwrap_or(0));
            e.modified = ts(datetime!(2026-01-01 00:00 UTC), Precision::Second);
            e
        })
        .collect()
}

/// A pane over a 100 000-entry listing, view built inline (tests only).
fn big_pane() -> FileListState {
    let ctx = Ctx::new();
    let mut s = remote_pane(&ctx);
    let reqs = s.reduce(PaneInput::Navigate(rdir("/big")), &ctx.get());
    let reqs = answer(&mut s, &ctx, &reqs, many(100_000));
    // Above the inline limit the view is built off-thread: run the job here.
    let Some(PaneRequest::BuildView {
        generation, job, ..
    }) = reqs.into_iter().next()
    else {
        panic!("expected BuildView");
    };
    let built = job.run();
    s.reduce(
        PaneInput::SortDone {
            generation,
            view: built.view,
            filtered: built.filtered,
        },
        &ctx.get(),
    );
    s
}

/// AC6: only the visible rows are formatted.
#[test]
fn render_formats_only_visible_rows() {
    let mut s = big_pane();
    assert_eq!(s.row_count(), 100_001);
    let l = look(false);
    render::ROWS_FORMATTED.with(|c| c.set(0));
    let _ = crate::testing::render(160, 48, draw_with(&mut s, &l, None));
    let n = render::ROWS_FORMATTED.with(std::cell::Cell::get);
    assert!(n > 0 && n <= 46, "{n} rows formatted");
}

fn arb_name() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop_oneof![
            any::<char>(),
            Just('\u{1b}'),
            Just('\u{202e}'),
            Just('\u{7f}'),
            Just('\u{85}'),
            Just('日'),
            Just('😀'),
            Just('\t'),
        ],
        1..20,
    )
    .prop_map(|v| v.into_iter().collect::<String>())
}

fn arb_entries() -> impl Strategy<Value = Vec<Entry>> {
    proptest::collection::vec(
        (
            arb_name(),
            any::<bool>(),
            proptest::option::of(any::<u64>()),
            proptest::option::of(".{0,12}"),
        ),
        0..30,
    )
    .prop_map(|v| {
        let entries = v
            .into_iter()
            .map(|(n, d, size, owner)| {
                let mut e = if d { dir(&n) } else { file(&n, 0) };
                e.size = size;
                e.owner = owner;
                e
            })
            .collect();
        Listing::clean_entries(entries).0
    })
}

fn is_control(c: char) -> bool {
    let n = u32::from(c);
    n < 0x20
        || n == 0x7f
        || (0x80..=0x9f).contains(&n)
        || (0x202a..=0x202e).contains(&n)
        || (0x2066..=0x2069).contains(&n)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// AC8: no size panics, including 0×0.
    #[test]
    fn prop_render_never_panics(entries in arb_entries(), w in 0u16..200, h in 0u16..60, mono in any::<bool>(), down in 0usize..40) {
        let ctx = Ctx::new();
        let mut s = remote_pane(&ctx);
        load(&mut s, &ctx, "/p", entries);
        for _ in 0..down {
            s.reduce(PaneInput::Key(PaneCommand::CursorDown), &ctx.get());
        }
        let l = look(mono);
        let _ = crate::testing::render(w, h, draw_with(&mut s, &l, None));
    }

    /// AC8: no raw control character reaches the buffer.
    #[test]
    fn prop_rendered_buffer_has_no_control_chars(entries in arb_entries(), w in 20u16..170, h in 6u16..50) {
        let ctx = Ctx::new();
        let mut s = remote_pane(&ctx);
        load(&mut s, &ctx, "/p", entries);
        let l = look(false);
        let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
        terminal.draw(draw_with(&mut s, &l, None)).unwrap();
        let text = buffer_to_string(terminal.backend().buffer());
        for c in text.chars().filter(|c| *c != '\n') {
            prop_assert!(!is_control(c), "control char U+{:04X}", u32::from(c));
        }
    }
}

/// A `LocalBackend` on a temp dir: enter, parent, refresh after creating a file.
#[tokio::test]
async fn navigates_local_tempdir_with_local_backend() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir(tmp.path().join("sub")).unwrap();
    std::fs::write(tmp.path().join("a.txt"), b"hello").unwrap();
    let (bctx, _rx) = courier_ftp_core::backend::mock::test_context();
    let ctx = Ctx::new();
    let mut s = FileListState::new(local_id(), &ctx.settings);
    let token = tokio_util::sync::CancellationToken::new;
    // Runs the pending `List` request through the real local listing.
    let run = |_s: &mut FileListState, reqs: Vec<PaneRequest>| {
        let bctx = bctx.clone();
        async move {
            let (request, d) = reqs
                .iter()
                .find_map(|r| match r {
                    PaneRequest::List { request, dir, .. } => Some((*request, dir.clone())),
                    _ => None,
                })
                .unwrap();
            let PaneDir::Local(p) = d.clone() else {
                panic!("local");
            };
            let result = super::service::list_local(bctx, p, Duration::from_secs(5), token()).await;
            let (dir, result) = match result {
                Ok((dir, l)) => (dir, Ok(l)),
                Err(e) => (d, Err(Arc::new(e))),
            };
            (request, dir, result)
        }
    };
    let reqs = s.reduce(
        PaneInput::Navigate(PaneDir::Local(LocalPath::new(tmp.path()))),
        &ctx.get(),
    );
    let (request, dir, result) = run(&mut s, reqs).await;
    s.reduce(
        PaneInput::ListingLoaded {
            request,
            dir,
            result,
        },
        &ctx.get(),
    );
    let names: Vec<String> = (0..s.row_count())
        .filter_map(|r| s.entry_at(r).map(|e| e.name.clone()))
        .collect();
    assert_eq!(names, ["sub", "a.txt"]);
    // Enter `sub`.
    s.reduce(PaneInput::Key(PaneCommand::Top), &ctx.get());
    s.reduce(PaneInput::Key(PaneCommand::CursorDown), &ctx.get());
    let reqs = s.reduce(PaneInput::Key(PaneCommand::Open), &ctx.get());
    let (request, dir, result) = run(&mut s, reqs).await;
    s.reduce(
        PaneInput::ListingLoaded {
            request,
            dir,
            result,
        },
        &ctx.get(),
    );
    assert_eq!(
        s.dir,
        Some(PaneDir::Local(LocalPath::new(tmp.path().join("sub"))))
    );
    assert_eq!(s.view().len(), 0);
    // Parent: the cursor is on `sub`.
    let reqs = s.reduce(PaneInput::Key(PaneCommand::Parent), &ctx.get());
    let (request, dir, result) = run(&mut s, reqs).await;
    s.reduce(
        PaneInput::ListingLoaded {
            request,
            dir,
            result,
        },
        &ctx.get(),
    );
    assert_eq!(s.cursor_entry().map(|e| e.name.as_str()), Some("sub"));
    // Refresh after creating a file.
    std::fs::write(tmp.path().join("b.txt"), b"x").unwrap();
    let reqs = s.reduce(
        PaneInput::Key(PaneCommand::FileOp(super::state::FileOp::Refresh)),
        &ctx.get(),
    );
    let (request, dir, result) = run(&mut s, reqs).await;
    s.reduce(
        PaneInput::ListingLoaded {
            request,
            dir,
            result,
        },
        &ctx.get(),
    );
    assert_eq!(s.view().len(), 3);
    assert_eq!(s.cursor_entry().map(|e| e.name.as_str()), Some("sub"));
    // A missing directory keeps the listing.
    let gone = PaneDir::Local(LocalPath::new(tmp.path().join("gone")));
    let reqs = s.reduce(PaneInput::Navigate(gone), &ctx.get());
    let (request, dir, result) = run(&mut s, reqs).await;
    s.reduce(
        PaneInput::ListingLoaded {
            request,
            dir,
            result,
        },
        &ctx.get(),
    );
    assert_eq!(s.view().len(), 3);
    let msg = s.notice.clone().unwrap().0;
    assert!(msg.starts_with("Directory not found: "), "{msg}");
}

/// The second visit of a remote directory is served by the cache (no backend call).
#[tokio::test]
async fn remote_navigation_uses_cache_hit() {
    use courier_ftp_core::backend::mock::{MockOp, MockServer, test_context};

    let server = MockServer::new();
    server.add_dir("/srv");
    server.add_file("/srv/a.txt", "x");
    let (bctx, _rx) = test_context();
    let events = bctx.events.clone();
    let mut backend = server.backend(bctx);
    backend
        .connect(tokio_util::sync::CancellationToken::new())
        .await
        .unwrap();
    let backend = Arc::new(tokio::sync::Mutex::new(backend));
    let cache = ListingCache::new(CachePolicy::default(), events);
    let id = super::tests::server();
    let dir = RemotePath::parse("/srv").unwrap();
    for (i, expected_calls) in [(0, 1), (1, 1)] {
        let b = Arc::clone(&backend);
        let d = dir.clone();
        let (l, _) =
            super::service::list_through_cache(&cache, &id, &dir, false, move || async move {
                b.lock()
                    .await
                    .list(&d, tokio_util::sync::CancellationToken::new())
                    .await
            })
            .await
            .unwrap();
        assert_eq!(l.entries.len(), 1, "visit {i}");
        assert_eq!(server.calls(MockOp::List), expected_calls, "visit {i}");
    }
    // `force` (Refresh) bypasses the cache.
    let b = Arc::clone(&backend);
    let d = dir.clone();
    super::service::list_through_cache(&cache, &id, &dir, true, move || async move {
        b.lock()
            .await
            .list(&d, tokio_util::sync::CancellationToken::new())
            .await
    })
    .await
    .unwrap();
    assert_eq!(server.calls(MockOp::List), 2);
}

/// AC7: above the inline limit the view is built off the UI thread; keys are handled
/// while `SortDone` is pending, and a stale generation is dropped.
#[test]
fn large_listing_sort_runs_off_thread() {
    let ctx = Ctx::new();
    let mut s = remote_pane(&ctx);
    let reqs = s.reduce(PaneInput::Navigate(rdir("/big")), &ctx.get());
    let reqs = answer(&mut s, &ctx, &reqs, many(100_000));
    let Some(PaneRequest::BuildView {
        generation, job, ..
    }) = reqs.into_iter().next()
    else {
        panic!("expected BuildView");
    };
    assert!(job.listing.entries.len() > INLINE_LIMIT);
    // The job runs on another thread while the pane keeps handling keys.
    let handle = std::thread::spawn(move || job.run());
    s.reduce(PaneInput::Key(PaneCommand::CursorDown), &ctx.get());
    s.reduce(PaneInput::Key(PaneCommand::Bottom), &ctx.get());
    // Sorting by size meanwhile starts a newer build.
    let newer = s.reduce(
        PaneInput::Key(PaneCommand::SortBy(
            courier_ftp_core::settings::Column::Size,
        )),
        &ctx.get(),
    );
    let built = handle.join().unwrap();
    s.reduce(
        PaneInput::SortDone {
            generation,
            view: built.view,
            filtered: built.filtered,
        },
        &ctx.get(),
    );
    assert_eq!(s.view().len(), 0, "stale generation dropped");
    let Some(PaneRequest::BuildView {
        generation, job, ..
    }) = newer.into_iter().next()
    else {
        panic!("expected BuildView");
    };
    let built = job.run();
    s.reduce(
        PaneInput::SortDone {
            generation,
            view: built.view,
            filtered: built.filtered,
        },
        &ctx.get(),
    );
    assert_eq!(s.view().len(), 100_000);
    s.reduce(PaneInput::Key(PaneCommand::CursorDown), &ctx.get());
    assert_eq!(
        s.cursor_entry().map(|e| e.name.as_str()),
        Some("file-0.txt")
    );
}

/// The app runs `BuildView` on the blocking pool and answers with `SortDone`.
#[test]
fn app_builds_large_views_on_the_blocking_pool() {
    use crate::{action::Action, config::Config, testing::AppHarness};

    let mut h = AppHarness::new(Config::default());
    let pane = local_id();
    let d = PaneDir::Local(LocalPath::new(std::path::absolute("big").unwrap()));
    h.action(Action::PaneInput(pane, PaneInput::Navigate(d.clone())));
    h.action(Action::PaneInput(
        pane,
        PaneInput::ListingLoaded {
            request: RequestId(1),
            dir: d,
            result: Ok(listing("/", many(20_000))),
        },
    ));
    for _ in 0..200 {
        h.settle();
        if h.render(80, 24).contains("file-0.txt") {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("the view was never built:\n{}", h.render(80, 24));
}

fn median_and_p99(mut v: Vec<Duration>) -> (Duration, Duration) {
    v.sort_unstable();
    (v[v.len() / 2], v[v.len() * 99 / 100])
}

/// Bench `file_list_render_100k` (AC6): run with `--ignored --release`.
#[test]
#[ignore = "timing; run in release: cargo test --release -p courier-ftp -- --ignored file_list_"]
fn file_list_render_100k() {
    let mut s = big_pane();
    let l = look(false);
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(160, 48)).unwrap();
    let mut times = Vec::new();
    let ctx = Ctx::new();
    for i in 0..200 {
        s.reduce(
            PaneInput::Key(if i % 2 == 0 {
                PaneCommand::PageDown
            } else {
                PaneCommand::CursorDown
            }),
            &ctx.get(),
        );
        let start = std::time::Instant::now();
        terminal.draw(draw_with(&mut s, &l, None)).unwrap();
        times.push(start.elapsed());
    }
    let (median, p99) = median_and_p99(times);
    eprintln!("file_list_render_100k: median {median:?}, p99 {p99:?}");
    if !cfg!(debug_assertions) {
        assert!(median <= Duration::from_millis(2) && p99 <= Duration::from_millis(5));
    }
}

/// Bench `file_list_view_build_100k` (AC7): run with `--ignored --release`.
#[test]
#[ignore = "timing; run in release: cargo test --release -p courier-ftp -- --ignored file_list_"]
fn file_list_view_build_100k() {
    let l = listing("/", many(100_000));
    let filters = FilterEngine::empty(courier_ftp_core::filters::Side::Remote);
    let params = view::ViewParams {
        show_hidden: true,
        quick: String::new(),
        sort: courier_ftp_core::settings::SortSpec::default(),
        natural: true,
        case_sensitive: false,
        dirs_first: true,
    };
    let mut times = Vec::new();
    for _ in 0..10 {
        let start = std::time::Instant::now();
        let v = view::build(&l, &params, &filters, "/");
        times.push(start.elapsed());
        assert_eq!(v.view.len(), 100_000);
    }
    let (median, _) = median_and_p99(times);
    eprintln!("file_list_view_build_100k: median {median:?}");
    if !cfg!(debug_assertions) {
        assert!(median <= Duration::from_millis(80));
    }
}
