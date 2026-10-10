//! T50 tests: layouts as snapshots, focus cycling, key routing, the core
//! event bridge.

use courier_ftp_core::{
    backend::Listing,
    events::{self, CoreEvent, LogKind, PromptKind, PromptResponse, SessionId, TrustDecision},
    model::{Entry, HostKeyFingerprint, RemotePath},
    settings::Layout,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};
use tokio_util::sync::CancellationToken;

use super::{KeyOutcome, MainScreen, Region, Side, Theme, dir_tree::DirTree};
use crate::{
    action::{Action, SyncChoice},
    app::Mode,
    config::Config,
};

fn screen(layout: Layout) -> MainScreen {
    let mut config = Config::builtin();
    config.settings.interface.layout = layout;
    // Independent of the locale of the machine running the tests.
    config.settings.interface.unicode_symbols = courier_ftp_core::settings::SymbolMode::Unicode;
    // Log lines carry the current time; leave it out of snapshots.
    config.settings.logging.show_timestamps = false;
    let mut s = MainScreen::new(config, Theme::new(None, true));
    // The same tree on every OS (Windows adds a "Computer" root and shortcuts).
    s.local_tree = DirTree::with_shortcuts(Side::Local, true, false, false);
    // Fixed content, independent of the machine running the test.
    s.update(&Action::ListingLoaded {
        side: Side::Local,
        result: Ok(Listing {
            dir: RemotePath::root(),
            entries: vec![
                Entry::file("index.html", 4096),
                Entry::dir("assets"),
                Entry::file("style.css", 900),
            ],
            fetched_at: std::time::Instant::now(),
            raw: None,
        }),
    });
    s.local.dir = None;
    let (tx, mut rx) = events::channel(2);
    let session = SessionId(1);
    tx.log(session, LogKind::Status, "Connecting to example.com:21...");
    tx.log(session, LogKind::Response, "230 Login successful.");
    while let Some(event) = rx.try_recv() {
        s.handle_core(event);
    }
    s
}

fn render(s: &mut MainScreen, width: u16, height: u16) -> Terminal<TestBackend> {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|f| s.draw(f)).unwrap();
    terminal
}

fn text(terminal: &Terminal<TestBackend>) -> String {
    terminal.backend().to_string()
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn alt(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::ALT)
}

#[test]
fn layouts_render_at_every_size() {
    for (layout, name) in [
        (Layout::Classic, "classic"),
        (Layout::Explorer, "explorer"),
        (Layout::Widescreen, "widescreen"),
    ] {
        // T76: every view at 80×24 and 160×48; T50: also 120×40 and 200×60.
        for (w, h) in [(80, 24), (120, 40), (160, 48), (200, 60)] {
            let mut s = screen(layout);
            let terminal = render(&mut s, w, h);
            insta::assert_snapshot!(format!("{name}_{w}x{h}"), terminal.backend());
        }
    }
}

#[test]
fn small_terminal_shows_one_pane() {
    let mut s = screen(Layout::Classic);
    let t = render(&mut s, 60, 20);
    insta::assert_snapshot!("compact_60x20", t.backend());
    s.update(&Action::FocusNext);
    let t = render(&mut s, 60, 20);
    assert!(text(&t).contains("Remote: not connected"), "{}", text(&t));
}

#[test]
fn tab_cycles_between_the_lists() {
    let mut s = screen(Layout::Classic);
    render(&mut s, 120, 40);
    assert_eq!(s.focus(), Region::LocalList);
    s.update(&Action::FocusNext);
    assert_eq!(s.focus(), Region::RemoteList);
    s.update(&Action::FocusPrev);
    assert_eq!(s.focus(), Region::LocalList);
    s.update(&Action::FocusLog);
    assert_eq!(s.focus(), Region::Log);
    s.update(&Action::FocusNext);
    assert_eq!(s.focus(), Region::LocalList);
}

#[test]
fn focus_leaves_hidden_regions() {
    let mut s = screen(Layout::Classic);
    s.update(&Action::FocusLog);
    s.update(&Action::ToggleLog);
    render(&mut s, 120, 40);
    assert_eq!(s.focus(), Region::LocalList);
    // Focusing a hidden region shows it again.
    s.update(&Action::FocusQueue);
    s.update(&Action::ToggleQueue);
    s.update(&Action::FocusQueue);
    render(&mut s, 120, 40);
    assert_eq!(s.focus(), Region::Queue);
}

#[test]
fn modes_follow_focus_and_dialogs() {
    let mut s = screen(Layout::Classic);
    assert_eq!(s.mode(), Mode::FileList);
    s.update(&Action::FocusLog);
    assert_eq!(s.mode(), Mode::Log);
    s.update(&Action::FocusQueue);
    assert_eq!(s.mode(), Mode::Queue);
    s.update(&Action::FocusQuickconnect);
    assert_eq!(s.mode(), Mode::Input);
    s.update(&Action::Help);
    assert_eq!(s.mode(), Mode::Dialog);
}

#[test]
fn a_modal_takes_every_key_until_closed() {
    let mut s = screen(Layout::Classic);
    assert_eq!(
        s.handle_key(key(KeyCode::Char('x'))),
        KeyOutcome::NotHandled
    );
    s.update(&Action::Help);
    assert!(s.has_modal());
    assert_eq!(s.handle_key(key(KeyCode::Tab)), KeyOutcome::Consumed);
    assert!(s.has_modal());
    assert_eq!(s.handle_key(key(KeyCode::Esc)), KeyOutcome::Consumed);
    assert!(!s.has_modal());
    assert_eq!(s.handle_key(key(KeyCode::Tab)), KeyOutcome::NotHandled);
}

#[test]
fn help_lists_bindings_from_the_config() {
    let mut s = screen(Layout::Classic);
    s.update(&Action::Help);
    let t = text(&render(&mut s, 120, 120));
    assert!(t.contains("Keys: FileList mode"), "{t}");
    // Global bindings show alongside the file list's own.
    assert!(t.contains("<Ctrl-q>") && t.contains("Quit"), "{t}");
    assert!(t.contains("<g><g>") && t.contains("Top"), "{t}");
    // The file list's `<j>` shadows nothing global, and Help itself is listed.
    assert!(t.contains("<F1>") && t.contains("Help"), "{t}");
}

#[tokio::test]
async fn prompts_open_a_dialog_and_answer() {
    let mut s = screen(Layout::Classic);
    let (tx, mut rx) = events::channel(2);
    let asker = tokio::spawn(async move {
        tx.ask(
            None,
            PromptKind::Message("Queue finished".into()),
            &CancellationToken::new(),
        )
        .await
    });
    let event = rx.recv().await.unwrap();
    assert!(matches!(event, CoreEvent::Prompt(_)));
    s.handle_core(event);
    assert!(s.has_modal());
    assert!(text(&render(&mut s, 120, 40)).contains("Queue finished"));
    s.handle_key(key(KeyCode::Enter));
    assert!(!s.has_modal());
    assert!(matches!(asker.await.unwrap(), Ok(PromptResponse::Ok)));
}

#[tokio::test]
async fn escaping_a_prompt_cancels_it() {
    let mut s = screen(Layout::Classic);
    let (tx, mut rx) = events::channel(2);
    let asker = tokio::spawn(async move {
        tx.ask(
            None,
            PromptKind::Password {
                for_: "bob@h".into(),
            },
            &CancellationToken::new(),
        )
        .await
    });
    s.handle_core(rx.recv().await.unwrap());
    s.handle_key(key(KeyCode::Esc));
    assert!(matches!(
        asker.await.unwrap(),
        Err(courier_ftp_core::Error::Cancelled)
    ));
}

#[test]
fn spinner_animates_while_a_listing_is_pending() {
    let mut s = screen(Layout::Classic);
    s.local.busy = true;
    let first = text(&render(&mut s, 120, 40));
    assert!(first.contains('⠋'), "{first}");
    s.update(&Action::Tick);
    let second = text(&render(&mut s, 120, 40));
    assert!(second.contains('⠙') && !second.contains('⠋'), "{second}");
    s.update(&Action::ListingLoaded {
        side: Side::Local,
        result: Err("permission denied".into()),
    });
    let done = text(&render(&mut s, 120, 40));
    assert!(
        !done.contains('⠙') && done.contains("permission denied"),
        "{done}"
    );
}

#[test]
fn status_indicators_follow_actions() {
    let mut s = screen(Layout::Classic);
    let before = text(&render(&mut s, 200, 40));
    assert!(
        before.contains("⇅ limit off") && before.contains("Auto"),
        "{before}"
    );
    s.update(&Action::ToggleSpeedLimit);
    s.update(&Action::CycleTransferType);
    // Comparison needs a directory on both sides.
    s.update(&loaded(Side::Local, "/l", vec![]));
    s.update(&loaded(Side::Remote, "/r", vec![]));
    s.update(&Action::ToggleCompare);
    let after = text(&render(&mut s, 200, 40));
    assert!(after.contains("⇅ limit ↓∞ ↑∞"), "{after}");
    assert!(
        after.contains("ASCII") && after.contains("≠ compare"),
        "{after}"
    );
    assert!(
        after.contains("Speed limit on"),
        "the toggle flashes a message: {after}"
    );
    s.update(&Action::ServerInfo);
    assert!(text(&render(&mut s, 200, 40)).contains("Not connected."));
}

// --- T69: trust prompts and the prompt queue ---

fn host_key_prompt(host: &str) -> PromptKind {
    PromptKind::TrustHostKey {
        host: host.into(),
        key: HostKeyFingerprint {
            algorithm: "ssh-ed25519".into(),
            bits: Some(256),
            sha256: "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s".into(),
            md5: None,
        },
        known: None,
        can_remember: true,
    }
}

/// Ask `kind` from a background task; the event is handed to the screen.
async fn ask(
    s: &mut MainScreen,
    kind: PromptKind,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<courier_ftp_core::Result<PromptResponse>> {
    let (tx, mut rx) = events::channel(2);
    let asker = tokio::spawn(async move { tx.ask(Some(SessionId(1)), kind, &cancel).await });
    s.handle_core(rx.recv().await.unwrap());
    asker
}

fn trust(r: courier_ftp_core::Result<PromptResponse>) -> TrustDecision {
    match r {
        Ok(PromptResponse::Trust(d)) => d,
        other => panic!("not a trust answer: {other:?}"),
    }
}

#[tokio::test]
async fn host_key_prompt_opens_and_answers() {
    let mut s = screen(Layout::Classic);
    let asker = ask(
        &mut s,
        host_key_prompt("a.example:22"),
        CancellationToken::new(),
    )
    .await;
    assert!(s.has_modal());
    let t = text(&render(&mut s, 120, 40));
    assert!(
        t.contains("Unknown host key") && t.contains("a.example:22"),
        "{t}"
    );
    s.handle_key(key(KeyCode::Enter));
    assert_eq!(trust(asker.await.unwrap()), TrustDecision::Always);
}

#[tokio::test]
async fn concurrent_prompts_queue_one_at_a_time() {
    let mut s = screen(Layout::Classic);
    let first = ask(
        &mut s,
        host_key_prompt("a.example:22"),
        CancellationToken::new(),
    )
    .await;
    let second = ask(
        &mut s,
        host_key_prompt("b.example:22"),
        CancellationToken::new(),
    )
    .await;
    let third = ask(
        &mut s,
        host_key_prompt("c.example:22"),
        CancellationToken::new(),
    )
    .await;
    assert_eq!(s.queued_prompts(), 2);
    let t = text(&render(&mut s, 200, 40));
    assert!(
        t.contains("a.example:22") && !t.contains("b.example"),
        "{t}"
    );
    assert!(t.contains("⚠ 2 prompts"), "{t}");

    // Answering doesn't open the next one under the user's fingers…
    s.handle_key(key(KeyCode::Esc));
    assert_eq!(trust(first.await.unwrap()), TrustDecision::Reject);
    assert!(!s.has_modal());
    s.update(&Action::Tick);
    assert!(!s.has_modal(), "the user just pressed a key");
    // …only once they are idle.
    s.set_last_key(None);
    s.update(&Action::Tick);
    assert!(s.has_modal());
    let t = text(&render(&mut s, 200, 40));
    assert!(
        t.contains("b.example:22") && t.contains("⚠ 1 prompt"),
        "{t}"
    );
    s.handle_key(alt('o'));
    assert_eq!(trust(second.await.unwrap()), TrustDecision::Always);

    // `<Ctrl-x><p>` opens the next one right away.
    s.update(&Action::OpenPrompt);
    assert!(s.has_modal());
    assert!(text(&render(&mut s, 200, 40)).contains("c.example:22"));
    s.handle_key(key(KeyCode::Esc));
    assert_eq!(trust(third.await.unwrap()), TrustDecision::Reject);
    assert_eq!(s.queued_prompts(), 0);
    assert!(!text(&render(&mut s, 200, 40)).contains("prompt"));
}

#[tokio::test]
async fn prompts_wait_while_the_user_types() {
    let mut s = screen(Layout::Classic);
    s.update(&Action::FocusQuickconnect);
    let asker = ask(
        &mut s,
        host_key_prompt("a.example:22"),
        CancellationToken::new(),
    )
    .await;
    s.update(&Action::Tick);
    assert!(!s.has_modal(), "a prompt must not steal text input");
    assert!(text(&render(&mut s, 200, 40)).contains("⚠ 1 prompt"));
    s.update(&Action::FocusLocal);
    s.update(&Action::Tick);
    assert!(s.has_modal());
    s.handle_key(key(KeyCode::Esc));
    assert_eq!(trust(asker.await.unwrap()), TrustDecision::Reject);
}

#[tokio::test]
async fn prompts_wait_for_an_open_dialog() {
    let mut s = screen(Layout::Classic);
    s.update(&Action::Help);
    let asker = ask(
        &mut s,
        host_key_prompt("a.example:22"),
        CancellationToken::new(),
    )
    .await;
    s.update(&Action::OpenPrompt);
    assert_eq!(s.queued_prompts(), 1, "never stacked over another dialog");
    s.handle_key(key(KeyCode::Esc)); // close help
    s.set_last_key(None);
    s.update(&Action::Tick);
    assert_eq!(s.queued_prompts(), 0);
    s.handle_key(key(KeyCode::Enter));
    assert_eq!(trust(asker.await.unwrap()), TrustDecision::Always);
}

#[tokio::test]
async fn cancelled_prompts_leave_the_queue_and_the_screen() {
    let mut s = screen(Layout::Classic);
    let cancel_a = CancellationToken::new();
    let cancel_b = CancellationToken::new();
    let a = ask(&mut s, host_key_prompt("a.example:22"), cancel_a.clone()).await;
    let b = ask(&mut s, host_key_prompt("b.example:22"), cancel_b.clone()).await;
    assert_eq!(s.queued_prompts(), 1);
    // The core gives up on both (connection cancelled).
    cancel_a.cancel();
    cancel_b.cancel();
    assert!(a.await.unwrap().is_err() && b.await.unwrap().is_err());
    s.update(&Action::Tick);
    assert_eq!(s.queued_prompts(), 0);
    render(&mut s, 120, 40);
    assert!(!s.has_modal(), "the open dialog closed itself");
}

#[test]
fn trees_are_off_by_default_and_load_only_when_shown() {
    let mut s = screen(Layout::Classic);
    s.update(&Action::ListingLoaded {
        side: Side::Local,
        result: Ok(Listing {
            dir: RemotePath::new("/srv/www"),
            entries: vec![Entry::dir("img")],
            fetched_at: std::time::Instant::now(),
            raw: None,
        }),
    });
    let t = render(&mut s, 120, 40);
    assert!(!text(&t).contains("Local tree"));
    assert!(s.take_actions().is_empty(), "a hidden tree lists nothing");

    // `T` focuses the tree of the focused side, showing the trees.
    s.update(&Action::FocusTree);
    assert_eq!(s.focus(), Region::LocalTree);
    assert_eq!(s.mode(), Mode::FileList);
    let t = render(&mut s, 120, 40);
    assert!(text(&t).contains("Local tree"), "{}", text(&t));
    let wanted: Vec<_> = s
        .take_actions()
        .into_iter()
        .filter_map(|a| match a {
            Action::TreeListDir { side, dir } => Some((side, dir.to_string())),
            _ => None,
        })
        .collect();
    // `/` is known from the first listing; `/srv/www` from the last.
    assert_eq!(wanted, vec![(Side::Local, "/srv".to_owned())]);

    s.update(&Action::TreeListingLoaded {
        side: Side::Local,
        dir: RemotePath::new("/srv"),
        result: Ok(Listing {
            dir: RemotePath::new("/srv"),
            entries: vec![Entry::dir("www"), Entry::dir("logs")],
            fetched_at: std::time::Instant::now(),
            raw: None,
        }),
    });
    let t = render(&mut s, 120, 40);
    assert!(text(&t).contains("▾ www"), "{}", text(&t));
    // Tree keys move the tree, not the list; Enter moves the list.
    s.update(&Action::ParentDir); // collapse www
    s.update(&Action::ParentDir); // up to /srv
    assert_eq!(s.handle_key(key(KeyCode::Enter)), KeyOutcome::Consumed);
    let actions = s.take_actions();
    assert!(
        actions.iter().any(|a| matches!(
            a,
            Action::ListDir { side: Side::Local, dir, .. } if dir.as_str() == "/srv"
        )),
        "{actions:?}"
    );
    s.update(&Action::FocusTree);
    assert_eq!(s.focus(), Region::LocalList);
    // Hiding the trees moves focus off them.
    s.update(&Action::FocusTree);
    s.update(&Action::ToggleTree);
    render(&mut s, 120, 40);
    assert_eq!(s.focus(), Region::LocalList);
}

// --- T66: directory comparison and synchronized browsing ---

fn loaded(side: Side, dir: &str, entries: Vec<Entry>) -> Action {
    Action::ListingLoaded {
        side,
        result: Ok(Listing {
            dir: RemotePath::new(dir),
            entries,
            fetched_at: std::time::Instant::now(),
            raw: None,
        }),
    }
}

fn file_at(name: &str, size: u64, minute: i64) -> Entry {
    let mut e = Entry::file(name, size);
    e.modified = Some(courier_ftp_core::model::Timestamp::new(
        time::macros::datetime!(2026-10-08 18:00 UTC) + time::Duration::minutes(minute),
        courier_ftp_core::model::Precision::Second,
    ));
    e
}

/// Local `/home/me/site` and remote `/var/www`: `img/` on both, `docs/`
/// local only, `cgi-bin/` remote only, `same.txt` identical, `big.css` of
/// different sizes, `new.html` newer locally, `only-local.txt`,
/// `only-remote.txt`.
fn comparing() -> MainScreen {
    let mut s = screen(Layout::Classic);
    s.update(&loaded(
        Side::Local,
        "/home/me/site",
        vec![
            Entry::dir("img"),
            Entry::dir("docs"),
            file_at("same.txt", 10, 0),
            file_at("big.css", 900, 0),
            file_at("new.html", 50, 30),
            file_at("only-local.txt", 1, 0),
        ],
    ));
    s.update(&loaded(
        Side::Remote,
        "/var/www",
        vec![
            Entry::dir("img"),
            Entry::dir("cgi-bin"),
            file_at("same.txt", 10, 0),
            file_at("big.css", 4096, 0),
            file_at("new.html", 50, 0),
            file_at("only-remote.txt", 2, 0),
        ],
    ));
    s.update(&Action::ToggleCompare);
    // Times in UTC, whatever the machine's zone.
    s.local.set_offset(time::UtcOffset::UTC);
    s.remote.set_offset(time::UtcOffset::UTC);
    s
}

fn list_dirs(actions: &[Action]) -> Vec<(Side, String)> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::ListDir { side, dir, .. } => Some((*side, dir.to_string())),
            _ => None,
        })
        .collect()
}

/// The screen line containing `needle`, and the columns of its matches.
fn find_cells(t: &Terminal<TestBackend>, needle: &str) -> (u16, Vec<u16>) {
    let buf = t.backend().buffer();
    for y in 0..buf.area.height {
        let cells: Vec<&str> = (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect();
        let line: String = cells.concat();
        if line.contains(needle) {
            let cols = line
                .match_indices(needle)
                .map(|(i, _)| line[..i].chars().count() as u16)
                .collect();
            return (y, cols);
        }
    }
    panic!("{needle} not on screen:\n{}", text(t));
}

#[test]
fn comparison_rows_are_aligned() {
    let mut s = comparing();
    let t = render(&mut s, 120, 30);
    let all = text(&t);
    assert!(all.contains("⇄ sync") && all.contains("≠ compare"), "{all}");
    assert!(!s.has_modal(), "same filters, no warning: {all}");
    insta::assert_snapshot!("compare_120x30", t.backend());
}

#[test]
fn comparison_rows_are_coloured() {
    use ratatui::style::Color;
    let mut config = Config::builtin();
    config.settings.interface.unicode_symbols = courier_ftp_core::settings::SymbolMode::Unicode;
    config.settings.logging.show_timestamps = false;
    let mut s = MainScreen::new(config, Theme::new(None, false));
    s.update(&loaded(
        Side::Local,
        "/l",
        vec![
            file_at("big.css", 1, 0),
            file_at("new.html", 5, 30),
            file_at("mine.txt", 1, 0),
        ],
    ));
    s.update(&loaded(
        Side::Remote,
        "/r",
        vec![
            file_at("big.css", 2, 0),
            file_at("new.html", 5, 0),
            file_at("yours.txt", 1, 0),
        ],
    ));
    s.update(&Action::ToggleCompare);
    // The cursor is on `..`, so no entry row has the cursor style.
    let t = render(&mut s, 120, 30);
    let buf = t.backend().buffer().clone();
    let fg = |needle: &str| {
        let (y, cols) = find_cells(&t, needle);
        cols.iter().map(|&x| buf[(x, y)].fg).collect::<Vec<_>>()
    };
    // Size mode: both sides of big.css red, one-side entries yellow, same
    // size plain.
    assert_eq!(fg("big.css"), [Color::Red, Color::Red]);
    assert_eq!(fg("mine.txt"), [Color::Yellow]);
    assert_eq!(fg("yours.txt"), [Color::Yellow]);
    assert_eq!(fg("new.html"), [Color::Reset, Color::Reset]);
    assert!(text(&t).contains("only here"), "legend: {}", text(&t));
    // Time mode: only the newer side is green.
    s.update(&Action::SetCompareOptions(Box::new(
        courier_ftp_core::compare::CompareOpts {
            mode: courier_ftp_core::compare::CompareMode::ModificationTime,
            ..courier_ftp_core::compare::CompareOpts::default()
        },
    )));
    let t = render(&mut s, 120, 30);
    let buf = t.backend().buffer().clone();
    let (y, cols) = find_cells(&t, "new.html");
    assert_eq!(buf[(cols[0], y)].fg, Color::Green, "local is newer");
    assert_eq!(buf[(cols[1], y)].fg, Color::Reset);
}

#[test]
fn hide_identical_drops_equal_files() {
    let mut s = comparing();
    let before = text(&render(&mut s, 120, 30));
    assert!(before.contains("same.txt"), "{before}");
    s.update(&Action::SetCompareOptions(Box::new(
        courier_ftp_core::compare::CompareOpts {
            hide_identical: true,
            ..courier_ftp_core::compare::CompareOpts::default()
        },
    )));
    let after = text(&render(&mut s, 120, 30));
    assert!(!after.contains("same.txt"), "{after}");
    assert!(
        after.contains("big.css") && after.contains("img/"),
        "{after}"
    );
}

#[test]
fn select_by_status_selects_on_the_focused_side() {
    let mut s = comparing();
    s.update(&Action::SelectCompareLonely);
    assert_eq!(s.local.selected_names(), ["docs", "only-local.txt"]);
    assert!(s.remote.selected_names().is_empty());
    s.update(&Action::FocusRemote);
    s.update(&Action::SelectCompareDifferent);
    assert_eq!(s.remote.selected_names(), ["big.css"]);
    // Newer needs time mode; in size mode nothing is green.
    s.update(&Action::SelectCompareNewer);
    assert_eq!(s.remote.selected_names(), ["big.css"]);
    s.update(&Action::ToggleCompare);
    s.update(&Action::SelectCompareLonely);
    assert_eq!(s.remote.selected_names(), ["big.css"], "comparison is off");
}

#[test]
fn cursors_move_in_lockstep_and_rows_rebuild() {
    let mut s = comparing();
    for _ in 0..3 {
        s.update(&Action::CursorDown);
    }
    assert_eq!(s.local.position().0, 3);
    assert_eq!(s.remote.position().0, 3);
    s.update(&Action::FocusRemote);
    s.update(&Action::CursorUp);
    assert_eq!(s.local.position().0, 2);
    // A new remote listing rebuilds the rows.
    s.update(&loaded(
        Side::Remote,
        "/var/www",
        vec![file_at("same.txt", 10, 0)],
    ));
    let t = text(&render(&mut s, 120, 30));
    assert!(t.contains("img/") && !t.contains("cgi-bin"), "{t}");
    // Turning comparison off restores the sorted view; sync stays on.
    s.update(&Action::ToggleCompare);
    let off = text(&render(&mut s, 120, 30));
    assert!(
        !off.contains("≠ compare") && off.contains("⇄ sync"),
        "{off}"
    );
}

#[test]
fn filters_differing_warns_once() {
    let mut s = screen(Layout::Classic);
    s.update(&loaded(Side::Local, "/l", vec![Entry::file(".env", 1)]));
    s.update(&loaded(Side::Remote, "/r", vec![Entry::file(".env", 1)]));
    // Hidden files are hidden locally by default and shown remotely.
    s.update(&Action::ToggleCompare);
    assert!(s.has_modal());
    s.update(&Action::CloseDialog);
    s.update(&loaded(Side::Remote, "/r", vec![Entry::file("x", 1)]));
    assert!(!s.has_modal(), "only once");
}

#[test]
fn sync_browsing_follows_enter_and_parent_both_ways() {
    let mut s = comparing();
    s.take_actions();
    // Rows: .., cgi-bin, docs, img, …
    for _ in 0..3 {
        s.update(&Action::CursorDown);
    }
    s.update(&Action::Open);
    // The other side goes first; this side waits for it.
    assert_eq!(
        list_dirs(&s.take_actions()),
        [(Side::Remote, "/var/www/img".to_owned())]
    );
    s.update(&loaded(Side::Remote, "/var/www/img", vec![]));
    assert_eq!(
        list_dirs(&s.take_actions()),
        [(Side::Local, "/home/me/site/img".to_owned())]
    );
    s.update(&loaded(Side::Local, "/home/me/site/img", vec![]));
    // Parent, from the remote side.
    s.update(&Action::FocusRemote);
    s.update(&Action::ParentDir);
    assert_eq!(
        list_dirs(&s.take_actions()),
        [(Side::Local, "/home/me/site".to_owned())]
    );
    s.update(&loaded(
        Side::Local,
        "/home/me/site",
        vec![Entry::dir("img")],
    ));
    assert_eq!(
        list_dirs(&s.take_actions()),
        [(Side::Remote, "/var/www".to_owned())]
    );
    let t = text(&render(&mut s, 120, 30));
    assert!(t.contains("⇄"), "{t}");
}

#[test]
fn missing_directory_asks_create_disable_or_stay() {
    let open_docs = |s: &mut MainScreen| {
        s.take_actions();
        s.update(&Action::FocusLocal);
        s.update(&Action::Top);
        for _ in 0..2 {
            s.update(&Action::CursorDown);
        }
        s.update(&Action::Open);
        assert_eq!(
            list_dirs(&s.take_actions()),
            [(Side::Remote, "/var/www/docs".to_owned())]
        );
        s.update(&Action::ListingLoaded {
            side: Side::Remote,
            result: Err("No such file".to_owned()),
        });
        assert!(s.has_modal());
        let t = text(&render(s, 120, 30));
        assert!(
            t.contains("Target directory does not exist on the other side")
                && t.contains("Create it"),
            "{t}"
        );
        s.update(&Action::CloseDialog);
    };

    // Stay: nothing changes.
    let mut s = comparing();
    open_docs(&mut s);
    s.update(&Action::SyncAnswer(SyncChoice::Stay));
    assert!(s.take_actions().is_empty());
    assert!(!s.local.busy);

    // Create it: mkdir, list it, then this side follows.
    open_docs(&mut s);
    s.update(&Action::SyncAnswer(SyncChoice::Create));
    let actions = s.take_actions();
    assert!(
        matches!(
            &actions[..],
            [Action::MakeDir { side: Side::Remote, dir }] if dir.as_str() == "/var/www/docs"
        ),
        "{actions:?}"
    );
    s.update(&Action::DirMade {
        side: Side::Remote,
        dir: RemotePath::new("/var/www/docs"),
        result: Ok(()),
    });
    assert_eq!(
        list_dirs(&s.take_actions()),
        [(Side::Remote, "/var/www/docs".to_owned())]
    );
    s.update(&loaded(Side::Remote, "/var/www/docs", vec![]));
    assert_eq!(
        list_dirs(&s.take_actions()),
        [(Side::Local, "/home/me/site/docs".to_owned())]
    );
    s.update(&loaded(Side::Local, "/home/me/site/docs", vec![]));
    s.update(&Action::ParentDir);
    s.take_actions();
    s.update(&loaded(
        Side::Remote,
        "/var/www",
        vec![Entry::dir("cgi-bin")],
    ));
    s.update(&loaded(
        Side::Local,
        "/home/me/site",
        vec![Entry::dir("docs"), Entry::dir("img")],
    ));
    s.take_actions();

    // Disable: this side goes alone.
    open_docs(&mut s);
    s.update(&Action::SyncAnswer(SyncChoice::Disable));
    assert_eq!(
        list_dirs(&s.take_actions()),
        [(Side::Local, "/home/me/site/docs".to_owned())]
    );
    let t = text(&render(&mut s, 120, 30));
    assert!(!t.contains("⇄ sync"), "{t}");
}

#[test]
fn leaving_the_base_asks_to_disable_sync() {
    let mut s = comparing();
    s.take_actions();
    s.update(&Action::ParentDir);
    assert!(s.has_modal());
    assert!(
        s.take_actions().is_empty(),
        "nothing moves before the answer"
    );
    s.update(&Action::CloseDialog);
    s.update(&Action::SyncAnswer(SyncChoice::Stay));
    assert!(s.take_actions().is_empty());
    assert!(!s.local.busy);
    s.update(&Action::ParentDir);
    s.update(&Action::CloseDialog);
    s.update(&Action::SyncAnswer(SyncChoice::Disable));
    assert_eq!(
        list_dirs(&s.take_actions()),
        [(Side::Local, "/home/me".to_owned())]
    );
    // Without sync, the panes move on their own.
    s.update(&loaded(Side::Local, "/home/me", vec![]));
    s.update(&Action::ParentDir);
    assert_eq!(
        list_dirs(&s.take_actions()),
        [(Side::Local, "/home".to_owned())]
    );
}

#[test]
fn sync_and_compare_need_both_sides() {
    let mut s = screen(Layout::Classic);
    s.update(&Action::ToggleSyncBrowsing);
    s.update(&Action::ToggleCompare);
    let t = text(&render(&mut s, 200, 40));
    assert!(!t.contains("⇄ sync") && !t.contains("≠ compare"), "{t}");
    // Site settings turn both on once connected.
    s.update(&loaded(Side::Local, "/l", vec![]));
    s.update(&loaded(Side::Remote, "/r", vec![]));
    s.connected_view(false, true, true);
    let t = text(&render(&mut s, 200, 40));
    assert!(t.contains("⇄ sync") && t.contains("≠ compare"), "{t}");
    // Disconnecting turns both off.
    s.remote_disconnected(None);
    let t = text(&render(&mut s, 200, 40));
    assert!(!t.contains("⇄ sync") && !t.contains("≠ compare"), "{t}");
}
