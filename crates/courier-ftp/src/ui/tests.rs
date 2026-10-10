//! T50 tests: layouts as snapshots, focus cycling, key routing, the core
//! event bridge.

use courier_ftp_core::{
    backend::Listing,
    events::{self, CoreEvent, LogKind, PromptKind, PromptResponse, SessionId},
    model::{Entry, RemotePath},
    settings::Layout,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};
use tokio_util::sync::CancellationToken;

use super::{KeyOutcome, MainScreen, Region, Side, Theme};
use crate::{action::Action, app::Mode, config::Config};

fn screen(layout: Layout) -> MainScreen {
    let mut config = Config::builtin();
    config.settings.interface.layout = layout;
    // Independent of the locale of the machine running the tests.
    config.settings.interface.unicode_symbols = courier_ftp_core::settings::SymbolMode::Unicode;
    let mut s = MainScreen::new(config, Theme::new(None, true));
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
    let t = text(&render(&mut s, 120, 100));
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
