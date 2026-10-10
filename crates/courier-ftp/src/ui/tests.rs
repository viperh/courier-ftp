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

use super::{KeyOutcome, MainScreen, Region, Side, Theme};
use crate::{action::Action, app::Mode, config::Config};

fn screen(layout: Layout) -> MainScreen {
    let mut config = Config::builtin();
    config.settings.interface.layout = layout;
    // Independent of the locale of the machine running the tests.
    config.settings.interface.unicode_symbols = courier_ftp_core::settings::SymbolMode::Unicode;
    // Log lines carry the current time; leave it out of snapshots.
    config.settings.logging.show_timestamps = false;
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
