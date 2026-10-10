//! T58: connecting through the quickconnect bar, against the core's
//! `MockServer`: connect → list → navigate → disconnect, failures,
//! reconnect and replacing a connection.

use std::{sync::Arc, time::Duration};

use courier_ftp_core::{Error, backend::MockServer, model::LogonType, settings::SymbolMode};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};

use super::*;
use crate::ui::Region;

fn server() -> MockServer {
    let server = MockServer::new();
    server.add_file("/srv/www/index.html", b"<html>");
    server.add_dir("/srv/logs");
    server.add_file("/srv/readme.txt", b"hello");
    server
}

fn app(server: &MockServer) -> App {
    let mut config = Config::builtin();
    config.settings.interface.unicode_symbols = SymbolMode::Unicode;
    config.settings.logging.show_timestamps = false;
    config.settings.connection.keepalive = false;
    let mut app = App::with_backends(config, Arc::new(server.clone()), 4.0, 60.0);
    app.screen.remote.set_offset(time::UtcOffset::UTC);
    app
}

/// Run actions and core events until nothing happens for a moment.
async fn settle(app: &mut App) {
    loop {
        tokio::select! {
            Some(action) = app.action_rx.recv() => app.dispatch(action).unwrap(),
            Some(event) = app.events_rx.recv() => app.screen.handle_core(event),
            Some(msg) = app.vault_rx.recv() => app.vault_message(msg),
            () = tokio::time::sleep(Duration::from_millis(100)) => break,
        }
    }
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn screen_text(app: &mut App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|f| app.screen.draw(f)).unwrap();
    terminal.backend().to_string()
}

/// Type `url` into the quickconnect bar and press Enter.
async fn quickconnect(app: &mut App, url: &str) {
    app.dispatch(Action::FocusQuickconnect).unwrap();
    settle(app).await;
    // Clear what the host field holds from the last connection.
    for c in ['e', 'u'] {
        app.handle_key_event(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL))
            .unwrap();
    }
    app.screen.handle_paste(url);
    app.handle_key_event(key(KeyCode::Enter)).unwrap();
    settle(app).await;
}

fn remote_dir(app: &App) -> Option<String> {
    app.screen.remote.dir.as_ref().map(ToString::to_string)
}

async fn open(app: &mut App, name: &str) {
    for _ in 0..10 {
        if app.screen.remote.current().is_some_and(|e| e.name == name) {
            break;
        }
        app.dispatch(Action::CursorDown).unwrap();
    }
    assert_eq!(app.screen.remote.current().unwrap().name, name);
    app.dispatch(Action::Open).unwrap();
    settle(app).await;
}

#[tokio::test]
async fn connect_list_navigate_disconnect() {
    let server = server();
    let mut app = app(&server);
    quickconnect(&mut app, "sftp://alice:s3cret@mock.invalid/srv").await;

    assert_eq!(server.connects(), 1);
    assert!(app.remote.as_ref().is_some_and(|r| r.connected));
    assert_eq!(remote_dir(&app).as_deref(), Some("/srv"));
    // Focus moved off the text field so prompts can open.
    assert_eq!(app.screen.focus(), Region::RemoteList);
    let text = screen_text(&mut app, 120, 40);
    assert!(text.contains("Remote: alice@mock.invalid /srv"), "{text}");
    for name in ["www", "logs", "readme.txt"] {
        assert!(text.contains(name), "{name} missing:\n{text}");
    }
    assert!(!text.contains("s3cret"), "{text}");

    open(&mut app, "www").await;
    assert_eq!(remote_dir(&app).as_deref(), Some("/srv/www"));
    assert!(screen_text(&mut app, 120, 40).contains("index.html"));
    app.dispatch(Action::ParentDir).unwrap();
    settle(&mut app).await;
    assert_eq!(remote_dir(&app).as_deref(), Some("/srv"));

    // Refresh lists again from the server, not the cache.
    let calls = server.calls();
    app.dispatch(Action::Refresh).unwrap();
    settle(&mut app).await;
    assert!(server.calls() > calls);

    app.dispatch(Action::Disconnect).unwrap();
    settle(&mut app).await;
    assert!(app.remote.is_none());
    assert_eq!(remote_dir(&app), None);
    let text = screen_text(&mut app, 120, 40);
    assert!(text.contains("Remote: not connected"), "{text}");
    assert!(
        text.contains("Disconnected from alice@mock.invalid"),
        "{text}"
    );
}

#[tokio::test]
async fn failures_show_in_the_pane_and_reconnect_retries() {
    let server = server();
    server.fail_connect(Error::Auth("bad password".into()));
    let mut app = app(&server);
    quickconnect(&mut app, "sftp://alice:s3cret@mock.invalid").await;

    assert!(app.remote.is_none());
    let text = screen_text(&mut app, 120, 40);
    assert!(
        text.contains("⚠ authentication failed: bad password"),
        "{text}"
    );
    assert!(
        text.contains("Could not connect to alice@mock.invalid"),
        "{text}"
    );
    assert!(!text.contains("s3cret"), "{text}");

    // The reconnect history has no password: it is asked for again.
    let last = app.last_connect.clone().unwrap();
    assert_eq!(
        last.info.logon,
        LogonType::AskForPassword {
            user: "alice".into()
        }
    );
    app.dispatch(Action::Reconnect).unwrap();
    settle(&mut app).await;
    assert_eq!(server.connects(), 2);
    assert_eq!(remote_dir(&app).as_deref(), Some("/"));
    assert!(screen_text(&mut app, 120, 40).contains("srv"));
}

#[tokio::test]
async fn a_missing_start_directory_falls_back_to_home() {
    let server = server();
    let mut app = app(&server);
    quickconnect(&mut app, "sftp://alice@mock.invalid/nope").await;
    assert_eq!(remote_dir(&app).as_deref(), Some("/"));
    assert!(screen_text(&mut app, 120, 40).contains("/nope: not found"));
}

#[tokio::test]
async fn replacing_a_connection_asks_first() {
    let server = server();
    let mut app = app(&server);
    quickconnect(&mut app, "sftp://alice@mock.invalid").await;
    assert_eq!(server.connects(), 1);

    // No: the connection stays.
    quickconnect(&mut app, "sftp://bob@mock.invalid/srv").await;
    assert!(app.screen.has_modal());
    let text = screen_text(&mut app, 120, 40);
    assert!(
        text.contains("Disconnect from alice@mock.invalid and connect to")
            && text.contains("bob@mock.invalid?"),
        "{text}"
    );
    app.handle_key_event(key(KeyCode::Esc)).unwrap();
    settle(&mut app).await;
    assert_eq!(server.connects(), 1);
    assert_eq!(remote_dir(&app).as_deref(), Some("/"));

    // Yes: replaced.
    quickconnect(&mut app, "sftp://bob@mock.invalid/srv").await;
    assert!(app.screen.has_modal());
    app.handle_key_event(key(KeyCode::Enter)).unwrap();
    settle(&mut app).await;
    assert_eq!(server.connects(), 2);
    assert_eq!(remote_dir(&app).as_deref(), Some("/srv"));
    assert!(screen_text(&mut app, 120, 40).contains("Remote: bob@mock.invalid /srv"));
}

#[tokio::test]
async fn results_of_a_cancelled_attempt_are_dropped() {
    let server = server();
    let mut app = app(&server);
    app.dispatch(Action::FocusQuickconnect).unwrap();
    app.screen.handle_paste("sftp://alice@mock.invalid");
    app.handle_key_event(key(KeyCode::Enter)).unwrap();
    // Connect is queued; disconnect right after it starts.
    let connect = app.action_rx.recv().await.unwrap();
    assert!(matches!(connect, Action::Connect { .. }));
    app.dispatch(connect).unwrap();
    assert!(screen_text(&mut app, 120, 40).contains("connecting to alice@mock.invalid"));
    app.dispatch(Action::Disconnect).unwrap();
    settle(&mut app).await;
    assert!(app.remote.is_none());
    assert_eq!(remote_dir(&app), None);
}

#[tokio::test]
async fn bad_quickconnect_input_stays_in_the_bar() {
    let server = server();
    let mut app = app(&server);
    quickconnect(&mut app, "gopher://x").await;
    assert_eq!(server.connects(), 0);
    assert_eq!(app.screen.focus(), Region::Quickconnect);
    let text = screen_text(&mut app, 120, 40);
    assert!(text.contains("unknown protocol"), "{text}");
}

#[tokio::test]
async fn disconnect_and_reconnect_without_a_connection_say_so() {
    let server = server();
    let mut app = app(&server);
    app.dispatch(Action::Disconnect).unwrap();
    assert!(screen_text(&mut app, 120, 40).contains("Not connected"));
    app.dispatch(Action::Reconnect).unwrap();
    assert!(screen_text(&mut app, 120, 40).contains("No server to reconnect to"));
    assert_eq!(server.connects(), 0);
}

#[tokio::test]
async fn connected_screen_snapshot() {
    let server = server();
    let mut app = app(&server);
    quickconnect(&mut app, "sftp://alice:s3cret@mock.invalid:2222/srv").await;
    let text = screen_text(&mut app, 120, 30);
    // Log lines carry the session number, which depends on test order.
    let remote: String = text
        .lines()
        .skip(9)
        .take(9)
        .map(|l| l.chars().skip(60).collect::<String>() + "\n")
        .collect();
    insta::assert_snapshot!("connected_remote_pane", remote);
}
