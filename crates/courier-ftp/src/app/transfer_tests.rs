//! T56: transfers end to end through the real engine, between a temporary
//! local directory and the core's `MockServer`: queueing from the file
//! lists, processing, the queue pane, listings refreshed afterwards, and the
//! quit warning.

use std::{sync::Arc, time::Duration};

use courier_ftp_core::{
    backend::MockServer,
    local::local_to_remote,
    queue::{QueueList, lock_queue},
    settings::SymbolMode,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};

use super::*;
use crate::ui::file_list_effect::Effect;

fn server() -> MockServer {
    let server = MockServer::new();
    server.add_file("/srv/readme.txt", b"hello from the server");
    server.add_dir("/srv/logs");
    server
}

fn app(server: &MockServer) -> Box<App> {
    let mut config = Config::builtin();
    config.settings.interface.unicode_symbols = SymbolMode::Unicode;
    config.settings.logging.show_timestamps = false;
    config.settings.connection.keepalive = false;
    Box::new(App::with_backends(
        config,
        Arc::new(server.clone()),
        4.0,
        60.0,
    ))
}

/// Run actions, core events and ticks until `done` holds (30 s cap).
async fn until(app: &mut App, what: &str, done: impl Fn(&App) -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        tokio::select! {
            Some(action) = app.action_rx.recv() => app.dispatch(action).unwrap(),
            Some(event) = app.events_rx.recv() => app.core_event(event),
            () = tokio::time::sleep(Duration::from_millis(50)) => {
                app.dispatch(Action::Tick).unwrap();
                if done(app) {
                    return;
                }
                assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
            }
        }
    }
}

fn screen_text(app: &mut App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|f| app.screen.draw(f)).unwrap();
    terminal.backend().to_string()
}

async fn connect(app: &mut App, url: &str) {
    app.dispatch(Action::FocusQuickconnect).unwrap();
    app.screen.handle_paste(url);
    app.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .unwrap();
    until(app, "connected", |a| {
        a.remote.as_ref().is_some_and(|r| r.connected) && !a.screen.remote.busy
    })
    .await;
}

async fn show_local(app: &mut App, dir: &std::path::Path) {
    let dir = local_to_remote(dir).unwrap();
    if let Some(Effect::Action(a)) = app.screen.local.go_to(dir.clone()) {
        app.dispatch(a).unwrap();
    }
    until(app, "local listing", |a| {
        a.screen.local.dir.as_ref() == Some(&dir) && !a.screen.local.busy
    })
    .await;
}

/// Move the cursor of `side`'s list onto `name`.
fn cursor_to(app: &mut App, side: Side, name: &str) {
    app.dispatch(match side {
        Side::Local => Action::FocusLocal,
        Side::Remote => Action::FocusRemote,
    })
    .unwrap();
    app.dispatch(Action::Top).unwrap();
    for _ in 0..20 {
        if app
            .screen
            .pane_mut(side)
            .current()
            .is_some_and(|e| e.name == name)
        {
            return;
        }
        app.dispatch(Action::CursorDown).unwrap();
    }
    panic!("{name} not in the {side:?} list");
}

fn count(app: &App, list: QueueList) -> usize {
    lock_queue(&app.transfers.queue).count(list)
}

#[tokio::test]
async fn upload_and_download_through_the_engine() {
    let server = server();
    let local = tempfile::tempdir().unwrap();
    std::fs::write(local.path().join("up.txt"), b"uploaded bytes").unwrap();
    let mut app = app(&server);
    connect(&mut app, "sftp://alice:s3cret@mock.invalid/srv").await;
    show_local(&mut app, local.path()).await;

    // F5 on a local file uploads it and starts the queue.
    cursor_to(&mut app, Side::Local, "up.txt");
    app.dispatch(Action::Copy).unwrap();
    until(&mut app, "upload done", |a| {
        count(a, QueueList::Successful) == 1
    })
    .await;
    assert_eq!(
        server.read_file("/srv/up.txt").as_deref(),
        Some(&b"uploaded bytes"[..])
    );
    // The remote listing was refreshed.
    until(&mut app, "remote list refreshed", |a| {
        a.screen
            .remote
            .visible_entries()
            .iter()
            .any(|e| e.name == "up.txt")
    })
    .await;

    // Shift-F5 on a remote file only queues it; Ctrl-p processes the queue.
    cursor_to(&mut app, Side::Remote, "readme.txt");
    app.dispatch(Action::QueueSelection).unwrap();
    until(&mut app, "queued", |a| count(a, QueueList::Queued) == 1).await;
    let text = screen_text(&mut app, 120, 40);
    assert!(text.contains("Queued files (1)"), "{text}");
    assert!(
        text.contains("sftp://alice@mock.invalid — 1 file"),
        "{text}"
    );
    assert!(!text.contains("s3cret"), "{text}");
    app.dispatch(Action::ProcessQueue).unwrap();
    until(&mut app, "download done", |a| {
        count(a, QueueList::Successful) == 2
    })
    .await;
    assert_eq!(
        std::fs::read(local.path().join("readme.txt")).unwrap(),
        b"hello from the server"
    );
    until(&mut app, "local list refreshed", |a| {
        a.screen
            .local
            .visible_entries()
            .iter()
            .any(|e| e.name == "readme.txt")
    })
    .await;
    let text = screen_text(&mut app, 120, 40);
    assert!(text.contains("Successful transfers (2)"), "{text}");
    assert!(
        text.contains("Queue finished: 1 file transferred"),
        "{text}"
    );
    app.transfers.shutdown().await;
}

#[tokio::test]
async fn directories_download_recursively_and_disconnected_panes_are_refused() {
    let server = server();
    let mut app = app(&server);
    app.dispatch(Action::FocusRemote).unwrap();
    app.dispatch(Action::Copy).unwrap();
    assert!(screen_text(&mut app, 120, 40).contains("Not connected"));

    connect(&mut app, "sftp://alice:pw@mock.invalid/srv").await;
    let local = tempfile::tempdir().unwrap();
    show_local(&mut app, local.path()).await;
    server.add_file("/srv/logs/sub/a.log", b"log line");
    cursor_to(&mut app, Side::Remote, "logs");
    app.dispatch(Action::Copy).unwrap();
    assert!(screen_text(&mut app, 160, 40).contains("Queued 1 directory"));
    // T43 expands the placeholder level by level.
    until(&mut app, "directory downloaded", |a| {
        count(a, QueueList::Queued) == 0 && !a.transfers.processing()
    })
    .await;
    assert_eq!(
        std::fs::read(local.path().join("logs/sub/a.log")).unwrap(),
        b"log line"
    );
    app.transfers.shutdown().await;
}

/// T67: filters changed in the dialog reach the engine's directory
/// expander at once (with "Apply filters to transfers" on, the default).
#[tokio::test]
async fn recursive_downloads_follow_filters_changed_at_runtime() {
    use courier_ftp_core::filters::{
        AppliesTo, Condition, Filter, FilterScope, MatchMode, StringOp,
    };

    let server = server();
    let mut app = app(&server);
    connect(&mut app, "sftp://alice:pw@mock.invalid/srv").await;
    let local = tempfile::tempdir().unwrap();
    show_local(&mut app, local.path()).await;
    server.add_file("/srv/logs/a.log", b"log line");
    server.add_file("/srv/logs/b.tmp", b"scratch");

    let mut filters = app.settings.filters.clone();
    filters.filters.push(Filter {
        name: "tmp".into(),
        applies_to: AppliesTo::Both,
        match_mode: MatchMode::All,
        case_sensitive: false,
        conditions: vec![Condition::Name {
            op: StringOp::EndsWith,
            value: ".tmp".into(),
        }],
        scope: FilterScope::Both,
    });
    let set = filters
        .sets
        .iter_mut()
        .find(|s| s.name == filters.active_set)
        .unwrap();
    set.enabled_remote.push("tmp".into());
    assert!(filters.apply_to_transfers);
    app.dispatch(Action::SetFilters(Box::new(filters))).unwrap();

    cursor_to(&mut app, Side::Remote, "logs");
    app.dispatch(Action::Copy).unwrap();
    until(&mut app, "directory downloaded", |a| {
        count(a, QueueList::Queued) == 0 && !a.transfers.processing()
    })
    .await;
    assert_eq!(
        std::fs::read(local.path().join("logs/a.log")).unwrap(),
        b"log line"
    );
    assert!(!local.path().join("logs/b.tmp").exists());
    app.transfers.shutdown().await;
}

#[tokio::test]
async fn failed_transfers_land_in_the_failed_tab() {
    let server = server();
    let local = tempfile::tempdir().unwrap();
    let mut app = app(&server);
    connect(&mut app, "sftp://alice:pw@mock.invalid/srv").await;
    show_local(&mut app, local.path()).await;
    cursor_to(&mut app, Side::Remote, "readme.txt");
    // The download's read fails for good.
    server.fail_next(courier_ftp_core::Error::PermissionDenied);
    app.dispatch(Action::Copy).unwrap();
    until(&mut app, "failed", |a| {
        count(a, QueueList::Failed) == 1 && !a.transfers.processing()
    })
    .await;
    app.dispatch(Action::QueueTabFailed).unwrap();
    let text = screen_text(&mut app, 120, 40);
    assert!(text.contains("Failed transfers (1)"), "{text}");
    assert!(text.contains("permission denied"), "{text}");

    // `r` in the failed tab requeues it; this time it works.
    app.dispatch(Action::FocusQueue).unwrap();
    app.dispatch(Action::Top).unwrap();
    app.dispatch(Action::CursorDown).unwrap();
    app.dispatch(Action::Requeue).unwrap();
    app.dispatch(Action::ProcessQueue).unwrap();
    until(&mut app, "requeued and done", |a| {
        count(a, QueueList::Successful) == 1
    })
    .await;
    app.transfers.shutdown().await;
}

#[tokio::test]
async fn quit_asks_when_queued_items_would_be_lost() {
    let server = server();
    let local = tempfile::tempdir().unwrap();
    let mut app = app(&server);
    // Nothing queued: quits at once.
    app.dispatch(Action::Quit).unwrap();
    until(&mut app, "quit", |a| a.should_quit).await;

    let mut app = self::app(&server);
    connect(&mut app, "sftp://alice:pw@mock.invalid/srv").await;
    show_local(&mut app, local.path()).await;
    cursor_to(&mut app, Side::Remote, "readme.txt");
    app.dispatch(Action::QueueSelection).unwrap();
    app.dispatch(Action::Quit).unwrap();
    until(&mut app, "quit dialog", |a| a.screen.has_modal()).await;
    assert!(!app.should_quit);
    let text = screen_text(&mut app, 120, 40);
    assert!(
        text.contains("1 queued or failed transfer will be lost"),
        "{text}"
    );
    // "Yes" quits.
    app.handle_key_event(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::ALT))
        .unwrap();
    until(&mut app, "quit after yes", |a| a.should_quit).await;
    app.transfers.shutdown().await;
}
