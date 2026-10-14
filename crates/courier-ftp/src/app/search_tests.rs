//! T65: the search view end to end against the core's `MockServer` and a
//! temporary local directory: streaming results, stopping a slow search,
//! downloading results with and without their directory structure,
//! deleting with confirmation, local search and "go to".

use std::{sync::Arc, time::Duration};

use courier_ftp_core::{
    backend::MockServer,
    local::local_to_remote,
    queue::{QueueList, lock_queue},
    settings::SymbolMode,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;

use super::*;
use crate::ui::file_list_effect::Effect;

fn server() -> MockServer {
    let server = MockServer::new();
    server.add_file("/srv/a/report.txt", b"report a");
    server.add_file("/srv/b/report.txt", b"report b");
    server.add_file("/srv/b/deep/notes.txt", b"notes");
    server.add_file("/srv/b/image.png", b"png");
    server.add_dir("/srv/empty");
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
async fn until(app: &mut App, what: &str, done: impl Fn(&mut App) -> bool) {
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

fn key(app: &mut App, code: KeyCode) {
    app.handle_key_event(KeyEvent::new(code, KeyModifiers::NONE))
        .unwrap();
}

fn ctrl(app: &mut App, c: char) {
    app.handle_key_event(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL))
        .unwrap();
}

fn typed(app: &mut App, text: &str) {
    for c in text.chars() {
        key(app, KeyCode::Char(c));
    }
}

async fn connect(app: &mut App, url: &str) {
    app.dispatch(Action::FocusQuickconnect).unwrap();
    app.screen.handle_paste(url);
    key(app, KeyCode::Enter);
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

/// The paths of the results shown, in order.
fn results(app: &mut App) -> Vec<String> {
    app.screen
        .search_view_mut()
        .and_then(|v| v.results_mut())
        .map(|r| r.visible().iter().map(|h| h.path.to_string()).collect())
        .unwrap_or_default()
}

fn running(app: &mut App) -> bool {
    app.screen.search_view_mut().is_some_and(|v| v.is_running())
}

/// `Ctrl-f` from the focused pane, type a filename condition, Enter.
fn search_for(app: &mut App, text: &str) {
    app.dispatch(Action::Search).unwrap();
    assert!(app.screen.search_shown());
    assert_eq!(app.screen.mode(), Mode::Dialog);
    typed(app, text);
    key(app, KeyCode::Enter);
}

async fn search_done(app: &mut App) {
    until(app, "search finished", |a| {
        a.screen.search_view_mut().is_some() && !running(a)
    })
    .await;
}

/// Replace the text of the focused dialog field.
fn replace_text(app: &mut App, text: &str) {
    ctrl(app, 'e');
    ctrl(app, 'u');
    app.screen.handle_paste(text);
}

#[tokio::test]
async fn remote_search_finds_and_shows_results() {
    let server = server();
    let mut app = app(&server);
    connect(&mut app, "sftp://alice:pw@mock.invalid/srv").await;
    app.dispatch(Action::FocusRemote).unwrap();
    search_for(&mut app, ".txt");
    search_done(&mut app).await;
    let mut found = results(&mut app);
    found.sort();
    assert_eq!(
        found,
        [
            "/srv/a/report.txt",
            "/srv/b/deep/notes.txt",
            "/srv/b/report.txt"
        ]
    );
    // The browse session was left alone: the search used its own.
    assert!(server.connects() >= 2);
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(100, 30)).unwrap();
    terminal.draw(|f| app.screen.draw(f)).unwrap();
    let text = terminal.backend().to_string();
    assert!(text.contains("Search results: remote /srv"), "{text}");
    assert!(text.contains("3 found"), "{text}");
}

#[tokio::test]
async fn a_slow_search_streams_and_stops() {
    let server = MockServer::new();
    for d in 0..40 {
        server.add_file(&format!("/srv/d{d:02}/hit.txt"), b"x");
    }
    let mut app = app(&server);
    connect(&mut app, "sftp://alice:pw@mock.invalid/srv").await;
    server.set_latency(Duration::from_millis(100));
    app.dispatch(Action::FocusRemote).unwrap();
    search_for(&mut app, "hit");
    // Results arrive while the search still runs.
    until(&mut app, "first results", |a| {
        !results(a).is_empty() && running(a)
    })
    .await;
    key(&mut app, KeyCode::Esc);
    until(&mut app, "stopped", |a| !running(a)).await;
    let n = results(&mut app).len();
    assert!(n > 0 && n < 40, "{n} results");
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(100, 30)).unwrap();
    terminal.draw(|f| app.screen.draw(f)).unwrap();
    assert!(terminal.backend().to_string().contains("· stopped"));
}

/// Search `.txt` remotely, select everything, `F5` into `target` with the
/// layout picked by `flatten`, and wait for the transfers.
async fn download_results(server: &MockServer, target: &std::path::Path, flatten: bool) {
    let mut app = app(server);
    connect(&mut app, "sftp://alice:pw@mock.invalid/srv").await;
    show_local(&mut app, target).await;
    app.dispatch(Action::FocusRemote).unwrap();
    search_for(&mut app, ".txt");
    search_done(&mut app).await;
    key(&mut app, KeyCode::Char('a'));
    key(&mut app, KeyCode::F(5));
    until(&mut app, "transfer dialog", |a| a.screen.has_modal()).await;
    // The target defaults to the local pane's directory.
    replace_text(&mut app, &target.display().to_string());
    key(&mut app, KeyCode::Tab);
    if flatten {
        key(&mut app, KeyCode::Right);
    }
    key(&mut app, KeyCode::Enter);
    until(&mut app, "downloads done", |a| {
        lock_queue(&a.transfers.queue).count(QueueList::Successful) == 3
    })
    .await;
}

#[tokio::test]
async fn download_results_keeping_the_structure() {
    let server = server();
    let local = tempfile::tempdir().unwrap();
    download_results(&server, local.path(), false).await;
    let read = |p: &str| std::fs::read(local.path().join(p)).unwrap();
    assert_eq!(read("a/report.txt"), b"report a");
    assert_eq!(read("b/report.txt"), b"report b");
    assert_eq!(read("b/deep/notes.txt"), b"notes");
}

#[tokio::test]
async fn download_results_flattened() {
    let server = server();
    let local = tempfile::tempdir().unwrap();
    download_results(&server, local.path(), true).await;
    let mut names: Vec<String> = std::fs::read_dir(local.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["notes.txt", "report (2).txt", "report.txt"]);
}

#[tokio::test]
async fn delete_results_after_confirmation() {
    let server = server();
    let mut app = app(&server);
    connect(&mut app, "sftp://alice:pw@mock.invalid/srv").await;
    app.dispatch(Action::FocusRemote).unwrap();
    search_for(&mut app, "report");
    search_done(&mut app).await;
    assert_eq!(results(&mut app).len(), 2);
    key(&mut app, KeyCode::Char('a'));
    // No: nothing happens.
    key(&mut app, KeyCode::F(8));
    until(&mut app, "confirm", |a| a.screen.has_modal()).await;
    key(&mut app, KeyCode::Char('n'));
    assert!(!app.screen.has_modal());
    assert!(server.exists("/srv/a/report.txt"));
    // Yes: both deleted and gone from the results.
    key(&mut app, KeyCode::F(8));
    until(&mut app, "confirm", |a| a.screen.has_modal()).await;
    key(&mut app, KeyCode::Char('y'));
    until(&mut app, "deleted", |a| results(a).is_empty()).await;
    assert!(!server.exists("/srv/a/report.txt"));
    assert!(!server.exists("/srv/b/report.txt"));
    assert!(server.exists("/srv/b/deep/notes.txt"));
}

#[tokio::test]
async fn local_search_and_go_to() {
    let server = server();
    let local = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(local.path().join("x/y")).unwrap();
    std::fs::write(local.path().join("x/y/needle.txt"), b"n").unwrap();
    std::fs::write(local.path().join("x/hay.txt"), b"h").unwrap();
    std::fs::write(local.path().join("x/y/other.txt"), b"o").unwrap();
    let mut app = app(&server);
    show_local(&mut app, local.path()).await;
    app.dispatch(Action::FocusLocal).unwrap();
    search_for(&mut app, "needle");
    search_done(&mut app).await;
    let dir = local_to_remote(&local.path().join("x/y")).unwrap();
    assert_eq!(
        results(&mut app),
        [dir.join("needle.txt").unwrap().to_string()]
    );
    // Enter: the local pane shows x/y with the cursor on the result.
    key(&mut app, KeyCode::Enter);
    until(&mut app, "pane at the result", |a| {
        !a.screen.search_shown()
            && a.screen.local.dir.as_ref() == Some(&dir)
            && !a.screen.local.busy
    })
    .await;
    assert_eq!(
        app.screen.local.current().map(|e| e.name.as_str()),
        Some("needle.txt")
    );
    // Ctrl-f again shows the results.
    app.dispatch(Action::Search).unwrap();
    assert!(app.screen.search_shown());
    assert_eq!(results(&mut app).len(), 1);
}

#[tokio::test]
async fn remote_go_to_and_not_connected() {
    let server = server();
    let mut app = app(&server);
    // Remote search without a connection fails in the view.
    app.dispatch(Action::Search).unwrap();
    typed(&mut app, "notes");
    // Back to "Search in", switch it to Remote and type the directory.
    for _ in 0..7 {
        key(&mut app, KeyCode::BackTab);
    }
    key(&mut app, KeyCode::Right);
    key(&mut app, KeyCode::Tab);
    replace_text(&mut app, "/srv");
    key(&mut app, KeyCode::Enter);
    until(&mut app, "failed", |a| !running(a)).await;
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(100, 30)).unwrap();
    terminal.draw(|f| app.screen.draw(f)).unwrap();
    assert!(
        terminal.backend().to_string().contains("Not connected"),
        "{}",
        terminal.backend()
    );
    // Back to the form, then hide the view.
    key(&mut app, KeyCode::Esc);
    key(&mut app, KeyCode::Esc);
    assert!(!app.screen.search_shown());

    connect(&mut app, "sftp://alice:pw@mock.invalid/srv").await;
    app.dispatch(Action::FocusRemote).unwrap();
    // The form opens on the remote side with the query kept.
    app.dispatch(Action::Search).unwrap();
    key(&mut app, KeyCode::Enter);
    search_done(&mut app).await;
    assert_eq!(results(&mut app), ["/srv/b/deep/notes.txt"]);
    key(&mut app, KeyCode::Enter);
    until(&mut app, "remote pane at the result", |a| {
        a.screen
            .remote
            .dir
            .as_ref()
            .map(ToString::to_string)
            .as_deref()
            == Some("/srv/b/deep")
            && !a.screen.remote.busy
    })
    .await;
    assert_eq!(
        app.screen.remote.current().map(|e| e.name.as_str()),
        Some("notes.txt")
    );
}

#[tokio::test]
async fn upload_local_results_keeping_the_structure() {
    let server = server();
    let local = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(local.path().join("x/y")).unwrap();
    std::fs::write(local.path().join("x/y/needle.txt"), b"needle").unwrap();
    std::fs::write(local.path().join("x/hay.txt"), b"hay").unwrap();
    std::fs::write(local.path().join("x/y/skip.bin"), b"skip").unwrap();
    let mut app = app(&server);
    connect(&mut app, "sftp://alice:pw@mock.invalid/srv").await;
    show_local(&mut app, local.path()).await;
    app.dispatch(Action::FocusLocal).unwrap();
    search_for(&mut app, ".txt");
    search_done(&mut app).await;
    assert_eq!(results(&mut app).len(), 2);
    key(&mut app, KeyCode::Char('a'));
    key(&mut app, KeyCode::F(5));
    until(&mut app, "transfer dialog", |a| a.screen.has_modal()).await;
    // The target defaults to the remote pane's directory.
    ctrl(&mut app, 'e');
    app.screen.handle_paste("/up");
    key(&mut app, KeyCode::Enter);
    until(&mut app, "uploads done", |a| {
        lock_queue(&a.transfers.queue).count(QueueList::Successful) == 2
    })
    .await;
    assert_eq!(
        server.read_file("/srv/up/x/y/needle.txt").as_deref(),
        Some(&b"needle"[..])
    );
    assert_eq!(
        server.read_file("/srv/up/x/hay.txt").as_deref(),
        Some(&b"hay"[..])
    );
    assert!(!server.exists("/srv/up/x/y/skip.bin"));
}
