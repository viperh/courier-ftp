//! T62: file operations end to end through the app — dialogs answered with
//! synthetic keys, the work done against the core's `MockServer` (or a
//! temporary local directory), and the panes and directory trees kept
//! current from the patched listing cache.

use std::time::Duration;

use courier_ftp_core::{
    backend::{Backend, MockServer},
    model::{Protocol, RemotePath, ServerAddress},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use tokio_util::sync::CancellationToken;

use super::{
    transfer_tests::{app, connect, cursor_to, screen_text, show_local, until},
    *,
};

/// The transfer tests' server, reporting the address the app connects to
/// (`alice@mock.invalid`), so the operations patch the listings the panes
/// show.
fn server() -> MockServer {
    let mut address = ServerAddress::new(Protocol::Sftp, "mock.invalid");
    address.user = Some("alice".to_owned());
    super::transfer_tests::server().with_address(address)
}

fn press(app: &mut App, code: KeyCode, modifiers: KeyModifiers) {
    app.handle_key_event(KeyEvent::new(code, modifiers))
        .unwrap();
}

fn key(app: &mut App, code: KeyCode) {
    press(app, code, KeyModifiers::NONE);
}

fn type_text(app: &mut App, text: &str) {
    for c in text.chars() {
        key(app, KeyCode::Char(c));
    }
}

/// Replace the text of the focused input of the dialog and press Enter.
fn answer(app: &mut App, text: &str) {
    press(app, KeyCode::Char('u'), KeyModifiers::CONTROL);
    type_text(app, text);
    key(app, KeyCode::Enter);
}

fn names(app: &App, side: Side) -> Vec<String> {
    let pane = match side {
        Side::Local => &app.screen.local,
        Side::Remote => &app.screen.remote,
    };
    let mut names: Vec<String> = pane
        .visible_entries()
        .iter()
        .map(|e| e.name.clone())
        .collect();
    names.sort();
    names
}

fn shows(app: &App, side: Side, name: &str) -> bool {
    names(app, side).iter().any(|n| n == name)
}

async fn mode(server: &MockServer, path: &str) -> u32 {
    let mut b = server.backend();
    b.connect(CancellationToken::new()).await.unwrap();
    let e = b.stat(&RemotePath::new(path)).await.unwrap();
    e.permissions.and_then(|p| p.bits()).unwrap() & 0o777
}

async fn wait_modal(app: &mut App, what: &str) {
    until(app, what, |a| a.screen.has_modal()).await;
}

#[tokio::test]
async fn mkdir_creates_nested_directories_and_updates_list_and_tree() {
    let server = server();
    let mut app = app(&server);
    connect(&mut app, "sftp://alice:pw@mock.invalid/srv").await;
    app.dispatch(Action::ToggleTree).unwrap();
    let calls = server.calls();

    app.dispatch(Action::FocusRemote).unwrap();
    app.dispatch(Action::Mkdir).unwrap();
    let text = screen_text(&mut app, 120, 40);
    // FileZilla style: the current path and "New directory".
    assert!(text.contains("/srv/New directory"), "{text}");
    answer(&mut app, "fresh/deeper");
    until(&mut app, "created", |a| shows(a, Side::Remote, "fresh")).await;
    assert!(server.exists("/srv/fresh/deeper"));
    // The list was patched from the cache, not listed again: only the
    // mkdirs (the first one fails: no parent) and stats reached the server:
    // mkdir, stat /srv, stat /srv/fresh, mkdir, stat, stat
    // /srv/fresh/deeper, mkdir, stat (and one listing of the tree's
    // expanded path at most).
    let made = server.calls() - calls;
    assert!(made <= 9, "{made}");
    let text = screen_text(&mut app, 120, 40);
    assert!(
        text.contains("Created directory /srv/fresh/deeper"),
        "{text}"
    );
    // The directory tree shows the new directory as well.
    let tree_rows = text.lines().filter(|l| l.contains("fresh")).count();
    assert!(tree_rows >= 1, "{text}");

    // Shift-F7 enters it.
    app.dispatch(Action::MkdirEnter).unwrap();
    answer(&mut app, "inside");
    let inside = RemotePath::new("/srv/inside");
    until(&mut app, "entered", |a| {
        a.screen.remote.dir.as_ref() == Some(&inside) && !a.screen.remote.busy
    })
    .await;

    // An existing name fails with a message.
    app.dispatch(Action::Mkdir).unwrap();
    answer(&mut app, "/srv/logs");
    until(&mut app, "refused", |a| {
        a.screen
            .status_text()
            .contains("Could not create /srv/logs")
    })
    .await;
    app.transfers.shutdown().await;
}

#[tokio::test]
async fn rename_asks_before_overwriting_and_moves_with_slash() {
    let server = server();
    server.add_file("/srv/new.txt", b"new contents");
    let mut app = app(&server);
    connect(&mut app, "sftp://alice:pw@mock.invalid/srv").await;

    // F2 onto an existing file: asked first (SFTP would replace silently).
    cursor_to(&mut app, Side::Remote, "new.txt");
    app.dispatch(Action::Rename).unwrap();
    answer(&mut app, "readme.txt");
    wait_modal(&mut app, "overwrite question").await;
    let text = screen_text(&mut app, 120, 40);
    assert!(text.contains("/srv/readme.txt already exists"), "{text}");
    // "No" keeps both files.
    type_text(&mut app, "n");
    until(&mut app, "no", |a| !a.screen.has_modal()).await;
    assert_eq!(
        server.read_file("/srv/readme.txt").unwrap(),
        b"hello from the server"
    );
    // Again, "Yes" replaces.
    app.dispatch(Action::Rename).unwrap();
    answer(&mut app, "readme.txt");
    wait_modal(&mut app, "overwrite question").await;
    type_text(&mut app, "y");
    until(&mut app, "renamed", |a| !shows(a, Side::Remote, "new.txt")).await;
    assert_eq!(
        server.read_file("/srv/readme.txt").unwrap(),
        b"new contents"
    );
    assert_eq!(names(&app, Side::Remote), ["logs", "readme.txt"]);

    // A name with `/` moves it into another directory.
    cursor_to(&mut app, Side::Remote, "readme.txt");
    app.dispatch(Action::Rename).unwrap();
    answer(&mut app, "logs/moved.txt");
    until(&mut app, "moved", |a| !shows(a, Side::Remote, "readme.txt")).await;
    assert!(server.exists("/srv/logs/moved.txt"));
    assert_eq!(names(&app, Side::Remote), ["logs"]);

    // F6: move into a directory, same side.
    server.add_file("/srv/a.txt", b"a");
    server.add_dir("/srv/archive");
    app.dispatch(Action::Refresh).unwrap();
    until(&mut app, "refreshed", |a| shows(a, Side::Remote, "a.txt")).await;
    cursor_to(&mut app, Side::Remote, "a.txt");
    app.dispatch(Action::Move).unwrap();
    answer(&mut app, "archive");
    until(&mut app, "moved into", |a| !shows(a, Side::Remote, "a.txt")).await;
    assert!(server.exists("/srv/archive/a.txt"));
    app.transfers.shutdown().await;
}

#[tokio::test]
async fn recursive_delete_confirms_and_shows_progress() {
    let server = server();
    for i in 0..5 {
        server.add_file(&format!("/srv/logs/sub/{i}.log"), b"line");
    }
    let mut app = app(&server);
    connect(&mut app, "sftp://alice:pw@mock.invalid/srv").await;
    cursor_to(&mut app, Side::Remote, "logs");
    app.dispatch(Action::Delete).unwrap();
    let text = screen_text(&mut app, 120, 40);
    assert!(
        text.contains("Really delete 1 directory from the server?"),
        "{text}"
    );
    assert!(text.contains("logs/"), "{text}");
    // Slow enough to see the progress.
    server.set_latency(Duration::from_millis(150));
    type_text(&mut app, "y");
    until(&mut app, "progress", |a| {
        a.file_ops.progress.is_some() && a.screen.status_text().contains("Deleting")
    })
    .await;
    let text = screen_text(&mut app, 120, 40);
    assert!(text.contains("Deleting"), "{text}");
    until(&mut app, "deleted", |a| {
        a.file_ops.progress.is_none() && !shows(a, Side::Remote, "logs")
    })
    .await;
    server.set_latency(Duration::ZERO);
    assert!(!server.exists("/srv/logs"));
    assert!(
        app.screen
            .status_text()
            .contains("Deleted 5 files and 2 directories"),
        "{}",
        app.screen.status_text()
    );
    // The progress dialog closed (at the next draw).
    screen_text(&mut app, 120, 40);
    assert!(!app.screen.has_modal());
    app.transfers.shutdown().await;
}

#[tokio::test]
async fn delete_can_be_cancelled_from_the_progress_dialog() {
    let server = server();
    for i in 0..20 {
        server.add_file(&format!("/srv/logs/{i}.log"), b"line");
    }
    let mut app = app(&server);
    connect(&mut app, "sftp://alice:pw@mock.invalid/srv").await;
    cursor_to(&mut app, Side::Remote, "logs");
    app.settings.interface.confirm_delete = false;
    // Slow calls, so the loop sees idle moments while it runs.
    server.set_latency(Duration::from_millis(150));
    app.dispatch(Action::Delete).unwrap();
    until(&mut app, "running", |a| {
        a.screen.status_text().contains("Deleting")
    })
    .await;
    key(&mut app, KeyCode::Esc);
    until(&mut app, "stopped", |a| a.file_ops.progress.is_none()).await;
    server.set_latency(Duration::ZERO);
    assert!(app.screen.status_text().contains("(cancelled)"));
    // Something is left.
    assert!(server.exists("/srv/logs"));
    app.transfers.shutdown().await;
}

#[tokio::test]
async fn chmod_single_and_recursive_files_only() {
    let server = server();
    server.add_file("/srv/logs/a.log", b"a");
    server.add_file("/srv/logs/sub/b.log", b"b");
    let mut app = app(&server);
    connect(&mut app, "sftp://alice:pw@mock.invalid/srv").await;

    // One file: tick "Public write" off→on (row 3, column 2).
    cursor_to(&mut app, Side::Remote, "readme.txt");
    app.dispatch(Action::Chmod).unwrap();
    let text = screen_text(&mut app, 120, 40);
    assert!(text.contains("Numeric value:"), "{text}");
    assert!(text.contains("644"), "{text}");
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Right);
    key(&mut app, KeyCode::Char(' '));
    key(&mut app, KeyCode::Enter);
    until(&mut app, "chmod done", |a| {
        a.file_ops.progress.is_none() && a.screen.status_text().contains("Changed")
    })
    .await;
    assert_eq!(mode(&server, "/srv/readme.txt").await, 0o646);
    // The list shows the new mode from the patched cache.
    let entry = app
        .screen
        .remote
        .visible_entries()
        .into_iter()
        .find(|e| e.name == "readme.txt")
        .unwrap();
    assert_eq!(
        entry.permissions.as_ref().and_then(|p| p.bits()).unwrap() & 0o777,
        0o646
    );

    // A directory, recursively, files only, numeric 600.
    cursor_to(&mut app, Side::Remote, "logs");
    app.dispatch(Action::Chmod).unwrap();
    key(&mut app, KeyCode::Tab);
    for _ in 0..3 {
        key(&mut app, KeyCode::Backspace);
    }
    type_text(&mut app, "600");
    key(&mut app, KeyCode::Tab);
    key(&mut app, KeyCode::Char(' '));
    key(&mut app, KeyCode::Tab);
    key(&mut app, KeyCode::Right);
    let text = screen_text(&mut app, 120, 40);
    assert!(text.contains("[x] Recurse into subdirectories"), "{text}");
    key(&mut app, KeyCode::Enter);
    until(&mut app, "recursive chmod done", |a| {
        a.file_ops.progress.is_none() && a.screen.status_text().contains("Changed")
    })
    .await;
    assert_eq!(mode(&server, "/srv/logs/a.log").await, 0o600);
    assert_eq!(mode(&server, "/srv/logs/sub/b.log").await, 0o600);
    // Directories untouched.
    assert_eq!(mode(&server, "/srv/logs").await, 0o755);
    assert_eq!(mode(&server, "/srv/logs/sub").await, 0o755);
    app.transfers.shutdown().await;
}

#[tokio::test]
async fn local_operations_keep_the_list_current() {
    let server = server();
    let local = tempfile::tempdir().unwrap();
    std::fs::write(local.path().join("one.txt"), b"1").unwrap();
    std::fs::create_dir_all(local.path().join("tree/sub")).unwrap();
    std::fs::write(local.path().join("tree/sub/f"), b"f").unwrap();
    let mut app = app(&server);
    show_local(&mut app, local.path()).await;

    app.dispatch(Action::FocusLocal).unwrap();
    app.dispatch(Action::Mkdir).unwrap();
    answer(&mut app, "made");
    until(&mut app, "local mkdir", |a| shows(a, Side::Local, "made")).await;
    assert!(local.path().join("made").is_dir());

    cursor_to(&mut app, Side::Local, "one.txt");
    app.dispatch(Action::Rename).unwrap();
    answer(&mut app, "two.txt");
    until(&mut app, "local rename", |a| {
        shows(a, Side::Local, "two.txt")
    })
    .await;
    assert!(local.path().join("two.txt").is_file());
    assert!(!shows(&app, Side::Local, "one.txt"));

    cursor_to(&mut app, Side::Local, "tree");
    app.dispatch(Action::Delete).unwrap();
    type_text(&mut app, "y");
    until(&mut app, "local delete", |a| !shows(a, Side::Local, "tree")).await;
    assert!(!local.path().join("tree").exists());
    app.transfers.shutdown().await;
}

#[tokio::test]
async fn operations_need_a_connection_and_a_list() {
    let server = server();
    let mut app = app(&server);
    app.dispatch(Action::FocusRemote).unwrap();
    app.dispatch(Action::Delete).unwrap();
    assert!(app.screen.status_text().contains("Not connected"));
    assert!(!app.screen.has_modal());
    app.dispatch(Action::FocusLog).unwrap();
    app.dispatch(Action::Rename).unwrap();
    assert!(
        app.screen
            .status_text()
            .contains("Select entries in a file list first")
    );
    app.transfers.shutdown().await;
}

#[tokio::test]
async fn new_file_is_created_empty() {
    let server = server();
    let mut app = app(&server);
    connect(&mut app, "sftp://alice:pw@mock.invalid/srv").await;
    app.dispatch(Action::FocusRemote).unwrap();
    app.dispatch(Action::NewFile).unwrap();
    answer(&mut app, "empty.txt");
    until(&mut app, "created", |a| shows(a, Side::Remote, "empty.txt")).await;
    assert_eq!(server.read_file("/srv/empty.txt").unwrap(), b"");
    // Not over an existing file.
    app.dispatch(Action::NewFile).unwrap();
    answer(&mut app, "readme.txt");
    until(&mut app, "refused", |a| {
        a.screen
            .status_text()
            .contains("Could not create /srv/readme.txt")
    })
    .await;
    assert_eq!(
        server.read_file("/srv/readme.txt").unwrap(),
        b"hello from the server"
    );

    // Locally too.
    let local = tempfile::tempdir().unwrap();
    show_local(&mut app, local.path()).await;
    app.dispatch(Action::FocusLocal).unwrap();
    app.dispatch(Action::NewFile).unwrap();
    answer(&mut app, "local.txt");
    until(&mut app, "local file", |a| {
        shows(a, Side::Local, "local.txt")
    })
    .await;
    assert_eq!(std::fs::read(local.path().join("local.txt")).unwrap(), b"");
    app.transfers.shutdown().await;
}

#[tokio::test]
async fn custom_command_goes_to_the_server_with_history() {
    let server = server();
    let mut app = app(&server);
    app.dispatch(Action::CommandLine).unwrap();
    assert!(app.screen.status_text().contains("Not connected"));
    connect(&mut app, "ftp://alice:pw@mock.invalid/srv").await;
    app.dispatch(Action::CommandLine).unwrap();
    type_text(&mut app, "SITE WHO");
    key(&mut app, KeyCode::Enter);
    until(&mut app, "reply", |a| {
        a.screen.status_text() == "200 SITE WHO"
    })
    .await;
    // Up brings it back.
    app.dispatch(Action::CommandLine).unwrap();
    key(&mut app, KeyCode::Up);
    let text = screen_text(&mut app, 120, 40);
    assert!(text.contains("Command: SITE WHO"), "{text}");
    key(&mut app, KeyCode::Esc);
    app.transfers.shutdown().await;
}

/// The next clipboard text the app asks for.
async fn clipboard(app: &mut App) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let action = tokio::time::timeout_at(deadline, app.action_rx.recv())
            .await
            .expect("no clipboard action")
            .unwrap();
        if let Action::CopyToClipboard(text) = action {
            return text;
        }
        app.dispatch(action).unwrap();
    }
}

#[tokio::test]
async fn copy_url_offers_port_and_password() {
    let server = server();
    let mut app = app(&server);
    connect(&mut app, "sftp://alice:s3cret@mock.invalid/srv").await;
    cursor_to(&mut app, Side::Remote, "readme.txt");
    app.dispatch(Action::CopyUrl).unwrap();
    let text = screen_text(&mut app, 120, 40);
    assert!(text.contains("Copy URL"), "{text}");
    assert!(text.contains("With the port and password"), "{text}");
    // The password is never drawn.
    assert!(!text.contains("s3cret"), "{text}");
    key(&mut app, KeyCode::Enter);
    assert_eq!(
        clipboard(&mut app).await,
        "sftp://alice@mock.invalid/srv/readme.txt"
    );
    app.dispatch(Action::CopyUrl).unwrap();
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Enter);
    assert_eq!(
        clipboard(&mut app).await,
        "sftp://alice:s3cret@mock.invalid:22/srv/readme.txt"
    );

    // Locally: the path.
    let local = tempfile::tempdir().unwrap();
    std::fs::write(local.path().join("x.txt"), b"x").unwrap();
    show_local(&mut app, local.path()).await;
    cursor_to(&mut app, Side::Local, "x.txt");
    app.dispatch(Action::CopyUrl).unwrap();
    assert_eq!(
        clipboard(&mut app).await,
        local.path().join("x.txt").display().to_string()
    );
    app.transfers.shutdown().await;
}
