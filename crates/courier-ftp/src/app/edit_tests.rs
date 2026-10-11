//! T63: viewing and editing end to end through the app, against the core's
//! `MockServer`, with shell one-liners standing in for the editor (Unix
//! only: they need `sh`).

#![cfg(unix)]

use std::path::{Path, PathBuf};

use courier_ftp_core::{
    backend::MockServer,
    edit::{EDIT_DIR, OpenKind},
    settings::FileAssociation,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;

use super::{
    edit::CopyState,
    transfer_tests::{app, connect, cursor_to, show_local, until},
    *,
};

const URL: &str = "sftp://alice:pw@mock.invalid/srv";

fn key(app: &mut App, code: KeyCode) {
    app.handle_key_event(KeyEvent::new(code, KeyModifiers::NONE))
        .unwrap();
}

/// An app editing with `command` for `*.txt` (`terminal`: in the
/// foreground), its copies under `root`.
fn editing_app(server: &MockServer, root: &Path, command: &str, terminal: bool) -> Box<App> {
    let mut app = app(server);
    app.edits.root = Some(root.to_path_buf());
    app.settings.editing.associations = vec![FileAssociation {
        pattern: "*.txt".into(),
        command: command.into(),
        terminal,
    }];
    app
}

fn copy_of(app: &App) -> PathBuf {
    app.edits.files[0].local.clone()
}

fn idle(app: &App) -> bool {
    app.edits
        .files
        .first()
        .is_some_and(|f| f.state == CopyState::Idle)
}

fn server_has(server: &MockServer, data: &[u8]) -> impl Fn(&App) -> bool {
    let server = server.clone();
    let data = data.to_vec();
    move |_| server.read_file("/srv/readme.txt").as_deref() == Some(&data[..])
}

/// The files in the copies' directory (recursively).
fn copies(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    walk(&root.join(EDIT_DIR), &mut out);
    out
}

#[tokio::test]
async fn terminal_editor_round_trip_uploads_after_yes() {
    let server = transfer_tests::server();
    let root = tempfile::tempdir().unwrap();
    let mut app = editing_app(
        &server,
        root.path(),
        r#"sh -c 'printf "edited by the test" > "$1"' editor"#,
        true,
    );
    connect(&mut app, URL).await;
    cursor_to(&mut app, Side::Remote, "readme.txt");
    app.dispatch(Action::Edit).unwrap();

    // Downloaded, edited in the "terminal", and the prompt is up.
    until(&mut app, "upload prompt", |a| {
        a.screen.has_modal()
            && a.edits
                .files
                .first()
                .is_some_and(|f| f.state == CopyState::Asking)
    })
    .await;
    let copy = copy_of(&app);
    assert!(copy.starts_with(root.path().join(EDIT_DIR)));
    assert_eq!(copy.file_name().unwrap(), "readme.txt");
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&copy).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    assert_eq!(std::fs::read(&copy).unwrap(), b"edited by the test");
    assert_eq!(
        server.read_file("/srv/readme.txt").as_deref(),
        Some(&b"hello from the server"[..]),
        "nothing uploaded before the answer"
    );
    let text = transfer_tests::screen_text(&mut app, 120, 40);
    assert!(text.contains("readme.txt has changed"), "{text}");

    key(&mut app, KeyCode::Enter); // Yes
    until(
        &mut app,
        "uploaded",
        server_has(&server, b"edited by the test"),
    )
    .await;
    until(&mut app, "idle", idle).await;
    assert!(!app.edits.files[0].is_dirty());
    assert_eq!(app.edit_quit_reason(), None);

    // Quitting deletes the copy.
    app.cleanup_edits();
    assert!(!copy.exists());
    assert_eq!(copies(root.path()), Vec::<PathBuf>::new());
}

#[tokio::test]
async fn gui_editor_save_prompts_and_a_server_change_is_a_conflict() {
    let server = transfer_tests::server();
    let root = tempfile::tempdir().unwrap();
    // Detached, saves a moment later (like an editor window).
    let mut app = editing_app(
        &server,
        root.path(),
        r#"sh -c 'sleep 0.3; printf "saved in the window" > "$1"' editor"#,
        false,
    );
    connect(&mut app, URL).await;
    cursor_to(&mut app, Side::Remote, "readme.txt");
    app.dispatch(Action::Edit).unwrap();
    until(&mut app, "downloaded", idle).await;
    // Someone changes the file on the server meanwhile.
    server.add_file("/srv/readme.txt", b"changed on the server meanwhile");

    until(&mut app, "upload prompt", |a| {
        a.screen.has_modal() && a.edits.files[0].state == CopyState::Asking
    })
    .await;
    key(&mut app, KeyCode::Enter); // Yes
    until(&mut app, "conflict warning", |a| {
        a.screen.has_modal() && a.edits.files[0].state == CopyState::Idle
    })
    .await;
    let text = transfer_tests::screen_text(&mut app, 120, 40);
    assert!(text.contains("changed on the server"), "{text}");
    assert_eq!(
        server.read_file("/srv/readme.txt").as_deref(),
        Some(&b"changed on the server meanwhile"[..])
    );
    assert!(app.edits.files[0].is_dirty());

    key(&mut app, KeyCode::Char('o')); // Overwrite
    until(
        &mut app,
        "overwritten",
        server_has(&server, b"saved in the window"),
    )
    .await;
    until(&mut app, "idle", idle).await;
    assert!(!app.edits.files[0].is_dirty());
}

#[tokio::test]
async fn always_uploads_later_saves_without_asking() {
    let server = transfer_tests::server();
    let root = tempfile::tempdir().unwrap();
    let mut app = editing_app(
        &server,
        root.path(),
        r#"sh -c 'printf "first save" > "$1"' editor"#,
        true,
    );
    connect(&mut app, URL).await;
    cursor_to(&mut app, Side::Remote, "readme.txt");
    app.dispatch(Action::Edit).unwrap();
    until(&mut app, "upload prompt", |a| a.screen.has_modal()).await;
    key(&mut app, KeyCode::Char('a')); // Always for this file
    until(&mut app, "first upload", server_has(&server, b"first save")).await;
    until(&mut app, "idle", idle).await;

    std::fs::write(copy_of(&app), b"second save, longer").unwrap();
    until(
        &mut app,
        "second upload",
        server_has(&server, b"second save, longer"),
    )
    .await;
    assert!(!app.screen.has_modal(), "not asked again");
}

#[tokio::test]
async fn no_keeps_the_change_then_discard_and_quit_warning() {
    let server = transfer_tests::server();
    let root = tempfile::tempdir().unwrap();
    let mut app = editing_app(
        &server,
        root.path(),
        r#"sh -c 'printf "not wanted" > "$1"' editor"#,
        true,
    );
    connect(&mut app, URL).await;
    cursor_to(&mut app, Side::Remote, "readme.txt");
    app.dispatch(Action::Edit).unwrap();
    until(&mut app, "upload prompt", |a| a.screen.has_modal()).await;
    key(&mut app, KeyCode::Char('n')); // No
    until(&mut app, "idle", |a| idle(a) && !a.screen.has_modal()).await;
    assert!(app.edits.files[0].is_dirty());
    let reason = app.edit_quit_reason().unwrap();
    assert!(reason.contains("1 edited file has changes"), "{reason}");

    // Files being edited → the file → Discard.
    let copy = copy_of(&app);
    app.dispatch(Action::EditedFiles).unwrap();
    let text = transfer_tests::screen_text(&mut app, 120, 40);
    assert!(text.contains("Files being edited"), "{text}");
    assert!(text.contains("changed, not uploaded"), "{text}");
    key(&mut app, KeyCode::Enter);
    until(&mut app, "file menu", |a| a.screen.has_modal()).await;
    key(&mut app, KeyCode::Char('d'));
    until(&mut app, "discarded", |a| a.edits.files.is_empty()).await;
    assert!(!copy.exists());
    assert_eq!(app.edit_quit_reason(), None);
    assert_eq!(
        server.read_file("/srv/readme.txt").as_deref(),
        Some(&b"hello from the server"[..])
    );
}

#[tokio::test]
async fn copies_with_changes_not_uploaded_are_kept_at_exit() {
    let server = transfer_tests::server();
    let root = tempfile::tempdir().unwrap();
    let mut app = editing_app(&server, root.path(), "true", true);
    connect(&mut app, URL).await;
    cursor_to(&mut app, Side::Remote, "readme.txt");
    app.dispatch(Action::Edit).unwrap();
    until(&mut app, "downloaded", idle).await;
    let copy = copy_of(&app);
    std::fs::write(&copy, b"unsaved work").unwrap();
    app.edits.files[0].tracker.as_mut().unwrap().poll(&copy);
    app.cleanup_edits();
    assert_eq!(copies(root.path()), vec![copy]);
}

#[tokio::test]
async fn view_runs_the_viewer_on_a_copy_and_deletes_it() {
    let server = transfer_tests::server();
    let root = tempfile::tempdir().unwrap();
    let seen = root.path().join("seen-by-viewer");
    let mut app = editing_app(
        &server,
        root.path(),
        &format!("sh -c 'cp \"$1\" \"$0\"' '{}'", seen.display()),
        true,
    );
    connect(&mut app, URL).await;
    cursor_to(&mut app, Side::Remote, "readme.txt");
    app.dispatch(Action::View).unwrap();
    until(&mut app, "viewed", |_| seen.exists()).await;
    until(&mut app, "copy deleted", |a| {
        a.edits.files.is_empty() && copies(root.path()).is_empty()
    })
    .await;
    assert_eq!(std::fs::read(&seen).unwrap(), b"hello from the server");
    // Views aren't watched or listed.
    app.dispatch(Action::EditedFiles).unwrap();
    assert!(!app.screen.has_modal());
}

#[tokio::test]
async fn local_files_open_in_place() {
    let server = transfer_tests::server();
    let root = tempfile::tempdir().unwrap();
    let local = tempfile::tempdir().unwrap();
    std::fs::write(local.path().join("notes.txt"), b"before").unwrap();
    let mut app = editing_app(
        &server,
        root.path(),
        r#"sh -c 'printf "after" > "$1"' editor"#,
        true,
    );
    show_local(&mut app, local.path()).await;
    cursor_to(&mut app, Side::Local, "notes.txt");
    app.dispatch(Action::Edit).unwrap();
    until(&mut app, "edited in place", |_| {
        std::fs::read(local.path().join("notes.txt")).unwrap() == b"after"
    })
    .await;
    assert!(app.edits.files.is_empty(), "no copy, nothing to upload");
    assert!(!root.path().join(EDIT_DIR).exists());
}

#[tokio::test]
async fn large_files_ask_before_downloading() {
    let server = transfer_tests::server();
    server.add_file("/srv/big.txt", &vec![b'x'; 2 * 1024 * 1024]);
    let root = tempfile::tempdir().unwrap();
    let mut app = editing_app(&server, root.path(), "true", true);
    app.settings.editing.max_size_mib = 1;
    connect(&mut app, URL).await;
    cursor_to(&mut app, Side::Remote, "big.txt");
    app.dispatch(Action::Edit).unwrap();
    let text = transfer_tests::screen_text(&mut app, 120, 40);
    assert!(text.contains("big.txt is 2 MiB"), "{text}");
    key(&mut app, KeyCode::Char('n'));
    until(&mut app, "closed", |a| !a.screen.has_modal()).await;
    assert!(app.edits.files.is_empty());

    app.dispatch(Action::Edit).unwrap();
    key(&mut app, KeyCode::Char('y'));
    until(&mut app, "downloaded", idle).await;
    assert_eq!(
        std::fs::metadata(copy_of(&app)).unwrap().len(),
        2 * 1024 * 1024
    );
}

#[tokio::test]
async fn search_results_open_with_f3_and_f4() {
    let server = transfer_tests::server();
    let root = tempfile::tempdir().unwrap();
    let mut app = editing_app(&server, root.path(), "true", true);
    connect(&mut app, URL).await;
    let info = app.remote.as_ref().unwrap().info.clone();
    let mut entry =
        courier_ftp_core::model::Entry::new("readme.txt", courier_ftp_core::model::EntryKind::File);
    entry.size = Some(21);
    let hit = courier_ftp_core::search::SearchHit {
        path: courier_ftp_core::model::RemotePath::new("/srv/readme.txt"),
        entry,
    };
    app.open_search_hit(OpenKind::Edit, Side::Remote, Some(&info), &hit);
    until(&mut app, "downloaded", idle).await;
    assert_eq!(
        std::fs::read(copy_of(&app)).unwrap(),
        b"hello from the server"
    );
}

#[tokio::test]
async fn stop_watching_deletes_a_clean_copy_and_keeps_a_changed_one() {
    let server = transfer_tests::server();
    let root = tempfile::tempdir().unwrap();
    let mut app = editing_app(&server, root.path(), "true", true);
    connect(&mut app, URL).await;
    cursor_to(&mut app, Side::Remote, "readme.txt");

    // Unchanged: Files being edited → Stop watching deletes the copy.
    app.dispatch(Action::Edit).unwrap();
    until(&mut app, "downloaded", idle).await;
    let clean = copy_of(&app);
    app.dispatch(Action::EditedFiles).unwrap();
    key(&mut app, KeyCode::Enter);
    until(&mut app, "file menu", |a| a.screen.has_modal()).await;
    key(&mut app, KeyCode::Char('s'));
    until(&mut app, "stopped", |a| a.edits.files.is_empty()).await;
    assert!(!clean.exists());

    // Changed: "Stop watching" in the prompt keeps the copy, also at exit.
    app.dispatch(Action::Edit).unwrap();
    until(&mut app, "downloaded again", idle).await;
    let changed = copy_of(&app);
    std::fs::write(&changed, b"work in progress").unwrap();
    until(&mut app, "upload prompt", |a| a.screen.has_modal()).await;
    key(&mut app, KeyCode::Char('s'));
    until(&mut app, "stopped", |a| a.edits.files.is_empty()).await;
    assert!(changed.exists());
    app.cleanup_edits();
    assert_eq!(copies(root.path()), vec![changed]);
    assert_eq!(
        server.read_file("/srv/readme.txt").as_deref(),
        Some(&b"hello from the server"[..])
    );
}
