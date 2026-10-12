//! T45: the action after the queue finishes, end to end through the real
//! engine and the core's `MockServer`, with the terminal output and the
//! started commands recorded instead of carried out.

use std::{sync::Arc, time::Duration};

use courier_ftp_core::{
    backend::MockServer,
    queue::{QueueList, lock_queue},
    settings::{NotifyMethod, OnComplete},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;

use super::{
    transfer_tests::{app, connect, cursor_to, screen_text, show_local, until},
    *,
};
use crate::completion::testing::Recorder;

fn recorded(app: &mut App) -> Recorder {
    let recorder = Recorder {
        exit_code: Some(0),
        ..Recorder::default()
    };
    app.completion.effects = Arc::new(recorder.clone());
    app.completion.countdown = Duration::from_millis(300);
    recorder
}

fn key(app: &mut App, code: KeyCode) {
    app.handle_key_event(KeyEvent::new(code, KeyModifiers::NONE))
        .unwrap();
}

fn count(app: &App, list: QueueList) -> usize {
    lock_queue(&app.transfers.queue).count(list)
}

/// Run the app for `d` without a condition.
async fn run_for(app: &mut App, d: Duration) {
    let end = tokio::time::Instant::now() + d;
    until(app, "never", |_| tokio::time::Instant::now() >= end).await;
}

/// Connect and download `readme.txt` (`n` = how many have finished after
/// this one), waiting for the run to end.
async fn download(app: &mut App, n: usize) {
    cursor_to(app, Side::Remote, "readme.txt");
    app.dispatch(Action::Copy).unwrap();
    until(app, "download done", |a| {
        count(a, QueueList::Successful) == n && !a.transfers.processing()
    })
    .await;
}

async fn connected(server: &MockServer) -> (Box<App>, tempfile::TempDir) {
    let local = tempfile::tempdir().unwrap();
    let mut app = app(server);
    connect(&mut app, "sftp://alice:pw@mock.invalid/srv").await;
    show_local(&mut app, local.path()).await;
    (app, local)
}

#[tokio::test]
async fn show_message_notifies_and_the_oneshot_resets() {
    let server = super::transfer_tests::server();
    let (mut app, local) = connected(&server).await;
    app.settings.queue.notify = NotifyMethod::Osc;
    let rec = recorded(&mut app);

    // The menu sets a one-shot "show a message"; the queue pane says so.
    app.dispatch(Action::FocusQueue).unwrap();
    app.dispatch(Action::QueueAfterMenu).unwrap();
    assert!(screen_text(&mut app, 120, 40).contains("As in the settings (nothing)"));
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Enter);
    until(&mut app, "one-shot set", |a| {
        a.completion.state.oneshot() == Some(&OnComplete::ShowMessage)
    })
    .await;
    assert!(screen_text(&mut app, 120, 40).contains("then: show a message"));

    download(&mut app, 1).await;
    until(&mut app, "message", |a| a.screen.has_modal()).await;
    let text = screen_text(&mut app, 120, 40);
    assert!(
        text.contains("Queue finished: 1 file, 21 B transferred"),
        "{text}"
    );
    assert!(!text.contains("then: show a message"), "{text}");
    let terminal = rec.terminal.lock().unwrap().clone();
    assert_eq!(terminal.len(), 1);
    assert!(terminal[0].starts_with("\x1b]9;courier-ftp: Queue finished: 1 file"));
    key(&mut app, KeyCode::Enter);
    assert!(!app.screen.has_modal());

    // The override was used up: the setting ("nothing") applies again.
    std::fs::remove_file(local.path().join("readme.txt")).unwrap();
    download(&mut app, 2).await;
    run_for(&mut app, Duration::from_millis(300)).await;
    assert!(!app.screen.has_modal());
    assert_eq!(rec.terminal.lock().unwrap().len(), 1);
    app.transfers.shutdown().await;
}

#[tokio::test]
async fn run_command_gets_the_totals_without_a_shell() {
    let server = super::transfer_tests::server();
    let (mut app, _local) = connected(&server).await;
    app.settings.queue.on_complete =
        OnComplete::RunCommand(r#"notify-send "Queue done" $HOME;x"#.into());
    let rec = recorded(&mut app);
    download(&mut app, 1).await;
    until(&mut app, "command started", |_| {
        !rec.commands.lock().unwrap().is_empty()
    })
    .await;
    let (command, env) = rec.commands.lock().unwrap()[0].clone();
    assert_eq!(command.program, "notify-send");
    assert_eq!(command.args, ["Queue done", "$HOME;x"]);
    assert_eq!(
        env,
        [
            ("COURIER_FTP_FILES_OK", "1".to_owned()),
            ("COURIER_FTP_FILES_FAILED", "0".to_owned()),
            ("COURIER_FTP_BYTES", "21".to_owned()),
        ]
    );
    // The exit is logged.
    let mut logged = false;
    for _ in 0..100 {
        run_for(&mut app, Duration::from_millis(50)).await;
        if screen_text(&mut app, 160, 50).contains("exited successfully") {
            logged = true;
            break;
        }
    }
    assert!(logged);
    app.transfers.shutdown().await;
}

#[tokio::test]
async fn disconnect_after_the_countdown() {
    let server = super::transfer_tests::server();
    let (mut app, _local) = connected(&server).await;
    app.settings.queue.on_complete = OnComplete::Disconnect;
    recorded(&mut app);
    download(&mut app, 1).await;
    until(&mut app, "countdown shown", |a| a.screen.has_modal()).await;
    assert!(screen_text(&mut app, 120, 40).contains("Disconnecting in"));
    until(&mut app, "disconnected", |a| a.remote.is_none()).await;
    screen_text(&mut app, 120, 40);
    assert!(!app.screen.has_modal());
    app.transfers.shutdown().await;
}

#[tokio::test]
async fn close_app_can_be_cancelled_and_otherwise_quits() {
    let server = super::transfer_tests::server();
    let (mut app, local) = connected(&server).await;
    app.settings.queue.on_complete = OnComplete::CloseApp;
    recorded(&mut app);
    app.completion.countdown = Duration::from_secs(2);
    download(&mut app, 1).await;
    until(&mut app, "countdown shown", |a| a.screen.has_modal()).await;
    assert!(screen_text(&mut app, 120, 40).contains("Closing courier-ftp in"));
    key(&mut app, KeyCode::Esc);
    run_for(&mut app, Duration::from_millis(2500)).await;
    assert!(!app.should_quit);
    assert!(app.remote.is_some());

    // Next time nobody cancels.
    app.completion.countdown = Duration::from_millis(200);
    std::fs::remove_file(local.path().join("readme.txt")).unwrap();
    download(&mut app, 2).await;
    until(&mut app, "quit", |a| a.should_quit).await;
    app.transfers.shutdown().await;
}

#[tokio::test]
async fn stopping_the_queue_does_nothing() {
    let server = super::transfer_tests::server();
    server.add_file("/srv/big.bin", &vec![7u8; 400_000]);
    server.set_stream_pace(4096, Duration::from_millis(20));
    let (mut app, _local) = connected(&server).await;
    app.settings.queue.on_complete = OnComplete::ShowMessage;
    let rec = recorded(&mut app);
    cursor_to(&mut app, Side::Remote, "big.bin");
    app.dispatch(Action::Copy).unwrap();
    until(&mut app, "transfer running", |a| {
        a.transfers.engine.status().active > 0
    })
    .await;
    app.dispatch(Action::ProcessQueue).unwrap();
    until(&mut app, "stopped", |a| !a.transfers.processing()).await;
    run_for(&mut app, Duration::from_millis(500)).await;
    assert!(!app.screen.has_modal());
    assert!(rec.terminal.lock().unwrap().is_empty());
    assert_eq!(count(&app, QueueList::Queued), 1);
    app.transfers.shutdown().await;
}
