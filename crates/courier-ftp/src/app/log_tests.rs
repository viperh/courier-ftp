//! T71 / T91 §4: what the app writes to its logs.
//!
//! A full session (connect, browse, errors, a failed connect, raw listing,
//! disconnect) with canary values as host, user, path and password, logged at
//! `trace` through the real file layer, with the session log on. Afterwards:
//! - no `INFO`/`WARN`/`ERROR` line of the application log names the host,
//!   user or paths (they may appear at `debug`);
//! - the password is in no file at all;
//! - the session log has the user-facing lines, hosts included.
//!
//! The files stay in `target/tmp/canary-tui-log/` for `scripts/canary-scan.sh`
//! (CI job `canary`), which is also run here on Linux.

use std::{path::PathBuf, sync::Arc, time::Duration};

use courier_ftp_core::{Error, backend::MockServer, settings::SymbolMode};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tracing_subscriber::prelude::*;

use super::*;
use crate::logging::{self, LogOptions};

const HOST: &str = "canary-host-tui-1.example";
// `scripts/canary-scan.sh` treats every other `canary-…` as a secret, and
// the session log may name users and paths, so these are checked here only.
const USER: &str = "tuiuser-7c1d";
const PASSWORD: &str = "CANARY-PW-tui-5b1e";
const DIR: &str = "/srv/tuipath-7c1d";

fn target_tmp() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    exe.ancestors().nth(3).unwrap().join("tmp")
}

async fn settle(app: &mut App) {
    loop {
        tokio::select! {
            Some(action) = app.action_rx.recv() => app.dispatch(action).unwrap(),
            Some(event) = app.events_rx.recv() => app.core_event(event),
            () = tokio::time::sleep(Duration::from_millis(100)) => break,
        }
    }
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

async fn quickconnect(app: &mut App, url: &str) {
    app.dispatch(Action::FocusQuickconnect).unwrap();
    settle(app).await;
    for c in ['e', 'u'] {
        app.handle_key_event(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL))
            .unwrap();
    }
    app.screen.handle_paste(url);
    app.handle_key_event(key(KeyCode::Enter)).unwrap();
    settle(app).await;
}

/// The level of each line of a log in the file layer's format; continuation
/// lines keep the level of the line they continue (as the scanner reads it).
fn levelled(text: &str) -> Vec<(String, &str)> {
    let mut level = String::new();
    text.lines()
        .map(|line| {
            let mut parts = line.split_whitespace();
            if let (Some(stamp), Some(lvl)) = (parts.next(), parts.next())
                && stamp.len() > 11
                && stamp.as_bytes()[10] == b'T'
                && ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"].contains(&lvl)
            {
                level = lvl.to_owned();
            }
            (level.clone(), line)
        })
        .collect()
}

#[tokio::test]
async fn info_and_above_never_name_hosts_users_or_paths() {
    let dir = target_tmp().join("canary-tui-log");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let writer = logging::writer(&dir).unwrap();
    let (filter, _) = logging::filter(LogOptions { debug: true }, Some("trace"));
    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(logging::file_layer(writer.clone()));
    // Spawned tasks run on this (current-thread) runtime's thread, so they log
    // here too.
    let guard = tracing::subscriber::set_default(subscriber);
    // With a single registered dispatcher, tracing caches callsite interest
    // from whichever thread hits a callsite first, so parallel tests without
    // a subscriber would switch these callsites off. A second (no-op)
    // dispatcher makes interest consider every live dispatcher.
    let second = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    tracing::callsite::rebuild_interest_cache();

    let server = MockServer::new();
    server.add_file(&format!("{DIR}/www/index.html"), b"<html>");
    server.add_file(&format!("{DIR}/readme.txt"), b"hello");
    let mut config = Config::builtin();
    config.settings.interface.unicode_symbols = SymbolMode::Unicode;
    config.settings.logging.show_timestamps = false;
    config.settings.logging.level = 4;
    config.settings.logging.show_raw_listing = true;
    config.settings.logging.log_to_file = true;
    config.settings.logging.log_file = Some(dir.join("session.log"));
    config.settings.connection.keepalive = false;
    let mut app = App::with_backends(config, Arc::new(server.clone()), 4.0, 60.0);

    // Connect, browse, a missing directory, an operation error.
    quickconnect(&mut app, &format!("sftp://{USER}:{PASSWORD}@{HOST}{DIR}")).await;
    assert!(app.remote.as_ref().is_some_and(|r| r.connected));
    app.dispatch(Action::FocusRemote).unwrap();
    app.dispatch(Action::ShowRawListing).unwrap();
    assert!(app.screen.has_modal(), "raw listing dialog opened");
    app.handle_key_event(key(KeyCode::Esc)).unwrap();
    app.dispatch(Action::ListDir {
        side: Side::Remote,
        dir: RemotePath::new(format!("{DIR}/missing")),
        force: true,
    })
    .unwrap();
    app.dispatch(Action::Error(format!(
        "{HOST}:{DIR}/readme.txt: permission denied"
    )))
    .unwrap();
    app.dispatch(Action::Refresh).unwrap();
    settle(&mut app).await;
    app.dispatch(Action::Disconnect).unwrap();
    settle(&mut app).await;

    // A failed connection.
    server.fail_connect(Error::Auth(format!("{USER} may not log in to {HOST}")));
    quickconnect(&mut app, &format!("sftp://{USER}:{PASSWORD}@{HOST}{DIR}")).await;
    assert!(app.remote.is_none());

    let session_log = app.diag.session_log().unwrap().clone();
    assert!(session_log.flush_timeout(Duration::from_secs(10)));
    assert!(writer.flush_timeout(Duration::from_secs(10)));
    drop(app);
    drop(guard);
    drop(second);

    let mut app_log = String::new();
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(entry.path()).unwrap();
        assert!(!text.contains(PASSWORD), "password in {name}:\n{text}");
        if name.starts_with("courier-ftp.") {
            app_log.push_str(&text);
        }
    }
    let lines = levelled(&app_log);
    for (level, line) in &lines {
        if ["INFO", "WARN", "ERROR"].contains(&level.as_str()) {
            for canary in [HOST, USER, DIR] {
                assert!(!line.contains(canary), "{canary} at {level}: {line}");
            }
        }
    }
    // Everything was captured (every action is logged at debug)…
    assert!(
        lines.iter().filter(|(l, _)| l == "DEBUG").count() >= 10,
        "{app_log}"
    );
    // …including the error call site above; its details went to debug.
    assert!(
        lines
            .iter()
            .any(|(level, l)| level == "DEBUG" && l.contains("permission denied")),
        "{app_log}"
    );

    // The session log is the user-facing record: hosts and paths belong there.
    let session = std::fs::read_to_string(dir.join("session.log")).unwrap();
    assert!(
        session.contains(&format!("Status: Disconnected from {USER}@{HOST}")),
        "{session}"
    );
    assert!(
        session.contains(&format!("Error: Could not connect to {USER}@{HOST}")),
        "{session}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("session.log"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(target_os = "linux")]
    {
        let script =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/canary-scan.sh");
        let out = std::process::Command::new("bash")
            .arg(&script)
            .arg("--require-files")
            .arg(&dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "canary scan failed:\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// `--debug-level` and the settings change the bus at runtime; 3+ includes
/// raw listings.
#[tokio::test]
async fn debug_level_applies_at_runtime() {
    let server = MockServer::new();
    let mut config = Config::builtin();
    config.settings.logging.level = 0;
    let mut app = App::with_backends(config, Arc::new(server), 4.0, 60.0);
    assert!(!app.events_tx.enabled(LogKind::Debug(1)));
    assert!(!app.events_tx.enabled(LogKind::ListingRaw));
    app.set_debug_level(3);
    assert!(app.events_tx.enabled(LogKind::Debug(3)));
    assert!(!app.events_tx.enabled(LogKind::Debug(4)));
    assert!(app.events_tx.enabled(LogKind::ListingRaw));
    app.set_debug_level(9);
    assert_eq!(app.settings.logging.level, 4);
}

/// "Show raw listing" for the local pane says why there is none; "Save log
/// as…" writes the filtered log to the chosen file.
#[tokio::test]
async fn raw_listing_and_save_log() {
    let dir = tempfile::tempdir().unwrap();
    let server = MockServer::new();
    let mut config = Config::builtin();
    config.settings.logging.show_timestamps = false;
    let mut app = App::with_backends(config, Arc::new(server), 4.0, 60.0);
    app.list(
        Side::Local,
        Some(RemotePath::new(dir.path().display().to_string())),
        false,
        false,
    );
    settle(&mut app).await;
    app.dispatch(Action::FocusLocal).unwrap();
    app.dispatch(Action::ShowRawListing).unwrap();
    assert!(!app.screen.has_modal());

    app.log_status("hello log");
    settle(&mut app).await;
    app.dispatch(Action::FocusLog).unwrap();
    app.dispatch(Action::SaveLog).unwrap();
    settle(&mut app).await;
    assert!(app.screen.has_modal(), "file name asked");
    // Replace the suggested name.
    for c in ['e', 'u'] {
        app.handle_key_event(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL))
            .unwrap();
    }
    let target = dir.path().join("saved.log");
    app.screen.handle_paste(&target.display().to_string());
    app.handle_key_event(key(KeyCode::Enter)).unwrap();
    for _ in 0..100 {
        settle(&mut app).await;
        if target.exists() {
            break;
        }
    }
    let saved = std::fs::read_to_string(&target).unwrap();
    assert!(saved.contains("Status:   hello log"), "{saved}");
}
