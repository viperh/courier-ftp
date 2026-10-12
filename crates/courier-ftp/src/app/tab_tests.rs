//! T61: connection tabs through the app, against the core's `MockServer`:
//! two tabs browsing independently, closing tabs, late results for
//! background and closed tabs, "disconnect" after the queue, duplicate and
//! rename, the tab bar, the per-tab log and restoring tabs from the vault
//! (real vault engine, cheap Argon2).

use std::{path::Path, sync::Arc, time::Duration};

use courier_ftp_core::{
    backend::MockServer,
    settings::{OnComplete, SymbolMode, TabConnect},
    vault::{DeviceBlobVault, MemKeyring},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};

use super::{
    vault_tests::{Rig, STRONG, opener},
    *,
};

fn server() -> MockServer {
    let server = MockServer::new();
    server.add_file("/srv/www/index.html", b"<html>");
    server.add_file("/srv/logs/access.log", b"GET /");
    server.add_file("/srv/readme.txt", b"hello");
    server
}

fn config() -> Config {
    let mut config = Config::builtin();
    config.settings.interface.unicode_symbols = SymbolMode::Unicode;
    config.settings.logging.show_timestamps = false;
    config.settings.connection.keepalive = false;
    // Connecting while connected opens a new tab without asking.
    config.settings.interface.connect_in_tab = TabConnect::NewTab;
    config
}

fn app(server: &MockServer) -> Box<App> {
    Box::new(App::with_backends(
        config(),
        Arc::new(server.clone()),
        4.0,
        60.0,
    ))
}

/// Run actions and core events until nothing happens for a moment.
async fn settle(app: &mut App) {
    loop {
        tokio::select! {
            Some(action) = app.action_rx.recv() => app.dispatch(action).unwrap(),
            Some(event) = app.events_rx.recv() => app.core_event(event),
            Some(msg) = app.vault_rx.recv() => app.vault_message(msg),
            () = tokio::time::sleep(Duration::from_millis(100)) => break,
        }
    }
}

/// Run until `done` holds (30 s cap).
async fn until(app: &mut App, what: &str, done: impl Fn(&App) -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !done(app) {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        settle(app).await;
    }
}

fn key(app: &mut App, code: KeyCode) {
    app.handle_key_event(KeyEvent::new(code, KeyModifiers::NONE))
        .unwrap();
}

fn screen_text(app: &mut App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|f| app.screen.draw(f)).unwrap();
    terminal.backend().to_string()
}

/// The tab bar's row (under the quickconnect bar).
fn tab_row(app: &mut App) -> String {
    screen_text(app, 100, 30)
        .lines()
        .nth(3)
        .unwrap_or_default()
        .trim_matches('"')
        .trim_end()
        .to_owned()
}

/// Type `url` into the quickconnect bar and press Enter.
async fn quickconnect(app: &mut App, url: &str) {
    app.dispatch(Action::FocusQuickconnect).unwrap();
    settle(app).await;
    for c in ['e', 'u'] {
        app.handle_key_event(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL))
            .unwrap();
    }
    app.screen.handle_paste(url);
    key(app, KeyCode::Enter);
    settle(app).await;
    until(app, "connected", connected).await;
}

fn connected(app: &App) -> bool {
    app.remote.as_ref().is_some_and(|r| r.connected)
}

fn remote_dir(app: &App) -> Option<String> {
    app.screen.remote.dir.as_ref().map(ToString::to_string)
}

/// Start like the event loop does: list the local home directory.
async fn started(app: &mut App) {
    app.list(Side::Local, None, false, false);
    until(app, "local listing", |a| a.screen.local.dir.is_some()).await;
}

async fn run(app: &mut App, action: Action) {
    app.dispatch(action).unwrap();
    settle(app).await;
}

/// Put the remote cursor on `name` and open it.
async fn open(app: &mut App, name: &str) {
    app.dispatch(Action::FocusRemote).unwrap();
    app.dispatch(Action::Top).unwrap();
    for _ in 0..10 {
        if app.screen.remote.current().is_some_and(|e| e.name == name) {
            break;
        }
        app.dispatch(Action::CursorDown).unwrap();
    }
    assert_eq!(app.screen.remote.current().unwrap().name, name);
    run(app, Action::Open).await;
}

/// Two connected tabs: alice on web.invalid in /srv/www (tab 1), bob on
/// backup.invalid in /srv/logs (tab 2, shown).
async fn two_tabs(server: &MockServer) -> Box<App> {
    let mut app = app(server);
    started(&mut app).await;
    quickconnect(&mut app, "sftp://alice@web.invalid/srv").await;
    open(&mut app, "www").await;
    assert_eq!(remote_dir(&app).as_deref(), Some("/srv/www"));
    quickconnect(&mut app, "sftp://bob@backup.invalid/srv/logs").await;
    assert_eq!(app.tabs.len(), 2);
    assert_eq!(app.tabs.active, 1);
    app
}

#[tokio::test]
async fn two_tabs_browse_independently() {
    let server = server();
    let mut app = two_tabs(&server).await;
    assert_eq!(server.connects(), 2);
    assert_eq!(server.open_connections(), 2);
    assert_eq!(remote_dir(&app).as_deref(), Some("/srv/logs"));
    assert_eq!(
        tab_row(&mut app),
        " [1 alice@web.invalid ●] [2 bob@backup.invalid ●]"
    );
    let text = screen_text(&mut app, 120, 40);
    assert!(text.contains("access.log"), "{text}");

    // Tab 2 has its own history.
    run(&mut app, Action::ParentDir).await;
    assert_eq!(remote_dir(&app).as_deref(), Some("/srv"));
    run(&mut app, Action::HistoryBack).await;
    assert_eq!(remote_dir(&app).as_deref(), Some("/srv/logs"));

    // Tab 1 is where it was, with its own connection and history.
    run(&mut app, Action::Tab1).await;
    assert_eq!(app.tabs.active, 0);
    assert_eq!(remote_dir(&app).as_deref(), Some("/srv/www"));
    assert_eq!(
        app.remote.as_ref().unwrap().info.address.host,
        "web.invalid"
    );
    let text = screen_text(&mut app, 120, 40);
    assert!(
        text.contains("Remote: alice@web.invalid /srv/www") && text.contains("index.html"),
        "{text}"
    );
    run(&mut app, Action::HistoryBack).await;
    assert_eq!(remote_dir(&app).as_deref(), Some("/srv"));

    // Next / previous wrap around.
    run(&mut app, Action::NextTab).await;
    assert_eq!(app.tabs.active, 1);
    assert_eq!(remote_dir(&app).as_deref(), Some("/srv/logs"));
    run(&mut app, Action::NextTab).await;
    assert_eq!(app.tabs.active, 0);
    run(&mut app, Action::PrevTab).await;
    assert_eq!(app.tabs.active, 1);
    run(&mut app, Action::Tab5).await;
    assert_eq!(app.tabs.active, 1);
    assert!(app.screen.status_text().contains("no tab 5"));
}

#[tokio::test]
async fn a_new_tab_starts_in_the_current_local_directory() {
    let server = server();
    let mut app = app(&server);
    started(&mut app).await;
    let local = app.screen.local.dir.clone();
    assert!(local.is_some());
    run(&mut app, Action::NewTab).await;
    assert_eq!(app.tabs.len(), 2);
    assert_eq!(app.screen.local.dir, local);
    assert!(app.remote.is_none());
    assert_eq!(tab_row(&mut app), " [1 local ○] [2 local ○]");
    // Not connected: connecting uses this tab, no question.
    app.settings.interface.connect_in_tab = TabConnect::Ask;
    quickconnect(&mut app, "sftp://alice@web.invalid/srv").await;
    assert_eq!(app.tabs.len(), 2);
    assert!(!app.screen.has_modal());
    assert_eq!(tab_row(&mut app), " [1 local ○] [2 alice@web.invalid ●]");
}

#[tokio::test]
async fn closing_a_connected_tab_disconnects_only_that_tab() {
    let server = server();
    let mut app = two_tabs(&server).await;
    let closed = app.remote.as_ref().unwrap().cancel.clone();

    // It asks first; No keeps the tab.
    run(&mut app, Action::CloseTab).await;
    assert!(app.screen.has_modal());
    assert!(screen_text(&mut app, 120, 40).contains("disconnect from bob@backup.invalid?"));
    key(&mut app, KeyCode::Char('n'));
    settle(&mut app).await;
    assert_eq!(app.tabs.len(), 2);

    run(&mut app, Action::CloseTab).await;
    key(&mut app, KeyCode::Enter);
    settle(&mut app).await;
    assert_eq!(app.tabs.len(), 1);
    assert!(closed.is_cancelled());
    until(&mut app, "one connection left", |_| {
        server.open_connections() == 1
    })
    .await;
    // Tab 1 is shown, still connected where it was.
    assert!(connected(&app));
    assert_eq!(remote_dir(&app).as_deref(), Some("/srv/www"));
    assert_eq!(tab_row(&mut app), " [1 alice@web.invalid ●]");

    // Closing the last tab leaves an empty one.
    run(&mut app, Action::CloseTab).await;
    key(&mut app, KeyCode::Enter);
    settle(&mut app).await;
    assert_eq!(app.tabs.len(), 1);
    assert!(app.remote.is_none());
    assert_eq!(remote_dir(&app), None);
    until(&mut app, "no connection left", |_| {
        server.open_connections() == 0
    })
    .await;
    assert_eq!(tab_row(&mut app), " [1 local ○]");
    assert!(app.screen.local.dir.is_some());
}

#[tokio::test]
async fn results_for_a_closed_tab_are_dropped() {
    let server = server();
    let mut app = app(&server);
    started(&mut app).await;
    quickconnect(&mut app, "sftp://alice@web.invalid/srv").await;
    let local = app.screen.local.dir.clone();

    // A connection still being opened when its tab closes.
    let mut request = app.last_connect.clone().unwrap();
    request.path = Some(RemotePath::new("/srv/logs"));
    server.set_latency(Duration::from_millis(300));
    run(&mut app, Action::NewTab).await;
    let tab = app.tabs.current_id();
    app.dispatch(Action::Connect {
        request: Box::new(request),
        target: ConnectTarget::Current,
    })
    .unwrap();
    // Run the connect without waiting for it.
    while let Ok(action) = app.action_rx.try_recv() {
        app.dispatch(action).unwrap();
    }
    let session = app.remote.as_ref().unwrap().session;
    run(&mut app, Action::CloseTabNow { tab }).await;
    assert_eq!(app.tabs.len(), 1);
    // A new local tab whose listing comes back after it closed.
    app.dispatch(Action::NewTab).unwrap();
    let tab = app.tabs.current_id();
    app.dispatch(Action::CloseTabNow { tab }).unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    settle(&mut app).await;

    assert_eq!(app.tabs.len(), 1);
    assert_eq!(app.tab_of_session(session), None);
    assert_eq!(remote_dir(&app).as_deref(), Some("/srv"));
    assert_eq!(app.screen.local.dir, local);
    assert_eq!(tab_row(&mut app), " [1 alice@web.invalid ●]");
    assert_eq!(server.open_connections(), 1);
}

#[tokio::test]
async fn a_listing_for_a_background_tab_lands_there() {
    let server = server();
    let mut app = app(&server);
    started(&mut app).await;
    quickconnect(&mut app, "sftp://alice@web.invalid/srv").await;
    server.set_latency(Duration::from_millis(300));
    // Open "logs", then switch to a new tab before the listing arrives.
    app.dispatch(Action::FocusRemote).unwrap();
    for _ in 0..10 {
        if app
            .screen
            .remote
            .current()
            .is_some_and(|e| e.name == "logs")
        {
            break;
        }
        app.dispatch(Action::CursorDown).unwrap();
    }
    app.dispatch(Action::Open).unwrap();
    while let Ok(action) = app.action_rx.try_recv() {
        app.dispatch(action).unwrap();
    }
    run(&mut app, Action::NewTab).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    settle(&mut app).await;
    assert_eq!(remote_dir(&app), None);
    assert!(!screen_text(&mut app, 120, 40).contains("access.log"));

    run(&mut app, Action::Tab1).await;
    assert_eq!(remote_dir(&app).as_deref(), Some("/srv/logs"));
    assert!(screen_text(&mut app, 120, 40).contains("access.log"));
}

#[tokio::test]
async fn disconnect_after_the_queue_closes_every_tab() {
    let server = server();
    let mut app = two_tabs(&server).await;
    run(&mut app, Action::QueueAfterDue(OnComplete::Disconnect)).await;
    until(&mut app, "all closed", |_| server.open_connections() == 0).await;
    assert_eq!(app.tabs.len(), 2);
    assert!(app.remote.is_none());
    assert!(!app.any_connection());
    assert_eq!(tab_row(&mut app), " [1 local ○] [2 local ○]");
    run(&mut app, Action::Tab1).await;
    assert_eq!(remote_dir(&app), None);
}

#[tokio::test]
async fn duplicate_and_rename() {
    let server = server();
    let mut app = app(&server);
    started(&mut app).await;
    quickconnect(&mut app, "sftp://alice:s3cret@web.invalid/srv").await;
    open(&mut app, "www").await;

    run(&mut app, Action::DuplicateTab).await;
    until(&mut app, "duplicate connected", connected).await;
    assert_eq!(app.tabs.len(), 2);
    assert_eq!(app.tabs.active, 1);
    assert_eq!(server.connects(), 2);
    assert_eq!(remote_dir(&app).as_deref(), Some("/srv/www"));

    run(&mut app, Action::RenameTab).await;
    assert!(app.screen.has_modal());
    for c in ['e', 'u'] {
        app.handle_key_event(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL))
            .unwrap();
    }
    app.screen.handle_paste("prod copy");
    key(&mut app, KeyCode::Enter);
    settle(&mut app).await;
    assert_eq!(
        tab_row(&mut app),
        " [1 alice@web.invalid ●] [2 prod copy ●]"
    );
    // An empty title is automatic again.
    let tab = app.tabs.current_id();
    run(
        &mut app,
        Action::TabRenamed {
            tab,
            title: " ".to_owned(),
        },
    )
    .await;
    assert_eq!(
        tab_row(&mut app),
        " [1 alice@web.invalid ●] [2 alice@web.invalid ●]"
    );
}

#[tokio::test]
async fn the_choice_can_be_remembered() {
    let server = server();
    let mut app = app(&server);
    app.settings.interface.connect_in_tab = TabConnect::Ask;
    started(&mut app).await;
    quickconnect(&mut app, "sftp://alice@web.invalid/srv").await;
    app.dispatch(Action::FocusQuickconnect).unwrap();
    for c in ['e', 'u'] {
        app.handle_key_event(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL))
            .unwrap();
    }
    app.screen.handle_paste("sftp://bob@backup.invalid/srv");
    key(&mut app, KeyCode::Enter);
    settle(&mut app).await;
    assert!(app.screen.has_modal());
    // Only the dialog: the local pane behind it shows this machine's home.
    let text = screen_text(&mut app, 100, 30);
    let dialog: Vec<String> = text
        .lines()
        .skip(12)
        .take(6)
        .map(|l| l.chars().skip(12).take(78).collect())
        .collect();
    insta::assert_snapshot!("connect_while_connected_dialog", dialog.join("\n"));
    // "this tab", "Remember my choice", Connect.
    key(&mut app, KeyCode::Right);
    key(&mut app, KeyCode::Tab);
    key(&mut app, KeyCode::Char(' '));
    key(&mut app, KeyCode::Enter);
    until(&mut app, "replaced", |a| {
        a.remote
            .as_ref()
            .is_some_and(|r| r.connected && r.info.address.host == "backup.invalid")
    })
    .await;
    assert_eq!(app.tabs.len(), 1);
    assert_eq!(app.settings.interface.connect_in_tab, TabConnect::Replace);
}

#[tokio::test]
async fn the_log_shows_the_current_tab() {
    let server = server();
    let mut app = two_tabs(&server).await;
    run(&mut app, Action::Tab1).await;
    run(&mut app, Action::Disconnect).await;
    assert!(screen_text(&mut app, 120, 40).contains("Disconnected from alice@web.invalid"));
    run(&mut app, Action::Tab2).await;
    assert!(!screen_text(&mut app, 120, 40).contains("Disconnected from alice@web.invalid"));
    // "All sessions" shows it.
    run(&mut app, Action::FocusLog).await;
    run(&mut app, Action::ToggleLogAll).await;
    assert!(screen_text(&mut app, 120, 40).contains("Disconnected from alice@web.invalid"));
}

#[tokio::test]
async fn tab_bar_snapshot() {
    let server = server();
    let mut app = two_tabs(&server).await;
    server.fail_connect(courier_ftp_core::Error::Auth("bad password".into()));
    run(&mut app, Action::NewTab).await;
    quickconnect_failing(&mut app, "sftp://carol@staging.invalid").await;
    run(&mut app, Action::NewTab).await;
    insta::assert_snapshot!("app_tab_bar", tab_row(&mut app));
}

async fn quickconnect_failing(app: &mut App, url: &str) {
    app.dispatch(Action::FocusQuickconnect).unwrap();
    for c in ['e', 'u'] {
        app.handle_key_event(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL))
            .unwrap();
    }
    app.screen.handle_paste(url);
    key(app, KeyCode::Enter);
    until(app, "failed", |a| a.remote.is_none()).await;
}

// --- restoring tabs (the vault) ---

async fn start(dir: &Path, keyring: &MemKeyring, server: &MockServer, restore: bool) -> Rig {
    let mut config = config();
    config.settings.interface.restore_tabs = restore;
    let host_keys = Arc::new(courier_ftp_core::trust::HostKeyStoreSlot::new(Arc::new(
        courier_ftp_core::trust::MemoryHostKeyStore::locked(),
    )));
    let app = App::with_backends(config, Arc::new(server.clone()), 4.0, 60.0).with_vault(
        opener(dir, keyring),
        Arc::clone(&host_keys),
        courier_ftp_proto_sftp::ssh::CredentialCache::new(),
    );
    let mut rig = Rig {
        app: Box::new(app),
        host_keys,
    };
    rig.app.start_vault();
    rig.settle().await;
    rig
}

#[tokio::test]
async fn tabs_are_restored_after_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    let server = server();
    let mut rig = start(dir.path(), &keyring, &server, true).await;
    rig.create(STRONG, false).await;
    rig.until("sites loaded", |a| a.site_snapshot.is_some())
        .await;
    // Tab 1: quickconnect in /srv/www.
    rig.quickconnect("sftp://alice@web.invalid/srv").await;
    rig.until("connected", Rig::connected).await;
    open(&mut rig.app, "www").await;
    // Tab 2: a saved site, "Connect in new tab" in the Site Manager.
    rig.create_mock_site().await;
    rig.alt('n');
    rig.settle().await;
    rig.until("site connected", Rig::connected).await;
    assert_eq!(rig.app.tabs.len(), 2);
    let site = rig.snapshot().tree.find_site("mock").unwrap().id;
    assert_eq!(rig.app.remote.as_ref().unwrap().site, Some(site));
    assert_eq!(remote_dir(&rig.app).as_deref(), Some("/srv"));
    assert_eq!(tab_row(&mut rig.app), " [1 alice@web.invalid ●] [2 mock ●]");
    let tab = rig.app.tabs.current_id();
    rig.app
        .dispatch(Action::TabRenamed {
            tab,
            title: "prod".to_owned(),
        })
        .unwrap();
    // A third, local tab, then tab 2 is shown when quitting.
    rig.app.dispatch(Action::NewTab).unwrap();
    rig.settle().await;
    rig.app.dispatch(Action::Tab2).unwrap();
    rig.settle().await;
    let local = rig.app.screen.local.dir.clone();
    rig.app.save_tabs().await;
    // Nothing secret in the saved tabs.
    let saved = rig.engine().load_blob("tabs").await.unwrap().unwrap();
    let text = String::from_utf8_lossy(&saved);
    assert!(!text.contains("s3cret"), "{text}");
    assert_eq!(super::tabs::decode(&saved).len(), 3);
    drop(rig);

    let connects = server.connects();
    let mut rig = start(dir.path(), &keyring, &server, true).await;
    rig.unlock(STRONG).await;
    rig.until("tabs restored and connected", |a| {
        a.tabs.len() == 3 && (0..2).all(|i| a.tab_conn(i).0.is_some_and(|r| r.connected))
    })
    .await;
    assert_eq!(server.connects(), connects + 2);
    // The tab shown at quit is shown again.
    assert_eq!(rig.app.tabs.active, 1);
    assert_eq!(rig.app.remote.as_ref().unwrap().site, Some(site));
    assert_eq!(remote_dir(&rig.app).as_deref(), Some("/srv"));
    assert_eq!(rig.app.screen.local.dir, local);
    assert_eq!(
        tab_row(&mut rig.app),
        " [1 alice@web.invalid ●] [2 prod ●] [3 local ○]"
    );
    rig.app.dispatch(Action::Tab1).unwrap();
    rig.settle().await;
    assert_eq!(remote_dir(&rig.app).as_deref(), Some("/srv/www"));
    // Locking again and unlocking doesn't open them twice.
    rig.app.dispatch(Action::LockVault).unwrap();
    rig.settle().await;
    rig.unlock(STRONG).await;
    rig.settle().await;
    assert_eq!(rig.app.tabs.len(), 3);

    // With the setting off, quitting deletes the saved tabs.
    rig.app.settings.interface.restore_tabs = false;
    rig.app.save_tabs().await;
    assert!(rig.engine().load_blob("tabs").await.unwrap().is_none());
    drop(rig);
    let mut rig = start(dir.path(), &keyring, &server, true).await;
    rig.unlock(STRONG).await;
    rig.settle().await;
    assert_eq!(rig.app.tabs.len(), 1);
    assert!(rig.app.remote.is_none());
}

#[test]
fn saved_tabs_round_trip_and_bad_data_is_ignored() {
    let tabs = vec![super::tabs::SavedTab {
        title: Some("prod".to_owned()),
        local_dir: Some(RemotePath::new("/home/me")),
        active: true,
        ..Default::default()
    }];
    assert_eq!(super::tabs::decode(&super::tabs::encode(&tabs)), tabs);
    assert!(super::tabs::decode(b"not json").is_empty());
    assert!(super::tabs::decode(br#"{"version":9,"tabs":[{}]}"#).is_empty());
}
