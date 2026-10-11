//! T68: the settings screen through the app: saving to the user config and
//! loading it back, live apply, the Security page against a real vault
//! engine (`Argon2Cost::TEST`), stored host keys, and proxy passwords in the
//! vault.

use std::{path::Path, sync::Arc, time::Duration};

use courier_ftp_core::{
    backend::MockServer,
    events::LogKind,
    model::item::ProxyCredential,
    settings::{GenericProxy, Layout, Settings},
    trust::{HostKey, HostKeyStore, KnownHost},
    vault::{ItemVaultExt, MemKeyring, VaultHostKeyStore},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};

use super::{
    vault_tests::{STRONG, config as vault_config, start},
    *,
};
use crate::ui::settings::{Section, SettingsView};

fn press(app: &mut App, code: KeyCode) {
    app.handle_key_event(KeyEvent::new(code, KeyModifiers::NONE))
        .unwrap();
}

fn chord(app: &mut App, c: char, modifiers: KeyModifiers) {
    app.handle_key_event(KeyEvent::new(KeyCode::Char(c), modifiers))
        .unwrap();
}

fn typed(app: &mut App, text: &str) {
    for c in text.chars() {
        press(app, KeyCode::Char(c));
    }
}

fn view(app: &App) -> &SettingsView {
    app.screen.settings_view().expect("settings screen open")
}

/// Run the app's channels until `done` holds (30 s at most: Argon2 and the
/// store are slow on CI runners).
async fn wait_for(app: &mut App, what: &str, done: impl Fn(&App) -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !done(app) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::select! {
            Some(action) = app.action_rx.recv() => app.dispatch(action).unwrap(),
            Some(event) = app.events_rx.recv() => app.core_event(event),
            Some(msg) = app.vault_rx.recv() => app.vault_message(msg),
            () = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }
}

/// Drain whatever is queued right now (no waiting on timers).
fn pump(app: &mut App) {
    while let Ok(action) = app.action_rx.try_recv() {
        app.dispatch(action).unwrap();
    }
}

/// Select `section` in the open settings screen (from the section list).
fn go_to(app: &mut App, section: Section) {
    for _ in 0..30 {
        if view(app).section() == section {
            return;
        }
        press(app, KeyCode::Down);
    }
    panic!("no section {section:?}");
}

fn message(app: &App) -> String {
    view(app)
        .message()
        .map(|(m, _)| m.clone())
        .unwrap_or_default()
}

fn mock_app(config_dir: &Path) -> App {
    let mut config = vault_config();
    config.config.config_dir = config_dir.to_path_buf();
    App::with_backends(config, Arc::new(MockServer::new()), 4.0, 60.0)
}

#[tokio::test]
async fn save_writes_a_minimal_config_that_loads_back_and_applies_live() {
    let dir = tempfile::tempdir().unwrap();
    let config_dir = dir.path().join("config");
    // Other keys in the user's file survive.
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.json"),
        r#"{"keybindings": {"Normal": {"<F12>": "Quit"}}}"#,
    )
    .unwrap();
    let mut app = mock_app(&config_dir);
    assert!(!app.events_tx.enabled(LogKind::Debug(4)));
    app.dispatch(Action::Settings).unwrap();
    pump(&mut app);

    // Connection: timeout 45.
    press(&mut app, KeyCode::Enter);
    chord(&mut app, 'e', KeyModifiers::CONTROL);
    chord(&mut app, 'u', KeyModifiers::CONTROL);
    typed(&mut app, "45");
    press(&mut app, KeyCode::Esc);
    // Interface: Explorer layout.
    go_to(&mut app, Section::Interface);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Esc);
    // Logging: debug level 4.
    go_to(&mut app, Section::Logging);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('4'));
    assert!(view(&app).is_dirty());
    // OK.
    chord(&mut app, 'o', KeyModifiers::ALT);
    wait_for(&mut app, "the screen to close", |a| {
        a.screen.settings_view().is_none()
    })
    .await;

    // Applied live.
    assert_eq!(app.settings.connection.timeout_secs, 45);
    assert_eq!(app.settings.interface.layout, Layout::Explorer);
    assert!(app.events_tx.enabled(LogKind::Debug(4)));

    // Only what differs from the defaults was written; the rest is kept.
    let doc: Value =
        serde_json::from_str(&std::fs::read_to_string(config_dir.join("config.json")).unwrap())
            .unwrap();
    assert_eq!(
        doc["settings"],
        json!({
            "connection": {"timeout_secs": 45, "keepalive": false},
            "interface": {"layout": "explorer", "unicode_symbols": "unicode"},
            "logging": {"level": 4, "show_timestamps": false},
        })
    );
    assert_eq!(doc["keybindings"], json!({"Normal": {"<F12>": "Quit"}}));

    // A new run reads the same settings back.
    let loaded = Config::load(&config_dir, &dir.path().join("data")).unwrap();
    assert!(
        loaded.settings_warnings.is_empty(),
        "{:?}",
        loaded.settings_warnings
    );
    assert_eq!(loaded.settings, app.settings);
}

#[tokio::test]
async fn cancel_keeps_the_old_settings_and_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = mock_app(dir.path());
    let before = app.settings.clone();
    app.dispatch(Action::Settings).unwrap();
    go_to(&mut app, Section::Transfers);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Up); // 4 → 5 (number field)
    assert_eq!(view(&app).draft().transfers.max_concurrent, 5);
    chord(&mut app, 'c', KeyModifiers::ALT);
    chord(&mut app, 'y', KeyModifiers::NONE);
    pump(&mut app);
    assert!(app.screen.settings_view().is_none());
    assert_eq!(app.settings, before);
    assert!(!dir.path().join("config.json").exists());
}

#[tokio::test]
async fn a_broken_config_file_is_not_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("config.json"), "{ not json").unwrap();
    let mut app = mock_app(dir.path());
    app.dispatch(Action::Settings).unwrap();
    go_to(&mut app, Section::Theme);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Right); // High contrast
    chord(&mut app, 's', KeyModifiers::CONTROL);
    wait_for(&mut app, "the failure", |a| !view(a).is_busy()).await;
    assert!(
        message(&app).starts_with("Could not save the settings"),
        "{}",
        message(&app)
    );
    assert!(view(&app).is_dirty());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("config.json")).unwrap(),
        "{ not json"
    );
    assert_eq!(app.settings, mock_app(dir.path()).settings);
}

#[tokio::test]
async fn without_a_vault_the_security_and_trust_pages_say_so() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = mock_app(dir.path());
    app.dispatch(Action::Settings).unwrap();
    pump(&mut app);
    go_to(&mut app, Section::Sftp);
    pump(&mut app);
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(110, 30)).unwrap();
    terminal.draw(|f| app.screen.draw(f)).unwrap();
    let text = terminal.backend().to_string();
    assert!(text.contains("this run has none"), "{text}");
}

fn known_host() -> KnownHost {
    let mut blob = Vec::new();
    for part in [b"ssh-ed25519".as_slice(), &[9u8; 32]] {
        blob.extend_from_slice(&u32::try_from(part.len()).unwrap().to_be_bytes());
        blob.extend_from_slice(part);
    }
    KnownHost::new(
        "sftp.example.com",
        2222,
        HostKey::from_blob(blob).unwrap(),
        time::OffsetDateTime::now_utc(),
    )
}

#[tokio::test]
async fn stored_host_keys_are_listed_and_forgotten() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    let mut rig = start(dir.path(), &keyring, vault_config()).await;
    rig.create(STRONG, false).await;
    // "Always trust" from a connection.
    rig.host_keys.remember(known_host()).await.unwrap();
    let app = &mut rig.app;
    app.dispatch(Action::Settings).unwrap();
    go_to(app, Section::Sftp);
    wait_for(app, "the host key list", |a| {
        a.screen
            .settings_view()
            .is_some_and(|v| v.lists_host_key("sftp.example.com"))
    })
    .await;
    press(app, KeyCode::Enter); // into the list
    press(app, KeyCode::Char('x'));
    press(app, KeyCode::Char('y'));
    wait_for(app, "the key to be forgotten", |a| {
        a.screen
            .settings_view()
            .is_some_and(|v| !v.lists_host_key("sftp.example.com"))
    })
    .await;
    assert!(
        message(app).contains("Forgot the ssh-ed25519 key"),
        "{}",
        message(app)
    );
    let engine = rig.engine();
    let store = VaultHostKeyStore::new(Arc::new(engine));
    assert!(store.list().await.unwrap().is_empty());
}

#[tokio::test]
async fn security_page_changes_the_password_and_keyring_and_locks() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    let mut rig = start(dir.path(), &keyring, vault_config()).await;
    rig.create(STRONG, false).await;
    let new_password = "lavender submarine orbit quartz meadow";
    {
        let app = &mut rig.app;
        app.dispatch(Action::Settings).unwrap();
        press(app, KeyCode::End);
        assert_eq!(view(app).section(), Section::Security);
        wait_for(app, "the vault state", |a| view(a).security_unlocked()).await;

        // Change master password.
        press(app, KeyCode::Enter); // into the page: the first button
        press(app, KeyCode::Enter);
        typed(app, STRONG);
        press(app, KeyCode::Tab);
        typed(app, new_password);
        press(app, KeyCode::Tab);
        typed(app, new_password);
        press(app, KeyCode::Enter);
        wait_for(app, "the password change", |a| {
            message(a) == "Master password changed"
        })
        .await;
    }
    let engine = rig.engine();
    engine
        .verify_password(&SecretString::from(new_password))
        .await
        .unwrap();
    assert!(
        engine
            .verify_password(&SecretString::from(STRONG))
            .await
            .is_err()
    );

    // Keyring unlock on.
    let app = &mut rig.app;
    press(app, KeyCode::Tab);
    press(app, KeyCode::Enter);
    wait_for(app, "keyring unlock", |a| {
        message(a) == "Keyring unlock is on for this device"
    })
    .await;
    assert!(engine.status().await.unwrap().keyring_enabled);
    wait_for(app, "the page to show it", |a| view(a).keyring_shown()).await;

    // Lock now: the unlock view covers everything.
    press(app, KeyCode::Tab);
    press(app, KeyCode::Enter);
    wait_for(app, "the lock", |a| {
        a.vault.as_ref().is_some_and(|v| v.phase == Phase::Locked)
    })
    .await;
    assert!(app.screen.vault_shown());
}

#[tokio::test]
async fn a_wrong_current_password_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    let mut rig = start(dir.path(), &keyring, vault_config()).await;
    rig.create(STRONG, false).await;
    let app = &mut rig.app;
    app.dispatch(Action::Settings).unwrap();
    press(app, KeyCode::End);
    wait_for(app, "the vault state", |a| view(a).security_unlocked()).await;
    press(app, KeyCode::Enter);
    press(app, KeyCode::Enter);
    typed(app, "not the password at all");
    press(app, KeyCode::Tab);
    typed(app, "lavender submarine orbit quartz meadow");
    press(app, KeyCode::Tab);
    typed(app, "lavender submarine orbit quartz meadow");
    press(app, KeyCode::Enter);
    wait_for(app, "the failure", |a| {
        message(a).starts_with("Could not change the master password")
    })
    .await;
    rig.engine()
        .verify_password(&SecretString::from(STRONG))
        .await
        .unwrap();
}

#[tokio::test]
async fn auto_lock_settings_apply_to_the_running_vault() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    let mut config = vault_config();
    config.config.config_dir = dir.path().join("config");
    let mut rig = start(dir.path(), &keyring, config).await;
    rig.create(STRONG, false).await;
    let app = &mut rig.app;
    app.dispatch(Action::Settings).unwrap();
    press(app, KeyCode::End);
    wait_for(app, "the vault state", |a| view(a).security_unlocked()).await;
    // Tab to the auto-lock field (after the three buttons).
    press(app, KeyCode::Enter);
    for _ in 0..3 {
        press(app, KeyCode::Tab);
    }
    chord(app, 'e', KeyModifiers::CONTROL);
    chord(app, 'u', KeyModifiers::CONTROL);
    typed(app, "0");
    chord(app, 'o', KeyModifiers::ALT);
    wait_for(app, "the screen to close", |a| {
        a.screen.settings_view().is_none()
    })
    .await;
    assert_eq!(app.settings.vault.auto_lock_minutes, 0);
    assert_eq!(app.vault.as_ref().unwrap().auto_lock.idle_timeout(), None);
}

#[tokio::test]
async fn proxy_password_goes_to_the_vault_not_the_config() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    let mut config = vault_config();
    config.config.config_dir = dir.path().join("config");
    let mut rig = start(dir.path(), &keyring, config).await;
    rig.create(STRONG, false).await;
    let app = &mut rig.app;
    app.dispatch(Action::Settings).unwrap();
    go_to(app, Section::GenericProxy);
    press(app, KeyCode::Enter);
    press(app, KeyCode::Char('h')); // HTTP CONNECT
    press(app, KeyCode::Tab);
    typed(app, "proxy.example.com");
    press(app, KeyCode::Tab);
    press(app, KeyCode::Tab);
    typed(app, "me");
    press(app, KeyCode::Tab);
    typed(app, "proxy-secret-canary");
    chord(app, 'o', KeyModifiers::ALT);
    wait_for(app, "the screen to close", |a| {
        a.screen.settings_view().is_none()
    })
    .await;

    let proxy = app.settings.proxy.clone();
    let GenericProxy::Http(server) = &proxy.generic else {
        panic!("{:?}", proxy.generic);
    };
    let id = server.password_ref.clone().expect("a vault reference");
    let text = std::fs::read_to_string(dir.path().join("config/config.json")).unwrap();
    assert!(!text.contains("proxy-secret-canary"), "{text}");
    assert!(text.contains(&id), "{text}");
    let creds = rig.engine().list_views::<ProxyCredential>().await.unwrap();
    let (item, view) = creds
        .iter()
        .find(|(item, _)| item.id.to_string() == id)
        .expect("the vault item");
    assert!(!item.read_only);
    assert_eq!(view.user, "me");
    assert_eq!(
        view.password.as_ref().map(|p| p.expose_secret().to_owned()),
        Some("proxy-secret-canary".to_owned())
    );
    let (loaded, _) =
        Settings::from_value(&serde_json::from_str::<Value>(&text).unwrap()["settings"]);
    assert_eq!(loaded.proxy, proxy);
}

#[tokio::test]
async fn proxy_password_needs_an_unlocked_vault() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = mock_app(dir.path());
    app.dispatch(Action::Settings).unwrap();
    go_to(&mut app, Section::GenericProxy);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('h'));
    press(&mut app, KeyCode::Tab);
    typed(&mut app, "proxy.example.com");
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Tab);
    typed(&mut app, "secret");
    chord(&mut app, 's', KeyModifiers::CONTROL);
    wait_for(&mut app, "the failure", |a| !view(a).is_busy()).await;
    assert!(
        message(&app).contains("Unlock the vault"),
        "{}",
        message(&app)
    );
    assert!(!dir.path().join("config.json").exists());
}

#[tokio::test]
async fn transfer_and_queue_settings_apply_to_the_running_engine() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = mock_app(dir.path());
    let mut new = app.settings.clone();
    new.queue.max_successful = 7;
    new.transfers.speed_limit_enabled = true;
    new.transfers.download_limit_kib = 512;
    new.transfers.max_concurrent = 1;
    app.apply_settings(new.clone());

    assert_eq!(
        courier_ftp_core::queue::lock_queue(&app.transfers.queue).max_successful(),
        7
    );
    assert_eq!(app.settings, new);
    // The engine is still running and took the change.
    assert!(app.transfers.engine.settings_changed(new));
}

/// T72: the network configuration wizard through the app: the test runs
/// for real (against a closed local port, so it reports the failed login
/// without contacting anything else) and *Apply* writes the settings.
#[tokio::test]
async fn the_network_wizard_tests_and_writes_the_settings() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = mock_app(dir.path());
    app.dispatch(Action::Settings).unwrap();
    pump(&mut app);
    go_to(&mut app, Section::Ftp);
    press(&mut app, KeyCode::Enter);
    // The wizard button is the FTP page's last row.
    for _ in 0..8 {
        press(&mut app, KeyCode::Tab);
    }
    press(&mut app, KeyCode::Enter);
    assert!(view(&app).wizard().is_some());
    pump(&mut app);
    for _ in 0..3 {
        chord(&mut app, 'n', KeyModifiers::ALT);
    }
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Tab);
    typed(&mut app, &format!("ftp://bob@127.0.0.1:{port}"));
    // No password: refused before connecting.
    chord(&mut app, 'r', KeyModifiers::ALT);
    wait_for(&mut app, "the password problem", |a| {
        view(a).wizard().is_some_and(|w| !w.is_testing())
    })
    .await;
    assert!(
        view(&app)
            .wizard()
            .unwrap()
            .report()
            .is_some_and(|r| r.steps.is_empty())
    );
    press(&mut app, KeyCode::Tab);
    typed(&mut app, "pw");
    chord(&mut app, 'r', KeyModifiers::ALT);
    wait_for(&mut app, "the test", |a| {
        view(a).wizard().is_some_and(|w| !w.is_testing())
    })
    .await;
    let report = view(&app).wizard().unwrap().report().unwrap().clone();
    assert_eq!(report.steps.len(), 5, "{report:#?}");
    assert_eq!(
        report.steps[0].status,
        courier_ftp_proto_ftp::probe::StepStatus::Failed
    );
    // Summary: active mode; Apply saves and applies it.
    chord(&mut app, 'n', KeyModifiers::ALT);
    press(&mut app, KeyCode::Right);
    chord(&mut app, 'a', KeyModifiers::ALT);
    wait_for(&mut app, "the save", |a| {
        a.settings.ftp.transfer_mode == courier_ftp_core::settings::FtpTransferMode::Active
    })
    .await;
    assert!(view(&app).wizard().is_none());
    let doc: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join("config.json")).unwrap())
            .unwrap();
    assert_eq!(doc["settings"]["ftp"], json!({"transfer_mode": "active"}));
}
