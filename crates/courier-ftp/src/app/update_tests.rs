//! T74: the update check's opt-outs and notice, and the splash screen, in the
//! app. No test here touches the network.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use courier_ftp_core::{backend::MockServer, settings::SymbolMode};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};

use super::*;
use crate::update::{Hook, Release, ReleaseSource};

fn app(configure: impl FnOnce(&mut Config)) -> App {
    let mut config = Config::builtin();
    config.settings.interface.unicode_symbols = SymbolMode::Unicode;
    config.settings.logging.show_timestamps = false;
    configure(&mut config);
    App::with_backends(config, Arc::new(MockServer::new()), 4.0, 60.0)
}

/// Answers with one release and counts how often a source was made.
struct OneRelease(&'static str);

#[async_trait::async_trait]
impl ReleaseSource for OneRelease {
    async fn releases(&self, _: bool) -> Result<Vec<Release>, String> {
        Ok(vec![Release {
            tag_name: self.0.into(),
            html_url: format!(
                "https://github.com/viperh/courier-ftp/releases/tag/{}",
                self.0
            ),
            prerelease: false,
            draft: false,
        }])
    }
}

/// A hook whose source panics if anything asks it for releases, counting
/// how often the source was made.
struct NoNetwork;

#[async_trait::async_trait]
impl ReleaseSource for NoNetwork {
    async fn releases(&self, _: bool) -> Result<Vec<Release>, String> {
        panic!("the update check must not run");
    }
}

fn hook(
    dir: &tempfile::TempDir,
    calls: &Arc<AtomicUsize>,
    source: impl ReleaseSource + Clone + 'static,
) -> Hook {
    let calls = Arc::clone(calls);
    Hook {
        data_dir: dir.path().to_owned(),
        source: Arc::new(move || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new(source.clone()) as Arc<dyn ReleaseSource>)
        }),
    }
}

impl Clone for OneRelease {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl Clone for NoNetwork {
    fn clone(&self) -> Self {
        Self
    }
}

async fn settle(app: &mut App) {
    loop {
        tokio::select! {
            Some(action) = app.action_rx.recv() => app.dispatch(action).unwrap(),
            Some(event) = app.events_rx.recv() => app.core_event(event),
            () = tokio::time::sleep(Duration::from_millis(200)) => break,
        }
    }
}

fn screen_text(app: &mut App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|f| app.screen.draw(f)).unwrap();
    terminal.backend().to_string()
}

#[tokio::test]
async fn setting_off_means_no_check() {
    let dir = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut app = app(|c| c.settings.interface.check_updates = false);
    app.set_update_hook(hook(&dir, &calls, NoNetwork));
    app.start_update_check();
    settle(&mut app).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
}

#[tokio::test]
async fn flag_or_env_opt_out_means_no_check() {
    let dir = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut app = app(|c| c.settings.interface.check_updates = true);
    app.set_update_hook(hook(&dir, &calls, NoNetwork));
    app.disable_update_check();
    app.start_update_check();
    settle(&mut app).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn apps_without_a_hook_never_check() {
    // `with_backends` (tests) has no hook; only `App::new` sets the real one.
    let mut app = app(|c| c.settings.interface.check_updates = true);
    assert!(app.update.is_none());
    app.start_update_check();
    settle(&mut app).await;
}

#[tokio::test]
async fn newer_release_shows_in_status_bar_log_and_help() {
    let dir = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut app = app(|c| c.settings.interface.check_updates = true);
    app.set_update_hook(hook(&dir, &calls, OneRelease("v99.1.0")));
    app.start_update_check();
    // Wait for the result itself (slow CI), not just for a quiet moment.
    let notice =
        "Update available: v99.1.0 — https://github.com/viperh/courier-ftp/releases/tag/v99.1.0";
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let action = tokio::time::timeout_at(deadline, app.action_rx.recv())
            .await
            .expect("no update notice")
            .unwrap();
        let done = matches!(action, Action::UpdateAvailable(_));
        app.dispatch(action).unwrap();
        if done {
            break;
        }
    }
    settle(&mut app).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // In the message log and the status bar.
    let text = screen_text(&mut app, 200, 30);
    assert!(text.contains(notice), "{text}");
    assert_eq!(
        text.matches("Update available: v99.1.0").count(),
        2,
        "{text}"
    );

    app.dispatch(Action::Help).unwrap();
    let help = screen_text(&mut app, 120, 60);
    assert!(help.contains("Update available: v99.1.0"), "{help}");
    assert!(
        help.contains("https://github.com/viperh/courier-ftp/releases/tag/v99.1.0"),
        "{help}"
    );
}

fn press(app: &mut App, code: KeyCode) {
    app.handle_key_event(KeyEvent::new(code, KeyModifiers::NONE))
        .unwrap();
}

#[tokio::test]
async fn any_key_skips_the_splash_and_does_nothing_else() {
    let mut app = app(|_| {});
    app.screen.show_splash("1.2.3", Instant::now());
    assert!(screen_text(&mut app, 80, 24).contains("loading…"));
    press(&mut app, KeyCode::F(1));
    settle(&mut app).await;
    assert!(!app.screen.splash_shown());
    let text = screen_text(&mut app, 80, 24);
    assert!(!text.contains("loading…"), "{text}");
    // F1 only skipped the splash; Help didn't open.
    assert!(!text.contains("Keys: "), "{text}");
}

#[tokio::test]
async fn splash_waits_a_second_and_for_the_vault() {
    let mut app = app(|_| {});
    let start = Instant::now();
    app.screen.show_splash("1.2.3", start);
    app.expire_splash(start + Duration::from_millis(500));
    assert!(app.screen.splash_shown());
    app.expire_splash(start + Duration::from_millis(1000));
    assert!(!app.screen.splash_shown());

    // While the vault is still opening, it stays (up to the cap).
    let mut app = app_with_opening_vault();
    app.screen.show_splash("1.2.3", start);
    app.expire_splash(start + Duration::from_secs(2));
    assert!(app.screen.splash_shown());
    app.expire_splash(start + crate::ui::SPLASH_MAX_SHOWN);
    assert!(!app.screen.splash_shown());
}

fn app_with_opening_vault() -> App {
    let dir = tempfile::tempdir().unwrap();
    let app = app(|_| {});
    let opener = crate::vault::opener(dir.path().to_owned());
    let backends = crate::backends::Backends::new(&app.settings);
    let app = app.with_vault(opener, backends.host_keys, backends.credentials);
    assert_eq!(app.vault.as_ref().map(|v| v.phase), Some(Phase::Opening));
    app
}
