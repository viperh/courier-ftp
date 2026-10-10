//! App-level tests of the status bar (T57): default keys, toggles, persistence,
//! indicators following the app state and the server information dialog.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::time::Duration;

use courier_ftp_core::settings::enums::TransferTypeChoice;
use pretty_assertions::assert_eq;

use super::{SessionSnapshot, StatusSources};
use crate::{
    action::Action,
    components::{
        server_info::tests::{ftp_plain, ftps, sftp},
        status_bar::{MessageLevel, QueueSummary, VaultIndicator},
    },
    config::Config,
    testing::{AppHarness, unicode_env},
};

fn last_row(screen: &str) -> String {
    screen.lines().last().unwrap_or_default().to_owned()
}

fn with_limits(c: &mut Config) {
    c.settings.transfers.download_limit_kib = 500;
    c.settings.transfers.upload_limit_kib = 100;
}

fn status_text(h: &AppHarness) -> Option<(String, MessageLevel)> {
    h.app().main.status().map(|m| (m.text.clone(), m.level))
}

#[test]
fn status_bar_default_keys() {
    let mut c = Config::default();
    with_limits(&mut c);
    let mut h = AppHarness::new(c);
    h.render(80, 24);
    h.keys("ctrl-x i");
    assert_eq!(h.app().modals.kinds(), [Some("server_info")]);
    let screen = h.render(80, 24);
    assert!(screen.contains("Not connected to any server."), "{screen}");
    h.keys("esc");
    assert!(h.app().modals.is_empty());

    h.keys("ctrl-x a");
    assert_eq!(
        h.app().settings.current().file_types.default_type,
        TransferTypeChoice::Binary
    );
    h.keys("ctrl-x k");
    assert!(h.app().settings.current().transfers.speed_limit_enabled);
    assert!(last_row(&h.render(160, 48)).contains("⇅ ↓500 KiB/s ↑100 KiB/s"));
}

#[test]
fn cycle_transfer_type_order_and_persist() {
    let mut h = AppHarness::temp(unicode_env(), |_| {});
    h.render(80, 24);
    for want in [
        TransferTypeChoice::Binary,
        TransferTypeChoice::Ascii,
        TransferTypeChoice::Auto,
        TransferTypeChoice::Binary,
    ] {
        h.action(Action::CycleTransferType);
        assert_eq!(h.app().settings.current().file_types.default_type, want);
    }
    assert_eq!(
        status_text(&h),
        Some(("Transfer type: Binary".to_owned(), MessageLevel::Info))
    );
    assert!(last_row(&h.render(80, 24)).contains("Type: Binary"));
    // The debounced save writes the user config.
    h.advance(Duration::from_secs(2)).wait_saved();
    let paths = h.paths().unwrap();
    let saved = Config::new(&paths).unwrap();
    assert_eq!(
        saved.settings.file_types.default_type,
        TransferTypeChoice::Binary
    );
}

#[test]
fn toggle_speed_limit_refused_without_limits() {
    let mut h = AppHarness::temp(unicode_env(), |_| {});
    h.render(80, 24);
    h.action(Action::ToggleSpeedLimit);
    assert!(!h.app().settings.current().transfers.speed_limit_enabled);
    assert_eq!(
        status_text(&h),
        Some((
            "No speed limits set (Settings → Transfers)".to_owned(),
            MessageLevel::Warning
        ))
    );
    // With a limit it flips and persists.
    h.app_mut()
        .settings
        .set_transient(|s| s.transfers.upload_limit_kib = 64);
    h.action(Action::ToggleSpeedLimit);
    assert!(h.app().settings.current().transfers.speed_limit_enabled);
    h.advance(Duration::from_secs(2)).wait_saved();
    let saved = Config::new(&h.paths().unwrap()).unwrap();
    assert!(saved.settings.transfers.speed_limit_enabled);
    assert_eq!(saved.settings.transfers.upload_limit_kib, 64);
    h.action(Action::ToggleSpeedLimit);
    assert!(!h.app().settings.current().transfers.speed_limit_enabled);
    assert_eq!(
        status_text(&h).map(|s| s.0),
        Some("Speed limits off".to_owned())
    );
}

#[test]
fn indicators_follow_app_state() {
    let mut c = Config::default();
    with_limits(&mut c);
    let mut h = AppHarness::new(c);
    h.render(160, 48);
    h.advance(Duration::from_millis(100));
    let frames = h.draw_count();
    let set = |h: &mut AppHarness, f: &dyn Fn(&mut StatusSources)| {
        f(&mut h.app_mut().status_sources);
        // The owners of these sources mark the app dirty (one frame later at most).
        h.action(Action::Redraw);
        h.advance(Duration::from_millis(20));
    };
    set(&mut h, &|s| s.filters_active = true);
    assert!(last_row(&h.render(160, 48)).contains("⚑ filters"));
    set(&mut h, &|s| s.sync_browsing = true);
    assert!(last_row(&h.render(160, 48)).contains("⇄ sync"));
    set(&mut h, &|s| s.vault = Some(VaultIndicator::Locked));
    assert!(last_row(&h.render(160, 48)).contains("vault locked"));
    set(&mut h, &|s| {
        s.queue = Some(QueueSummary {
            files: 2,
            bytes: 2048,
            ..QueueSummary::default()
        });
    });
    assert!(last_row(&h.render(160, 48)).contains("Queue: 2 files, 2.00 KiB"));
    set(&mut h, &|s| {
        let (info, addr) = ftps();
        s.session = Some(SessionSnapshot { info, addr });
    });
    assert!(last_row(&h.render(160, 48)).contains("TLS 1.3"));
    // A speed-limit toggle shows in the next frame.
    let before = h.draw_count();
    h.action(Action::ToggleSpeedLimit);
    h.advance(Duration::from_millis(20));
    assert!(h.draw_count() > before);
    assert!(last_row(&h.render(160, 48)).contains("⇅ ↓500 KiB/s ↑100 KiB/s"));
    assert!(h.draw_count() > frames);
}

#[test]
fn plain_ftp_session_shows_plain_ftp() {
    let mut h = AppHarness::new(Config::default());
    let (info, addr) = ftp_plain();
    h.app_mut().status_sources.session = Some(SessionSnapshot { info, addr });
    assert!(last_row(&h.render(80, 24)).contains("plain FTP"));
    assert!(last_row(&h.render(60, 16)).contains("plain FTP"));
}

#[test]
fn server_info_dialog_for_sessions() {
    let mut h = AppHarness::new(Config::default());
    let (info, addr) = sftp();
    h.app_mut().status_sources.session = Some(SessionSnapshot { info, addr });
    h.render(160, 48);
    h.action(Action::ServerInfo);
    let screen = h.render(160, 48);
    assert!(screen.contains("ssh-ed25519 256"), "{screen}");
    assert!(!screen.contains("[ Details ]"));
    h.keys("esc");

    let (info, addr) = ftps();
    h.app_mut().status_sources.session = Some(SessionSnapshot { info, addr });
    h.action(Action::ServerInfo);
    let screen = h.render(80, 24);
    assert!(screen.contains("[ Details ]"), "{screen}");
    // `Details` opens T69's certificate chain view.
    h.keys("backtab enter");
    assert_eq!(h.app().modals.kinds(), [Some("certificate_chain")]);
    let screen = h.render(80, 24);
    assert!(screen.contains("Certificate 1 of"), "{screen}");
    h.keys("esc");
    assert!(h.app().modals.is_empty());
}
