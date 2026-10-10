//! Snapshots of the vault screens at 80×24 and 160×48 (AC9): the locked screens
//! through `App::draw` (vault box + status bar), the forms shown over the unlocked app
//! as their box alone (the app behind them is the panes' business). `*_mono_ascii`
//! variants use ASCII glyphs and `NO_COLOR`.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::time::Duration;

use crossterm::event::KeyCode;
use ratatui::layout::Rect;

use super::*;
use crate::{
    testing::{AppHarness, assert_view_snapshots, unicode_env},
    ui::symbols::TermEnv,
    views::Look,
};

fn ascii_env() -> TermEnv {
    TermEnv {
        term: Some("xterm".into()),
        lang: Some("C".into()),
        no_color: true,
        ..TermEnv::default()
    }
}

fn fake_in(env: TermEnv) -> AppHarness {
    let mut h = AppHarness::temp(env, |_| {});
    h.with_vault(VaultStartOptions::default());
    h
}

fn fake() -> AppHarness {
    fake_in(unicode_env())
}

fn ev(h: &mut AppHarness, e: VaultEvent) {
    h.action(Action::Vault(e));
}

fn status(initialized: bool) -> VaultEvent {
    VaultEvent::Status(VaultStatusInfo {
        initialized,
        keyring_available: true,
        ..VaultStatusInfo::default()
    })
}

fn type_text(h: &mut AppHarness, text: &str) {
    for c in text.chars() {
        h.key(KeyChord::key(KeyCode::Char(c)));
    }
}

/// Snapshots the whole app at both sizes.
fn snap_app(h: &mut AppHarness, name: &str) {
    h.with_app(|app| {
        assert_view_snapshots!(name, |f: &mut Frame| app.draw(f));
    });
}

/// Snapshots `draw` (a form's box) centred above an empty status row.
fn snap_box(name: &str, mono_ascii: bool, draw: impl Fn(&mut Frame, Rect, Look<'_>)) {
    let (theme, _) = crate::ui::theme::Theme::load(
        crate::ui::theme::ThemePreset::Default,
        &std::collections::BTreeMap::new(),
        mono_ascii,
    );
    let symbols = if mono_ascii {
        crate::ui::symbols::Symbols::ascii()
    } else {
        crate::ui::symbols::Symbols::unicode()
    };
    assert_view_snapshots!(name, |f: &mut Frame| {
        let area = f.area();
        let body = Rect {
            height: area.height.saturating_sub(1),
            ..area
        };
        draw(f, body, Look::new(&theme, &symbols));
    });
}

fn assert_ascii(h: &mut AppHarness) {
    for (w, hh) in crate::testing::SIZES {
        let s = h.render(w, hh);
        assert!(s.is_ascii(), "{s}");
    }
}

#[test]
fn unlock_startup() {
    let mut h = fake();
    ev(&mut h, status(true));
    type_text(&mut h, "secret12");
    snap_app(&mut h, "unlock_startup");
}

#[test]
fn unlock_startup_mono_ascii() {
    let mut h = fake_in(ascii_env());
    ev(&mut h, status(true));
    type_text(&mut h, "secret12");
    assert_ascii(&mut h);
    snap_app(&mut h, "unlock_startup_mono_ascii");
}

#[test]
fn unlock_wrong_password() {
    let mut h = fake();
    ev(&mut h, status(true));
    type_text(&mut h, "wrong");
    h.keys("enter");
    ev(
        &mut h,
        VaultEvent::UnlockFailed(UnlockFailure::WrongPassword {
            failures: 2,
            retry_after: None,
        }),
    );
    snap_app(&mut h, "unlock_wrong_password");
}

#[test]
fn unlock_backoff() {
    let mut h = fake();
    ev(&mut h, status(true));
    type_text(&mut h, "wrong");
    h.keys("enter");
    ev(
        &mut h,
        VaultEvent::UnlockFailed(UnlockFailure::Backoff {
            retry_after: Duration::from_millis(3500),
        }),
    );
    snap_app(&mut h, "unlock_backoff");
}

#[test]
fn unlock_busy() {
    let mut h = fake();
    ev(&mut h, status(true));
    type_text(&mut h, "secret12");
    h.keys("enter");
    snap_app(&mut h, "unlock_busy");
}

#[test]
fn first_run() {
    let mut h = fake();
    ev(&mut h, status(false));
    type_text(&mut h, "password123");
    snap_app(&mut h, "first_run");
}

#[test]
fn first_run_mono_ascii() {
    let mut h = fake_in(ascii_env());
    ev(&mut h, status(false));
    type_text(&mut h, "password123");
    assert_ascii(&mut h);
    snap_app(&mut h, "first_run_mono_ascii");
}

#[test]
fn first_run_keyring_checked() {
    let mut h = fake();
    ev(&mut h, status(false));
    type_text(&mut h, "correct horse battery staple violin");
    h.keys("tab");
    type_text(&mut h, "correct horse battery staple violin");
    h.keys("tab space");
    snap_app(&mut h, "first_run_keyring_checked");
}

#[test]
fn forgot_all_options() {
    let mut h = fake();
    ev(&mut h, status(true));
    h.app_mut().vault.screen = VaultScreen::Forgot(ForgotScreen {
        keyring: true,
        sync: true,
        restore: true,
    });
    snap_app(&mut h, "forgot_all_options");
}

#[test]
fn forgot_no_recovery() {
    let mut h = fake();
    ev(&mut h, status(true));
    h.keys("ctrl-r");
    snap_app(&mut h, "forgot_no_recovery");
}

#[test]
fn new_vault_confirm() {
    let mut h = fake();
    ev(&mut h, status(true));
    h.keys("ctrl-r n");
    type_text(&mut h, "NEW");
    snap_app(&mut h, "new_vault_confirm");
}

fn locked_with_transfer(env: TermEnv) -> AppHarness {
    let mut h = fake_in(env);
    ev(&mut h, status(true));
    ev(
        &mut h,
        VaultEvent::Unlocked {
            via_keyring: false,
            note: None,
        },
    );
    h.core_event(courier_ftp_core::events::CoreEvent::SessionOpened {
        session: courier_ftp_core::events::SessionId::next(),
        purpose: courier_ftp_core::events::SessionPurpose::Transfer,
        label: "transfer".into(),
    });
    h.action(Action::LockVault);
    type_text(&mut h, "abc");
    h
}

#[test]
fn lock_overlay() {
    let mut h = locked_with_transfer(unicode_env());
    snap_app(&mut h, "lock_overlay");
}

#[test]
fn lock_overlay_mono_ascii() {
    let mut h = locked_with_transfer(ascii_env());
    assert_ascii(&mut h);
    snap_app(&mut h, "lock_overlay_mono_ascii");
}

#[test]
fn change_password_recovery() {
    let mut form = ChangePasswordForm::recovery();
    for c in "correct horse battery staple".chars() {
        form.handle_key(KeyChord::key(KeyCode::Char(c)));
    }
    snap_box("change_password_recovery", false, |f, area, look| {
        form.render(f, area, look);
    });
}

#[test]
fn change_password_mismatch() {
    let mut form = ChangePasswordForm::new();
    for c in "old pass".chars() {
        form.handle_key(KeyChord::key(KeyCode::Char(c)));
    }
    form.handle_key(KeyChord::key(KeyCode::Tab));
    for c in "correct horse battery staple".chars() {
        form.handle_key(KeyChord::key(KeyCode::Char(c)));
    }
    form.handle_key(KeyChord::key(KeyCode::Tab));
    for c in "correct horse battery stapl".chars() {
        form.handle_key(KeyChord::key(KeyCode::Char(c)));
    }
    form.handle_key(KeyChord::key(KeyCode::Enter));
    assert_eq!(form.error.as_deref(), Some("The passwords do not match"));
    snap_box("change_password_mismatch", false, |f, area, look| {
        form.render(f, area, look);
    });
}

#[test]
fn password_elsewhere() {
    let form = PasswordElsewhereForm::default();
    snap_box("password_elsewhere", false, |f, area, look| {
        form.render(f, area, look);
    });
}

/// Every screen at odd sizes: no panic, "Terminal too small" below 40×12, and the
/// password is still accepted there.
#[test]
fn vault_screens_render_at_small_sizes() {
    let mut h = fake();
    ev(&mut h, status(true));
    for (w, hh) in [(1, 1), (10, 5), (39, 11), (40, 12), (41, 13), (200, 60)] {
        let s = h.render(w, hh);
        if w < 40 || hh < 12 {
            assert!(s.contains("Terminal too small") || w < 18, "{w}x{hh}:\n{s}");
        } else {
            assert!(s.contains("Password:"), "{w}x{hh}:\n{s}");
        }
    }
    h.render(20, 6);
    type_text(&mut h, "pw");
    h.keys("enter");
    assert!(h.app().vault_effects.iter().any(|e| matches!(
        e,
        VaultEffect::Unlock(UnlockRequest::Password(p)) if p.expose() == "pw"
    )));
}
