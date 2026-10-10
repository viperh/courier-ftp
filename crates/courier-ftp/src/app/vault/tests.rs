//! UI-flow tests of the vault (sverb `app/vault/tests.rs`, ported): startup, keyring,
//! backoff, recovery, lock, auto-lock, quit while locked, launch intents. The flows
//! that need the engine run a real vault service over a real `VaultEngine` on a temp
//! database (`Argon2Cost::TEST`, a memory keyring); the others inject vault events.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::{path::Path, sync::Arc, time::Duration};

use courier_ftp_core::{
    events::{CoreEvent, SessionId, SessionPurpose},
    secret::SecretString,
    trust::{MemoryHostKeyStore, SwitchableHostKeyStore},
    vault::{
        Argon2Cost, KeyringStore, LockReason, MemKeyring, NoKeyring, VaultEngine, VaultOptions,
    },
};
use crossterm::event::KeyCode;
use ratatui::{Frame, layout::Rect};

use super::*;
use crate::{
    components::{Component, DrawCx, main_screen::layout::Region},
    services::vault::{VAULT_DB, VaultConfig},
    testing::{AppHarness, unicode_env},
};

/// The master password of the prepared vaults.
const PW: &str = "correct horse battery staple violin";
/// Another strong password.
const PW2: &str = "plum tractor whistle granite lantern";

fn opts() -> VaultOptions {
    VaultOptions {
        cost: Argon2Cost::TEST,
        ..VaultOptions::default()
    }
}

fn host_keys() -> Arc<SwitchableHostKeyStore> {
    Arc::new(SwitchableHostKeyStore::new(Arc::new(
        MemoryHostKeyStore::new(),
    )))
}

/// Creates a vault at `db` with [`PW`] (and keyring unlock), locked again.
fn init_vault(db: &Path, keyring: Arc<dyn KeyringStore>, with_keyring: bool) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let store = courier_ftp_store::Store::open(db).unwrap();
        let e = VaultEngine::new(store, keyring, opts(), host_keys());
        let report = e
            .initialize(SecretString::from(PW), with_keyring)
            .await
            .unwrap();
        assert_eq!(report.keyring_error, None);
        e.lock(LockReason::Shutdown).await;
    });
}

/// A harness with a temp home; `prepare` may create the vault database first.
fn home(prepare: impl FnOnce(&Path)) -> AppHarness {
    AppHarness::temp(unicode_env(), |p| prepare(&p.data_dir.join(VAULT_DB)))
}

/// Starts the vault and a real service with `keyring`.
fn start(h: &mut AppHarness, keyring: Arc<dyn KeyringStore>, no_keyring: bool) {
    let db = h.paths().unwrap().data_dir.join(VAULT_DB);
    h.with_vault(VaultStartOptions {
        no_vault: false,
        no_keyring,
    });
    h.attach_vault(VaultConfig {
        db_path: db,
        keyring,
        opts: opts(),
        host_keys: host_keys(),
    });
}

/// A harness with a vault but no service: tests inject `VaultEvent`s.
fn fake() -> AppHarness {
    let mut h = AppHarness::temp(unicode_env(), |_| {});
    h.with_vault(VaultStartOptions::default());
    h
}

fn ev(h: &mut AppHarness, e: VaultEvent) {
    h.action(Action::Vault(e));
}

fn initialized() -> VaultEvent {
    VaultEvent::Status(VaultStatusInfo {
        initialized: true,
        ..VaultStatusInfo::default()
    })
}

fn unlocked_ev() -> VaultEvent {
    VaultEvent::Unlocked {
        via_keyring: false,
        note: None,
    }
}

/// A fake harness, unlocked.
fn unlocked(edit: impl FnOnce(&mut courier_ftp_core::settings::Settings)) -> AppHarness {
    let mut h = fake();
    h.app_mut().settings.set_transient(edit);
    ev(&mut h, initialized());
    ev(&mut h, unlocked_ev());
    assert_eq!(h.app().lock_state(), LockState::Unlocked);
    h.app_mut().vault_effects.clear();
    h
}

fn type_text(h: &mut AppHarness, text: &str) {
    for c in text.chars() {
        h.key(KeyChord::key(KeyCode::Char(c)));
    }
}

fn screen(h: &mut AppHarness) -> String {
    h.render(80, 24)
}

fn status(h: &AppHarness) -> String {
    h.app()
        .main
        .status()
        .map(|m| m.text.clone())
        .unwrap_or_default()
}

fn has_lock(h: &AppHarness) -> bool {
    h.app().vault_effects.contains(&VaultEffect::Lock)
}

fn unlock_form(h: &AppHarness) -> UnlockForm {
    match h.app().vault_screen() {
        VaultScreen::Unlock(f) => f.clone(),
        other => panic!("expected the unlock form, got {other:?}"),
    }
}

/// A component that reports running transfers (quit blocker).
struct Transfers;

impl Component for Transfers {
    fn quit_blocker(&self) -> Option<String> {
        Some("1 transfer is running".into())
    }

    fn draw(&mut self, _frame: &mut Frame, _area: Rect, _cx: &DrawCx) -> color_eyre::Result<()> {
        Ok(())
    }
}

#[test]
fn auto_lock_timeout_zero_is_none() {
    assert_eq!(auto_lock_timeout(0), None);
    assert_eq!(auto_lock_timeout(15), Some(Duration::from_secs(900)));
    assert_eq!(
        auto_lock_timeout(5000),
        Some(Duration::from_secs(1440 * 60))
    );
    assert!(LockState::Locked.is_locked() && LockState::Unlocking.is_locked());
    assert!(LockState::Locked.can_start_unlock());
    assert!(!LockState::Unlocking.can_start_unlock());
}

#[test]
fn vault_password_debug_is_redacted() {
    let p = VaultPassword::new(Zeroizing::new("hunter2".into()));
    assert_eq!(format!("{p:?}"), "VaultPassword([REDACTED])");
    let e = VaultEffect::Unlock(UnlockRequest::Password(p.clone()));
    assert!(!format!("{e:?}").contains("hunter2"));
    let a = Action::VaultRequest(VaultEffect::ChangePassword {
        current: Some(p.clone()),
        new: p,
    });
    assert!(!format!("{a:?}").contains("hunter2"));
}

// ---- startup ------------------------------------------------------------------------

/// AC1, AC4, AC8.
#[test]
fn startup_first_run_then_launch_after_unlock() {
    let keyring = Arc::new(MemKeyring::new());
    let mut h = home(|_| {});
    start(&mut h, keyring.clone(), false);
    assert_eq!(
        h.app_mut()
            .vault_defer_launch(LaunchIntent::Url("sftp://h".into())),
        None,
        "the launch waits for unlock"
    );
    let VaultScreen::FirstRun(f) = h.app().vault_screen() else {
        panic!("first run expected: {:?}", h.app().vault_screen());
    };
    assert!(f.keyring_available, "the memory keyring works");
    let s = screen(&mut h);
    assert!(s.contains("Welcome to courier-ftp"), "{s}");
    assert!(
        s.contains(NO_RECOVERY_WARNING.split(' ').next().unwrap()),
        "{s}"
    );
    assert!(!s.contains("Local"), "no pane before unlock:\n{s}");

    // A weak password shows the zxcvbn feedback and creates nothing.
    type_text(&mut h, "password123");
    h.keys("enter");
    type_text(&mut h, "password123");
    h.keys("enter");
    let VaultScreen::FirstRun(f) = h.app().vault_screen() else {
        panic!();
    };
    assert!(f.error.as_deref().unwrap_or("").starts_with("Too weak"));
    assert!(h.app().vault_effects.is_empty());

    // A strong one with the keyring box ticked.
    h.keys("backtab ctrl-u");
    type_text(&mut h, PW);
    h.keys("tab ctrl-u");
    type_text(&mut h, PW);
    h.keys("tab space enter");
    assert!(
        matches!(
            h.app().vault_effects.first(),
            Some(VaultEffect::Initialize { keyring: true, .. })
        ),
        "{:?} {:?}",
        h.app().vault_effects,
        h.app().vault_screen()
    );
    assert_eq!(h.app().lock_state(), LockState::Unlocked);
    assert_eq!(h.app().vault_screen(), &VaultScreen::None);
    assert_eq!(h.app().launched, [LaunchIntent::Url("sftp://h".into())]);
    assert_eq!(keyring.accounts().len(), 1, "keyring unlock enrolled");
    let s = screen(&mut h);
    assert!(s.contains("Local"), "panes after unlock:\n{s}");
}

/// AC1: without keyring unlock every start shows the prompt.
#[test]
fn startup_without_keyring_shows_the_prompt() {
    let mut h = home(|db| init_vault(db, Arc::new(NoKeyring), false));
    start(&mut h, Arc::new(NoKeyring), false);
    let f = unlock_form(&h);
    assert!(f.startup && f.busy.is_none());
    assert!(h.app().vault_service().and_then(|v| v.engine()).is_some());
    let s = screen(&mut h);
    assert!(s.contains("Unlock courier-ftp"), "{s}");
    assert!(!s.contains("Local"), "{s}");
    type_text(&mut h, PW);
    h.keys("enter");
    assert_eq!(h.app().lock_state(), LockState::Unlocked);
}

/// AC2.
#[test]
fn keyring_first_then_fallback_to_prompt() {
    let keyring = Arc::new(MemKeyring::new());
    let k2 = keyring.clone();
    let mut h = home(move |db| init_vault(db, k2, true));
    start(&mut h, keyring.clone(), false);
    assert_eq!(
        h.app().vault_effects,
        [VaultEffect::Unlock(UnlockRequest::Keyring)]
    );
    assert_eq!(h.app().lock_state(), LockState::Unlocked, "no prompt");

    // A broken keyring: the prompt with the reason.
    let keyring = Arc::new(MemKeyring::new());
    let k2 = keyring.clone();
    let mut h = home(move |db| init_vault(db, k2, true));
    keyring.set_unavailable(true);
    start(&mut h, keyring.clone(), false);
    assert_eq!(h.app().lock_state(), LockState::Locked);
    let f = unlock_form(&h);
    assert!(f.busy.is_none() && f.keyring_enabled);
    let msg = status(&h);
    assert!(
        msg.starts_with("Keyring unlock failed (") && msg.ends_with("enter your master password"),
        "{msg}"
    );
    type_text(&mut h, PW);
    h.keys("enter");
    assert_eq!(h.app().lock_state(), LockState::Unlocked);

    // `--no-keyring`: never tried.
    let keyring = Arc::new(MemKeyring::new());
    let k2 = keyring.clone();
    let mut h = home(move |db| init_vault(db, k2, true));
    start(&mut h, keyring, true);
    assert!(h.app().vault_effects.is_empty());
    assert_eq!(h.app().lock_state(), LockState::Locked);
}

/// AC3.
#[test]
fn backoff_countdown_disables_input() {
    let mut h = home(|db| init_vault(db, Arc::new(NoKeyring), false));
    start(&mut h, Arc::new(NoKeyring), false);
    for n in 1..=4 {
        type_text(&mut h, "wrong");
        h.keys("enter");
        let f = unlock_form(&h);
        assert!(f.password.is_empty(), "the field is cleared");
        let s = if n == 1 { "" } else { "s" };
        assert_eq!(
            f.error.as_deref(),
            Some(format!("Wrong password ({n} failed attempt{s})").as_str())
        );
        assert_eq!(f.countdown, None, "attempt {n}: no delay");
    }
    type_text(&mut h, "wrong");
    h.keys("enter");
    let f = unlock_form(&h);
    assert_eq!(
        f.error.as_deref(),
        Some("Wrong password (5 failed attempts)")
    );
    assert_eq!(f.countdown, Some(1));
    assert!(screen(&mut h).contains("Too many failed attempts. Try again in 1s."));
    type_text(&mut h, "x");
    assert!(unlock_form(&h).password.is_empty(), "input ignored");
    h.advance(Duration::from_secs(1));
    let f = unlock_form(&h);
    assert_eq!(f.countdown, None);
    type_text(&mut h, "x");
    assert_eq!(unlock_form(&h).password.len(), 1, "input accepted again");
}

/// AC3 (T30 `UnlockInProgress`).
#[test]
fn unlock_in_progress_keeps_form_busy() {
    let mut h = fake();
    ev(&mut h, initialized());
    type_text(&mut h, "secret");
    h.keys("enter");
    assert_eq!(unlock_form(&h).busy.as_deref(), Some("Unlocking…"));
    assert_eq!(h.app().lock_state(), LockState::Unlocking);
    ev(&mut h, VaultEvent::UnlockFailed(UnlockFailure::InProgress));
    assert_eq!(unlock_form(&h).busy.as_deref(), Some("Unlocking…"));
    assert_eq!(h.app().lock_state(), LockState::Unlocking);
    ev(&mut h, unlocked_ev());
    assert_eq!(h.app().lock_state(), LockState::Unlocked);
}

// ---- recovery -----------------------------------------------------------------------

/// AC5: keyring path → recovery change-password form → new password works.
#[test]
fn keyring_recovery_opens_the_new_password_form() {
    let keyring = Arc::new(MemKeyring::new());
    let k2 = keyring.clone();
    let mut h = home(move |db| init_vault(db, k2, true));
    start(&mut h, keyring, false);
    assert_eq!(h.app().lock_state(), LockState::Unlocked);
    h.keys("ctrl-x ctrl-l");
    assert_eq!(h.app().lock_state(), LockState::Locked);
    h.keys("ctrl-r");
    let VaultScreen::Forgot(f) = h.app().vault_screen() else {
        panic!("forgot screen expected");
    };
    assert!(f.keyring);
    h.keys("k");
    let VaultScreen::ChangePassword(f) = h.app().vault_screen() else {
        panic!("recovery form expected: {:?}", h.app().vault_screen());
    };
    assert!(f.is_recovery());
    // It cannot be cancelled.
    h.keys("esc");
    assert!(matches!(
        h.app().vault_screen(),
        VaultScreen::ChangePassword(f) if f.error.is_some()
    ));
    type_text(&mut h, PW2);
    h.keys("enter");
    type_text(&mut h, PW2);
    h.keys("enter");
    assert_eq!(h.app().vault_screen(), &VaultScreen::None);
    assert_eq!(status(&h), "Master password changed");
    // The new password unlocks; the old one does not.
    h.keys("ctrl-x ctrl-l ctrl-r esc");
    type_text(&mut h, PW);
    h.keys("enter");
    assert_eq!(h.app().lock_state(), LockState::Locked);
    type_text(&mut h, PW2);
    h.keys("enter");
    assert_eq!(h.app().lock_state(), LockState::Unlocked);
}

/// AC5: with neither keyring nor sync, only `n` (and `b` once T73 exists); `n` keeps
/// the old database file.
#[test]
fn start_new_vault_moves_database_aside() {
    let mut h = home(|db| init_vault(db, Arc::new(NoKeyring), false));
    start(&mut h, Arc::new(NoKeyring), false);
    h.keys("ctrl-r");
    assert_eq!(
        h.app().vault_screen(),
        &VaultScreen::Forgot(ForgotScreen::default())
    );
    let s = screen(&mut h);
    assert!(s.contains("cannot be recovered here"), "{s}");
    h.keys("k s");
    assert!(matches!(h.app().vault_screen(), VaultScreen::Forgot(_)));
    h.keys("n");
    type_text(&mut h, "NEW VAU");
    h.keys("enter");
    assert!(matches!(
        h.app().vault_screen(),
        VaultScreen::NewVaultConfirm(c) if c.error.is_some()
    ));
    type_text(&mut h, "LT");
    h.keys("enter");
    assert!(
        matches!(h.app().vault_screen(), VaultScreen::FirstRun(_)),
        "{:?}",
        h.app().vault_screen()
    );
    let data = h.paths().unwrap().data_dir;
    let kept: Vec<String> = std::fs::read_dir(&data)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("courier-ftp.db.bak-"))
        .collect();
    assert!(!kept.is_empty(), "the old database is kept");
    let msg = status(&h);
    assert!(msg.contains("courier-ftp.db.bak-"), "{msg}");
}

// ---- auto-lock ----------------------------------------------------------------------

/// AC6.
#[test]
fn auto_lock_after_idle_minutes() {
    let mut h = unlocked(|s| s.vault.auto_lock_minutes = 1);
    h.advance(Duration::from_secs(59));
    assert_eq!(h.app().lock_state(), LockState::Unlocked);
    h.advance(Duration::from_secs(1));
    assert!(has_lock(&h));
    assert_eq!(h.app().lock_state(), LockState::Locked);
}

/// AC6.
#[test]
fn input_resets_the_idle_timer() {
    let mut h = unlocked(|s| s.vault.auto_lock_minutes = 1);
    h.advance(Duration::from_secs(59));
    h.keys("j");
    h.advance(Duration::from_secs(59));
    assert!(!has_lock(&h));
    assert_eq!(h.app().lock_state(), LockState::Unlocked);
    h.advance(Duration::from_secs(1));
    assert!(has_lock(&h));
}

/// AC6.
#[test]
fn zero_never_locks() {
    let mut h = unlocked(|s| s.vault.auto_lock_minutes = 0);
    h.keys("j");
    h.advance(Duration::from_secs(20 * 60));
    assert!(!has_lock(&h));
    assert_eq!(h.app().lock_state(), LockState::Unlocked);
}

/// AC6.
#[test]
fn resume_from_sleep_locks_when_configured() {
    let mut h = unlocked(|_| {});
    h.advance(Duration::from_secs(2));
    h.app_mut().wall_jump += Duration::from_secs(3600);
    h.advance(Duration::from_millis(500));
    assert_eq!(h.app().lock_state(), LockState::Locked);

    let mut h = unlocked(|s| s.vault.lock_on_suspend = false);
    h.advance(Duration::from_secs(2));
    h.app_mut().wall_jump += Duration::from_secs(3600);
    h.advance(Duration::from_millis(500));
    assert_eq!(h.app().lock_state(), LockState::Unlocked);
}

// ---- while locked -------------------------------------------------------------------

/// AC7.
#[test]
fn locked_app_gets_no_input_and_overlay_renders() {
    let mut h = unlocked(|_| {});
    let before = h.app().settings.current().interface.show_log;
    h.keys("ctrl-x ctrl-l");
    assert!(has_lock(&h));
    assert_eq!(h.app().lock_state(), LockState::Locked);
    assert_eq!(h.app().status_sources.vault, Some(VaultIndicator::Locked));
    // `ctrl-l` (ToggleLog), `tab`, `f1`: nothing reaches the app.
    h.keys("ctrl-l tab f1");
    assert_eq!(h.app().settings.current().interface.show_log, before);
    assert!(h.app().modals.is_empty());
    h.paste("ab\n\x1b[31m");
    h.keys("enter");
    assert!(h.app().vault_effects.iter().any(|e| matches!(
        e,
        VaultEffect::Unlock(UnlockRequest::Password(p)) if p.expose() == "ab[31m"
    )));
    let s = h.render(80, 24);
    assert!(s.contains("Vault locked"), "{s}");
    assert!(!s.contains("Local"), "{s}");
    ev(&mut h, unlocked_ev());
    h.keys("ctrl-l");
    assert_ne!(h.app().settings.current().interface.show_log, before);
}

/// AC7.
#[test]
fn quit_while_locked() {
    let mut h = unlocked(|_| {});
    h.keys("ctrl-x ctrl-l");
    h.keys("ctrl-q");
    assert!(h.app().should_quit());
}

/// AC7.
#[test]
fn quit_while_locked_with_transfers_needs_second_press() {
    let mut h = unlocked(|_| {});
    h.app_mut()
        .main
        .set_component(Region::Queue, Box::new(Transfers));
    h.keys("ctrl-x ctrl-l ctrl-q");
    assert!(!h.app().should_quit());
    assert_eq!(
        unlock_form(&h).notice.as_deref(),
        Some("Transfers are running. Press Ctrl-q again within 3 s to quit.")
    );
    assert!(h.render(80, 24).contains("Press Ctrl-q again"));
    // The arming expires after 3 s.
    h.advance(Duration::from_secs(3));
    assert_eq!(unlock_form(&h).notice, None);
    h.keys("ctrl-q");
    assert!(!h.app().should_quit());
    h.advance(Duration::from_secs(1));
    h.keys("ctrl-q");
    assert!(h.app().should_quit());
}

/// AC7.
#[test]
fn lock_disconnects_sessions_when_configured() {
    let session = SessionId::next();
    let opened = || CoreEvent::SessionOpened {
        session,
        purpose: SessionPurpose::Browse,
        label: "s".into(),
    };
    let mut h = unlocked(|s| s.vault.lock_disconnects = true);
    h.core_event(opened());
    h.keys("ctrl-x ctrl-l");
    assert_eq!(h.app().disconnect_requests, [session]);
    assert!(!unlock_form(&h).sessions_open);

    // Default: sessions stay connected behind the overlay.
    let mut h = unlocked(|_| {});
    h.core_event(opened());
    h.keys("ctrl-x ctrl-l");
    assert!(h.app().disconnect_requests.is_empty());
    assert!(unlock_form(&h).sessions_open);
    let s = h.render(80, 24);
    assert!(s.contains("Connections and transfers keep running"), "{s}");
}

/// AC7.
#[test]
fn lock_discards_forms_and_toasts_after_unlock() {
    let mut h = unlocked(|_| {});
    let form =
        crate::components::dialog::prompt_text("Rename", "Name", "old", None).discard_guard(true);
    h.with_app(|app| app.modals.push_then(form, |_| None));
    type_text(&mut h, "x");
    assert!(h.app().modals.any_dirty());
    // Dialogs take `ctrl-x`; the idle timer (or `LockRequested`) locks.
    ev(&mut h, VaultEvent::LockRequested);
    assert!(h.app().modals.is_empty());
    ev(&mut h, unlocked_ev());
    assert_eq!(status(&h), DISCARDED_FORMS);

    // A clean dialog closes without the toast.
    let mut h = unlocked(|_| {});
    h.keys("f1");
    h.action(Action::LockVault);
    assert!(h.app().modals.is_empty());
    ev(&mut h, unlocked_ev());
    assert_ne!(status(&h), DISCARDED_FORMS);
}

// ---- modes --------------------------------------------------------------------------

#[test]
fn without_a_vault_service_nothing_changes() {
    let mut h = AppHarness::temp(unicode_env(), |_| {});
    h.with_vault(VaultStartOptions {
        no_vault: true,
        no_keyring: false,
    });
    assert_eq!(h.app().vault.mode, VaultMode::Disabled);
    assert_eq!(h.app().status_sources.vault, Some(VaultIndicator::NoVault));
    let s = screen(&mut h);
    assert!(s.contains("Local") && s.contains("no vault"), "{s}");
    h.keys("ctrl-x ctrl-l");
    assert_eq!(status(&h), "There is no vault (--no-vault)");
    assert!(h.app().vault_effects.is_empty());
    assert_eq!(
        h.app_mut()
            .vault_defer_launch(LaunchIntent::Url("u".into())),
        Some(LaunchIntent::Url("u".into()))
    );
    h.advance(Duration::from_secs(60));
    assert_eq!(h.app().vault_screen(), &VaultScreen::None);
}

/// AC8.
#[test]
fn continue_without_vault_runs_url_intent_and_rejects_site_intent() {
    let mut h = fake();
    ev(&mut h, initialized());
    assert_eq!(
        h.app_mut()
            .vault_defer_launch(LaunchIntent::Url("sftp://h".into())),
        None
    );
    h.keys("ctrl-n");
    assert_eq!(h.app().vault.mode, VaultMode::WithoutVault);
    assert_eq!(h.app().lock_state(), LockState::Locked);
    assert_eq!(h.app().launched, [LaunchIntent::Url("sftp://h".into())]);
    let s = screen(&mut h);
    assert!(s.contains("Local") && s.contains("vault locked"), "{s}");
    // Keys reach the app again.
    let before = h.app().settings.current().interface.show_log;
    h.keys("ctrl-l");
    assert_ne!(h.app().settings.current().interface.show_log, before);
    // `--site` needs the vault.
    let site = h
        .app_mut()
        .vault_defer_launch(LaunchIntent::Site("s".into()))
        .unwrap();
    h.with_app(|app| app.on_launch(site));
    assert_eq!(status(&h), "Unlock the vault to open saved sites");
    // A component asks for the vault: the unlock form over the app; Esc returns.
    h.with_app(App::request_unlock);
    let f = unlock_form(&h);
    assert!(!f.startup);
    h.keys("esc");
    assert_eq!(h.app().vault_screen(), &VaultScreen::None);
    // Unlocking from there returns to normal mode with auto-lock.
    h.with_app(App::request_unlock);
    type_text(&mut h, "pw");
    h.keys("enter");
    ev(&mut h, unlocked_ev());
    assert_eq!(h.app().vault.mode, VaultMode::Normal);
    assert_eq!(h.app().lock_state(), LockState::Unlocked);
    assert!(h.app().vault.auto_lock_armed);
}

#[test]
fn password_changed_elsewhere_and_change_password_forms() {
    let mut h = unlocked(|_| {});
    ev(&mut h, VaultEvent::PasswordChangedElsewhere);
    assert!(matches!(
        h.app().vault_screen(),
        VaultScreen::PasswordElsewhere(_)
    ));
    type_text(&mut h, "new");
    h.keys("enter");
    assert!(h.app().vault_effects.iter().any(|e| matches!(
        e,
        VaultEffect::Relogin { password } if password.expose() == "new"
    )));
    ev(&mut h, VaultEvent::Relogin(Err("Wrong password".into())));
    assert!(matches!(
        h.app().vault_screen(),
        VaultScreen::PasswordElsewhere(f) if f.error.as_deref() == Some("Wrong password")
    ));
    h.keys("esc");
    assert_eq!(h.app().vault_screen(), &VaultScreen::None);

    h.with_app(App::open_change_password);
    assert!(matches!(
        h.app().vault_screen(),
        VaultScreen::ChangePassword(f) if !f.is_recovery()
    ));
    h.keys("esc");
    assert_eq!(h.app().vault_screen(), &VaultScreen::None);
}

#[test]
fn keyring_toggle_asks_for_the_password() {
    let mut h = unlocked(|_| {});
    h.with_app(|app| app.toggle_keyring_unlock(true));
    type_text(&mut h, "pw");
    h.keys("enter");
    assert!(h.app().vault_effects.iter().any(|e| matches!(
        e,
        VaultEffect::SetKeyringUnlock { enable: true, password: Some(p) } if p.expose() == "pw"
    )));
    ev(&mut h, VaultEvent::KeyringChanged { enabled: true });
    assert!(h.app().vault.keyring_enabled);
    h.with_app(|app| app.toggle_keyring_unlock(false));
    h.keys("tab enter");
    assert!(h.app().vault_effects.iter().any(|e| matches!(
        e,
        VaultEffect::SetKeyringUnlock {
            enable: false,
            password: None
        }
    )));
}

// ---- secrets (AC10) -----------------------------------------------------------------

#[test]
fn password_never_appears_in_debug_output() {
    const CANARY: &str = "CANARY-pw-7d41e0";
    let mut h = fake();
    ev(&mut h, initialized());
    type_text(&mut h, CANARY);
    let dbg = format!("{:?} {:?}", h.app(), h.app().vault);
    assert!(!dbg.contains(CANARY), "{dbg}");
    h.keys("enter");
    let dbg = format!("{:?} {:?}", h.app().vault_effects, h.app().vault);
    assert!(!dbg.contains(CANARY), "{dbg}");
    assert!(!h.render(160, 48).contains(CANARY));
}

#[derive(Clone, Default)]
struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

std::thread_local! {
    static THREAD_CAPTURE: std::cell::RefCell<Option<Captured>> =
        const { std::cell::RefCell::new(None) };
}

/// Writes into this thread's capture buffer, if any.
struct ThreadCapture;

impl std::io::Write for ThreadCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        THREAD_CAPTURE.with(|c| {
            if let Some(cap) = &*c.borrow() {
                cap.0.lock().unwrap().extend_from_slice(buf);
            }
        });
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Captures this thread's tracing output through one global TRACE subscriber
/// (installed once; a thread-local default is not enough: callsite interest is cached
/// process-wide).
fn capture_tracing() -> Captured {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(|| ThreadCapture)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
    });
    let captured = Captured::default();
    THREAD_CAPTURE.with(|c| *c.borrow_mut() = Some(captured.clone()));
    captured
}

fn files_contain(dir: &Path, needle: &[u8]) -> Vec<String> {
    let mut hits = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return hits;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            hits.extend(files_contain(&p, needle));
        } else if let Ok(bytes) = std::fs::read(&p)
            && bytes.windows(needle.len()).any(|w| w == needle)
        {
            hits.push(p.display().to_string());
        }
    }
    hits
}

#[test]
fn canary_password_not_in_logs_or_files() {
    const CANARY: &str = "canary plum 7d41e0 tractor whistle";
    let captured = capture_tracing();
    let mut h = home(|_| {});
    start(&mut h, Arc::new(MemKeyring::new()), false);
    type_text(&mut h, CANARY);
    h.keys("enter");
    type_text(&mut h, CANARY);
    h.keys("enter");
    assert_eq!(h.app().lock_state(), LockState::Unlocked);
    let mut screens = h.render(80, 24);
    h.keys("ctrl-x ctrl-l");
    type_text(&mut h, &format!("{CANARY}x"));
    screens.push_str(&h.render(160, 48));
    h.keys("enter");
    type_text(&mut h, CANARY);
    h.keys("enter");
    assert_eq!(h.app().lock_state(), LockState::Unlocked);
    h.finish();
    let log = String::from_utf8_lossy(&captured.0.lock().unwrap()).into_owned();
    assert!(
        log.contains("vault unlock"),
        "tracing captured nothing:\n{log}"
    );
    assert!(!log.contains(CANARY), "{log}");
    assert!(!screens.contains(CANARY));
    let home = h.paths().unwrap();
    for dir in [home.config_dir, home.data_dir, home.cache_dir] {
        let hits = files_contain(&dir, CANARY.as_bytes());
        assert!(hits.is_empty(), "{hits:?}");
    }
}
