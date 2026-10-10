//! T60: the vault screens on their own (key handling, rendering). The flows
//! against a real engine are in `app/vault_tests.rs`.

use std::time::{Duration, Instant};

use courier_ftp_core::vault::VaultError;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};
use secrecy::ExposeSecret;

use super::*;

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn alt(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::ALT)
}

fn typed(view: &mut VaultView, text: &str, now: Instant) {
    for c in text.chars() {
        assert!(view.handle_key(key(KeyCode::Char(c)), now).is_none());
    }
}

fn render(view: &VaultView, w: u16, h: u16, now: Instant) -> String {
    let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
    terminal
        .draw(|f| view.draw(f, f.area(), &Theme::default(), now))
        .unwrap();
    terminal.backend().to_string()
}

const STRONG: &str = "correct horse battery staple violin";

fn unlock_view(facts: VaultFacts, now: Instant) -> VaultView {
    let mut v = VaultView::opening(true);
    v.show_unlock(facts, 0, None, now);
    v
}

#[test]
fn unlock_view_snapshot_and_masking() {
    let now = Instant::now();
    let mut v = unlock_view(VaultFacts::default(), now);
    typed(&mut v, "hunter2", now);
    let text = render(&v, 80, 24, now);
    assert!(!text.contains("hunter2"), "{text}");
    assert!(text.contains("•••••••"), "{text}");
    insta::assert_snapshot!("vault_unlock_80x24", text);
    insta::assert_snapshot!("vault_unlock_160x48", render(&v, 160, 48, now));
}

#[test]
fn enter_asks_to_unlock_and_clears_the_field() {
    let now = Instant::now();
    let mut v = unlock_view(VaultFacts::default(), now);
    // Empty: refused inline.
    assert!(v.handle_key(key(KeyCode::Enter), now).is_none());
    assert!(render(&v, 80, 24, now).contains("Enter the master password."));
    typed(&mut v, "pw", now);
    let Some(VaultRequest::Unlock(secret)) = v.handle_key(key(KeyCode::Enter), now) else {
        panic!("unlock expected");
    };
    assert_eq!(secret.expose_secret(), "pw");
    assert!(v.is_busy());
    let text = render(&v, 80, 24, now);
    assert!(text.contains("Unlocking…"), "{text}");
    assert!(!text.contains("••"), "the field is cleared: {text}");
    // Input is ignored while Argon2 runs; quitting still works.
    assert!(v.handle_key(key(KeyCode::Char('x')), now).is_none());
    assert!(matches!(
        v.handle_key(
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL),
            now
        ),
        Some(VaultRequest::Quit)
    ));
}

#[test]
fn buttons_skip_and_forgot() {
    let now = Instant::now();
    let mut v = unlock_view(VaultFacts::default(), now);
    assert!(matches!(
        v.handle_key(alt('c'), now),
        Some(VaultRequest::Skip)
    ));
    // Tab to the buttons, → → Enter: Forgot password?
    v.handle_key(key(KeyCode::Tab), now);
    v.handle_key(key(KeyCode::Right), now);
    v.handle_key(key(KeyCode::Right), now);
    assert!(v.handle_key(key(KeyCode::Enter), now).is_none());
    assert_eq!(v.page(), VaultPage::Forgot);
    v.handle_key(key(KeyCode::Esc), now);
    assert_eq!(v.page(), VaultPage::Unlock);
}

#[test]
fn backoff_countdown_is_shown_and_enforced() {
    let now = Instant::now();
    let mut v = unlock_view(VaultFacts::default(), now);
    typed(&mut v, "wrong", now);
    assert!(v.handle_key(key(KeyCode::Enter), now).is_some());
    v.unlock_failed(
        &VaultError::WrongPassword {
            failures: 6,
            retry_after: Some(Duration::from_secs(2)),
        },
        now,
    );
    let text = render(&v, 80, 24, now);
    assert!(text.contains("Wrong master password."), "{text}");
    assert!(
        text.contains("6 failed attempts · next try in 2 s"),
        "{text}"
    );
    insta::assert_snapshot!("vault_backoff_80x24", text);

    // During the backoff Unlock does nothing but say so.
    let later = now + Duration::from_millis(1500);
    typed(&mut v, "again", later);
    assert!(v.handle_key(key(KeyCode::Enter), later).is_none());
    let text = render(&v, 80, 24, later);
    assert!(text.contains("try again in 1 s"), "{text}");
    assert!(text.contains("next try in 1 s"), "{text}");

    // Afterwards it unlocks again; the counter stays visible.
    let after = now + Duration::from_secs(3);
    let text = render(&v, 80, 24, after);
    assert!(text.contains("6 failed attempts"), "{text}");
    assert!(!text.contains("next try"), "{text}");
    assert!(matches!(
        v.handle_key(key(KeyCode::Enter), after),
        Some(VaultRequest::Unlock(_))
    ));
}

#[test]
fn backoff_from_the_engine_at_start() {
    let now = Instant::now();
    let mut v = VaultView::opening(true);
    v.show_unlock(
        VaultFacts::default(),
        5,
        Some(Duration::from_millis(900)),
        now,
    );
    assert!(render(&v, 80, 24, now).contains("5 failed attempts · next try in 1 s"));
}

#[test]
fn first_run_snapshot_and_strength_rules() {
    let now = Instant::now();
    let mut v = VaultView::opening(true);
    v.show_create(VaultFacts {
        keyring_available: true,
        ..VaultFacts::default()
    });
    insta::assert_snapshot!("vault_first_run_80x24", render(&v, 80, 24, now));

    // Weak: refused with feedback.
    typed(&mut v, "password123", now);
    v.handle_key(key(KeyCode::Tab), now);
    typed(&mut v, "password123", now);
    assert!(v.handle_key(key(KeyCode::Enter), now).is_none());
    let text = render(&v, 80, 24, now);
    assert!(text.contains("Too weak"), "{text}");
    assert!(!text.contains("password123"), "{text}");

    // Strong but not confirmed: refused.
    let mut v = VaultView::opening(true);
    v.show_create(VaultFacts {
        keyring_available: true,
        ..VaultFacts::default()
    });
    typed(&mut v, STRONG, now);
    v.handle_key(key(KeyCode::Tab), now);
    typed(&mut v, "something else", now);
    assert!(v.handle_key(key(KeyCode::Enter), now).is_none());
    let text = render(&v, 80, 24, now);
    assert!(text.contains("The passwords don't match."), "{text}");
    insta::assert_snapshot!("vault_first_run_mismatch_80x24", text);

    // Fix the confirmation, tick the keyring box, create.
    for _ in 0..20 {
        v.handle_key(key(KeyCode::Backspace), now);
    }
    typed(&mut v, STRONG, now);
    v.handle_key(key(KeyCode::Tab), now);
    v.handle_key(key(KeyCode::Char(' ')), now);
    let Some(VaultRequest::Create { password, keyring }) = v.handle_key(key(KeyCode::Enter), now)
    else {
        panic!("create expected");
    };
    assert_eq!(password.expose_secret(), STRONG);
    assert!(keyring);
    assert!(render(&v, 80, 24, now).contains("Creating the vault…"));
}

#[test]
fn first_run_without_keyring_hides_the_checkbox() {
    let now = Instant::now();
    let mut v = VaultView::opening(false);
    v.show_create(VaultFacts::default());
    let text = render(&v, 80, 24, now);
    assert!(!text.contains("keyring on this device"), "{text}");
    assert!(text.contains("a forgotten password means your saved sites are lost"));
    // Esc doesn't skip the first run by accident; the button does.
    assert!(v.handle_key(key(KeyCode::Esc), now).is_none());
    assert!(matches!(
        v.handle_key(alt('c'), now),
        Some(VaultRequest::Skip)
    ));
}

#[test]
fn forgot_password_with_keyring_resets() {
    let now = Instant::now();
    let mut v = unlock_view(
        VaultFacts {
            keyring_enabled: true,
            ..VaultFacts::default()
        },
        now,
    );
    v.handle_key(alt('f'), now);
    assert_eq!(v.page(), VaultPage::Forgot);
    let text = render(&v, 80, 24, now);
    assert!(
        text.contains("Unlock with the system keyring and set a new password"),
        "{text}"
    );
    assert!(!text.contains("new empty vault"), "{text}");
    insta::assert_snapshot!("vault_forgot_keyring_80x24", text);
    v.handle_key(key(KeyCode::Enter), now);
    assert_eq!(v.page(), VaultPage::Reset);
    typed(&mut v, STRONG, now);
    v.handle_key(key(KeyCode::Tab), now);
    typed(&mut v, STRONG, now);
    let Some(VaultRequest::Reset(pw)) = v.handle_key(key(KeyCode::Enter), now) else {
        panic!("reset expected");
    };
    assert_eq!(pw.expose_secret(), STRONG);
}

#[test]
fn forgot_password_without_recovery_explains_and_offers_a_new_vault() {
    let now = Instant::now();
    let mut v = unlock_view(VaultFacts::default(), now);
    v.handle_key(alt('f'), now);
    let text = render(&v, 80, 24, now);
    assert!(
        text.contains("There is no way to recover a forgotten master password"),
        "{text}"
    );
    insta::assert_snapshot!("vault_forgot_none_80x24", text);
    // Restore: not there yet.
    v.handle_key(key(KeyCode::Enter), now);
    assert!(render(&v, 80, 24, now).contains("not available in this build yet"));
    // New vault: asks first, defaults to Back.
    v.handle_key(key(KeyCode::Down), now);
    v.handle_key(key(KeyCode::Enter), now);
    assert_eq!(v.page(), VaultPage::NewVault);
    assert!(v.handle_key(key(KeyCode::Enter), now).is_none());
    assert_eq!(v.page(), VaultPage::Forgot);
    v.handle_key(key(KeyCode::Down), now);
    v.handle_key(key(KeyCode::Enter), now);
    v.handle_key(key(KeyCode::Left), now);
    assert!(matches!(
        v.handle_key(key(KeyCode::Enter), now),
        Some(VaultRequest::NewVault)
    ));
}

#[test]
fn unavailable_database_offers_retry() {
    let now = Instant::now();
    let mut v = VaultView::opening(true);
    v.show_unavailable(VaultError::Busy.to_string());
    let text = render(&v, 80, 24, now);
    assert!(text.contains("The database is busy"), "{text}");
    assert!(matches!(
        v.handle_key(key(KeyCode::Enter), now),
        Some(VaultRequest::Retry)
    ));
    assert!(matches!(
        v.handle_key(alt('c'), now),
        Some(VaultRequest::Skip)
    ));
}

#[test]
fn paste_goes_to_the_password_field() {
    let now = Instant::now();
    let mut v = unlock_view(VaultFacts::default(), now);
    v.handle_paste("pasted pw");
    let Some(VaultRequest::Unlock(secret)) = v.handle_key(key(KeyCode::Enter), now) else {
        panic!("unlock expected");
    };
    assert_eq!(secret.expose_secret(), "pasted pw");
}

#[test]
fn requests_never_debug_print_secrets() {
    let r = VaultRequest::Unlock(SecretString::from("topsecret"));
    assert_eq!(format!("{r:?}"), "Unlock");
}

#[test]
fn wrap_breaks_on_words() {
    assert_eq!(wrap("aa bb cc", 5), vec!["aa bb", "cc"]);
    assert_eq!(wrap("", 5), vec![String::new()]);
}
