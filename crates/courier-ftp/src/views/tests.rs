//! Unit tests of the vault forms (sverb `views/unlock.rs` and `views/first_run.rs`
//! tests, ported) and the property tests of T60.

use courier_ftp_core::vault::MIN_SCORE;
use crossterm::event::KeyCode;
use proptest::prelude::*;

use super::{
    first_run::{FirstRunFocus, FirstRunForm},
    forgot::{ForgotScreen, NEW_VAULT_PHRASE, NewVaultConfirm},
    unlock::{ChangePasswordForm, FormAction, MaskedField, UnlockForm},
};
use crate::keymap::chord::{KeyChord, Mods};

const STRONG: &str = "correct horse battery staple violin";

fn key(code: KeyCode) -> KeyChord {
    KeyChord::key(code)
}

fn ctrl(c: char) -> KeyChord {
    KeyChord::new(KeyCode::Char(c), Mods::CTRL)
}

fn type_str(form: &mut FirstRunForm, s: &str) {
    for c in s.chars() {
        form.handle_key(key(KeyCode::Char(c)));
    }
}

#[test]
fn masked_field_never_debugs_its_text() {
    let mut f = MaskedField::default();
    f.push_str("hunter2\n");
    assert_eq!(f.expose(), "hunter2");
    assert_eq!(format!("{f:?}"), "MaskedField(7 chars)");
    assert_eq!(f.masked("•"), "•••••••");
    let long = "x".repeat(50);
    let mut g = MaskedField::default();
    g.push_str(&long);
    assert_eq!(g.masked("*").len(), 32, "capped at 32");
    assert_eq!(f.take().as_str(), "hunter2");
    assert!(f.is_empty());
}

#[test]
fn unlock_form_keys() {
    let mut form = UnlockForm {
        startup: true,
        ..UnlockForm::default()
    };
    assert_eq!(form.handle_key(key(KeyCode::Enter)), FormAction::None);
    assert_eq!(
        form.handle_key(key(KeyCode::Char('q'))),
        FormAction::Changed
    );
    assert_eq!(form.handle_key(key(KeyCode::Enter)), FormAction::Submit);
    assert_eq!(form.handle_key(ctrl('r')), FormAction::Forgot);
    assert_eq!(form.handle_key(ctrl('n')), FormAction::ContinueWithoutVault);
    // Esc clears; Esc on an empty field asks to leave.
    assert_eq!(form.handle_key(key(KeyCode::Esc)), FormAction::Changed);
    assert!(form.password.is_empty());
    assert_eq!(form.handle_key(key(KeyCode::Esc)), FormAction::Cancel);
    form.handle_key(key(KeyCode::Char('a')));
    form.handle_key(key(KeyCode::Char('b')));
    assert_eq!(
        form.handle_key(key(KeyCode::Backspace)),
        FormAction::Changed
    );
    assert_eq!(form.password.expose(), "a");
    // Counting down: input is ignored.
    form.countdown = Some(3);
    assert_eq!(form.handle_key(key(KeyCode::Char('x'))), FormAction::None);
    assert_eq!(form.handle_key(ctrl('r')), FormAction::None);
    assert_eq!(form.password.expose(), "a");
    // Not at startup: Ctrl-n does nothing.
    let mut later = UnlockForm::default();
    assert_eq!(later.handle_key(ctrl('n')), FormAction::None);
}

#[test]
fn change_form_validates() {
    let mut form = ChangePasswordForm::new();
    assert_eq!(form.handle_key(key(KeyCode::Enter)), FormAction::Changed);
    assert_eq!(form.focus, 1);
    form.focus = 2;
    assert_eq!(form.handle_key(key(KeyCode::Enter)), FormAction::Changed);
    assert_eq!(form.error.as_deref(), Some("Enter your current password"));
    form.current = Some(crate::app::vault::masked("old"));
    form.focus = 1;
    for c in STRONG.chars() {
        form.handle_key(key(KeyCode::Char(c)));
    }
    form.handle_key(key(KeyCode::Tab));
    for c in "nope".chars() {
        form.handle_key(key(KeyCode::Char(c)));
    }
    assert_eq!(form.handle_key(key(KeyCode::Enter)), FormAction::Changed);
    assert_eq!(form.error.as_deref(), Some("The passwords do not match"));
    for _ in 0..4 {
        form.handle_key(key(KeyCode::Backspace));
    }
    for c in STRONG.chars() {
        form.handle_key(key(KeyCode::Char(c)));
    }
    assert_eq!(form.handle_key(key(KeyCode::Enter)), FormAction::Submit);
    assert_eq!(form.handle_key(key(KeyCode::Esc)), FormAction::Cancel);
}

#[test]
fn recovery_change_form_cannot_be_cancelled() {
    let mut form = ChangePasswordForm::recovery();
    assert!(form.is_recovery());
    assert_eq!(form.handle_key(key(KeyCode::Esc)), FormAction::Changed);
    assert_eq!(
        form.error.as_deref(),
        Some("Set a new password to finish recovery")
    );
}

#[test]
fn first_run_validation_and_feedback() {
    let mut form = FirstRunForm::new(false);
    type_str(&mut form, "password123");
    assert!(form.new.strength.score < MIN_SCORE);
    form.handle_key(key(KeyCode::Enter));
    assert_eq!(form.focus, FirstRunFocus::Confirm);
    type_str(&mut form, "password123");
    assert_eq!(form.handle_key(key(KeyCode::Enter)), FormAction::Changed);
    let err = form.error.clone().unwrap_or_default();
    assert!(err.starts_with("Too weak ("), "{err}");
    assert!(err.contains(&form.new.strength.feedback()), "{err}");

    let mut form = FirstRunForm::new(true);
    type_str(&mut form, STRONG);
    form.handle_key(key(KeyCode::Tab));
    type_str(&mut form, "nope");
    form.handle_key(key(KeyCode::Enter));
    assert_eq!(form.error.as_deref(), Some("The passwords do not match"));

    let mut empty = FirstRunForm::new(false);
    empty.focus = FirstRunFocus::Confirm;
    empty.handle_key(key(KeyCode::Enter));
    assert_eq!(empty.error.as_deref(), Some("Enter a master password"));
}

#[test]
fn first_run_keyring_row_only_when_available() {
    let mut form = FirstRunForm::new(true);
    type_str(&mut form, STRONG);
    form.handle_key(key(KeyCode::Tab));
    type_str(&mut form, STRONG);
    form.handle_key(key(KeyCode::Tab));
    assert_eq!(form.focus, FirstRunFocus::Keyring);
    form.handle_key(key(KeyCode::Char(' ')));
    assert!(form.use_keyring);
    assert_eq!(form.handle_key(key(KeyCode::Enter)), FormAction::Submit);

    let mut form = FirstRunForm::new(false);
    form.handle_key(key(KeyCode::Tab));
    form.handle_key(key(KeyCode::Tab));
    assert_eq!(form.focus, FirstRunFocus::Password, "no checkbox row");
    form.handle_key(KeyChord::new(KeyCode::Tab, Mods::SHIFT));
    assert_eq!(form.focus, FirstRunFocus::Confirm);
    // A space in a password field is part of the password.
    form.handle_key(key(KeyCode::Char(' ')));
    assert_eq!(form.new.confirm.expose(), " ");
    assert!(!form.use_keyring);
    let text = crate::testing::render(80, 24, |f| {
        form.render(f, f.area(), super::Look::new(&theme(), &symbols()));
    });
    assert!(!text.contains("system keyring"), "{text}");
}

fn theme() -> crate::ui::theme::Theme {
    crate::ui::theme::Theme::load(
        crate::ui::theme::ThemePreset::Default,
        &std::collections::BTreeMap::new(),
        false,
    )
    .0
}

fn symbols() -> crate::ui::symbols::Symbols {
    crate::ui::symbols::Symbols::unicode()
}

#[test]
fn forgot_screen_lists_only_available_options() {
    let all = ForgotScreen {
        keyring: true,
        sync: true,
        restore: true,
    };
    let keys: Vec<char> = all.options().iter().map(|(k, _)| *k).collect();
    assert_eq!(keys, ['k', 's', 'b', 'n']);
    assert_eq!(
        all.handle_key(key(KeyCode::Char('k'))),
        FormAction::Choose('k')
    );
    let none = ForgotScreen::default();
    let keys: Vec<char> = none.options().iter().map(|(k, _)| *k).collect();
    assert_eq!(keys, ['n']);
    assert_eq!(none.handle_key(key(KeyCode::Char('k'))), FormAction::None);
    assert_eq!(none.handle_key(key(KeyCode::Char('s'))), FormAction::None);
    assert_eq!(
        none.handle_key(key(KeyCode::Char('n'))),
        FormAction::Choose('n')
    );
    assert_eq!(none.handle_key(key(KeyCode::Esc)), FormAction::Cancel);
    let text = crate::testing::render(80, 24, |f| {
        none.render(f, f.area(), super::Look::new(&theme(), &symbols()));
    });
    assert!(text.contains("cannot be recovered here"), "{text}");
}

#[test]
fn new_vault_requires_typed_confirmation() {
    let mut c = NewVaultConfirm::default();
    assert_eq!(c.handle_key(key(KeyCode::Enter)), FormAction::Changed);
    assert!(c.error.is_some());
    for ch in "new vault".chars() {
        c.handle_key(key(KeyCode::Char(ch)));
    }
    assert_eq!(
        c.handle_key(key(KeyCode::Enter)),
        FormAction::Changed,
        "case matters"
    );
    c.typed.clear();
    for ch in NEW_VAULT_PHRASE.chars() {
        c.handle_key(key(KeyCode::Char(ch)));
    }
    assert_eq!(c.handle_key(key(KeyCode::Enter)), FormAction::Submit);
    assert_eq!(c.handle_key(key(KeyCode::Esc)), FormAction::Cancel);
}

proptest! {
    #[test]
    fn prop_masked_field_drops_control_chars(s in "\\PC*|[\\x00-\\x1f\\x7f\\n\\r\\t a-z]{0,40}") {
        let mut f = MaskedField::default();
        f.push_str(&s);
        prop_assert!(!f.expose().chars().any(char::is_control));
        prop_assert_eq!(f.len(), s.chars().filter(|c| !c.is_control()).count());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Every vault screen renders at any size from 0×0 to 200×60 without panicking.
    #[test]
    fn prop_vault_screens_render_at_any_size(w in 0_u16..=200, h in 0_u16..=60, ascii: bool) {
        let theme = theme();
        let symbols = if ascii {
            crate::ui::symbols::Symbols::ascii()
        } else {
            symbols()
        };
        let look = super::Look::new(&theme, &symbols);
        let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(
            w.max(1),
            h.max(1),
        ))
        .unwrap();
        let area = ratatui::layout::Rect::new(0, 0, w, h);
        let mut first = FirstRunForm::new(true);
        first.error = Some("Too weak (fair): Add another word or two.".into());
        let unlock = UnlockForm {
            startup: true,
            countdown: Some(4),
            ..UnlockForm::default()
        };
        let change = ChangePasswordForm::new();
        let forgot = ForgotScreen { keyring: true, sync: true, restore: true };
        let confirm = NewVaultConfirm::default();
        let elsewhere = super::unlock::PasswordElsewhereForm::default();
        terminal
            .draw(|f| {
                first.render(f, area, look);
                unlock.render(f, area, look);
                change.render(f, area, look);
                ChangePasswordForm::recovery().render(f, area, look);
                forgot.render(f, area, look);
                ForgotScreen::default().render(f, area, look);
                confirm.render(f, area, look);
                elsewhere.render(f, area, look);
                super::lock_overlay::render(f, area, look, "Ctrl-q");
            })
            .unwrap();
    }
}
