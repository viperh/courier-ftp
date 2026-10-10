//! Password and key passphrase prompts (T69 §4; T07/T10/T15/T20 produce them). The
//! typed value lives in a [`SecretInput`] (zeroized on drop) and leaves it only as a
//! `SecretString`.

use std::fmt;

use courier_ftp_core::events::{PassphrasePrompt, PasswordPrompt, PasswordPurpose, PromptResponse};
use ratatui::{
    Frame,
    layout::{Position, Rect},
    style::Style,
    text::Line,
};

use super::{
    PromptDialog, Step,
    layout::{
        Body, BodyCx, Btn, K, LABEL_W, Row, checkbox, classify, clean, pad_label, step_focus,
    },
};
use crate::{
    components::widgets::{Notice, SecretInput, Widget, WidgetCx},
    keymap::chord::KeyChord,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Field,
    Remember,
    Save,
    Ok,
    Cancel,
}

const FOCUS: [Focus; 5] = [
    Focus::Field,
    Focus::Remember,
    Focus::Save,
    Focus::Ok,
    Focus::Cancel,
];

/// The password / passphrase dialog.
pub(crate) struct SecretDialog {
    title: &'static str,
    label: &'static str,
    first_line: String,
    retry_line: Option<String>,
    can_save: bool,
    input: SecretInput,
    remember: bool,
    save: bool,
    focus: Focus,
}

impl fmt::Debug for SecretDialog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretDialog")
            .field("title", &self.title)
            .field("value", &format_args!("[REDACTED]"))
            .field("remember", &self.remember)
            .field("save", &self.save)
            .field("focus", &self.focus)
            .finish_non_exhaustive()
    }
}

impl SecretDialog {
    fn new(
        title: &'static str,
        label: &'static str,
        first_line: String,
        retry_line: Option<String>,
        can_save: bool,
    ) -> Self {
        Self {
            title,
            label,
            first_line,
            retry_line,
            can_save,
            input: SecretInput::new(),
            remember: false,
            save: false,
            focus: Focus::Field,
        }
    }

    /// A password prompt.
    pub(crate) fn password(p: &PasswordPrompt) -> Self {
        let target = clean(&p.target);
        let first = match p.purpose {
            PasswordPurpose::Login => format!("Password for {target}"),
            PasswordPurpose::Account => format!("Account password for {target}"),
            PasswordPurpose::Proxy | PasswordPurpose::FtpProxy => {
                format!("Proxy password for {target}")
            }
        };
        let retry = p.retry.then(|| {
            format!(
                "Permission denied, please try again (attempt {} of {}).",
                p.attempt, p.max_attempts
            )
        });
        Self::new("Password required", "Password:", first, retry, p.can_save)
    }

    /// A key passphrase prompt.
    pub(crate) fn passphrase(p: &PassphrasePrompt) -> Self {
        let first = format!("Passphrase for key {}", clean(&p.key_label));
        let retry = p.retry.then(|| {
            format!(
                "Wrong passphrase, please try again (attempt {} of {}).",
                p.attempt, p.max_attempts
            )
        });
        Self::new(
            "Key passphrase required",
            "Passphrase:",
            first,
            retry,
            p.can_save,
        )
    }

    fn enabled(&self, f: Focus) -> bool {
        f != Focus::Save || self.can_save
    }

    fn submit(&mut self) -> Step {
        Step::Answer(PromptResponse::Secret {
            value: self.input.take(),
            remember_session: self.remember,
            save_in_vault: self.save && self.can_save,
        })
    }

    fn move_focus(&mut self, forward: bool) {
        let cur = FOCUS.iter().position(|f| *f == self.focus).unwrap_or(0);
        self.focus = FOCUS[step_focus(cur, FOCUS.len(), forward, |i| self.enabled(FOCUS[i]))];
    }
}

impl PromptDialog for SecretDialog {
    fn kind(&self) -> &'static str {
        "secret"
    }

    fn title(&self, _unicode: bool) -> String {
        self.title.to_owned()
    }

    fn handle_key(&mut self, key: KeyChord) -> Step {
        match classify(key) {
            K::Esc | K::Alt('c') => return Step::Answer(PromptResponse::Cancel),
            K::Alt('o') => return self.submit(),
            K::Tab => self.move_focus(true),
            K::BackTab => self.move_focus(false),
            K::Enter => {
                return match self.focus {
                    Focus::Cancel => Step::Answer(PromptResponse::Cancel),
                    _ => self.submit(),
                };
            }
            K::Space if matches!(self.focus, Focus::Remember) => self.remember = !self.remember,
            K::Space if matches!(self.focus, Focus::Save) => self.save = !self.save,
            K::Left | K::Up if matches!(self.focus, Focus::Cancel) => self.focus = Focus::Ok,
            K::Right | K::Down if matches!(self.focus, Focus::Ok) => self.focus = Focus::Cancel,
            _ if self.focus == Focus::Field => {
                self.input.handle_key(key);
            }
            _ => {}
        }
        Step::Continue
    }

    fn handle_paste(&mut self, text: &str) {
        if self.focus == Focus::Field {
            self.input.handle_paste(text);
        }
    }

    fn take_notice(&mut self) -> Option<String> {
        match self.input.take_notice() {
            Some(Notice::Status(s)) => Some(s),
            _ => None,
        }
    }

    fn body(&self, width: u16, cx: &BodyCx) -> Body {
        let width = usize::from(width);
        let mut b = Body::default();
        b.para(&self.first_line, width, Style::default());
        if let Some(r) = &self.retry_line {
            b.para(r, width, cx.danger());
        }
        b.blank();
        let field_w = u16::try_from(width.saturating_sub(LABEL_W + 6).max(10)).unwrap_or(10);
        let row = b.push(Row::Input {
            label: Line::from(pad_label(self.label)),
            field: 0,
            width: field_w,
            focused: self.focus == Focus::Field,
            enabled: true,
            suffix: None,
        });
        if self.focus == Focus::Field {
            b.focus_row = row;
        }
        b.blank();
        let row = b.line(checkbox(
            "Remember for this session",
            self.remember,
            self.focus == Focus::Remember,
            true,
            cx.theme,
        ));
        if self.focus == Focus::Remember {
            b.focus_row = row;
        }
        if self.can_save {
            let row = b.line(checkbox(
                "Save in the vault",
                self.save,
                self.focus == Focus::Save,
                true,
                cx.theme,
            ));
            if self.focus == Focus::Save {
                b.focus_row = row;
            }
        }
        b.blank();
        let row = b.push(Row::Buttons(vec![
            Btn::new("OK", self.focus == Focus::Ok),
            Btn::new("Cancel", self.focus == Focus::Cancel),
        ]));
        if matches!(self.focus, Focus::Ok | Focus::Cancel) {
            b.focus_row = row;
        }
        b
    }

    fn draw_input(
        &self,
        frame: &mut Frame,
        _field: usize,
        area: Rect,
        cx: &WidgetCx,
    ) -> Option<Position> {
        self.input.render(frame, area, cx);
        self.input.cursor(area)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

    use super::*;
    use crate::components::prompts::tests::{k, password_prompt, pw_key};

    #[test]
    fn typed_password_answers_with_flags() {
        let mut d = SecretDialog::password(&password_prompt(pw_key("h"), false));
        for c in "hunter2".chars() {
            d.handle_key(KeyChord::char(c));
        }
        d.handle_key(k("tab"));
        d.handle_key(k("space"));
        // can_save: the Save checkbox is the next stop.
        d.handle_key(k("tab"));
        d.handle_key(k("space"));
        match d.handle_key(k("enter")) {
            Step::Answer(PromptResponse::Secret {
                value,
                remember_session,
                save_in_vault,
            }) => {
                assert_eq!(value.expose(), "hunter2");
                assert!(remember_session && save_in_vault);
            }
            other => panic!("unexpected {other:?}"),
        }
        let mut d = SecretDialog::password(&password_prompt(pw_key("h"), false));
        assert!(matches!(
            d.handle_key(k("esc")),
            Step::Answer(PromptResponse::Cancel)
        ));
    }
}
