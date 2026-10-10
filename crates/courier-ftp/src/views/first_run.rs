//! The first-run screen (sverb `views/first_run.rs`, D13): what the vault is, master
//! password + confirmation, a live zxcvbn strength meter, the no-recovery warning and
//! "Also unlock with the system keyring" when a keyring works on this device.

use courier_ftp_core::vault::{MIN_SCORE, NO_RECOVERY_WARNING, PasswordStrength, USER_INPUTS};
use crossterm::event::KeyCode;
use ratatui::{Frame, layout::Rect};

use super::{
    Look,
    unlock::{
        BoxLine, FormAction, MaskedField, field_line, is_backtab, is_ctrl, is_plain, render_box,
    },
};
use crate::keymap::chord::KeyChord;

/// Which of the two new-password fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NewPasswordField {
    /// The password.
    Password,
    /// The confirmation.
    Confirm,
}

/// A new password with confirmation and a live strength estimate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct NewPassword {
    /// The password.
    pub password: MaskedField,
    /// The confirmation.
    pub confirm: MaskedField,
    /// zxcvbn estimate of `password` (updated on every edit).
    pub strength: PasswordStrength,
}

impl NewPassword {
    /// Edit one field with a key; returns whether it changed.
    pub(crate) fn edit(&mut self, field: NewPasswordField, key: KeyChord) -> bool {
        let changed = match field {
            NewPasswordField::Password => self.password.edit(key),
            NewPasswordField::Confirm => self.confirm.edit(key),
        };
        if changed && field == NewPasswordField::Password {
            self.refresh_strength();
        }
        changed
    }

    /// Re-estimates the strength of `password`.
    pub(crate) fn refresh_strength(&mut self) {
        self.strength = courier_ftp_core::vault::estimate(self.password.expose(), &USER_INPUTS);
    }

    /// Non-empty, matching and strong enough (score ≥ 3).
    ///
    /// # Errors
    /// A message for the form (with zxcvbn feedback for weak passwords).
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.password.is_empty() {
            return Err("Enter a master password".into());
        }
        if self.password.expose() != self.confirm.expose() {
            return Err("The passwords do not match".into());
        }
        if self.strength.score < MIN_SCORE {
            let feedback = self.strength.feedback();
            return Err(if feedback.is_empty() {
                format!(
                    "Too weak ({}); use a longer passphrase",
                    self.strength.label()
                )
            } else {
                format!("Too weak ({}): {feedback}", self.strength.label())
            });
        }
        Ok(())
    }
}

/// Focus on the first-run screen.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum FirstRunFocus {
    /// The password field.
    #[default]
    Password,
    /// The confirmation field.
    Confirm,
    /// The keyring checkbox (only when a keyring is available).
    Keyring,
}

/// The first-run form.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FirstRunForm {
    /// New password, confirmation, strength.
    pub new: NewPassword,
    /// Focused row.
    pub focus: FirstRunFocus,
    /// A keyring works on this device (probed by writing and deleting an entry).
    pub keyring_available: bool,
    /// "Also unlock with the system keyring on this device" (default off, D3).
    pub use_keyring: bool,
    /// The last validation or creation error.
    pub error: Option<String>,
    /// Creating the vault ("Creating your vault…").
    pub busy: bool,
    /// (courier) `Ctrl-b` restore from a backup (T73).
    pub restore_available: bool,
    /// (courier) `Ctrl-g` log in to a sync server (T90, feature `sync`).
    pub sync_available: bool,
}

impl FirstRunForm {
    /// A form; the checkbox is offered only if `keyring_available`.
    pub(crate) fn new(keyring_available: bool) -> Self {
        Self {
            keyring_available,
            ..Self::default()
        }
    }

    fn next(&self) -> FirstRunFocus {
        match self.focus {
            FirstRunFocus::Password => FirstRunFocus::Confirm,
            FirstRunFocus::Confirm if self.keyring_available => FirstRunFocus::Keyring,
            FirstRunFocus::Confirm | FirstRunFocus::Keyring => FirstRunFocus::Password,
        }
    }

    fn prev(&self) -> FirstRunFocus {
        match self.focus {
            FirstRunFocus::Password if self.keyring_available => FirstRunFocus::Keyring,
            FirstRunFocus::Password | FirstRunFocus::Keyring => FirstRunFocus::Confirm,
            FirstRunFocus::Confirm => FirstRunFocus::Password,
        }
    }

    /// Pasted text into the focused field.
    pub(crate) fn paste(&mut self, text: &str) {
        if self.busy {
            return;
        }
        match self.focus {
            FirstRunFocus::Password => {
                self.new.password.push_str(text);
                self.new.refresh_strength();
            }
            FirstRunFocus::Confirm => self.new.confirm.push_str(text),
            FirstRunFocus::Keyring => return,
        }
        self.error = None;
    }

    /// Handle a key.
    pub(crate) fn handle_key(&mut self, key: KeyChord) -> FormAction {
        if self.busy {
            return FormAction::None;
        }
        if is_ctrl(key, 'n') {
            return FormAction::ContinueWithoutVault;
        }
        if is_ctrl(key, 'b') && self.restore_available {
            return FormAction::Restore;
        }
        if is_ctrl(key, 'g') && self.sync_available {
            return FormAction::SyncLogin;
        }
        if is_plain(key, KeyCode::Tab) || is_plain(key, KeyCode::Down) {
            self.focus = self.next();
            return FormAction::Changed;
        }
        if is_backtab(key) || is_plain(key, KeyCode::Up) {
            self.focus = self.prev();
            return FormAction::Changed;
        }
        if is_plain(key, KeyCode::Enter) {
            if self.focus == FirstRunFocus::Password {
                self.focus = FirstRunFocus::Confirm;
                return FormAction::Changed;
            }
            return match self.new.validate() {
                Ok(()) => FormAction::Submit,
                Err(e) => {
                    self.error = Some(e);
                    FormAction::Changed
                }
            };
        }
        if self.focus == FirstRunFocus::Keyring {
            if is_plain(key, KeyCode::Char(' ')) {
                self.use_keyring = !self.use_keyring;
                return FormAction::Changed;
            }
            return FormAction::None;
        }
        let field = if self.focus == FirstRunFocus::Password {
            NewPasswordField::Password
        } else {
            NewPasswordField::Confirm
        };
        if self.new.edit(field, key) {
            self.error = None;
            FormAction::Changed
        } else {
            FormAction::None
        }
    }

    /// Draw the screen centred in `area`.
    pub(crate) fn render(&self, frame: &mut Frame<'_>, area: Rect, look: Look<'_>) {
        let mut lines = vec![
            BoxLine::Text(
                "courier-ftp keeps your sites, passwords, bookmarks, history and trusted keys \
                 encrypted on this machine. The master password is the only key; with sync it \
                 is also your account password."
                    .into(),
                look.style("text"),
            ),
            BoxLine::Blank,
            field_line(
                look,
                "Master password",
                &self.new.password,
                self.focus == FirstRunFocus::Password && !self.busy,
            ),
            field_line(
                look,
                "Confirm",
                &self.new.confirm,
                self.focus == FirstRunFocus::Confirm && !self.busy,
            ),
            BoxLine::Blank,
            render_meter(&self.new.strength, look),
            BoxLine::Blank,
        ];
        if self.keyring_available {
            let focused = self.focus == FirstRunFocus::Keyring && !self.busy;
            let mut text = "Also unlock with the system keyring on this device".to_owned();
            if self.use_keyring {
                text.push_str(" (it is also the only local recovery path)");
            }
            lines.push(BoxLine::spans(vec![
                (
                    if self.use_keyring { "[x] " } else { "[ ] " }.to_owned(),
                    if focused {
                        look.style("accent")
                    } else {
                        look.style("text")
                    },
                ),
                (
                    text,
                    if focused {
                        look.style("accent")
                    } else {
                        look.style("text")
                    },
                ),
            ]));
            lines.push(BoxLine::Blank);
        }
        lines.push(BoxLine::Text(
            NO_RECOVERY_WARNING.to_owned(),
            look.style("warn"),
        ));
        lines.push(BoxLine::Blank);
        lines.push(if self.busy {
            BoxLine::Text(
                format!("{} Creating your vault…", look.spinner()),
                look.style("info"),
            )
        } else if let Some(err) = &self.error {
            BoxLine::Text(err.clone(), look.style("error"))
        } else {
            BoxLine::Blank
        });
        let mut hints = "Tab next field · ".to_owned();
        if self.keyring_available {
            hints.push_str("Space toggle · ");
        }
        hints.push_str("Enter create · Ctrl-n continue without vault");
        lines.push(BoxLine::Text(hints, look.style("dim")));
        let extra: Vec<&str> = [
            (self.restore_available, "Ctrl-b restore from backup"),
            (self.sync_available, "Ctrl-g log in to a sync server"),
        ]
        .into_iter()
        .filter_map(|(on, t)| on.then_some(t))
        .collect();
        if !extra.is_empty() {
            lines.push(BoxLine::Text(extra.join(" · "), look.style("dim")));
        }
        let max = if frame.area().width <= 80 { 84 } else { 110 };
        render_box(frame, area, " Welcome to courier-ftp ", lines, look, max);
    }
}

/// `Strength          ████░ strong — feedback` (feedback only below the minimum
/// score; the label carries the strength without colour).
pub(crate) fn render_meter(strength: &PasswordStrength, look: Look<'_>) -> BoxLine {
    let filled = usize::from(strength.score.min(4)) + 1;
    let style = match strength.score {
        0 | 1 => look.style("error"),
        2 => look.style("warn"),
        _ => look.style("ok"),
    };
    let mut parts = vec![
        (format!("{:<18}", "Strength"), look.style("dim")),
        (look.symbols.bar_full.repeat(filled), style),
        (look.symbols.bar_empty.repeat(5 - filled), look.style("dim")),
        (format!(" {}", strength.label()), style),
    ];
    let feedback = strength.feedback();
    if !feedback.is_empty() && strength.score < MIN_SCORE {
        parts.push((format!(" — {feedback}"), look.style("dim")));
    }
    BoxLine::spans(parts)
}
