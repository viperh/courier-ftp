//! (courier) "Forgot master password": the recovery options that exist on this device
//! (keyring unlock, the sync account's recovery key, a backup file, a new vault) and
//! the typed confirmation before a new, empty vault replaces the current one.

use crossterm::event::KeyCode;
use ratatui::{Frame, layout::Rect};

use super::{
    Look,
    unlock::{BoxLine, FormAction, is_plain, render_box},
};
use crate::keymap::chord::KeyChord;

/// The text `NewVaultConfirm` wants typed.
pub(crate) const NEW_VAULT_PHRASE: &str = "NEW VAULT";

/// The Forgot screen: which options exist on this device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ForgotScreen {
    /// `k`: keyring unlock is enabled.
    pub keyring: bool,
    /// `s`: a sync account exists (feature `sync`, T90).
    pub sync: bool,
    /// `b`: restoring from a backup is available (T73).
    pub restore: bool,
}

impl ForgotScreen {
    /// The option letters shown, in order.
    pub(crate) fn options(&self) -> Vec<(char, &'static str)> {
        let mut out = Vec::new();
        if self.keyring {
            out.push((
                'k',
                "Unlock with the system keyring, then set a new master password",
            ));
        }
        if self.sync {
            out.push(('s', "Use the 24-word recovery key of your sync account"));
        }
        if self.restore {
            out.push(('b', "Restore from a backup file (.cftp-backup)"));
        }
        out.push((
            'n',
            "Start a new, empty vault (the current one is kept as a file)",
        ));
        out
    }

    /// Handle a key: an available option letter, or `Esc` (back).
    pub(crate) fn handle_key(&self, key: KeyChord) -> FormAction {
        if is_plain(key, KeyCode::Esc) {
            return FormAction::Cancel;
        }
        match key.printable() {
            Some(c) if self.options().iter().any(|(k, _)| *k == c) => FormAction::Choose(c),
            _ => FormAction::None,
        }
    }

    /// Draw the screen centred in `area`.
    pub(crate) fn render(&self, frame: &mut Frame<'_>, area: Rect, look: Look<'_>) {
        let mut lines = Vec::new();
        if self.keyring || self.sync {
            lines.push(BoxLine::Text(
                "Choose how to get back into your vault on this device:".into(),
                look.style("text"),
            ));
        } else {
            lines.push(BoxLine::Text(
                "Keyring unlock is off and no sync account is set up on this device, so a \
                 forgotten master password cannot be recovered here. Your saved sites, \
                 passwords and trusted keys can only be opened with the master password."
                    .into(),
                look.style("warn"),
            ));
        }
        lines.push(BoxLine::Blank);
        for (k, text) in self.options() {
            lines.push(BoxLine::spans(vec![
                (format!("{k}  "), look.style("accent")),
                (text.to_owned(), look.style("text")),
            ]));
        }
        lines.push(BoxLine::Blank);
        lines.push(BoxLine::Text("Esc back".into(), look.style("dim")));
        render_box(frame, area, " Forgot master password ", lines, look, 72);
    }
}

/// Type `NEW VAULT` to confirm starting over.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct NewVaultConfirm {
    /// What was typed (not a secret).
    pub typed: String,
    /// The last error.
    pub error: Option<String>,
}

impl NewVaultConfirm {
    /// Handle a key.
    pub(crate) fn handle_key(&mut self, key: KeyChord) -> FormAction {
        if is_plain(key, KeyCode::Esc) {
            return FormAction::Cancel;
        }
        if is_plain(key, KeyCode::Enter) {
            if self.typed == NEW_VAULT_PHRASE {
                return FormAction::Submit;
            }
            self.error = Some(format!("Type {NEW_VAULT_PHRASE} to confirm"));
            return FormAction::Changed;
        }
        if is_plain(key, KeyCode::Backspace) {
            self.typed.pop();
            self.error = None;
            return FormAction::Changed;
        }
        match key.printable() {
            Some(c) if self.typed.chars().count() < 32 => {
                self.typed.push(c);
                self.error = None;
                FormAction::Changed
            }
            _ => FormAction::None,
        }
    }

    /// Draw the screen centred in `area`.
    pub(crate) fn render(&self, frame: &mut Frame<'_>, area: Rect, look: Look<'_>) {
        let typed = crate::ui::text::sanitize(&self.typed).into_owned();
        let lines = vec![
            BoxLine::Text(
                "A new, empty vault replaces the current one. The current database is kept \
                 as a file next to it (courier-ftp.db.bak-…); nothing is deleted."
                    .into(),
                look.style("text"),
            ),
            BoxLine::Blank,
            BoxLine::spans(vec![
                (
                    format!("Type {NEW_VAULT_PHRASE} to confirm: "),
                    look.style("dim"),
                ),
                (typed, look.style("accent")),
                (look.cursor().to_owned(), look.style("accent")),
            ]),
            BoxLine::Blank,
            match &self.error {
                Some(e) => BoxLine::Text(e.clone(), look.style("error")),
                None => BoxLine::Blank,
            },
            BoxLine::Text("Enter start over · Esc back".into(), look.style("dim")),
        ];
        render_box(frame, area, " Start a new vault ", lines, look, 72);
    }
}
