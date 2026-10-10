//! The unlock prompt, the change-password form, the "password changed on another
//! device" form and the shared pieces of every vault screen: [`MaskedField`],
//! [`FormAction`] and [`render_box`] (sverb `views/unlock.rs`, D13).

use std::fmt;

use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};
use zeroize::Zeroizing;

use super::{
    Look,
    first_run::{NewPassword, NewPasswordField, render_meter},
};
use crate::{
    components::dialog::wrap_text,
    keymap::chord::{KeyChord, Mods},
};

/// Masked fields show at most this many mask glyphs (the length beyond is not shown).
pub(crate) const MASK_CAP: usize = 32;

/// A masked text field. `Debug` never prints the text; the buffer is zeroized on drop.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct MaskedField {
    text: Zeroizing<String>,
}

impl fmt::Debug for MaskedField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MaskedField({} chars)", self.len())
    }
}

impl MaskedField {
    /// Number of characters typed.
    pub(crate) fn len(&self) -> usize {
        self.text.chars().count()
    }

    /// Nothing typed.
    pub(crate) fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// The text (keep borrows short).
    pub(crate) fn expose(&self) -> &str {
        &self.text
    }

    /// Append one character (control characters are ignored).
    pub(crate) fn push(&mut self, c: char) {
        if !c.is_control() {
            self.text.push(c);
        }
    }

    /// Append pasted text (control characters and newlines are dropped).
    pub(crate) fn push_str(&mut self, s: &str) {
        for c in s.chars() {
            self.push(c);
        }
    }

    /// Delete the last character.
    pub(crate) fn pop(&mut self) {
        self.text.pop();
    }

    /// Clear (zeroizes the old buffer).
    pub(crate) fn clear(&mut self) {
        self.text = Zeroizing::new(String::new());
    }

    /// Take the text out, leaving the field empty.
    pub(crate) fn take(&mut self) -> Zeroizing<String> {
        std::mem::take(&mut self.text)
    }

    /// The masked display: one `mask` per character, at most [`MASK_CAP`].
    pub(crate) fn masked(&self, mask: &str) -> String {
        mask.repeat(self.len().min(MASK_CAP))
    }

    /// Edit with a key: printable characters, `Backspace`; `Ctrl-u`/`Ctrl-w` clear the
    /// field (deleting by word would reveal word boundaries, T52). Returns whether the
    /// text changed.
    pub(crate) fn edit(&mut self, key: KeyChord) -> bool {
        if let Some(c) = key.printable() {
            self.push(c);
            return true;
        }
        let had = !self.is_empty();
        match key.code {
            KeyCode::Backspace if key.mods == Mods::NONE => {
                self.pop();
                had
            }
            KeyCode::Char('u' | 'w') if key.mods == Mods::CTRL => {
                self.clear();
                had
            }
            _ => false,
        }
    }
}

/// `ctrl-<c>`.
pub(crate) fn is_ctrl(key: KeyChord, c: char) -> bool {
    key.code == KeyCode::Char(c) && key.mods == Mods::CTRL
}

/// A key without modifiers.
pub(crate) fn is_plain(key: KeyChord, code: KeyCode) -> bool {
    key.code == code && key.mods == Mods::NONE
}

/// `Shift-Tab` (normalised to `Tab` + SHIFT, T51).
pub(crate) fn is_backtab(key: KeyChord) -> bool {
    key.code == KeyCode::BackTab || (key.code == KeyCode::Tab && key.mods == Mods::SHIFT)
}

/// What a form wants after a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FormAction {
    /// Nothing to do (the key was swallowed).
    None,
    /// Redraw (the form changed).
    Changed,
    /// Submit the form.
    Submit,
    /// Cancel / back.
    Cancel,
    /// "Forgot password?" (courier: opens the recovery options first).
    Forgot,
    /// (courier) Continue without the vault (quickconnect only).
    ContinueWithoutVault,
    /// (courier) Restore from a backup file (T73).
    Restore,
    /// (courier) Log in to a sync server (T90).
    SyncLogin,
    /// (courier) A letter option of the Forgot screen.
    Choose(char),
}

/// The unlock prompt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct UnlockForm {
    /// The master password.
    pub password: MaskedField,
    /// The last error ("Wrong password", …).
    pub error: Option<String>,
    /// An unlock is running ("Unlocking…"); input is ignored.
    pub busy: Option<String>,
    /// Backoff countdown in whole seconds; input is ignored while set.
    pub countdown: Option<u64>,
    /// Keyring unlock is enabled.
    pub keyring_enabled: bool,
    /// Connections or transfers keep running behind the lock overlay.
    pub sessions_open: bool,
    /// (courier) Shown at startup: offers `Ctrl-n` (continue without vault).
    pub startup: bool,
    /// (courier) A warning in the status row (second `Ctrl-q` to quit).
    pub notice: Option<String>,
}

impl UnlockForm {
    /// Whether keys are ignored (busy or counting down).
    pub(crate) fn input_disabled(&self) -> bool {
        self.busy.is_some() || self.countdown.is_some()
    }

    /// Handle a key.
    pub(crate) fn handle_key(&mut self, key: KeyChord) -> FormAction {
        if self.input_disabled() {
            return FormAction::None;
        }
        self.notice = None;
        if is_plain(key, KeyCode::Enter) {
            return if self.password.is_empty() {
                FormAction::None
            } else {
                FormAction::Submit
            };
        }
        if is_plain(key, KeyCode::Esc) {
            if self.password.is_empty() && self.error.is_none() {
                return FormAction::Cancel;
            }
            self.password.clear();
            self.error = None;
            return FormAction::Changed;
        }
        if is_ctrl(key, 'r') {
            return FormAction::Forgot;
        }
        if is_ctrl(key, 'n') && self.startup {
            return FormAction::ContinueWithoutVault;
        }
        if self.password.edit(key) {
            self.error = None;
            FormAction::Changed
        } else {
            FormAction::None
        }
    }

    /// The box lines.
    fn lines(&self, look: Look<'_>) -> Vec<BoxLine> {
        let intro = if self.sessions_open {
            "The vault is locked. Connections and transfers keep running."
        } else {
            "Enter your master password to unlock courier-ftp."
        };
        let mut lines = vec![
            BoxLine::Text(intro.to_owned(), look.style("text")),
            BoxLine::Blank,
            BoxLine::spans(vec![
                ("Password: ".to_owned(), look.style("dim")),
                (self.password.masked(look.mask()), look.style("accent")),
                (
                    if self.input_disabled() {
                        String::new()
                    } else {
                        look.cursor().to_owned()
                    },
                    look.style("accent"),
                ),
            ]),
            BoxLine::Blank,
        ];
        lines.push(if let Some(busy) = &self.busy {
            BoxLine::Text(format!("{} {busy}", look.spinner()), look.style("info"))
        } else if let Some(secs) = self.countdown {
            BoxLine::Text(
                format!("Too many failed attempts. Try again in {secs}s."),
                look.style("warn"),
            )
        } else if let Some(notice) = &self.notice {
            BoxLine::Text(notice.clone(), look.style("warn"))
        } else if let Some(err) = &self.error {
            BoxLine::Text(err.clone(), look.style("error"))
        } else {
            BoxLine::Blank
        });
        lines.push(BoxLine::Text(
            "Enter unlock · Esc clear · Ctrl-r forgot password?".to_owned(),
            look.style("dim"),
        ));
        if self.startup {
            lines.push(BoxLine::Text(
                "Ctrl-n continue without vault (quickconnect only, nothing saved)".to_owned(),
                look.style("dim"),
            ));
        }
        lines
    }

    /// Draw the prompt centred in `area`.
    pub(crate) fn render(&self, frame: &mut Frame<'_>, area: Rect, look: Look<'_>) {
        let title = format!(" {} Unlock courier-ftp ", look.lock());
        render_box(frame, area, &title, self.lines(look), look, 72);
    }
}

/// Change the master password, or set a new one after a keyring recovery (no current
/// password).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ChangePasswordForm {
    /// The current password; `None` in the keyring recovery flow.
    pub current: Option<MaskedField>,
    /// New password + confirmation + strength meter.
    pub new: NewPassword,
    /// Focused row: 0 = current (if any), then the new-password fields.
    pub focus: usize,
    /// The last error.
    pub error: Option<String>,
    /// A change is running.
    pub busy: bool,
}

impl ChangePasswordForm {
    /// The normal flow (asks for the current password).
    pub(crate) fn new() -> Self {
        Self {
            current: Some(MaskedField::default()),
            ..Self::default()
        }
    }

    /// The keyring recovery flow (no current password, cannot be cancelled).
    pub(crate) fn recovery() -> Self {
        Self::default()
    }

    /// The recovery variant.
    pub(crate) fn is_recovery(&self) -> bool {
        self.current.is_none()
    }

    fn rows(&self) -> usize {
        usize::from(self.current.is_some()) + 2
    }

    fn new_field(&self) -> Option<NewPasswordField> {
        let offset = usize::from(self.current.is_some());
        match self.focus.checked_sub(offset) {
            Some(0) => Some(NewPasswordField::Password),
            Some(1) => Some(NewPasswordField::Confirm),
            _ => None,
        }
    }

    /// Validate before submitting.
    ///
    /// # Errors
    /// A message for the form.
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.current.as_ref().is_some_and(MaskedField::is_empty) {
            return Err("Enter your current password".into());
        }
        self.new.validate()
    }

    /// The focused field.
    pub(crate) fn focused_field(&mut self) -> Option<&mut MaskedField> {
        match (self.new_field(), self.current.as_mut()) {
            (Some(NewPasswordField::Password), _) => Some(&mut self.new.password),
            (Some(NewPasswordField::Confirm), _) => Some(&mut self.new.confirm),
            (None, cur) => cur,
        }
    }

    /// Pasted text into the focused field.
    pub(crate) fn paste(&mut self, text: &str) {
        if self.busy {
            return;
        }
        let refresh = self.new_field() == Some(NewPasswordField::Password);
        if let Some(f) = self.focused_field() {
            f.push_str(text);
        }
        if refresh {
            self.new.refresh_strength();
        }
        self.error = None;
    }

    /// Handle a key.
    pub(crate) fn handle_key(&mut self, key: KeyChord) -> FormAction {
        if self.busy {
            return FormAction::None;
        }
        if is_plain(key, KeyCode::Esc) {
            if self.is_recovery() {
                self.error = Some("Set a new password to finish recovery".into());
                return FormAction::Changed;
            }
            return FormAction::Cancel;
        }
        if is_plain(key, KeyCode::Tab) || is_plain(key, KeyCode::Down) {
            self.focus = (self.focus + 1) % self.rows();
            return FormAction::Changed;
        }
        if is_backtab(key) || is_plain(key, KeyCode::Up) {
            self.focus = (self.focus + self.rows() - 1) % self.rows();
            return FormAction::Changed;
        }
        if is_plain(key, KeyCode::Enter) {
            if self.focus + 1 < self.rows() {
                self.focus += 1;
                return FormAction::Changed;
            }
            return match self.validate() {
                Ok(()) => FormAction::Submit,
                Err(e) => {
                    self.error = Some(e);
                    FormAction::Changed
                }
            };
        }
        let changed = match (self.new_field(), self.current.as_mut()) {
            (Some(field), _) => self.new.edit(field, key),
            (None, Some(cur)) => cur.edit(key),
            (None, None) => false,
        };
        if changed {
            self.error = None;
            FormAction::Changed
        } else {
            FormAction::None
        }
    }

    /// Draw the form centred in `area`.
    pub(crate) fn render(&self, frame: &mut Frame<'_>, area: Rect, look: Look<'_>) {
        let mut lines = Vec::new();
        if self.current.is_none() {
            lines.push(BoxLine::Text(
                "Unlocked with the keyring. Choose a new master password.".into(),
                look.style("text"),
            ));
            lines.push(BoxLine::Blank);
        }
        let mut row = 0;
        if let Some(cur) = &self.current {
            lines.push(field_line(
                look,
                "Current password",
                cur,
                self.focus == row && !self.busy,
            ));
            row += 1;
        }
        lines.push(field_line(
            look,
            "New password",
            &self.new.password,
            self.focus == row && !self.busy,
        ));
        lines.push(field_line(
            look,
            "Confirm",
            &self.new.confirm,
            self.focus == row + 1 && !self.busy,
        ));
        lines.push(BoxLine::Blank);
        lines.push(render_meter(&self.new.strength, look));
        lines.push(BoxLine::Blank);
        lines.push(if self.busy {
            BoxLine::Text(
                format!("{} Changing the password…", look.spinner()),
                look.style("info"),
            )
        } else if let Some(err) = &self.error {
            BoxLine::Text(err.clone(), look.style("error"))
        } else {
            BoxLine::Blank
        });
        let hints = if self.is_recovery() {
            "Tab next field · Enter save"
        } else {
            "Tab next field · Enter save · Esc cancel"
        };
        lines.push(BoxLine::Text(hints.into(), look.style("dim")));
        render_box(frame, area, " Change master password ", lines, look, 76);
    }
}

/// (courier) The master password was changed on another device (T87 §10).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PasswordElsewhereForm {
    /// The new password.
    pub password: MaskedField,
    /// The last error.
    pub error: Option<String>,
    /// Signing in.
    pub busy: bool,
}

impl PasswordElsewhereForm {
    /// Handle a key.
    pub(crate) fn handle_key(&mut self, key: KeyChord) -> FormAction {
        if self.busy {
            return FormAction::None;
        }
        if is_plain(key, KeyCode::Esc) {
            return FormAction::Cancel;
        }
        if is_plain(key, KeyCode::Enter) {
            return if self.password.is_empty() {
                FormAction::None
            } else {
                FormAction::Submit
            };
        }
        if self.password.edit(key) {
            self.error = None;
            FormAction::Changed
        } else {
            FormAction::None
        }
    }

    /// Draw the form centred in `area`.
    pub(crate) fn render(&self, frame: &mut Frame<'_>, area: Rect, look: Look<'_>) {
        let mut lines = vec![
            BoxLine::Text(
                "Your master password was changed on another device. Sync is paused on this \
                 device until you enter the new password. Local unlock keeps using the old \
                 one until then."
                    .into(),
                look.style("text"),
            ),
            BoxLine::Blank,
            BoxLine::spans(vec![
                ("New password: ".to_owned(), look.style("dim")),
                (self.password.masked(look.mask()), look.style("accent")),
                (
                    if self.busy {
                        String::new()
                    } else {
                        look.cursor().to_owned()
                    },
                    look.style("accent"),
                ),
            ]),
            BoxLine::Blank,
        ];
        if self.busy {
            lines.push(BoxLine::Text(
                format!("{} Signing in…", look.spinner()),
                look.style("info"),
            ));
        } else if let Some(err) = &self.error {
            lines.push(BoxLine::Text(err.clone(), look.style("error")));
        }
        lines.push(BoxLine::Text(
            "Enter continue · Esc later (sync stays paused)".into(),
            look.style("dim"),
        ));
        render_box(
            frame,
            area,
            " Password changed on another device ",
            lines,
            look,
            76,
        );
    }
}

/// `Label             ••••▏` (labels padded to 18 columns).
pub(crate) fn field_line(
    look: Look<'_>,
    label: &str,
    field: &MaskedField,
    focused: bool,
) -> BoxLine {
    let label_style = if focused {
        look.style("accent")
    } else {
        look.style("dim")
    };
    let value_style = if focused {
        look.style("accent")
    } else {
        look.style("text")
    };
    BoxLine::spans(vec![
        (format!("{label:<18}"), label_style),
        (field.masked(look.mask()), value_style),
        (
            if focused {
                look.cursor().to_owned()
            } else {
                String::new()
            },
            look.style("accent"),
        ),
    ])
}

/// One line of a vault box.
#[derive(Debug, Clone)]
pub(crate) enum BoxLine {
    /// Styled spans drawn as they are (cut at the box width).
    Spans(Vec<(String, Style)>),
    /// Text wrapped at the box width, in one style.
    Text(String, Style),
    /// An empty line.
    Blank,
}

impl BoxLine {
    /// Spans from `(text, style)` pairs.
    pub(crate) fn spans(parts: Vec<(String, Style)>) -> Self {
        Self::Spans(parts)
    }

    fn width(&self) -> usize {
        match self {
            Self::Spans(parts) => parts.iter().map(|(t, _)| crate::ui::text::width(t)).sum(),
            Self::Text(t, _) => crate::ui::text::width(t),
            Self::Blank => 0,
        }
    }
}

/// A centred, cleared, bordered box sized to its content: width = longest line + 4,
/// capped at `max_width` and the area; text lines wrap at the inner width; height =
/// the (wrapped) lines + 2, capped at the area (sverb `render_box`). Infallible at any
/// size.
pub(crate) fn render_box(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    lines: Vec<BoxLine>,
    look: Look<'_>,
    max_width: u16,
) {
    if area.width < 3 || area.height < 3 {
        return;
    }
    let title = look.text(title).into_owned();
    let natural = lines
        .iter()
        .map(BoxLine::width)
        .max()
        .unwrap_or(0)
        .max(crate::ui::text::width(&title) + 2);
    let width = u16::try_from(natural.saturating_add(4))
        .unwrap_or(u16::MAX)
        .min(max_width)
        .min(area.width);
    let inner = width.saturating_sub(2).max(1);
    let mut rendered: Vec<Line<'static>> = Vec::new();
    for line in lines {
        match line {
            BoxLine::Blank => rendered.push(Line::raw("")),
            BoxLine::Spans(parts) => rendered.push(Line::from(
                parts
                    .into_iter()
                    .map(|(t, s)| Span::styled(look.text(&t).into_owned(), s))
                    .collect::<Vec<_>>(),
            )),
            BoxLine::Text(text, style) => {
                for l in wrap_text(&look.text(&text), inner) {
                    rendered.push(Line::styled(l, style));
                }
            }
        }
    }
    let height = u16::try_from(rendered.len().saturating_add(2))
        .unwrap_or(u16::MAX)
        .min(area.height);
    let rect = Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, rect);
    let block = Block::bordered()
        .border_set(look.symbols.border)
        .border_style(look.style("border"))
        .title(Span::styled(title, look.style("title")));
    frame.render_widget(
        Paragraph::new(rendered)
            .style(look.style("text"))
            .block(block),
        rect,
    );
}
