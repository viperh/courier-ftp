//! `ButtonRow`: dialog buttons with mnemonics and roles.

use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{Widget, WidgetCx, WidgetOutcome, mnemonic_of};
use crate::{
    keymap::chord::{KeyChord, Mods},
    ui::text::{sanitize, width},
};

/// How a button behaves and looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ButtonRole {
    /// A plain button.
    Normal,
    /// Pressed by `Enter` (`DialogSubmit`) anywhere in the dialog.
    Default,
    /// The safe choice of a dangerous question (initial focus of `choose`).
    Safe,
    /// Destroys or overwrites something (drawn in `button_danger`).
    Danger,
}

/// One button.
#[derive(Debug, Clone)]
pub(crate) struct Button {
    /// Identifier returned when pressed.
    pub id: &'static str,
    /// Label (`OK`).
    pub label: String,
    /// Mnemonic letter (lower case); shown underlined.
    pub mnemonic: Option<char>,
    /// Role.
    pub role: ButtonRole,
}

impl Button {
    /// A button whose mnemonic is the label's first letter.
    pub(crate) fn new(id: &'static str, label: &str, role: ButtonRole) -> Self {
        Self {
            id,
            label: label.to_owned(),
            mnemonic: label
                .chars()
                .find(|c| c.is_alphanumeric())
                .map(|c| c.to_ascii_lowercase()),
            role,
        }
    }

    /// Without a mnemonic.
    #[must_use]
    pub(crate) fn no_mnemonic(mut self) -> Self {
        self.mnemonic = None;
        self
    }

    /// Drawn width: `[ label ]`.
    fn width(&self) -> usize {
        width(&sanitize(&self.label)) + 4
    }
}

/// A row of buttons; one has the focus.
#[derive(Debug, Clone)]
pub(crate) struct ButtonRow {
    buttons: Vec<Button>,
    focused: usize,
}

impl ButtonRow {
    /// A row with the focus on the default button (else the first).
    pub(crate) fn new(buttons: Vec<Button>) -> Self {
        let focused = buttons
            .iter()
            .position(|b| b.role == ButtonRole::Default)
            .unwrap_or(0);
        Self { buttons, focused }
    }

    /// The buttons.
    pub(crate) fn buttons(&self) -> &[Button] {
        &self.buttons
    }

    /// Index of the focused button.
    pub(crate) fn focused(&self) -> usize {
        self.focused
    }

    /// Focuses button `i` (clamped).
    pub(crate) fn set_focus(&mut self, i: usize) {
        self.focused = i.min(self.buttons.len().saturating_sub(1));
    }

    /// Id of the focused button.
    pub(crate) fn focused_id(&self) -> Option<&'static str> {
        self.buttons.get(self.focused).map(|b| b.id)
    }

    /// Id of the default button, if any.
    pub(crate) fn default_id(&self) -> Option<&'static str> {
        self.buttons
            .iter()
            .find(|b| b.role == ButtonRole::Default)
            .map(|b| b.id)
    }

    /// Index of the button whose mnemonic `key` is (`alt-<letter>` always, a plain
    /// letter when `plain`); focuses it.
    pub(crate) fn mnemonic(&mut self, key: KeyChord, plain: bool) -> Option<usize> {
        let c = mnemonic_of(key, plain)?;
        let i = self.buttons.iter().position(|b| b.mnemonic == Some(c))?;
        self.focused = i;
        Some(i)
    }

    /// Index of the default button, if any.
    pub(crate) fn default_index(&self) -> Option<usize> {
        self.buttons
            .iter()
            .position(|b| b.role == ButtonRole::Default)
    }

    /// Moves the focus; returns false at either end.
    pub(crate) fn move_focus(&mut self, forward: bool) -> bool {
        if forward && self.focused + 1 < self.buttons.len() {
            self.focused += 1;
            true
        } else if !forward && self.focused > 0 {
            self.focused -= 1;
            true
        } else {
            false
        }
    }

    /// Display width of the whole row.
    pub(crate) fn total_width(&self) -> usize {
        self.buttons.iter().map(Button::width).sum::<usize>()
            + 2 * self.buttons.len().saturating_sub(1)
    }
}

impl Widget for ButtonRow {
    fn handle_key(&mut self, key: KeyChord) -> WidgetOutcome {
        if key.mods.contains(Mods::CTRL) || key.mods.contains(Mods::ALT) {
            return WidgetOutcome::Ignored;
        }
        match key.code {
            KeyCode::Left | KeyCode::Char('h') => {
                self.move_focus(false);
                WidgetOutcome::Consumed
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.move_focus(true);
                WidgetOutcome::Consumed
            }
            KeyCode::Enter | KeyCode::Char(' ') => WidgetOutcome::Activated,
            _ => WidgetOutcome::Ignored,
        }
    }

    /// Centred when the row is narrower than `area`.
    fn render(&self, frame: &mut Frame, area: Rect, cx: &WidgetCx) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        let mut spans = Vec::new();
        let total = self.total_width();
        let pad = usize::from(area.width).saturating_sub(total) / 2;
        spans.push(Span::raw(" ".repeat(pad)));
        for (i, b) in self.buttons.iter().enumerate() {
            if i > 0 {
                spans.push(Span::raw("  "));
            }
            let mut style = match b.role {
                ButtonRole::Danger => cx.theme.style("button_danger"),
                _ => cx.theme.style("button"),
            };
            let focused = cx.focused && i == self.focused;
            if focused {
                style = style.patch(cx.theme.style("button_focused"));
            }
            if !cx.enabled {
                style = style.patch(cx.theme.style("field_help"));
            }
            let label = sanitize(&b.label).into_owned();
            spans.push(Span::styled("[ ", style));
            let mut marked = false;
            for ch in label.chars() {
                let s = if !marked && Some(ch.to_ascii_lowercase()) == b.mnemonic {
                    marked = true;
                    style.add_modifier(Modifier::UNDERLINED)
                } else {
                    style
                };
                spans.push(Span::styled(ch.to_string(), s));
            }
            spans.push(Span::styled(" ]", style));
        }
        frame.render_widget(
            Paragraph::new(Line::from(spans)).style(Style::default()),
            Rect { height: 1, ..area },
        );
    }
}
