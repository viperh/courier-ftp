//! `NumberInput`: a `TextInput` restricted to digits (and a leading `-` when the range
//! allows negatives); `↑`/`↓` step by 1, `PageUp`/`PageDown` by 10, clamped.

use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Position, Rect},
};

use super::{Notice, TextInput, Widget, WidgetCx, WidgetOutcome, clean_single_line};
use crate::keymap::chord::{KeyChord, Mods};

/// An integer field.
#[derive(Debug)]
pub(crate) struct NumberInput {
    input: TextInput,
    min: i64,
    max: i64,
    optional: bool,
}

impl NumberInput {
    /// A field for `min..=max` holding `value`.
    pub(crate) fn new(value: Option<i64>, min: i64, max: i64) -> Self {
        let (min, max) = if min <= max { (min, max) } else { (max, min) };
        let text = value
            .map(|v| v.clamp(min, max).to_string())
            .unwrap_or_default();
        Self {
            input: TextInput::new(&text).max_chars(20),
            min,
            max,
            optional: false,
        }
    }

    /// Empty is allowed (the value is then `None`).
    #[must_use]
    pub(crate) fn optional(mut self) -> Self {
        self.optional = true;
        self
    }

    /// The value; `None` when empty or not a number.
    pub(crate) fn value(&self) -> Option<i64> {
        self.input.value().parse().ok()
    }

    /// Sets the value (clamped).
    pub(crate) fn set_value(&mut self, v: Option<i64>) {
        let text = v
            .map(|v| v.clamp(self.min, self.max).to_string())
            .unwrap_or_default();
        self.input.set_value(&text);
    }

    /// The message of the last failed validation.
    pub(crate) fn error(&self) -> Option<&str> {
        self.input.error()
    }

    /// Checks emptiness and the range.
    pub(crate) fn validate(&mut self) -> bool {
        let text = self.input.value();
        let err = if text.is_empty() {
            (!self.optional).then(|| "A number is required".to_owned())
        } else {
            match text.parse::<i64>() {
                Ok(v) if (self.min..=self.max).contains(&v) => None,
                _ => Some(format!("Enter a number from {} to {}", self.min, self.max)),
            }
        };
        self.input.set_error(err);
        self.input.error().is_none()
    }

    fn accepts(&self, c: char) -> bool {
        c.is_ascii_digit()
            || (c == '-'
                && self.min < 0
                && self.input.cursor_index() == 0
                && !self.input.value().starts_with('-'))
    }

    fn step(&mut self, by: i64) -> WidgetOutcome {
        let base = self
            .value()
            .unwrap_or(if self.min > 0 { self.min } else { 0 }.min(self.max));
        let next = base.saturating_add(by).clamp(self.min, self.max);
        if self.value() == Some(next) {
            return WidgetOutcome::Consumed;
        }
        self.input.set_value(&next.to_string());
        WidgetOutcome::Changed
    }
}

impl Widget for NumberInput {
    fn handle_key(&mut self, key: KeyChord) -> WidgetOutcome {
        let plain = !key.mods.contains(Mods::CTRL) && !key.mods.contains(Mods::ALT);
        match key.code {
            KeyCode::Up if plain => self.step(1),
            KeyCode::Down if plain => self.step(-1),
            KeyCode::PageUp if plain => self.step(10),
            KeyCode::PageDown if plain => self.step(-10),
            KeyCode::Char(c) if key.printable().is_some() => {
                if self.accepts(c) {
                    self.input.handle_key(key)
                } else {
                    WidgetOutcome::Consumed
                }
            }
            _ => self.input.handle_key(key),
        }
    }

    fn handle_paste(&mut self, text: &str) -> WidgetOutcome {
        let clean: String = clean_single_line(text)
            .chars()
            .filter(char::is_ascii_digit)
            .collect();
        if self.input.insert_clean(&clean) > 0 {
            WidgetOutcome::Changed
        } else {
            WidgetOutcome::Consumed
        }
    }

    fn render(&self, frame: &mut Frame, area: Rect, cx: &WidgetCx) {
        self.input.render(frame, area, cx);
    }

    fn is_text(&self) -> bool {
        true
    }

    fn uses_vertical_keys(&self) -> bool {
        true
    }

    fn cursor(&self, area: Rect) -> Option<Position> {
        self.input.cursor(area)
    }

    fn take_notice(&mut self) -> Option<Notice> {
        self.input.take_notice()
    }
}
