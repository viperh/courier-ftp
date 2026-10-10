//! Text fields: [`TextInput`] (also masked, for passwords), [`NumberInput`]
//! and [`PathInput`] with Tab completion.

use std::path::Path;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::Modifier,
    text::{Line, Span},
    widgets::Paragraph,
};
use secrecy::SecretString;

use super::{Field, FieldOutcome, FieldValue};
use crate::ui::theme::Theme;

/// What a masked field shows per character. The real text is never drawn.
const MASK: char = '•';

type Validator = Box<dyn Fn(&str) -> Result<(), String> + Send>;

/// A single-line text field.
pub(crate) struct TextInput {
    label: String,
    chars: Vec<char>,
    cursor: usize,
    masked: bool,
    placeholder: String,
    max_len: Option<usize>,
    validator: Option<Validator>,
    /// Show the error only after the user typed or tried to submit.
    touched: bool,
}

impl TextInput {
    pub(crate) fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            chars: Vec::new(),
            cursor: 0,
            masked: false,
            placeholder: String::new(),
            max_len: None,
            validator: None,
            touched: false,
        }
    }

    /// A password field: shows `•` per character. Its characters are zeroized
    /// when cleared and when the field is dropped.
    pub(crate) fn password(label: impl Into<String>) -> Self {
        let mut input = Self::new(label);
        input.masked = true;
        // Room for a long passphrase up front, so typing doesn't reallocate
        // (and leave copies of the text behind) in the common case.
        input.chars.reserve(256);
        input
    }

    /// The text as a secret (for password fields), without an intermediate
    /// copy that outlives the call.
    pub(crate) fn secret(&self) -> SecretString {
        SecretString::from(self.text())
    }

    /// Run `f` on the text in a buffer that is zeroized afterwards (strength
    /// meters).
    pub(crate) fn with_text<T>(&self, f: impl FnOnce(&str) -> T) -> T {
        let text = zeroize::Zeroizing::new(self.text());
        f(&text)
    }

    /// Whether the field is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.chars.is_empty()
    }

    /// Empty the field, zeroizing what it held.
    pub(crate) fn clear(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.chars);
        self.cursor = 0;
    }

    pub(crate) fn with_value(mut self, value: &str) -> Self {
        self.set_value(value);
        self
    }

    pub(crate) fn with_placeholder(mut self, placeholder: impl Into<String>) -> Self {
        self.placeholder = placeholder.into();
        self
    }

    pub(crate) fn with_max_len(mut self, max: usize) -> Self {
        self.max_len = Some(max);
        self.chars.truncate(max);
        self.cursor = self.cursor.min(self.chars.len());
        self
    }

    pub(crate) fn with_validator(
        mut self,
        validator: impl Fn(&str) -> Result<(), String> + Send + 'static,
    ) -> Self {
        self.validator = Some(Box::new(validator));
        self
    }

    pub(crate) fn text(&self) -> String {
        self.chars.iter().collect()
    }

    pub(crate) fn set_value(&mut self, value: &str) {
        self.chars = value.chars().collect();
        if let Some(max) = self.max_len {
            self.chars.truncate(max);
        }
        self.cursor = self.chars.len();
    }

    /// Mark as touched so a validation error shows (the form does this on
    /// submit).
    pub(crate) fn touch(&mut self) {
        self.touched = true;
    }

    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    fn insert(&mut self, text: &str) {
        for c in text.chars() {
            if self.max_len.is_some_and(|max| self.chars.len() >= max) {
                break;
            }
            self.chars.insert(self.cursor, c);
            self.cursor += 1;
        }
        self.touched = true;
    }

    fn word_left(&self) -> usize {
        let mut i = self.cursor;
        while i > 0 && self.chars[i - 1].is_whitespace() {
            i -= 1;
        }
        while i > 0 && !self.chars[i - 1].is_whitespace() {
            i -= 1;
        }
        i
    }

    fn word_right(&self) -> usize {
        let n = self.chars.len();
        let mut i = self.cursor;
        while i < n && !self.chars[i].is_whitespace() {
            i += 1;
        }
        while i < n && self.chars[i].is_whitespace() {
            i += 1;
        }
        i
    }

    pub(crate) fn validation(&self) -> Result<(), String> {
        match &self.validator {
            Some(v) => v(&self.text()),
            None => Ok(()),
        }
    }

    /// The visible text: masked, scrolled so the cursor stays in `width`.
    fn visible(&self, width: usize) -> (String, usize) {
        let shown: Vec<char> = if self.masked {
            vec![MASK; self.chars.len()]
        } else {
            self.chars.clone()
        };
        let width = width.max(1);
        let start = self.cursor.saturating_sub(width - 1);
        let end = (start + width).min(shown.len());
        (shown[start..end].iter().collect(), self.cursor - start)
    }
}

impl Drop for TextInput {
    fn drop(&mut self) {
        if self.masked {
            zeroize::Zeroize::zeroize(&mut self.chars);
        }
    }
}

impl Field for TextInput {
    fn label(&self) -> &str {
        &self.label
    }

    fn handle_key(&mut self, key: KeyEvent) -> FieldOutcome {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            // Alt + letter is a button mnemonic, never text.
            KeyCode::Char(_) if key.modifiers.contains(KeyModifiers::ALT) => {
                return FieldOutcome::Ignored;
            }
            KeyCode::Char('w') if ctrl => {
                let start = self.word_left();
                self.chars.drain(start..self.cursor);
                self.cursor = start;
                self.touched = true;
            }
            KeyCode::Char('u') if ctrl => {
                self.chars.drain(..self.cursor);
                self.cursor = 0;
                self.touched = true;
            }
            KeyCode::Char('a') if ctrl => self.cursor = 0,
            KeyCode::Char('e') if ctrl => self.cursor = self.chars.len(),
            KeyCode::Char(_) if ctrl => return FieldOutcome::Ignored,
            KeyCode::Char(c) => self.insert(&c.to_string()),
            KeyCode::Backspace => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    self.chars.remove(self.cursor);
                    self.touched = true;
                }
            }
            KeyCode::Delete => {
                if self.cursor < self.chars.len() {
                    self.chars.remove(self.cursor);
                    self.touched = true;
                }
            }
            KeyCode::Left if ctrl => self.cursor = self.word_left(),
            KeyCode::Right if ctrl => self.cursor = self.word_right(),
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => self.cursor = (self.cursor + 1).min(self.chars.len()),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.chars.len(),
            _ => return FieldOutcome::Ignored,
        }
        FieldOutcome::Consumed
    }

    /// Single-line field: line breaks in pasted text become spaces.
    fn handle_paste(&mut self, text: &str) {
        let flat: String = text
            .replace("\r\n", "\n")
            .chars()
            .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
            .filter(|c| !c.is_control())
            .collect();
        self.insert(&flat);
    }

    fn draw(&self, frame: &mut Frame, area: Rect, focused: bool, theme: &Theme) {
        let width = usize::from(area.width.max(1));
        let line = if self.chars.is_empty() && !focused {
            Line::styled(self.placeholder.clone(), theme.dim)
        } else {
            let (text, cursor) = self.visible(width);
            let mut spans: Vec<Span> = Vec::new();
            let chars: Vec<char> = text.chars().collect();
            let before: String = chars[..cursor.min(chars.len())].iter().collect();
            spans.push(Span::raw(before));
            if focused {
                let at = chars.get(cursor).map_or(' ', |c| *c);
                spans.push(Span::styled(
                    at.to_string(),
                    theme.selection.add_modifier(Modifier::REVERSED),
                ));
                let after: String = chars.iter().skip(cursor + 1).collect();
                spans.push(Span::raw(after));
            } else {
                let after: String = chars.iter().skip(cursor).collect();
                spans.push(Span::raw(after));
            }
            Line::from(spans)
        };
        let style = if focused { theme.title } else { theme.border };
        frame.render_widget(
            Paragraph::new(line).style(style.remove_modifier(Modifier::BOLD)),
            area,
        );
    }

    fn value(&self) -> FieldValue {
        if self.masked {
            FieldValue::Secret(SecretString::from(self.text()))
        } else {
            FieldValue::Text(self.text())
        }
    }

    fn error(&self) -> Option<String> {
        if !self.touched {
            return None;
        }
        self.validation().err()
    }

    fn touch(&mut self) {
        self.touched = true;
    }
}

/// A number field with a range; `Up`/`Down` step by one.
pub(crate) struct NumberInput {
    input: TextInput,
    min: i64,
    max: i64,
}

impl NumberInput {
    pub(crate) fn new(label: impl Into<String>, value: i64, min: i64, max: i64) -> Self {
        Self {
            input: TextInput::new(label).with_value(&value.to_string()),
            min,
            max,
        }
    }

    pub(crate) fn number(&self) -> Option<i64> {
        self.input.text().trim().parse().ok()
    }

    fn check(&self) -> Result<(), String> {
        match self.number() {
            Some(n) if (self.min..=self.max).contains(&n) => Ok(()),
            Some(_) => Err(format!("must be between {} and {}", self.min, self.max)),
            None => Err("must be a number".to_owned()),
        }
    }
}

impl Field for NumberInput {
    fn label(&self) -> &str {
        self.input.label()
    }

    fn handle_key(&mut self, key: KeyEvent) -> FieldOutcome {
        match key.code {
            KeyCode::Up | KeyCode::Down => {
                let step = if key.code == KeyCode::Up { 1 } else { -1 };
                let n = self.number().unwrap_or(self.min).saturating_add(step);
                self.input
                    .set_value(&n.clamp(self.min, self.max).to_string());
                self.input.touch();
                FieldOutcome::Consumed
            }
            KeyCode::Char(c)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !(c.is_ascii_digit() || (c == '-' && self.min < 0)) =>
            {
                FieldOutcome::Consumed // swallow non-digits
            }
            _ => self.input.handle_key(key),
        }
    }

    fn handle_paste(&mut self, text: &str) {
        let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
        self.input.handle_paste(&digits);
    }

    fn draw(&self, frame: &mut Frame, area: Rect, focused: bool, theme: &Theme) {
        self.input.draw(frame, area, focused, theme);
    }

    fn value(&self) -> FieldValue {
        FieldValue::Number(self.number().unwrap_or(self.min).clamp(self.min, self.max))
    }

    fn error(&self) -> Option<String> {
        self.check().err()
    }
}

/// Suggests completions for a path prefix.
pub(crate) trait Completer: Send {
    /// Every candidate that starts with `prefix` (full paths). Directories end
    /// with the separator.
    fn complete(&self, prefix: &str) -> Vec<String>;
}

/// Completes local paths from the filesystem.
#[derive(Debug, Default)]
pub(crate) struct LocalPathCompleter;

impl Completer for LocalPathCompleter {
    fn complete(&self, prefix: &str) -> Vec<String> {
        let sep = std::path::MAIN_SEPARATOR;
        let (dir, partial) = match prefix.rfind(['/', sep]) {
            Some(i) => (&prefix[..=i], &prefix[i + 1..]),
            None => ("", prefix),
        };
        let read_from = if dir.is_empty() { "." } else { dir };
        let Ok(entries) = std::fs::read_dir(Path::new(read_from)) else {
            return Vec::new();
        };
        let mut out: Vec<String> = entries
            .filter_map(Result::ok)
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                if !name.starts_with(partial) {
                    return None;
                }
                let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
                Some(format!("{dir}{name}{}", if is_dir { "/" } else { "" }))
            })
            .collect();
        out.sort();
        out
    }
}

/// A text field that completes paths with `Tab`. A unique match is filled in;
/// several matches fill in their common prefix. `Tab` with nothing to add
/// moves to the next field as usual.
pub(crate) struct PathInput {
    input: TextInput,
    completer: Box<dyn Completer>,
}

impl PathInput {
    pub(crate) fn new(label: impl Into<String>, completer: Box<dyn Completer>) -> Self {
        Self {
            input: TextInput::new(label),
            completer,
        }
    }

    pub(crate) fn with_value(mut self, value: &str) -> Self {
        self.input.set_value(value);
        self
    }

    pub(crate) fn text(&self) -> String {
        self.input.text()
    }
}

pub(super) fn common_prefix(items: &[String]) -> String {
    let Some(first) = items.first() else {
        return String::new();
    };
    let mut len = first.len();
    for item in &items[1..] {
        len = len.min(
            first
                .char_indices()
                .zip(item.chars())
                .take_while(|((_, a), b)| a == b)
                .last()
                .map_or(0, |((i, a), _)| i + a.len_utf8()),
        );
    }
    first[..len].to_owned()
}

impl Field for PathInput {
    fn label(&self) -> &str {
        self.input.label()
    }

    fn handle_key(&mut self, key: KeyEvent) -> FieldOutcome {
        if key.code == KeyCode::Tab && key.modifiers.is_empty() {
            let current = self.input.text();
            let candidates = self.completer.complete(&current);
            let completed = common_prefix(&candidates);
            if completed.len() > current.len() {
                self.input.set_value(&completed);
                return FieldOutcome::Consumed;
            }
            return FieldOutcome::Ignored;
        }
        self.input.handle_key(key)
    }

    fn handle_paste(&mut self, text: &str) {
        self.input.handle_paste(text);
    }

    fn draw(&self, frame: &mut Frame, area: Rect, focused: bool, theme: &Theme) {
        self.input.draw(frame, area, focused, theme);
    }

    fn value(&self) -> FieldValue {
        self.input.value()
    }

    fn error(&self) -> Option<String> {
        self.input.error()
    }

    fn touch(&mut self) {
        self.input.touch();
    }
}
