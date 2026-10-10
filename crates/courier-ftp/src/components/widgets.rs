//! Standalone widgets (T52): text, secret and number fields, checkboxes, radio groups,
//! buttons, selects, lists, path completion, multi-line text and a read-only viewer.
//!
//! Widgets are plain state machines: they get [`KeyChord`]s before any key table
//! ("fixed keys", T51), report what they did as a [`WidgetOutcome`] and draw themselves
//! into a [`Rect`]. They work inside dialogs ([`crate::components::dialog`]) and outside
//! them (address bar T53, quickconnect T58, the `:` line T62). Every value drawn passes
//! through [`sanitize`](crate::ui::text::sanitize) (defence in depth, T91).

#![allow(
    dead_code,
    unused_imports,
    reason = "framework: parts are used only by the dialogs of T53–T71"
)]

use ratatui::{
    Frame,
    layout::{Position, Rect},
};
use tokio::time::Instant;

use crate::{
    keymap::chord::KeyChord,
    ui::{symbols::Symbols, theme::Theme},
};

mod button;
mod list_view;
mod number;
mod path_input;
mod secret;
mod select;
mod text_area;
mod text_input;
mod text_view;
mod toggle;

#[cfg(test)]
mod tests;

pub(crate) use button::{Button, ButtonRole, ButtonRow};
pub(crate) use list_view::{ListRow, ListView};
pub(crate) use number::NumberInput;
pub(crate) use path_input::{Completion, LocalPathCompleter, PathCompleter, PathInput};
pub(crate) use secret::SecretInput;
pub(crate) use select::{Select, SelectOption};
pub(crate) use text_area::TextArea;
pub(crate) use text_input::{TextInput, Validator};
pub(crate) use text_view::TextView;
pub(crate) use toggle::{Checkbox, RadioGroup, TriState, TriStateCheckbox};

/// What a widget did with a key or a paste.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WidgetOutcome {
    /// Not used; the container (form, key table) handles it.
    Ignored,
    /// Used, the value did not change (cursor moved, popup opened).
    Consumed,
    /// The value changed.
    Changed,
    /// Enter on a list row, a button press, a choice in a popup.
    Activated,
}

impl WidgetOutcome {
    /// The widget used the key.
    pub(crate) fn is_used(self) -> bool {
        self != Self::Ignored
    }
}

/// Something a widget wants its container to do, outside of a key's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Notice {
    /// Show this on the status line ("Pasted text was cut to 10 characters").
    Status(String),
    /// Move the focus to the next field (a path completion found nothing).
    NextField,
}

/// Read-only context for drawing a widget.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WidgetCx<'a> {
    /// Resolved styles.
    pub theme: &'a Theme,
    /// Glyphs.
    pub symbols: &'a Symbols,
    /// The widget has the focus.
    pub focused: bool,
    /// The widget can be used (disabled widgets are drawn dim).
    pub enabled: bool,
    /// Now (virtual in tests).
    pub now: Instant,
}

/// A widget (see the module docs).
pub(crate) trait Widget {
    /// A key, before any key table.
    fn handle_key(&mut self, key: KeyChord) -> WidgetOutcome;

    /// Bracketed paste (only text widgets take it).
    fn handle_paste(&mut self, text: &str) -> WidgetOutcome {
        let _ = text;
        WidgetOutcome::Ignored
    }

    /// Async results (path completion) arrived; called on `Action::Wake` and every
    /// tick. Returns whether something changed.
    fn poll(&mut self) -> bool {
        false
    }

    /// Draws the widget into `area`.
    fn render(&self, frame: &mut Frame, area: Rect, cx: &WidgetCx);

    /// Draws what goes on top of everything else (an open `Select` popup, completion
    /// candidates) below the widget's `area`, inside `bounds`.
    fn render_overlay(&self, frame: &mut Frame, area: Rect, bounds: Rect, cx: &WidgetCx) {
        let _ = (frame, area, bounds, cx);
    }

    /// Rows needed at this width (1 for single-line widgets).
    fn height(&self, width: u16) -> u16 {
        let _ = width;
        1
    }

    /// Plain letters are typed into it (so mnemonics need Alt while it has focus).
    fn is_text(&self) -> bool {
        false
    }

    /// The widget uses `↑`/`↓` itself (so they do not move between form fields).
    fn uses_vertical_keys(&self) -> bool {
        false
    }

    /// Where to place the terminal cursor when focused.
    fn cursor(&self, area: Rect) -> Option<Position> {
        let _ = area;
        None
    }

    /// A pending [`Notice`] (taken once).
    fn take_notice(&mut self) -> Option<Notice> {
        None
    }
}

/// C0 controls, DEL and C1 controls.
pub(crate) fn is_control(c: char) -> bool {
    let n = u32::from(c);
    n < 0x20 || n == 0x7F || (0x80..=0x9F).contains(&n)
}

/// Word separators of the text editing keys: whitespace and `/ \ . - _ : @`.
pub(crate) fn is_word_separator(g: &str) -> bool {
    let mut chars = g.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) => {
            c.is_whitespace() || matches!(c, '/' | '\\' | '.' | '-' | '_' | ':' | '@')
        }
        _ => false,
    }
}

fn strip_trailing_newlines(text: &str) -> &str {
    text.trim_end_matches(['\r', '\n'])
}

/// Paste rules for single-line fields: trailing `\r`/`\n` removed, each remaining
/// `\r\n`, `\r`, `\n` and `\t` becomes one space, other C0/C1 controls and DEL are
/// removed.
pub(crate) fn clean_single_line(text: &str) -> String {
    let text = strip_trailing_newlines(text);
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push(' ');
            }
            '\n' | '\t' => out.push(' '),
            c if is_control(c) => {}
            c => out.push(c),
        }
    }
    out
}

/// Paste rules for `TextArea`: `\r\n` and `\r` become `\n`, `\t` four spaces, other
/// controls are removed; a trailing line break is dropped.
pub(crate) fn clean_multi_line(text: &str) -> String {
    let text = strip_trailing_newlines(text);
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push('\n');
            }
            '\n' => out.push('\n'),
            '\t' => out.push_str("    "),
            c if is_control(c) => {}
            c => out.push(c),
        }
    }
    out
}

/// The status message for a paste cut to `n` characters.
pub(crate) fn paste_cut_message(n: usize) -> String {
    format!("Pasted text was cut to {n} characters")
}

/// Mnemonic letter of a key: `alt-<letter>` always, a plain letter when `plain` is
/// allowed (the focused widget is not text-like). Lower-cased.
pub(crate) fn mnemonic_of(key: KeyChord, plain: bool) -> Option<char> {
    use crossterm::event::KeyCode;

    use crate::keymap::chord::Mods;
    let KeyCode::Char(c) = key.code else {
        return None;
    };
    if !c.is_alphanumeric() {
        return None;
    }
    let m = key.mods;
    if m.contains(Mods::CTRL) || m.contains(Mods::SUPER) {
        return None;
    }
    if m.contains(Mods::ALT) || plain {
        return Some(c.to_ascii_lowercase());
    }
    None
}
