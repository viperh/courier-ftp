//! `SecretInput`: a password field. The value lives in a `Zeroizing<String>` whose
//! buffer is allocated once at full size (so typing never reallocates and leaves a
//! copy behind), is drawn as one mask glyph per character, never appears in `Debug`,
//! and is zeroed on `take()` and on drop.

use std::{cell::Cell, fmt};

use courier_ftp_core::secret::SecretString;
use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Position, Rect},
};
use zeroize::{Zeroize, Zeroizing};

use super::{
    Notice, Widget, WidgetCx, WidgetOutcome, clean_single_line, is_control, paste_cut_message,
    text_input::render_line,
};
use crate::keymap::chord::{KeyChord, Mods};

/// Maximum length in chars.
const MAX_CHARS: usize = 1024;

/// A password field (see the module docs).
pub(crate) struct SecretInput {
    value: Zeroizing<String>,
    chars: usize,
    max_chars: usize,
    scroll: Cell<usize>,
    notice: Option<Notice>,
    /// Times the buffer was wiped (tests check `take()` zeroes it).
    #[cfg(test)]
    pub(crate) wipes: usize,
}

impl fmt::Debug for SecretInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretInput(****)")
    }
}

impl Default for SecretInput {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretInput {
    /// An empty field; at most 1024 chars.
    pub(crate) fn new() -> Self {
        Self {
            // 4 bytes per char: the buffer never grows, so never moves.
            value: Zeroizing::new(String::with_capacity(MAX_CHARS * 4)),
            chars: 0,
            max_chars: MAX_CHARS,
            scroll: Cell::new(0),
            notice: None,
            #[cfg(test)]
            wipes: 0,
        }
    }

    /// Returns the value as a `SecretString` and clears (zeroes) the field.
    pub(crate) fn take(&mut self) -> SecretString {
        let out = SecretString::from(self.value.as_str());
        self.wipe();
        out
    }

    /// A copy of the value, leaving the field as is (form values).
    pub(crate) fn snapshot(&self) -> SecretString {
        SecretString::from(self.value.as_str())
    }

    /// No character typed.
    pub(crate) fn is_empty(&self) -> bool {
        self.chars == 0
    }

    /// Number of characters.
    pub(crate) fn len_chars(&self) -> usize {
        self.chars
    }

    fn wipe(&mut self) {
        // `String::zeroize` zeroes the whole capacity, then clears.
        self.value.zeroize();
        self.chars = 0;
        #[cfg(test)]
        {
            self.wipes += 1;
        }
    }

    fn push(&mut self, c: char) -> bool {
        if self.chars >= self.max_chars || is_control(c) {
            return false;
        }
        self.value.push(c);
        self.chars += 1;
        true
    }

    fn pop(&mut self) -> bool {
        // Zero the removed bytes too.
        let Some(c) = self.value.chars().next_back() else {
            return false;
        };
        let new_len = self.value.len() - c.len_utf8();
        // `String::pop` would leave the removed bytes in the buffer: rebuild instead.
        let kept: Zeroizing<String> = Zeroizing::new(self.value[..new_len].to_owned());
        self.value.zeroize();
        self.value.push_str(&kept);
        self.chars -= 1;
        true
    }
}

impl Widget for SecretInput {
    fn handle_key(&mut self, key: KeyChord) -> WidgetOutcome {
        let ctrl = key.mods.contains(Mods::CTRL);
        let alt = key.mods.contains(Mods::ALT);
        match key.code {
            KeyCode::Char(c) if !ctrl && !alt && !key.mods.contains(Mods::SUPER) => {
                if self.push(c) {
                    WidgetOutcome::Changed
                } else {
                    WidgetOutcome::Consumed
                }
            }
            KeyCode::Backspace if !ctrl && !alt => {
                if self.pop() {
                    WidgetOutcome::Changed
                } else {
                    WidgetOutcome::Consumed
                }
            }
            // Word deletion would reveal word boundaries: these clear the field.
            KeyCode::Char('w' | 'u') if ctrl => {
                self.wipe();
                WidgetOutcome::Changed
            }
            KeyCode::Backspace => {
                self.wipe();
                WidgetOutcome::Changed
            }
            // The cursor always stays at the end.
            KeyCode::Left | KeyCode::Right | KeyCode::Home | KeyCode::End | KeyCode::Delete => {
                WidgetOutcome::Consumed
            }
            KeyCode::Char('a' | 'e' | 'k') if ctrl => WidgetOutcome::Consumed,
            KeyCode::Char('b' | 'f' | 'd') if alt => WidgetOutcome::Consumed,
            _ => WidgetOutcome::Ignored,
        }
    }

    fn handle_paste(&mut self, text: &str) -> WidgetOutcome {
        let clean = Zeroizing::new(clean_single_line(text));
        let mut n = 0;
        let mut total = 0;
        for c in clean.chars() {
            total += 1;
            if self.push(c) {
                n += 1;
            }
        }
        if n < total {
            self.notice = Some(Notice::Status(paste_cut_message(n)));
        }
        if n > 0 {
            WidgetOutcome::Changed
        } else {
            WidgetOutcome::Consumed
        }
    }

    fn render(&self, frame: &mut Frame, area: Rect, cx: &WidgetCx) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        let area = Rect { height: 1, ..area };
        let mask = cx.symbols.bullet;
        let cells: Vec<(String, usize)> = (0..self.chars).map(|_| (mask.to_owned(), 1)).collect();
        render_line(
            frame,
            area,
            &cells,
            self.chars,
            &self.scroll,
            cx.theme.style("input"),
        );
    }

    fn is_text(&self) -> bool {
        true
    }

    fn cursor(&self, area: Rect) -> Option<Position> {
        if area.width == 0 || area.height == 0 {
            return None;
        }
        let start = self.scroll.get().min(self.chars);
        let x = u16::try_from(self.chars - start)
            .unwrap_or(u16::MAX)
            .min(area.width.saturating_sub(1));
        Some(Position::new(area.x.saturating_add(x), area.y))
    }

    fn take_notice(&mut self) -> Option<Notice> {
        self.notice.take()
    }
}
