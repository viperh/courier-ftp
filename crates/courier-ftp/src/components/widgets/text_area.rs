//! `TextArea`: multi-line plain text (site comments, T59). The text editing keys work
//! on the cursor line; `Enter` splits it, `↑`/`↓` and `PageUp`/`PageDown` move between
//! lines, `Tab` leaves the field.

use std::cell::Cell;

use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Position, Rect},
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{
    Notice, Widget, WidgetCx, WidgetOutcome, clean_multi_line, is_control, paste_cut_message,
    text_input::{Edit, apply_edit, display_cells, grapheme_len},
};
use crate::keymap::chord::{KeyChord, Mods};

/// Maximum size in bytes (lines joined with `\n`).
const MAX_BYTES: usize = 65536;

/// A multi-line field.
#[derive(Debug)]
pub(crate) struct TextArea {
    lines: Vec<String>,
    row: usize,
    /// Grapheme column.
    col: usize,
    max_bytes: usize,
    visible_rows: u16,
    scroll: Cell<(usize, usize)>,
    notice: Option<Notice>,
}

impl TextArea {
    /// A field holding `initial` (cursor at the end).
    pub(crate) fn new(initial: &str) -> Self {
        let mut t = Self {
            lines: vec![String::new()],
            row: 0,
            col: 0,
            max_bytes: MAX_BYTES,
            visible_rows: 4,
            scroll: Cell::new((0, 0)),
            notice: None,
        };
        t.set_value(initial);
        t
    }

    /// Rows the widget asks for inside a form (default 4).
    #[must_use]
    pub(crate) fn visible_rows(mut self, n: u16) -> Self {
        self.visible_rows = n.max(1);
        self
    }

    /// The text, lines joined with `\n`.
    pub(crate) fn value(&self) -> String {
        self.lines.join("\n")
    }

    /// The lines.
    pub(crate) fn lines(&self) -> &[String] {
        &self.lines
    }

    /// Replaces the text (cleaned, cut to 64 KiB); cursor to the end.
    pub(crate) fn set_value(&mut self, v: &str) {
        let clean = clean_multi_line(v);
        let mut end = clean.len().min(self.max_bytes);
        while !clean.is_char_boundary(end) {
            end -= 1;
        }
        self.lines = clean[..end].split('\n').map(str::to_owned).collect();
        self.row = self.lines.len() - 1;
        self.col = grapheme_len(&self.lines[self.row]);
    }

    /// Cursor (row, grapheme column).
    pub(crate) fn cursor_pos(&self) -> (usize, usize) {
        (self.row, self.col)
    }

    fn total_bytes(&self) -> usize {
        self.lines.iter().map(String::len).sum::<usize>() + self.lines.len() - 1
    }

    fn line_len(&self, row: usize) -> usize {
        self.lines.get(row).map_or(0, |l| grapheme_len(l))
    }

    fn move_rows(&mut self, by: isize) {
        let last = self.lines.len() - 1;
        let row = if by < 0 {
            self.row.saturating_sub(by.unsigned_abs())
        } else {
            (self.row + by.unsigned_abs()).min(last)
        };
        self.row = row;
        self.col = self.col.min(self.line_len(row));
    }

    fn insert_text(&mut self, text: &str) {
        let line = &mut self.lines[self.row];
        let b = super::text_input::grapheme_bounds(line);
        let at = b[self.col.min(b.len() - 1)];
        let tail = line.split_off(at);
        let mut parts = text.split('\n');
        if let Some(first) = parts.next() {
            line.push_str(first);
        }
        for p in parts {
            self.row += 1;
            self.lines.insert(self.row, p.to_owned());
        }
        let cur = &mut self.lines[self.row];
        self.col = grapheme_len(cur);
        cur.push_str(&tail);
    }
}

impl Widget for TextArea {
    fn handle_key(&mut self, key: KeyChord) -> WidgetOutcome {
        let ctrl = key.mods.contains(Mods::CTRL);
        let alt = key.mods.contains(Mods::ALT);
        let page = isize::try_from(self.visible_rows.max(2) - 1).unwrap_or(1);
        match key.code {
            KeyCode::Enter if !ctrl && !alt => {
                if self.total_bytes() < self.max_bytes {
                    self.insert_text("\n");
                    return WidgetOutcome::Changed;
                }
                return WidgetOutcome::Consumed;
            }
            KeyCode::Up if !ctrl && !alt => {
                self.move_rows(-1);
                return WidgetOutcome::Consumed;
            }
            KeyCode::Down if !ctrl && !alt => {
                self.move_rows(1);
                return WidgetOutcome::Consumed;
            }
            KeyCode::PageUp => {
                self.move_rows(-page);
                return WidgetOutcome::Consumed;
            }
            KeyCode::PageDown => {
                self.move_rows(page);
                return WidgetOutcome::Consumed;
            }
            KeyCode::Backspace if !ctrl && !alt && self.col == 0 => {
                if self.row == 0 {
                    return WidgetOutcome::Consumed;
                }
                let line = self.lines.remove(self.row);
                self.row -= 1;
                self.col = self.line_len(self.row);
                self.lines[self.row].push_str(&line);
                return WidgetOutcome::Changed;
            }
            KeyCode::Delete if self.col >= self.line_len(self.row) => {
                if self.row + 1 >= self.lines.len() {
                    return WidgetOutcome::Consumed;
                }
                let next = self.lines.remove(self.row + 1);
                self.lines[self.row].push_str(&next);
                return WidgetOutcome::Changed;
            }
            KeyCode::Char(c)
                if key.printable().is_some()
                    && (is_control(c) || self.total_bytes() + c.len_utf8() > self.max_bytes) =>
            {
                return WidgetOutcome::Consumed;
            }
            _ => {}
        }
        let line = &mut self.lines[self.row];
        match apply_edit(line, &mut self.col, key, usize::MAX) {
            Edit::NotEditing => WidgetOutcome::Ignored,
            e => e.outcome(),
        }
    }

    fn handle_paste(&mut self, text: &str) -> WidgetOutcome {
        let clean = clean_multi_line(text);
        let room = self.max_bytes.saturating_sub(self.total_bytes());
        let mut end = clean.len().min(room);
        while !clean.is_char_boundary(end) {
            end -= 1;
        }
        let kept = &clean[..end];
        if end < clean.len() {
            self.notice = Some(Notice::Status(paste_cut_message(kept.chars().count())));
        }
        if kept.is_empty() {
            return WidgetOutcome::Consumed;
        }
        self.insert_text(kept);
        WidgetOutcome::Changed
    }

    fn render(&self, frame: &mut Frame, area: Rect, cx: &WidgetCx) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        let rows = usize::from(area.height);
        let w = usize::from(area.width);
        let (mut top, mut left) = self.scroll.get();
        if self.row < top {
            top = self.row;
        } else if self.row >= top + rows {
            top = self.row + 1 - rows;
        }
        let cells = display_cells(&self.lines[self.row]);
        left = left.min(self.col);
        while left < self.col && cells[left..self.col].iter().map(|c| c.1).sum::<usize>() + 1 > w {
            left += 1;
        }
        self.scroll.set((top, left));
        let style = cx.theme.style("input");
        let lines: Vec<Line> = (top..(top + rows))
            .map(|r| {
                let Some(l) = self.lines.get(r) else {
                    return Line::from(Span::styled(" ".repeat(w), style));
                };
                let mut used = 0;
                let mut s = String::new();
                for (g, gw) in display_cells(l).into_iter().skip(left) {
                    if used + gw > w {
                        break;
                    }
                    used += gw;
                    s.push_str(&g);
                }
                s.push_str(&" ".repeat(w - used));
                Line::from(Span::styled(s, style))
            })
            .collect();
        frame.render_widget(Paragraph::new(lines), area);
    }

    fn height(&self, _width: u16) -> u16 {
        self.visible_rows
    }

    fn is_text(&self) -> bool {
        true
    }

    fn uses_vertical_keys(&self) -> bool {
        true
    }

    fn cursor(&self, area: Rect) -> Option<Position> {
        if area.width == 0 || area.height == 0 {
            return None;
        }
        let (top, left) = self.scroll.get();
        let y = self.row.checked_sub(top)?;
        let cells = display_cells(&self.lines[self.row]);
        let x: usize = cells
            .get(left.min(self.col)..self.col.min(cells.len()))
            .map_or(0, |c| c.iter().map(|c| c.1).sum());
        let y = u16::try_from(y).ok().filter(|y| *y < area.height)?;
        let x = u16::try_from(x).unwrap_or(u16::MAX).min(area.width - 1);
        Some(Position::new(area.x + x, area.y + y))
    }

    fn take_notice(&mut self) -> Option<Notice> {
        self.notice.take()
    }
}
