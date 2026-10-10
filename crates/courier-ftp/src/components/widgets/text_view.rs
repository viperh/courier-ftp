//! `TextView`: read-only text (raw listings, the app log, configuration problems) with
//! vertical and horizontal scrolling and a search.

use std::cell::Cell;

use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Position, Rect},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};
use unicode_width::UnicodeWidthChar;

use super::{Widget, WidgetCx, WidgetOutcome, is_control};
use crate::{
    keymap::chord::{KeyChord, Mods},
    ui::text::{sanitize, truncate_to_width},
};

/// Lines kept at most.
pub(crate) const MAX_LINES: usize = 1_000_000;
/// Columns per `h`/`l`.
const HSTEP: usize = 4;

/// A read-only text viewer.
#[derive(Debug)]
pub(crate) struct TextView {
    lines: Vec<String>,
    row: usize,
    col: usize,
    page: Cell<u16>,
    search: String,
    typing: bool,
    not_found: bool,
}

impl TextView {
    /// A viewer over `text`, sanitised, at most 1 000 000 lines.
    pub(crate) fn new(text: &str) -> Self {
        let mut lines: Vec<String> = text
            .split('\n')
            .take(MAX_LINES)
            .map(|l| sanitize(l.strip_suffix('\r').unwrap_or(l)).into_owned())
            .collect();
        if lines.len() > 1 && lines.last().is_some_and(String::is_empty) {
            lines.pop();
        }
        Self {
            lines,
            row: 0,
            col: 0,
            page: Cell::new(10),
            search: String::new(),
            typing: false,
            not_found: false,
        }
    }

    /// The lines (sanitised).
    pub(crate) fn lines(&self) -> &[String] {
        &self.lines
    }

    /// First visible row and column.
    pub(crate) fn scroll(&self) -> (usize, usize) {
        (self.row.min(self.max_row()), self.col)
    }

    fn max_row(&self) -> usize {
        self.lines
            .len()
            .saturating_sub(usize::from(self.page.get()).max(1))
    }

    fn scroll_by(&mut self, by: isize) {
        let row = self.row.min(self.max_row());
        let r = if by < 0 {
            row.saturating_sub(by.unsigned_abs())
        } else {
            row + by.unsigned_abs()
        };
        self.row = r.min(self.max_row());
    }

    fn find(&mut self, forward: bool, from_next: bool) {
        if self.search.is_empty() {
            return;
        }
        let q = self.search.to_lowercase();
        let n = self.lines.len();
        let start = if from_next { 1 } else { 0 };
        for k in start..n + start {
            let i = if forward {
                (self.row + k) % n
            } else {
                (self.row + n - k % n) % n
            };
            if self.lines[i].to_lowercase().contains(&q) {
                self.row = i;
                self.not_found = false;
                return;
            }
        }
        self.not_found = true;
    }

    fn search_key(&mut self, key: KeyChord) -> WidgetOutcome {
        match key.code {
            KeyCode::Esc => {
                self.typing = false;
                self.search.clear();
                self.not_found = false;
            }
            KeyCode::Enter => {
                self.typing = false;
                self.find(true, false);
            }
            KeyCode::Backspace => {
                self.search.pop();
            }
            KeyCode::Char(c) if key.printable().is_some() && !is_control(c) => self.search.push(c),
            _ => {}
        }
        WidgetOutcome::Consumed
    }

    fn cut(line: &str, col: usize, w: usize) -> String {
        let mut skipped = 0;
        let mut s = String::new();
        let mut used = 0;
        for c in line.chars() {
            let cw = c.width().unwrap_or(0);
            if skipped < col {
                skipped += cw;
                continue;
            }
            if used + cw > w {
                break;
            }
            used += cw;
            s.push(c);
        }
        s
    }
}

impl Widget for TextView {
    fn handle_key(&mut self, key: KeyChord) -> WidgetOutcome {
        if self.typing {
            return self.search_key(key);
        }
        if key.mods.contains(Mods::CTRL) || key.mods.contains(Mods::ALT) {
            return WidgetOutcome::Ignored;
        }
        let page = isize::try_from(self.page.get().max(2) - 1).unwrap_or(1);
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => self.scroll_by(1),
            KeyCode::Up | KeyCode::Char('k') => self.scroll_by(-1),
            KeyCode::PageDown => self.scroll_by(page),
            KeyCode::PageUp => self.scroll_by(-page),
            KeyCode::Home => self.row = 0,
            // Clamped when drawn (the page height may change with the search bar).
            KeyCode::End => self.row = self.lines.len(),
            KeyCode::Left | KeyCode::Char('h') => self.col = self.col.saturating_sub(HSTEP),
            KeyCode::Right | KeyCode::Char('l') => self.col += HSTEP,
            KeyCode::Char('/') => {
                self.typing = true;
                self.search.clear();
                self.not_found = false;
            }
            KeyCode::Char('n') => self.find(true, true),
            KeyCode::Char('N') => self.find(false, true),
            KeyCode::Esc if !self.search.is_empty() => {
                self.search.clear();
                self.not_found = false;
            }
            _ => return WidgetOutcome::Ignored,
        }
        WidgetOutcome::Consumed
    }

    fn render(&self, frame: &mut Frame, area: Rect, cx: &WidgetCx) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        let bar = (self.typing || !self.search.is_empty()) && area.height > 1;
        let rows = area.height - u16::from(bar);
        self.page.set(rows);
        let w = usize::from(area.width);
        let q = (!self.search.is_empty() && !self.typing).then(|| self.search.to_lowercase());
        let mut lines: Vec<Line> = self
            .lines
            .iter()
            .skip(
                self.row
                    .min(self.lines.len().saturating_sub(usize::from(rows))),
            )
            .take(usize::from(rows))
            .map(|l| {
                let s = Self::cut(l, self.col, w);
                let hit = q.as_ref().is_some_and(|q| l.to_lowercase().contains(q));
                let style = if hit {
                    cx.theme.style("list_marked")
                } else {
                    Style::default()
                };
                Line::from(Span::styled(s, style))
            })
            .collect();
        if bar {
            while lines.len() < usize::from(rows) {
                lines.push(Line::default());
            }
            let caret = if self.typing && cx.focused { "_" } else { "" };
            let mut t = format!("/{}{caret}", sanitize(&self.search));
            if self.not_found {
                t.push_str("  (not found)");
            }
            lines.push(Line::from(Span::styled(
                truncate_to_width(&t, w, cx.symbols.ellipsis).into_owned(),
                cx.theme.style("field_help"),
            )));
        }
        frame.render_widget(Paragraph::new(lines), area);
    }

    fn height(&self, _width: u16) -> u16 {
        u16::try_from(self.lines.len().clamp(1, 20)).unwrap_or(20)
    }

    fn is_text(&self) -> bool {
        self.typing
    }

    fn uses_vertical_keys(&self) -> bool {
        true
    }

    fn cursor(&self, _area: Rect) -> Option<Position> {
        None
    }
}
