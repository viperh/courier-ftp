//! `ListView`: a virtualised list with section headers, marks, per-row checkboxes, a
//! substring filter and keyboard reordering.

use std::cell::Cell;

use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{Widget, WidgetCx, WidgetOutcome, is_control};
use crate::{
    keymap::chord::{KeyChord, Mods},
    ui::text::{sanitize, truncate_to_width, width},
};

/// A row of a [`ListView`].
#[derive(Debug, Clone)]
pub(crate) enum ListRow<T> {
    /// A section title; never selectable.
    Header(String),
    /// A selectable row.
    Item {
        /// Shown text (sanitised when drawn).
        label: Line<'static>,
        /// The value.
        value: T,
        /// `Some` draws a checkbox that `space` toggles.
        checked: Option<bool>,
    },
}

impl<T> ListRow<T> {
    /// An item without checkbox.
    pub(crate) fn item(label: &str, value: T) -> Self {
        Self::Item {
            label: Line::from(label.to_owned()),
            value,
            checked: None,
        }
    }

    /// An item with a checkbox.
    pub(crate) fn check(label: &str, value: T, checked: bool) -> Self {
        Self::Item {
            label: Line::from(label.to_owned()),
            value,
            checked: Some(checked),
        }
    }

    fn is_item(&self) -> bool {
        matches!(self, Self::Item { .. })
    }

    fn text(&self) -> String {
        match self {
            Self::Header(h) => h.clone(),
            Self::Item { label, .. } => label.spans.iter().map(|s| s.content.as_ref()).collect(),
        }
    }
}

/// A list widget (see the module docs).
#[derive(Debug)]
pub(crate) struct ListView<T> {
    rows: Vec<ListRow<T>>,
    marks: Vec<bool>,
    /// Indices into `rows` currently shown (filter applied).
    view: Vec<usize>,
    /// Position in `view`.
    cursor: usize,
    scroll: Cell<usize>,
    filter: String,
    typing_filter: bool,
    markable: bool,
    reorderable: bool,
    visible_rows: u16,
}

impl<T> ListView<T> {
    /// A list over `rows`, cursor on the first item.
    pub(crate) fn new(rows: Vec<ListRow<T>>) -> Self {
        let n = rows.len();
        let mut l = Self {
            rows,
            marks: vec![false; n],
            view: Vec::new(),
            cursor: 0,
            scroll: Cell::new(0),
            filter: String::new(),
            typing_filter: false,
            markable: false,
            reorderable: false,
            visible_rows: 6,
        };
        l.rebuild_view();
        l
    }

    /// `space` marks rows (rows without a checkbox).
    #[must_use]
    pub(crate) fn markable(mut self, on: bool) -> Self {
        self.markable = on;
        self
    }

    /// `K`/`J` move the item up/down.
    #[must_use]
    pub(crate) fn reorderable(mut self, on: bool) -> Self {
        self.reorderable = on;
        self
    }

    /// Rows the widget asks for inside a form (default 6).
    #[must_use]
    pub(crate) fn visible_rows(mut self, n: u16) -> Self {
        self.visible_rows = n.max(1);
        self
    }

    /// All rows, in their current order.
    pub(crate) fn rows(&self) -> &[ListRow<T>] {
        &self.rows
    }

    /// The value under the cursor.
    pub(crate) fn cursor_value(&self) -> Option<&T> {
        match self.rows.get(*self.view.get(self.cursor)?)? {
            ListRow::Item { value, .. } => Some(value),
            ListRow::Header(_) => None,
        }
    }

    /// Index (into [`Self::rows`]) of the row under the cursor.
    pub(crate) fn cursor_row(&self) -> Option<usize> {
        self.view.get(self.cursor).copied()
    }

    /// The checkbox state of every item (`false` for items without one), in row order,
    /// headers skipped.
    pub(crate) fn checked(&self) -> Vec<bool> {
        self.rows
            .iter()
            .filter_map(|r| match r {
                ListRow::Item { checked, .. } => Some(checked.unwrap_or(false)),
                ListRow::Header(_) => None,
            })
            .collect()
    }

    /// Values of the marked items.
    pub(crate) fn marked(&self) -> Vec<&T> {
        self.rows
            .iter()
            .zip(&self.marks)
            .filter_map(|(r, m)| match r {
                ListRow::Item { value, .. } if *m => Some(value),
                _ => None,
            })
            .collect()
    }

    /// The filter text.
    pub(crate) fn filter(&self) -> &str {
        &self.filter
    }

    /// Sets the filter (substring, case-insensitive).
    pub(crate) fn set_filter(&mut self, f: &str) {
        f.clone_into(&mut self.filter);
        self.rebuild_view();
    }

    fn rebuild_view(&mut self) {
        let keep = self.cursor_row();
        if self.filter.is_empty() {
            self.view = (0..self.rows.len()).collect();
        } else {
            let f = self.filter.to_lowercase();
            self.view = self
                .rows
                .iter()
                .enumerate()
                .filter(|(_, r)| r.is_item() && r.text().to_lowercase().contains(&f))
                .map(|(i, _)| i)
                .collect();
        }
        self.cursor = keep
            .and_then(|k| self.view.iter().position(|&i| i == k))
            .unwrap_or(0);
        self.fix_cursor(true);
    }

    fn is_item_at(&self, pos: usize) -> bool {
        self.view
            .get(pos)
            .is_some_and(|&i| self.rows.get(i).is_some_and(ListRow::is_item))
    }

    /// Moves the cursor off a header, preferring `forward`.
    fn fix_cursor(&mut self, forward: bool) {
        if self.view.is_empty() {
            self.cursor = 0;
            return;
        }
        self.cursor = self.cursor.min(self.view.len() - 1);
        if self.is_item_at(self.cursor) {
            return;
        }
        let find = |fwd: bool| {
            if fwd {
                (self.cursor..self.view.len()).find(|&p| self.is_item_at(p))
            } else {
                (0..=self.cursor).rev().find(|&p| self.is_item_at(p))
            }
        };
        if let Some(p) = find(forward).or_else(|| find(!forward)) {
            self.cursor = p;
        }
    }

    fn move_by(&mut self, by: isize) {
        if self.view.is_empty() {
            return;
        }
        let last = self.view.len() - 1;
        let mut c = self.cursor;
        let mut left = by.unsigned_abs();
        while left > 0 {
            let next = if by > 0 {
                (c + 1..=last).find(|&p| self.is_item_at(p))
            } else {
                (0..c).rev().find(|&p| self.is_item_at(p))
            };
            match next {
                Some(n) => c = n,
                None => break,
            }
            left -= 1;
        }
        self.cursor = c;
    }

    fn page(&self) -> isize {
        isize::try_from(self.visible_rows.max(2) - 1).unwrap_or(1)
    }

    fn toggle(&mut self) -> WidgetOutcome {
        let Some(i) = self.cursor_row() else {
            return WidgetOutcome::Consumed;
        };
        match self.rows.get_mut(i) {
            Some(ListRow::Item {
                checked: Some(c), ..
            }) => {
                *c = !*c;
                WidgetOutcome::Changed
            }
            Some(ListRow::Item { .. }) if self.markable => {
                self.marks[i] = !self.marks[i];
                self.move_by(1);
                WidgetOutcome::Changed
            }
            _ => WidgetOutcome::Consumed,
        }
    }

    fn reorder(&mut self, down: bool) -> WidgetOutcome {
        if !self.reorderable || !self.filter.is_empty() {
            return WidgetOutcome::Consumed;
        }
        let Some(i) = self.cursor_row() else {
            return WidgetOutcome::Consumed;
        };
        let j = if down { i + 1 } else { i.wrapping_sub(1) };
        if self.rows.get(j).is_none_or(|r| !r.is_item()) {
            return WidgetOutcome::Consumed;
        }
        self.rows.swap(i, j);
        self.marks.swap(i, j);
        self.cursor = j;
        WidgetOutcome::Changed
    }

    fn filter_key(&mut self, key: KeyChord) -> WidgetOutcome {
        match key.code {
            KeyCode::Esc => {
                self.typing_filter = false;
                self.set_filter("");
            }
            KeyCode::Enter => self.typing_filter = false,
            KeyCode::Backspace => {
                let mut f = self.filter.clone();
                f.pop();
                self.set_filter(&f);
            }
            KeyCode::Char(c) if key.printable().is_some() && !is_control(c) => {
                let mut f = self.filter.clone();
                f.push(c);
                self.set_filter(&f);
            }
            KeyCode::Down | KeyCode::Up => {
                self.move_by(if key.code == KeyCode::Down { 1 } else { -1 });
            }
            _ => {}
        }
        WidgetOutcome::Consumed
    }
}

impl<T> Widget for ListView<T> {
    fn handle_key(&mut self, key: KeyChord) -> WidgetOutcome {
        if self.typing_filter {
            return self.filter_key(key);
        }
        if key.mods.contains(Mods::CTRL) || key.mods.contains(Mods::ALT) {
            return WidgetOutcome::Ignored;
        }
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => self.move_by(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_by(-1),
            KeyCode::PageDown => self.move_by(self.page()),
            KeyCode::PageUp => self.move_by(-self.page()),
            KeyCode::Home => {
                self.cursor = 0;
                self.fix_cursor(true);
            }
            KeyCode::End => {
                self.cursor = self.view.len().saturating_sub(1);
                self.fix_cursor(false);
            }
            KeyCode::Char(' ') => return self.toggle(),
            KeyCode::Enter => {
                return if self.cursor_row().is_some() {
                    WidgetOutcome::Activated
                } else {
                    WidgetOutcome::Consumed
                };
            }
            KeyCode::Char('/') => self.typing_filter = true,
            KeyCode::Esc if !self.filter.is_empty() => self.set_filter(""),
            KeyCode::Char('K') => return self.reorder(false),
            KeyCode::Char('J') => return self.reorder(true),
            _ => return WidgetOutcome::Ignored,
        }
        WidgetOutcome::Consumed
    }

    fn render(&self, frame: &mut Frame, area: Rect, cx: &WidgetCx) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        let show_filter = self.typing_filter || !self.filter.is_empty();
        let rows = usize::from(area.height) - usize::from(show_filter && area.height > 1);
        let mut scroll = self.scroll.get().min(self.view.len().saturating_sub(rows));
        if self.cursor < scroll {
            scroll = self.cursor;
        } else if rows > 0 && self.cursor >= scroll + rows {
            scroll = self.cursor + 1 - rows;
        }
        self.scroll.set(scroll);
        let w = usize::from(area.width);
        let mut lines: Vec<Line> = Vec::with_capacity(rows + 1);
        for (pos, &i) in self.view.iter().enumerate().skip(scroll).take(rows) {
            let Some(row) = self.rows.get(i) else {
                continue;
            };
            match row {
                ListRow::Header(h) => {
                    let t = truncate_to_width(&sanitize(h), w, cx.symbols.ellipsis).into_owned();
                    lines.push(Line::from(Span::styled(t, cx.theme.style("list_header"))));
                }
                ListRow::Item { label, checked, .. } => {
                    let mut prefix = String::new();
                    if self.markable {
                        prefix.push_str(if self.marks[i] {
                            cx.symbols.bullet
                        } else {
                            " "
                        });
                        prefix.push(' ');
                    }
                    if let Some(c) = checked {
                        prefix.push_str(if *c { "[x] " } else { "[ ] " });
                    }
                    let text: String = label
                        .spans
                        .iter()
                        .map(|s| sanitize(&s.content).into_owned())
                        .collect();
                    let full = format!("{prefix}{text}");
                    let t = truncate_to_width(&full, w, cx.symbols.ellipsis).into_owned();
                    let pad = w.saturating_sub(width(&t));
                    let mut style = if self.marks[i] {
                        cx.theme.style("list_marked")
                    } else {
                        Style::default()
                    };
                    if pos == self.cursor && cx.focused {
                        style = style.patch(cx.theme.style("list_cursor"));
                    }
                    lines.push(Line::from(Span::styled(
                        format!("{t}{}", " ".repeat(pad)),
                        style,
                    )));
                }
            }
        }
        if self.view.is_empty() {
            lines.push(Line::from(Span::styled(
                "(no matches)",
                cx.theme.style("field_help"),
            )));
        }
        while lines.len() < rows {
            lines.push(Line::default());
        }
        if show_filter && area.height > 1 {
            let caret = if self.typing_filter && cx.focused {
                "_"
            } else {
                ""
            };
            let t = format!("/{}{caret}", sanitize(&self.filter));
            lines.push(Line::from(Span::styled(
                truncate_to_width(&t, w, cx.symbols.ellipsis).into_owned(),
                cx.theme.style("field_help"),
            )));
        }
        frame.render_widget(Paragraph::new(lines), area);
    }

    fn height(&self, _width: u16) -> u16 {
        self.visible_rows
    }

    fn is_text(&self) -> bool {
        self.typing_filter
    }

    fn uses_vertical_keys(&self) -> bool {
        true
    }
}
