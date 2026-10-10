//! [`ListView`]: a scrollable list with one highlighted item (pickers).

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{Frame, layout::Rect, text::Line, widgets::Paragraph};

use super::{Field, FieldOutcome, FieldValue};
use crate::ui::theme::Theme;

/// A list of items; arrows, `PageUp`/`PageDown`, `Home`/`End` move.
pub(crate) struct ListView {
    label: String,
    items: Vec<String>,
    selected: usize,
    rows: u16,
}

impl ListView {
    pub(crate) fn new(label: impl Into<String>, items: Vec<String>, rows: u16) -> Self {
        Self {
            label: label.into(),
            items,
            selected: 0,
            rows: rows.max(1),
        }
    }

    pub(crate) fn selected(&self) -> usize {
        self.selected
    }
}

impl Field for ListView {
    fn label(&self) -> &str {
        &self.label
    }

    fn height(&self) -> u16 {
        self.rows
    }

    fn handle_key(&mut self, key: KeyEvent) -> FieldOutcome {
        let last = self.items.len().saturating_sub(1);
        let page = usize::from(self.rows);
        self.selected = match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.selected.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => (self.selected + 1).min(last),
            KeyCode::PageUp => self.selected.saturating_sub(page),
            KeyCode::PageDown => (self.selected + page).min(last),
            KeyCode::Home => 0,
            KeyCode::End => last,
            _ => return FieldOutcome::Ignored,
        };
        FieldOutcome::Consumed
    }

    fn draw(&self, frame: &mut Frame, area: Rect, focused: bool, theme: &Theme) {
        let rows = usize::from(area.height.max(1));
        let start = self.selected.saturating_sub(rows - 1);
        let lines: Vec<Line> = self
            .items
            .iter()
            .enumerate()
            .skip(start)
            .take(rows)
            .map(|(i, item)| {
                if i == self.selected {
                    Line::styled(
                        format!("> {item}"),
                        if focused {
                            theme.selection
                        } else {
                            theme.title
                        },
                    )
                } else {
                    Line::raw(format!("  {item}"))
                }
            })
            .collect();
        frame.render_widget(Paragraph::new(lines), area);
    }

    fn value(&self) -> FieldValue {
        FieldValue::Index(self.selected)
    }
}
