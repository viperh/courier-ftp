//! [`ButtonRow`]: `[ OK ]  [ Cancel ]`.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::ui::theme::Theme;

/// A row of buttons. `←`/`→` move between them, `Enter` presses the
/// highlighted one, `Alt` + a button's first letter presses it directly.
#[derive(Debug, Clone)]
pub(crate) struct ButtonRow {
    labels: Vec<String>,
    /// The highlighted button.
    pub(crate) current: usize,
}

impl ButtonRow {
    pub(crate) fn new(labels: &[&str], default: usize) -> Self {
        Self {
            labels: labels.iter().map(|l| (*l).to_owned()).collect(),
            current: default.min(labels.len().saturating_sub(1)),
        }
    }

    /// The button a key presses, or `None` (moving the highlight is handled
    /// here and also returns `None`).
    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> Option<usize> {
        match key.code {
            KeyCode::Left => self.current = self.current.saturating_sub(1),
            KeyCode::Right => {
                self.current = (self.current + 1).min(self.labels.len().saturating_sub(1));
            }
            KeyCode::Enter => return Some(self.current),
            KeyCode::Char(c) if key.modifiers.contains(KeyModifiers::ALT) => {
                return self
                    .labels
                    .iter()
                    .position(|l| l.chars().next().is_some_and(|f| f.eq_ignore_ascii_case(&c)));
            }
            _ => {}
        }
        None
    }

    pub(crate) fn draw(&self, frame: &mut Frame, area: Rect, focused: bool, theme: &Theme) {
        let mut spans = Vec::new();
        for (i, label) in self.labels.iter().enumerate() {
            let style = if i == self.current {
                if focused {
                    theme.selection
                } else {
                    theme.title
                }
            } else {
                ratatui::style::Style::new()
            };
            spans.push(Span::styled(format!("[ {label} ]"), style));
            spans.push(Span::raw("  "));
        }
        frame.render_widget(Paragraph::new(Line::from(spans)).centered(), area);
    }
}
