//! Choice fields: [`Checkbox`], [`TriStateCheckbox`], [`Select`] and
//! [`RadioGroup`].

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};

use super::{Field, FieldOutcome, FieldValue};
use crate::ui::theme::Theme;

fn focus_style(focused: bool, theme: &Theme) -> ratatui::style::Style {
    if focused {
        theme.selection
    } else {
        ratatui::style::Style::new()
    }
}

/// An on/off box; `Space` toggles.
pub(crate) struct Checkbox {
    label: String,
    checked: bool,
}

impl Checkbox {
    pub(crate) fn new(label: impl Into<String>, checked: bool) -> Self {
        Self {
            label: label.into(),
            checked,
        }
    }
}

impl Field for Checkbox {
    fn label(&self) -> &str {
        &self.label
    }

    fn handle_key(&mut self, key: KeyEvent) -> FieldOutcome {
        match key.code {
            KeyCode::Char(' ') => {
                self.checked = !self.checked;
                FieldOutcome::Consumed
            }
            _ => FieldOutcome::Ignored,
        }
    }

    fn draw(&self, frame: &mut Frame, area: Rect, focused: bool, theme: &Theme) {
        let mark = if self.checked { "[x]" } else { "[ ]" };
        frame.render_widget(
            Paragraph::new(Span::styled(mark, focus_style(focused, theme))),
            area,
        );
    }

    fn value(&self) -> FieldValue {
        FieldValue::Bool(self.checked)
    }
}

/// On, off, or "leave as it is" (chmod of several files, T62).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TriState {
    On,
    Off,
    Unchanged,
}

/// A checkbox with a third, "unchanged" state; `Space` cycles.
pub(crate) struct TriStateCheckbox {
    label: String,
    state: TriState,
}

impl TriStateCheckbox {
    pub(crate) fn new(label: impl Into<String>, state: TriState) -> Self {
        Self {
            label: label.into(),
            state,
        }
    }
}

impl Field for TriStateCheckbox {
    fn label(&self) -> &str {
        &self.label
    }

    fn handle_key(&mut self, key: KeyEvent) -> FieldOutcome {
        match key.code {
            KeyCode::Char(' ') => {
                self.state = match self.state {
                    TriState::Unchanged => TriState::On,
                    TriState::On => TriState::Off,
                    TriState::Off => TriState::Unchanged,
                };
                FieldOutcome::Consumed
            }
            _ => FieldOutcome::Ignored,
        }
    }

    fn draw(&self, frame: &mut Frame, area: Rect, focused: bool, theme: &Theme) {
        let mark = match self.state {
            TriState::On => "[x]",
            TriState::Off => "[ ]",
            TriState::Unchanged => "[-]",
        };
        frame.render_widget(
            Paragraph::new(Span::styled(mark, focus_style(focused, theme))),
            area,
        );
    }

    fn value(&self) -> FieldValue {
        FieldValue::Tri(self.state)
    }
}

/// A dropdown. Closed: `←`/`→` change the choice, a letter jumps to the next
/// option starting with it, `Enter`/`Space` open the list. Open: `↑`/`↓`
/// move, `Enter` picks, `Esc` closes.
pub(crate) struct Select {
    label: String,
    options: Vec<String>,
    selected: usize,
    open: Option<usize>,
}

impl Select {
    pub(crate) fn new(label: impl Into<String>, options: Vec<String>, selected: usize) -> Self {
        let selected = selected.min(options.len().saturating_sub(1));
        Self {
            label: label.into(),
            options,
            selected,
            open: None,
        }
    }

    pub(crate) fn selected(&self) -> usize {
        self.selected
    }

    fn jump(&mut self, c: char, from: usize) -> usize {
        let n = self.options.len();
        (1..=n)
            .map(|step| (from + step) % n)
            .find(|&i| {
                self.options[i]
                    .chars()
                    .next()
                    .is_some_and(|f| f.to_lowercase().eq(c.to_lowercase()))
            })
            .unwrap_or(from)
    }
}

impl Field for Select {
    fn label(&self) -> &str {
        &self.label
    }

    fn handle_key(&mut self, key: KeyEvent) -> FieldOutcome {
        let n = self.options.len();
        if n == 0 {
            return FieldOutcome::Ignored;
        }
        if let Some(hl) = self.open {
            match key.code {
                KeyCode::Up => self.open = Some(hl.saturating_sub(1)),
                KeyCode::Down => self.open = Some((hl + 1).min(n - 1)),
                KeyCode::Enter | KeyCode::Char(' ') => {
                    self.selected = hl;
                    self.open = None;
                }
                KeyCode::Esc => self.open = None,
                KeyCode::Char(c) => self.open = Some(self.jump(c, hl)),
                _ => {}
            }
            return FieldOutcome::Consumed;
        }
        match key.code {
            KeyCode::Left => self.selected = self.selected.saturating_sub(1),
            KeyCode::Right => self.selected = (self.selected + 1).min(n - 1),
            KeyCode::Enter | KeyCode::Char(' ') => self.open = Some(self.selected),
            KeyCode::Char(c) => self.selected = self.jump(c, self.selected),
            _ => return FieldOutcome::Ignored,
        }
        FieldOutcome::Consumed
    }

    fn draw(&self, frame: &mut Frame, area: Rect, focused: bool, theme: &Theme) {
        let current = self.options.get(self.selected).cloned().unwrap_or_default();
        frame.render_widget(
            Paragraph::new(Line::from(vec![Span::styled(
                format!("{current} ▾"),
                focus_style(focused, theme),
            )])),
            area,
        );
    }

    fn draw_overlay(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let Some(hl) = self.open else { return };
        let screen = frame.area();
        let width = self
            .options
            .iter()
            .map(|o| o.chars().count())
            .max()
            .unwrap_or(0)
            .saturating_add(2);
        let width = u16::try_from(width)
            .unwrap_or(u16::MAX)
            .max(area.width.min(20));
        let rows = u16::try_from(self.options.len()).unwrap_or(u16::MAX);
        let below = screen.bottom().saturating_sub(area.bottom());
        let height = (rows + 2).min(below.max(3));
        let rect = Rect::new(area.x, area.bottom(), width, height).intersection(screen);
        let visible = usize::from(height.saturating_sub(2)).max(1);
        let start = hl.saturating_sub(visible - 1);
        let lines: Vec<Line> = self
            .options
            .iter()
            .enumerate()
            .skip(start)
            .take(visible)
            .map(|(i, o)| {
                if i == hl {
                    Line::styled(o.clone(), theme.selection)
                } else {
                    Line::raw(o.clone())
                }
            })
            .collect();
        frame.render_widget(Clear, rect);
        frame.render_widget(
            Paragraph::new(lines).block(Block::bordered().border_style(theme.focused_border)),
            rect,
        );
    }

    fn value(&self) -> FieldValue {
        FieldValue::Index(self.selected)
    }

    fn is_capturing(&self) -> bool {
        self.open.is_some()
    }
}

/// One choice out of a few, all visible: `(•) a  ( ) b`. Arrow keys move.
pub(crate) struct RadioGroup {
    label: String,
    options: Vec<String>,
    selected: usize,
}

impl RadioGroup {
    pub(crate) fn new(label: impl Into<String>, options: Vec<String>, selected: usize) -> Self {
        let selected = selected.min(options.len().saturating_sub(1));
        Self {
            label: label.into(),
            options,
            selected,
        }
    }
}

impl Field for RadioGroup {
    fn label(&self) -> &str {
        &self.label
    }

    fn handle_key(&mut self, key: KeyEvent) -> FieldOutcome {
        let n = self.options.len();
        match key.code {
            KeyCode::Left | KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Right | KeyCode::Down => {
                self.selected = (self.selected + 1).min(n.saturating_sub(1));
            }
            _ => return FieldOutcome::Ignored,
        }
        FieldOutcome::Consumed
    }

    fn draw(&self, frame: &mut Frame, area: Rect, focused: bool, theme: &Theme) {
        let mut spans = Vec::new();
        for (i, o) in self.options.iter().enumerate() {
            let mark = if i == self.selected { "(•)" } else { "( )" };
            let style = if focused && i == self.selected {
                theme.selection
            } else {
                ratatui::style::Style::new()
            };
            spans.push(Span::styled(format!("{mark} {o}"), style));
            spans.push(Span::raw("  "));
        }
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn value(&self) -> FieldValue {
        FieldValue::Index(self.selected)
    }
}
