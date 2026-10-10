//! `Checkbox`, `TriStateCheckbox` and `RadioGroup`.

use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{Widget, WidgetCx, WidgetOutcome};
use crate::{
    keymap::chord::{KeyChord, Mods},
    ui::text::sanitize,
};

fn mark_style(cx: &WidgetCx) -> Style {
    let s = if cx.enabled {
        Style::default()
    } else {
        cx.theme.style("field_help")
    };
    if cx.focused {
        s.add_modifier(Modifier::REVERSED)
    } else {
        s
    }
}

fn draw_mark(frame: &mut Frame, area: Rect, mark: &str, label: &str, cx: &WidgetCx) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let mut spans = vec![Span::styled(mark.to_owned(), mark_style(cx))];
    if !label.is_empty() {
        spans.push(Span::raw(" "));
        spans.push(Span::raw(sanitize(label).into_owned()));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)),
        Rect { height: 1, ..area },
    );
}

fn is_space(key: KeyChord) -> bool {
    key.code == KeyCode::Char(' ')
        && !key.mods.contains(Mods::CTRL)
        && !key.mods.contains(Mods::ALT)
}

/// `[x] label`; `space` toggles.
#[derive(Debug, Clone)]
pub(crate) struct Checkbox {
    /// Checked.
    pub checked: bool,
    label: String,
}

impl Checkbox {
    /// A checkbox with an inline `label` (may be empty when the form label says it all).
    pub(crate) fn new(label: &str, checked: bool) -> Self {
        Self {
            checked,
            label: label.to_owned(),
        }
    }
}

impl Widget for Checkbox {
    fn handle_key(&mut self, key: KeyChord) -> WidgetOutcome {
        if is_space(key) {
            self.checked = !self.checked;
            return WidgetOutcome::Changed;
        }
        WidgetOutcome::Ignored
    }

    fn render(&self, frame: &mut Frame, area: Rect, cx: &WidgetCx) {
        let mark = if self.checked { "[x]" } else { "[ ]" };
        draw_mark(frame, area, mark, &self.label, cx);
    }
}

/// A checkbox that may also leave a value unchanged (chmod of several files, T62).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TriState {
    /// Set.
    On,
    /// Cleared.
    Off,
    /// Left as it is.
    Unchanged,
}

/// `[x]` / `[ ]` / `[-]`; `space` cycles On → Off → Unchanged (when allowed) → On.
#[derive(Debug, Clone)]
pub(crate) struct TriStateCheckbox {
    /// Current state.
    pub state: TriState,
    /// `Unchanged` is part of the cycle.
    pub allow_unchanged: bool,
    label: String,
}

impl TriStateCheckbox {
    /// A tri-state checkbox.
    pub(crate) fn new(label: &str, state: TriState, allow_unchanged: bool) -> Self {
        Self {
            state,
            allow_unchanged,
            label: label.to_owned(),
        }
    }
}

impl Widget for TriStateCheckbox {
    fn handle_key(&mut self, key: KeyChord) -> WidgetOutcome {
        if !is_space(key) {
            return WidgetOutcome::Ignored;
        }
        self.state = match (self.state, self.allow_unchanged) {
            (TriState::On, _) => TriState::Off,
            (TriState::Off, true) => TriState::Unchanged,
            (TriState::Off | TriState::Unchanged, _) => TriState::On,
        };
        WidgetOutcome::Changed
    }

    fn render(&self, frame: &mut Frame, area: Rect, cx: &WidgetCx) {
        let mark = match self.state {
            TriState::On => "[x]",
            TriState::Off => "[ ]",
            TriState::Unchanged => "[-]",
        };
        draw_mark(frame, area, mark, &self.label, cx);
    }
}

/// One of several options; vertical (one per row) or horizontal.
#[derive(Debug, Clone)]
pub(crate) struct RadioGroup {
    labels: Vec<String>,
    disabled: Vec<bool>,
    selected: usize,
    horizontal: bool,
}

impl RadioGroup {
    /// A vertical group with the first option selected.
    pub(crate) fn new(labels: &[&str]) -> Self {
        Self {
            labels: labels.iter().map(|s| (*s).to_owned()).collect(),
            disabled: vec![false; labels.len()],
            selected: 0,
            horizontal: false,
        }
    }

    /// All options on one row (`←`/`→` move).
    #[must_use]
    pub(crate) fn horizontal(mut self) -> Self {
        self.horizontal = true;
        self
    }

    /// Selects option `i` (ignored when out of range or disabled).
    #[must_use]
    pub(crate) fn selected(mut self, i: usize) -> Self {
        self.select(i);
        self
    }

    /// Disables option `i`.
    #[must_use]
    pub(crate) fn disable(mut self, i: usize) -> Self {
        if let Some(d) = self.disabled.get_mut(i) {
            *d = true;
        }
        self
    }

    /// The selected option.
    pub(crate) fn value(&self) -> usize {
        self.selected
    }

    /// Selects option `i` when it exists and is enabled.
    pub(crate) fn select(&mut self, i: usize) -> bool {
        if i < self.labels.len() && !self.disabled[i] && i != self.selected {
            self.selected = i;
            return true;
        }
        false
    }

    fn step(&mut self, forward: bool) -> WidgetOutcome {
        let n = self.labels.len();
        let mut i = self.selected;
        for _ in 0..n {
            i = if forward {
                (i + 1).min(n.saturating_sub(1))
            } else {
                i.saturating_sub(1)
            };
            if !self.disabled[i] {
                break;
            }
        }
        if self.select(i) {
            WidgetOutcome::Changed
        } else {
            WidgetOutcome::Consumed
        }
    }
}

impl Widget for RadioGroup {
    fn handle_key(&mut self, key: KeyChord) -> WidgetOutcome {
        if key.mods.contains(Mods::CTRL) || key.mods.contains(Mods::ALT) {
            return WidgetOutcome::Ignored;
        }
        let (prev, next) = if self.horizontal {
            (
                matches!(key.code, KeyCode::Left | KeyCode::Char('h')),
                matches!(key.code, KeyCode::Right | KeyCode::Char('l')),
            )
        } else {
            (
                matches!(key.code, KeyCode::Up | KeyCode::Char('k')),
                matches!(key.code, KeyCode::Down | KeyCode::Char('j')),
            )
        };
        if prev || next {
            return self.step(next);
        }
        if is_space(key) {
            return WidgetOutcome::Consumed;
        }
        WidgetOutcome::Ignored
    }

    fn render(&self, frame: &mut Frame, area: Rect, cx: &WidgetCx) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        let item = |i: usize, label: &str| {
            let on = i == self.selected;
            let mark = if on {
                cx.symbols.radio_on
            } else {
                cx.symbols.radio_off
            };
            let mut style = if self.disabled[i] || !cx.enabled {
                cx.theme.style("field_help")
            } else {
                Style::default()
            };
            if on && cx.focused {
                style = style.add_modifier(Modifier::REVERSED);
            }
            vec![
                Span::styled(mark.to_owned(), style),
                Span::raw(" "),
                Span::styled(sanitize(label).into_owned(), style),
            ]
        };
        if self.horizontal {
            let mut spans = Vec::new();
            for (i, l) in self.labels.iter().enumerate() {
                if i > 0 {
                    spans.push(Span::raw("  "));
                }
                spans.extend(item(i, l));
            }
            frame.render_widget(
                Paragraph::new(Line::from(spans)),
                Rect { height: 1, ..area },
            );
        } else {
            let lines: Vec<Line> = self
                .labels
                .iter()
                .enumerate()
                .map(|(i, l)| Line::from(item(i, l)))
                .collect();
            frame.render_widget(Paragraph::new(lines), area);
        }
    }

    fn height(&self, _width: u16) -> u16 {
        if self.horizontal {
            1
        } else {
            u16::try_from(self.labels.len().max(1)).unwrap_or(u16::MAX)
        }
    }

    fn uses_vertical_keys(&self) -> bool {
        !self.horizontal
    }
}
