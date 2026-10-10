//! `Select`: one value from a list, chosen in a popup or stepped with `←`/`→`.

use std::time::Duration;

use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
};
use tokio::time::Instant;

use super::{Widget, WidgetCx, WidgetOutcome};
use crate::{
    keymap::chord::{KeyChord, Mods},
    ui::text::{sanitize, truncate_to_width, width},
};

/// Type-to-jump forgets what was typed after this long.
const JUMP_RESET: Duration = Duration::from_secs(1);
/// Rows of the open popup.
const POPUP_ROWS: usize = 8;

/// One option of a [`Select`].
#[derive(Debug, Clone)]
pub(crate) struct SelectOption<T> {
    /// Shown text.
    pub label: String,
    /// The value.
    pub value: T,
    /// Why it cannot be chosen (shown dim after the label), if it cannot.
    pub disabled: Option<String>,
}

impl<T> SelectOption<T> {
    /// An enabled option.
    pub(crate) fn new(label: &str, value: T) -> Self {
        Self {
            label: label.to_owned(),
            value,
            disabled: None,
        }
    }
}

#[derive(Debug, Clone)]
struct PopupState {
    cursor: usize,
    scroll: usize,
    typed: String,
    typed_at: Option<Instant>,
}

/// A drop-down select.
#[derive(Debug, Clone)]
pub(crate) struct Select<T> {
    options: Vec<SelectOption<T>>,
    selected: usize,
    popup: Option<PopupState>,
}

impl<T> Select<T> {
    /// A select over `options`, the first enabled one selected.
    pub(crate) fn new(options: Vec<SelectOption<T>>) -> Self {
        let selected = options
            .iter()
            .position(|o| o.disabled.is_none())
            .unwrap_or(0);
        Self {
            options,
            selected,
            popup: None,
        }
    }

    /// Selects option `i` (ignored when out of range or disabled).
    #[must_use]
    pub(crate) fn selected(mut self, i: usize) -> Self {
        self.select(i);
        self
    }

    /// Index of the selected option.
    pub(crate) fn index(&self) -> usize {
        self.selected
    }

    /// The selected value.
    pub(crate) fn value(&self) -> Option<&T> {
        self.options.get(self.selected).map(|o| &o.value)
    }

    /// The options.
    pub(crate) fn options(&self) -> &[SelectOption<T>] {
        &self.options
    }

    /// Selects option `i` when it exists and is enabled.
    pub(crate) fn select(&mut self, i: usize) -> bool {
        match self.options.get(i) {
            Some(o) if o.disabled.is_none() && i != self.selected => {
                self.selected = i;
                true
            }
            _ => false,
        }
    }

    /// The popup is open.
    pub(crate) fn is_open(&self) -> bool {
        self.popup.is_some()
    }

    fn enabled(&self, i: usize) -> bool {
        self.options.get(i).is_some_and(|o| o.disabled.is_none())
    }

    /// The next enabled index from `from` in direction `forward` (`from` itself
    /// excluded), or `None`.
    fn next_enabled(&self, from: usize, forward: bool) -> Option<usize> {
        let n = self.options.len();
        let mut i = from;
        loop {
            if forward {
                i += 1;
                if i >= n {
                    return None;
                }
            } else {
                i = i.checked_sub(1)?;
            }
            if self.enabled(i) {
                return Some(i);
            }
        }
    }

    /// Moves `cursor` by `by` rows, skipping disabled options.
    fn move_cursor(&self, cursor: usize, by: isize) -> usize {
        let mut c = cursor;
        for _ in 0..by.unsigned_abs() {
            match self.next_enabled(c, by > 0) {
                Some(n) => c = n,
                None => break,
            }
        }
        c
    }

    fn first_enabled(&self) -> Option<usize> {
        (0..self.options.len()).find(|&i| self.enabled(i))
    }

    fn last_enabled(&self) -> Option<usize> {
        (0..self.options.len()).rev().find(|&i| self.enabled(i))
    }

    /// Opens the popup on the selected option.
    pub(crate) fn open(&mut self) {
        self.popup = Some(PopupState {
            cursor: self.selected,
            scroll: 0,
            typed: String::new(),
            typed_at: None,
        });
    }

    /// Keys with an explicit time (type-to-jump; tests inject it).
    pub(crate) fn handle_key_at(&mut self, key: KeyChord, now: Instant) -> WidgetOutcome {
        let ctrl = key.mods.contains(Mods::CTRL);
        let alt = key.mods.contains(Mods::ALT);
        let Some(mut p) = self.popup.take() else {
            return match key.code {
                KeyCode::Char(' ') if !ctrl && !alt => {
                    self.open();
                    WidgetOutcome::Consumed
                }
                KeyCode::Down if alt => {
                    self.open();
                    WidgetOutcome::Consumed
                }
                KeyCode::Left | KeyCode::Char('h') if !ctrl && !alt => {
                    match self.next_enabled(self.selected, false) {
                        Some(i) if self.select(i) => WidgetOutcome::Changed,
                        _ => WidgetOutcome::Consumed,
                    }
                }
                KeyCode::Right | KeyCode::Char('l') if !ctrl && !alt => {
                    match self.next_enabled(self.selected, true) {
                        Some(i) if self.select(i) => WidgetOutcome::Changed,
                        _ => WidgetOutcome::Consumed,
                    }
                }
                _ => WidgetOutcome::Ignored,
            };
        };
        let page = isize::try_from(POPUP_ROWS).unwrap_or(8);
        let outcome = match key.code {
            KeyCode::Esc => return WidgetOutcome::Consumed,
            KeyCode::Enter => {
                let changed = self.select(p.cursor);
                return if changed {
                    WidgetOutcome::Changed
                } else {
                    WidgetOutcome::Consumed
                };
            }
            KeyCode::Down | KeyCode::Char('j') if !ctrl && !alt => {
                p.cursor = self.move_cursor(p.cursor, 1);
                WidgetOutcome::Consumed
            }
            KeyCode::Up | KeyCode::Char('k') if !ctrl && !alt => {
                p.cursor = self.move_cursor(p.cursor, -1);
                WidgetOutcome::Consumed
            }
            KeyCode::PageDown => {
                p.cursor = self.move_cursor(p.cursor, page);
                WidgetOutcome::Consumed
            }
            KeyCode::PageUp => {
                p.cursor = self.move_cursor(p.cursor, -page);
                WidgetOutcome::Consumed
            }
            KeyCode::Home => {
                p.cursor = self.first_enabled().unwrap_or(p.cursor);
                WidgetOutcome::Consumed
            }
            KeyCode::End => {
                p.cursor = self.last_enabled().unwrap_or(p.cursor);
                WidgetOutcome::Consumed
            }
            KeyCode::Char(c) if key.printable().is_some() => {
                if p.typed_at
                    .is_none_or(|t| now.duration_since(t) >= JUMP_RESET)
                {
                    p.typed.clear();
                }
                p.typed.extend(c.to_lowercase());
                p.typed_at = Some(now);
                if let Some(i) = (0..self.options.len()).find(|&i| {
                    self.enabled(i) && self.options[i].label.to_lowercase().starts_with(&p.typed)
                }) {
                    p.cursor = i;
                }
                WidgetOutcome::Consumed
            }
            // Everything else is swallowed while the popup is open.
            _ => WidgetOutcome::Consumed,
        };
        self.popup = Some(p);
        outcome
    }

    fn label_width(&self) -> usize {
        self.options
            .iter()
            .map(|o| {
                width(&sanitize(&o.label))
                    + o.disabled.as_ref().map_or(0, |r| width(&sanitize(r)) + 3)
            })
            .max()
            .unwrap_or(0)
    }
}

impl<T> Widget for Select<T> {
    fn handle_key(&mut self, key: KeyChord) -> WidgetOutcome {
        self.handle_key_at(key, Instant::now())
    }

    fn render(&self, frame: &mut Frame, area: Rect, cx: &WidgetCx) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        let w = usize::from(area.width);
        let label = self
            .options
            .get(self.selected)
            .map(|o| sanitize(&o.label).into_owned())
            .unwrap_or_default();
        let mut style = cx.theme.style("input");
        if !cx.enabled {
            style = style.patch(cx.theme.style("field_help"));
        }
        let mark_w = width(cx.symbols.dropdown) + 1;
        let shown = truncate_to_width(&label, w.saturating_sub(mark_w), cx.symbols.ellipsis);
        let pad = w.saturating_sub(width(&shown) + mark_w);
        let mut mark = Style::default();
        if cx.focused {
            mark = mark.add_modifier(Modifier::REVERSED);
        }
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(shown.into_owned(), style),
                Span::styled(" ".repeat(pad), style),
                Span::raw(" "),
                Span::styled(cx.symbols.dropdown.to_owned(), mark),
            ])),
            Rect { height: 1, ..area },
        );
    }

    fn render_overlay(&self, frame: &mut Frame, area: Rect, bounds: Rect, cx: &WidgetCx) {
        let Some(p) = &self.popup else {
            return;
        };
        if bounds.width < 4 || bounds.height < 3 || self.options.is_empty() {
            return;
        }
        let rows = self.options.len().min(POPUP_ROWS);
        let h = u16::try_from(rows + 2).unwrap_or(u16::MAX);
        let w = u16::try_from(self.label_width() + 4)
            .unwrap_or(u16::MAX)
            .max(area.width.min(30))
            .min(bounds.width);
        let below = area.y.saturating_add(1);
        let space_below = bounds.bottom().saturating_sub(below);
        let space_above = area.y.saturating_sub(bounds.y);
        let (y, h) = if space_below >= h || space_below >= space_above {
            (below, h.min(space_below))
        } else {
            (
                area.y.saturating_sub(h.min(space_above)),
                h.min(space_above),
            )
        };
        if h < 3 {
            return;
        }
        let x = area.x.min(bounds.right().saturating_sub(w)).max(bounds.x);
        let r = Rect::new(x, y, w, h);
        let visible = usize::from(h - 2);
        let mut scroll = p.scroll.min(self.options.len().saturating_sub(visible));
        if p.cursor < scroll {
            scroll = p.cursor;
        } else if p.cursor >= scroll + visible {
            scroll = p.cursor + 1 - visible;
        }
        let inner_w = usize::from(w.saturating_sub(2));
        let lines: Vec<Line> = self
            .options
            .iter()
            .enumerate()
            .skip(scroll)
            .take(visible)
            .map(|(i, o)| {
                let mut text = sanitize(&o.label).into_owned();
                let mut style = Style::default();
                if let Some(reason) = &o.disabled {
                    text.push_str(&format!(" ({})", sanitize(reason)));
                    style = cx.theme.style("field_help");
                }
                let text = truncate_to_width(&text, inner_w, cx.symbols.ellipsis).into_owned();
                let pad = inner_w.saturating_sub(width(&text));
                if i == p.cursor {
                    style = style.patch(cx.theme.style("list_cursor"));
                }
                Line::from(Span::styled(format!("{text}{}", " ".repeat(pad)), style))
            })
            .collect();
        frame.render_widget(Clear, r);
        frame.render_widget(
            Paragraph::new(lines).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_set(cx.symbols.border)
                    .border_style(cx.theme.style("popup_border")),
            ),
            r,
        );
    }

    fn uses_vertical_keys(&self) -> bool {
        self.popup.is_some()
    }
}
