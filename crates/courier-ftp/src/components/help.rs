//! The help overlay: the effective bindings of the mode that was active when it opened,
//! one row per action with all its keys, grouped by [`Group`], with the registry's
//! descriptions (T50, T51).

use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Clear, Paragraph},
};

use super::{Component, DrawCx, KeyOutcome, modal::Modal, region_block};
use crate::{
    action::{Action, Group},
    app::Mode,
    keymap::{chord::KeyChord, dump::grouped, map::BindingRow},
    ui::text::{sanitize, truncate_to_width},
};

/// One binding row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HelpRow {
    /// Help group.
    pub group: Group,
    /// Keys (`j, down`).
    pub keys: String,
    /// Action name.
    pub action: String,
    /// Description from the registry.
    pub description: String,
}

impl HelpRow {
    fn matches(&self, filter: &str) -> bool {
        let f = filter.to_lowercase();
        self.keys.to_lowercase().contains(&f)
            || self.action.to_lowercase().contains(&f)
            || self.description.to_lowercase().contains(&f)
    }
}

/// The full-screen help modal.
#[derive(Debug)]
pub(crate) struct HelpOverlay {
    rows: Vec<HelpRow>,
    scroll: usize,
    filter: String,
    typing_filter: bool,
    done: bool,
    page: usize,
}

impl HelpOverlay {
    /// From the effective bindings of a chain (`Keymap::bindings_for`).
    pub(crate) fn new(bindings: &[BindingRow]) -> Self {
        let rows = grouped(bindings)
            .into_iter()
            .flat_map(|(group, entries)| {
                entries.into_iter().map(move |(action, keys)| HelpRow {
                    group,
                    keys: keys.join(", "),
                    description: action
                        .meta()
                        .map_or_else(String::new, |m| m.description.to_owned()),
                    action: action.to_string(),
                })
            })
            .collect();
        Self {
            rows,
            scroll: 0,
            filter: String::new(),
            typing_filter: false,
            done: false,
            page: 10,
        }
    }

    /// The rows matching the filter.
    pub(crate) fn visible_rows(&self) -> Vec<&HelpRow> {
        self.rows
            .iter()
            .filter(|r| self.filter.is_empty() || r.matches(&self.filter))
            .collect()
    }

    fn lines(&self, cx: &DrawCx, width: usize) -> Vec<Line<'static>> {
        let mut out = Vec::new();
        let mut current: Option<Group> = None;
        let rows = self.visible_rows();
        let kw = rows
            .iter()
            .map(|r| r.keys.chars().count())
            .max()
            .unwrap_or(0)
            .clamp(4, 24);
        let aw = rows
            .iter()
            .map(|r| r.action.len())
            .max()
            .unwrap_or(0)
            .max(6);
        let sep = cx.symbols.separator;
        for r in rows {
            if current != Some(r.group) {
                if current.is_some() {
                    out.push(Line::default());
                }
                current = Some(r.group);
                out.push(Line::from(Span::styled(
                    r.group.title().to_owned(),
                    cx.theme.style("help_group"),
                )));
            }
            let clean = sanitize(&r.keys);
            let keys = truncate_to_width(&clean, kw, cx.symbols.ellipsis);
            let keys = format!("{keys:<kw$}");
            let rest = format!(" {sep} {:<aw$} {sep} {}", r.action, r.description);
            let rest = truncate_to_width(&rest, width.saturating_sub(kw), cx.symbols.ellipsis)
                .into_owned();
            out.push(Line::from(vec![
                Span::styled(keys, cx.theme.style("help_key")),
                Span::raw(rest),
            ]));
        }
        if out.is_empty() {
            out.push(Line::from(Span::styled(
                "No matching bindings",
                cx.theme.style("placeholder"),
            )));
        }
        out
    }
}

impl Component for HelpOverlay {
    fn key_mode(&self) -> Mode {
        Mode::Dialog
    }

    fn handle_key(&mut self, key: KeyChord) -> color_eyre::Result<KeyOutcome> {
        if self.typing_filter {
            match (key.code, key.printable()) {
                (KeyCode::Enter, _) => self.typing_filter = false,
                (KeyCode::Esc, _) => {
                    self.typing_filter = false;
                    self.filter.clear();
                }
                (KeyCode::Backspace, _) => {
                    self.filter.pop();
                }
                (_, Some(c)) => self.filter.push(c),
                _ => return Ok(KeyOutcome::Ignored),
            }
            self.scroll = 0;
            return Ok(KeyOutcome::Consumed(None));
        }
        let max = self.visible_rows().len().saturating_sub(1);
        match (key.code, key.printable()) {
            (KeyCode::Esc | KeyCode::F(1), _) | (_, Some('q')) => self.done = true,
            (KeyCode::Down, _) | (_, Some('j')) => self.scroll = (self.scroll + 1).min(max),
            (KeyCode::Up, _) | (_, Some('k')) => self.scroll = self.scroll.saturating_sub(1),
            (KeyCode::PageDown, _) => self.scroll = (self.scroll + self.page).min(max),
            (KeyCode::PageUp, _) => self.scroll = self.scroll.saturating_sub(self.page),
            (_, Some('/')) => {
                self.typing_filter = true;
                self.filter.clear();
            }
            _ => return Ok(KeyOutcome::Ignored),
        }
        Ok(KeyOutcome::Consumed(None))
    }

    fn update(&mut self, action: &Action) -> color_eyre::Result<Option<Action>> {
        if matches!(action, Action::Cancel | Action::DialogCancel | Action::Help) {
            self.done = true;
        }
        Ok(None)
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect, cx: &DrawCx) -> color_eyre::Result<()> {
        frame.render_widget(Clear, area);
        let block = region_block("Help: key bindings", cx);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if inner.height == 0 {
            return Ok(());
        }
        let footer = if self.typing_filter || !self.filter.is_empty() {
            format!("/{}", sanitize(&self.filter))
        } else {
            "j/k scroll  / filter  Esc close".to_owned()
        };
        let body_h = inner.height.saturating_sub(1);
        self.page = usize::from(body_h.max(1));
        let lines = self.lines(cx, usize::from(inner.width));
        let body = Rect {
            height: body_h,
            ..inner
        };
        let scroll = u16::try_from(self.scroll).unwrap_or(u16::MAX);
        frame.render_widget(Paragraph::new(lines).scroll((scroll, 0)), body);
        let foot = Rect {
            y: inner.y + body_h,
            height: 1,
            ..inner
        };
        frame.render_widget(
            Paragraph::new(Span::styled(footer, cx.theme.style("placeholder"))),
            foot,
        );
        Ok(())
    }
}

impl Modal for HelpOverlay {
    fn is_done(&self) -> bool {
        self.done
    }
}
