//! The help overlay: the effective bindings of the mode that was active when it opened,
//! grouped by key table (T50; T51 adds descriptions and groups).

use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Clear, Paragraph},
};

use super::{Component, DrawCx, KeyOutcome, modal::Modal, region_block};
use crate::{
    action::Action,
    app::Mode,
    keymap::{chord::KeyChord, resolver::display_keys},
    ui::text::{sanitize, truncate_to_width},
};

/// One binding row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HelpRow {
    /// Key table.
    pub mode: Mode,
    /// Keys (`ctrl-x d`).
    pub keys: String,
    /// Action name.
    pub action: String,
    /// Description (T51).
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
    /// From the resolver's effective bindings (`KeyResolver::bindings`).
    pub(crate) fn new(bindings: Vec<(Mode, Vec<KeyChord>, Action)>) -> Self {
        let rows = bindings
            .into_iter()
            .map(|(mode, keys, action)| HelpRow {
                mode,
                keys: display_keys(&keys),
                action: action.to_string(),
                description: String::new(),
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
        let mut current: Option<Mode> = None;
        let rows = self.visible_rows();
        let kw = rows
            .iter()
            .map(|r| r.keys.chars().count())
            .max()
            .unwrap_or(0)
            .max(4);
        let aw = rows
            .iter()
            .map(|r| r.action.len())
            .max()
            .unwrap_or(0)
            .max(6);
        let sep = cx.symbols.separator;
        for r in rows {
            if current != Some(r.mode) {
                if current.is_some() {
                    out.push(Line::default());
                }
                current = Some(r.mode);
                out.push(Line::from(Span::styled(
                    format!("{:?}", r.mode),
                    cx.theme.style("help_group"),
                )));
            }
            let keys = format!("{:<kw$}", sanitize(&r.keys));
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
        if matches!(action, Action::Cancel | Action::Help) {
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
