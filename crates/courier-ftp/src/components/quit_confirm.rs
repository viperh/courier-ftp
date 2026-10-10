//! "Quit courier-ftp?" with the reasons to stay (T50's minimal modal; T52 replaces it
//! with `confirm()`).

use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::Rect,
    style::Modifier,
    text::{Line, Span},
    widgets::{Clear, Paragraph, Wrap},
};

use super::{Component, DrawCx, KeyOutcome, modal::Modal, region_block};
use crate::{action::Action, app::Mode, keymap::chord::KeyChord, ui::text::sanitize};

/// Buttons *Quit* / *Cancel*; *Cancel* is the default. The `Quit` action pressed again
/// confirms.
#[derive(Debug)]
pub(crate) struct QuitConfirm {
    reasons: Vec<String>,
    quit_selected: bool,
    done: bool,
}

impl QuitConfirm {
    /// The modal for these blockers.
    pub(crate) fn new(reasons: Vec<String>) -> Self {
        Self {
            reasons,
            quit_selected: false,
            done: false,
        }
    }

    fn finish(&mut self, quit: bool) -> Option<Action> {
        self.done = true;
        quit.then_some(Action::QuitConfirmed)
    }
}

impl Component for QuitConfirm {
    fn key_mode(&self) -> Mode {
        Mode::Dialog
    }

    fn handle_key(&mut self, key: KeyChord) -> color_eyre::Result<KeyOutcome> {
        let out = match (key.code, key.printable()) {
            (KeyCode::Left | KeyCode::Right | KeyCode::Tab, _) => {
                self.quit_selected = !self.quit_selected;
                None
            }
            (KeyCode::Enter, _) => self.finish(self.quit_selected),
            (_, Some('y')) => self.finish(true),
            (_, Some('n')) => self.finish(false),
            _ => return Ok(KeyOutcome::Ignored),
        };
        Ok(KeyOutcome::Consumed(out))
    }

    fn update(&mut self, action: &Action) -> color_eyre::Result<Option<Action>> {
        Ok(match action {
            Action::Quit => self.finish(true),
            Action::Cancel | Action::DialogCancel => self.finish(false),
            _ => None,
        })
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect, cx: &DrawCx) -> color_eyre::Result<()> {
        let width = area.width.min(60);
        let height = (u16::try_from(self.reasons.len()).unwrap_or(u16::MAX))
            .saturating_add(6)
            .min(area.height);
        let r = Rect {
            x: area.x + (area.width - width) / 2,
            y: area.y + (area.height - height) / 2,
            width,
            height,
        };
        frame.render_widget(Clear, r);
        let mut lines = vec![Line::from("Quit courier-ftp?"), Line::default()];
        for reason in &self.reasons {
            lines.push(Line::from(format!(
                "{} {}",
                cx.symbols.bullet,
                sanitize(reason)
            )));
        }
        lines.push(Line::default());
        let button = |label: &'static str, on: bool| {
            let style = if on {
                cx.theme
                    .style("dialog_border")
                    .add_modifier(Modifier::REVERSED)
            } else {
                cx.theme.style("dialog_border")
            };
            let marker = if on { cx.symbols.focus_marker } else { " " };
            Span::styled(format!("{marker}[ {label} ]"), style)
        };
        lines.push(Line::from(vec![
            button("Quit", self.quit_selected),
            Span::raw("  "),
            button("Cancel", !self.quit_selected),
        ]));
        let block = region_block("Quit", cx).border_style(cx.theme.style("dialog_border"));
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(block),
            r,
        );
        Ok(())
    }
}

impl Modal for QuitConfirm {
    fn is_done(&self) -> bool {
        self.done
    }
}
