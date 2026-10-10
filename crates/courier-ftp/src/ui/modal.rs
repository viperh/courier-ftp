//! The modal stack's contract and the dialogs T50 needs: the help overlay and
//! a basic prompt dialog. T52 adds the form widgets and standard dialogs; T69
//! the trust prompts.

use courier_ftp_core::events::{PromptKind, PromptRequest, PromptResponse};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Wrap},
};

use super::theme::Theme;

/// What a modal did with a key.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ModalOutcome {
    /// Stay open.
    Keep,
    /// Close this modal.
    Close,
}

/// A dialog on the modal stack. It gets every key while it is on top.
pub(crate) trait Modal: Send {
    /// Draw inside `area` (the whole screen; the modal picks its own size).
    fn draw(&mut self, frame: &mut Frame, area: Rect, theme: &Theme);
    /// Handle a key.
    fn handle_key(&mut self, key: KeyEvent) -> ModalOutcome;
}

/// A centred rectangle of at most `width`×`height` inside `area`.
pub(crate) fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    )
}

/// `F1`: the keybindings of the mode the user was in, generated from the
/// config.
pub(crate) struct HelpOverlay {
    title: String,
    lines: Vec<(String, String)>,
    scroll: u16,
}

impl HelpOverlay {
    /// `bindings` are (key sequence, action) pairs.
    pub(crate) fn new(mode: &str, mut bindings: Vec<(String, String)>) -> Self {
        bindings.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        Self {
            title: format!(" Keys: {mode} mode "),
            lines: bindings,
            scroll: 0,
        }
    }
}

impl Modal for HelpOverlay {
    fn draw(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let key_width = self.lines.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
        let height = u16::try_from(self.lines.len())
            .unwrap_or(u16::MAX)
            .saturating_add(3);
        let rect = centered(area, 60, height);
        let body: Vec<Line> = self
            .lines
            .iter()
            .map(|(key, action)| {
                Line::from(vec![
                    Span::styled(format!("{key:<key_width$}  "), theme.key_hint),
                    Span::raw(action.clone()),
                ])
            })
            .chain(std::iter::once(Line::styled(
                "Esc closes · ↑/↓ scroll",
                theme.dim,
            )))
            .collect();
        frame.render_widget(Clear, rect);
        frame.render_widget(
            Paragraph::new(body).scroll((self.scroll, 0)).block(
                Block::bordered()
                    .title(self.title.as_str())
                    .border_style(theme.focused_border),
            ),
            rect,
        );
    }

    fn handle_key(&mut self, key: KeyEvent) -> ModalOutcome {
        match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::F(1) | KeyCode::Char('q') => {
                ModalOutcome::Close
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.scroll = self.scroll.saturating_add(1);
                ModalOutcome::Keep
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.scroll = self.scroll.saturating_sub(1);
                ModalOutcome::Keep
            }
            _ => ModalOutcome::Keep,
        }
    }
}

/// A question from the core (T04). For now only messages can be answered;
/// the other kinds get their dialogs in T52/T58/T69 and can only be
/// cancelled here (closing drops the request, which the core treats as
/// "cancel").
pub(crate) struct PromptDialog {
    request: Option<PromptRequest>,
}

impl PromptDialog {
    pub(crate) fn new(request: PromptRequest) -> Self {
        Self {
            request: Some(request),
        }
    }

    fn text(&self) -> (String, String, bool) {
        match self.request.as_ref().map(|r| &r.kind) {
            Some(PromptKind::Message(m)) => (" Message ".into(), m.clone(), true),
            Some(PromptKind::TrustHostKey {
                host,
                fingerprint_sha256,
                ..
            }) => (
                " Unknown host key ".into(),
                format!("{host}\n{fingerprint_sha256}\n\n(Trust prompts arrive with T69.)"),
                false,
            ),
            Some(PromptKind::Password { for_ }) => (
                " Password ".into(),
                format!("Password for {for_}\n\n(Password input arrives with T52.)"),
                false,
            ),
            Some(other) => (
                " Question ".into(),
                format!("{other:?}\n\n(Not answerable yet.)"),
                false,
            ),
            None => (String::new(), String::new(), false),
        }
    }
}

impl Modal for PromptDialog {
    fn draw(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let (title, text, answerable) = self.text();
        let hint = if answerable {
            "Enter OK · Esc cancel"
        } else {
            "Esc cancel"
        };
        let rect = centered(area, 60, 9);
        frame.render_widget(Clear, rect);
        frame.render_widget(
            Paragraph::new(format!("{text}\n\n{hint}"))
                .wrap(Wrap { trim: false })
                .block(
                    Block::bordered()
                        .title(title)
                        .border_style(theme.focused_border),
                ),
            rect,
        );
    }

    fn handle_key(&mut self, key: KeyEvent) -> ModalOutcome {
        match key.code {
            KeyCode::Esc => {
                self.request = None; // dropping the reply cancels
                ModalOutcome::Close
            }
            KeyCode::Enter => {
                if let Some(req) = self.request.take()
                    && matches!(req.kind, PromptKind::Message(_))
                {
                    let _ = req.reply.send(PromptResponse::Ok);
                }
                ModalOutcome::Close
            }
            _ => ModalOutcome::Keep,
        }
    }
}
