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
    /// Insert pasted text (bracketed paste) into the focused field.
    fn handle_paste(&mut self, _text: &str) {}
    /// Whether the modal closed itself (a finished progress dialog).
    fn is_done(&self) -> bool {
        false
    }
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

/// The dialog for a question from the core (T04). The answer goes back
/// through the request's `reply`; closing a dialog without answering drops
/// it, which the core treats as "cancel". Trust prompts get their dialogs in
/// T69 and file-exists prompts in T42; until then they can only be
/// cancelled.
pub(crate) fn prompt_modal(request: PromptRequest) -> Box<dyn Modal> {
    use super::dialog::{Form, FormDialog, TextInput, message, prompt_password};
    let PromptRequest { kind, reply, .. } = request;
    match kind {
        PromptKind::Message(text) => {
            let (modal, rx) = message("Message", &text);
            forward(rx, reply, |()| Some(PromptResponse::Ok));
            modal
        }
        PromptKind::Password { for_ } => {
            let (modal, rx) = prompt_password("Password", &format!("Password for {for_}"));
            forward(rx, reply, |pw| pw.map(PromptResponse::Secret));
            modal
        }
        PromptKind::KeyPassphrase { path } => {
            let (modal, rx) = prompt_password(
                "Key passphrase",
                &format!("Passphrase for {}", path.to_display()),
            );
            forward(rx, reply, |pw| pw.map(PromptResponse::Secret));
            modal
        }
        PromptKind::KeyboardInteractive {
            name,
            instructions,
            prompts,
        } => {
            let count = prompts.len();
            let mut form = Form::new(&["OK", "Cancel"]);
            for (i, (label, echo)) in prompts.into_iter().enumerate() {
                let field = if echo {
                    TextInput::new(label)
                } else {
                    TextInput::password(label)
                };
                form = form.field(&format!("p{i}"), field);
            }
            let title = if name.is_empty() {
                "Authentication".to_owned()
            } else {
                name
            };
            let title = if instructions.is_empty() {
                title
            } else {
                format!("{title}: {instructions}")
            };
            let (dialog, rx) = FormDialog::new(title, 60, form, move |v| {
                Ok((0..count)
                    .map(|i| {
                        let key = format!("p{i}");
                        v.secret(&key)
                            .unwrap_or_else(|| secrecy::SecretString::from(v.text(&key)))
                    })
                    .collect::<Vec<_>>())
            });
            forward(rx, reply, |answers| answers.map(PromptResponse::Answers));
            Box::new(dialog)
        }
        other => Box::new(PendingPrompt {
            kind: other,
            _reply: reply,
        }),
    }
}

/// Wait for a dialog's answer and pass it to the core.
fn forward<T: Send + 'static>(
    rx: tokio::sync::oneshot::Receiver<T>,
    reply: tokio::sync::oneshot::Sender<PromptResponse>,
    map: impl FnOnce(T) -> Option<PromptResponse> + Send + 'static,
) {
    tokio::spawn(async move {
        // A dropped dialog or `None` drops `reply`: the core sees "cancel".
        if let Ok(answer) = rx.await
            && let Some(response) = map(answer)
        {
            let _ = reply.send(response);
        }
    });
}

/// A prompt whose dialog doesn't exist yet: shows the question, `Esc`
/// cancels.
struct PendingPrompt {
    kind: PromptKind,
    _reply: tokio::sync::oneshot::Sender<PromptResponse>,
}

impl Modal for PendingPrompt {
    fn draw(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let text = match &self.kind {
            PromptKind::TrustHostKey {
                host,
                fingerprint_sha256,
                ..
            } => format!(
                "Unknown host key for {host}\n{fingerprint_sha256}\n\n(Trust prompts arrive with T69.)"
            ),
            other => format!("{other:?}\n\n(Not answerable yet.)"),
        };
        let rect = centered(area, 60, 9);
        frame.render_widget(Clear, rect);
        frame.render_widget(
            Paragraph::new(format!("{text}\n\nEsc cancel"))
                .wrap(Wrap { trim: false })
                .block(
                    Block::bordered()
                        .title(" Question ")
                        .border_style(theme.focused_border),
                ),
            rect,
        );
    }

    fn handle_key(&mut self, key: KeyEvent) -> ModalOutcome {
        if key.code == KeyCode::Esc {
            ModalOutcome::Close
        } else {
            ModalOutcome::Keep
        }
    }
}
