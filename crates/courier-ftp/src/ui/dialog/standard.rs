//! Standard dialogs: [`confirm`], [`ask`], [`message`], [`error`], [`prompt_text`],
//! [`prompt_password`], [`choose`], and the [`ProgressDialog`].
//!
//! Each returns the modal to push and a receiver for the answer. A dropped
//! dialog closes the receiver, which callers treat as "cancelled".

use std::sync::{Arc, Mutex};

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::Rect,
    text::Line,
    widgets::{Gauge, Paragraph, Wrap},
};
use secrecy::SecretString;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use super::{ButtonRow, Form, FormDialog, ListView, TextInput, form::dialog_frame};
use crate::ui::{
    modal::{Modal, ModalOutcome},
    theme::Theme,
};

type OnClose = Box<dyn FnOnce(Option<usize>) + Send>;

/// Text and a row of buttons. Reports the pressed button, or `None` for Esc.
struct ChoiceBox {
    title: String,
    text: String,
    buttons: ButtonRow,
    on_close: Option<OnClose>,
}

impl ChoiceBox {
    fn new(title: &str, text: &str, buttons: &[&str], default: usize, on_close: OnClose) -> Self {
        Self {
            title: title.to_owned(),
            text: text.to_owned(),
            buttons: ButtonRow::new(buttons, default),
            on_close: Some(on_close),
        }
    }

    fn close(&mut self, pressed: Option<usize>) -> ModalOutcome {
        if let Some(f) = self.on_close.take() {
            f(pressed);
        }
        ModalOutcome::Close
    }
}

impl Modal for ChoiceBox {
    fn draw(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let width = 56u16.min(area.width.saturating_sub(4)).max(20);
        let text_rows = self
            .text
            .lines()
            .map(|l| (l.chars().count() as u16 / width.max(1)) + 1)
            .sum::<u16>()
            .max(1);
        if let Some(inner) = dialog_frame(frame, area, &self.title, width, text_rows + 2, theme) {
            frame.render_widget(
                Paragraph::new(self.text.as_str()).wrap(Wrap { trim: false }),
                Rect::new(
                    inner.x,
                    inner.y,
                    inner.width,
                    inner.height.saturating_sub(2),
                ),
            );
            self.buttons.draw(
                frame,
                Rect::new(inner.x, inner.bottom().saturating_sub(1), inner.width, 1),
                true,
                theme,
            );
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> ModalOutcome {
        if key.code == KeyCode::Esc {
            return self.close(None);
        }
        // `y`/`n` answer yes/no dialogs directly.
        if let KeyCode::Char(c) = key.code
            && key.modifiers.is_empty()
            && let Some(i) = self.buttons_starting_with(c)
        {
            return self.close(Some(i));
        }
        match self.buttons.handle_key(key) {
            Some(i) => self.close(Some(i)),
            None => ModalOutcome::Keep,
        }
    }
}

impl ChoiceBox {
    fn buttons_starting_with(&self, c: char) -> Option<usize> {
        // The same lookup as an Alt-mnemonic, without moving the highlight.
        self.buttons.clone().handle_key(key_with_alt(c))
    }
}

fn key_with_alt(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), crossterm::event::KeyModifiers::ALT)
}

/// Yes/No. `Esc` means no.
pub(crate) fn confirm(
    title: &str,
    text: &str,
    default_yes: bool,
) -> (Box<dyn Modal>, oneshot::Receiver<bool>) {
    let (tx, rx) = oneshot::channel();
    let modal = ChoiceBox::new(
        title,
        text,
        &["Yes", "No"],
        if default_yes { 0 } else { 1 },
        Box::new(move |pressed| {
            let _ = tx.send(pressed == Some(0));
        }),
    );
    (Box::new(modal), rx)
}

/// Text with a row of `buttons`: the index of the pressed one, `None` for
/// Esc.
pub(crate) fn ask(
    title: &str,
    text: &str,
    buttons: &[&str],
    default: usize,
) -> (Box<dyn Modal>, oneshot::Receiver<Option<usize>>) {
    let (tx, rx) = oneshot::channel();
    let modal = ChoiceBox::new(
        title,
        text,
        buttons,
        default,
        Box::new(move |pressed| {
            let _ = tx.send(pressed);
        }),
    );
    (Box::new(modal), rx)
}

/// A message with OK.
pub(crate) fn message(title: &str, text: &str) -> (Box<dyn Modal>, oneshot::Receiver<()>) {
    let (tx, rx) = oneshot::channel();
    let modal = ChoiceBox::new(
        title,
        text,
        &["OK"],
        0,
        Box::new(move |_| {
            let _ = tx.send(());
        }),
    );
    (Box::new(modal), rx)
}

/// An error with its chain of causes.
pub(crate) fn error(
    err: &(dyn std::error::Error + 'static),
) -> (Box<dyn Modal>, oneshot::Receiver<()>) {
    let mut text = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        text.push_str(&format!("\n  caused by: {cause}"));
        source = cause.source();
    }
    message("Error", &text)
}

/// One line of text. `None` when cancelled.
pub(crate) fn prompt_text(
    title: &str,
    label: &str,
    initial: &str,
) -> (Box<dyn Modal>, oneshot::Receiver<Option<String>>) {
    let form =
        Form::new(&["OK", "Cancel"]).field("value", TextInput::new(label).with_value(initial));
    let (dialog, rx) = FormDialog::new(title, 50, form, |v| Ok(v.text("value")));
    (Box::new(dialog), rx)
}

/// A password (never drawn). `None` when cancelled.
pub(crate) fn prompt_password(
    title: &str,
    label: &str,
) -> (Box<dyn Modal>, oneshot::Receiver<Option<SecretString>>) {
    let form = Form::new(&["OK", "Cancel"]).field("value", TextInput::password(label));
    let (dialog, rx) = FormDialog::new(title, 50, form, |v| {
        v.secret("value").ok_or_else(|| "no password".to_owned())
    });
    (Box::new(dialog), rx)
}

/// Pick one of `options`. `None` when cancelled.
pub(crate) fn choose(
    title: &str,
    options: Vec<String>,
) -> (Box<dyn Modal>, oneshot::Receiver<Option<usize>>) {
    let rows = u16::try_from(options.len())
        .unwrap_or(u16::MAX)
        .clamp(1, 15);
    let form = Form::new(&[]).field("choice", ListView::new("", options, rows));
    let (dialog, rx) = FormDialog::new(title, 50, form, |v| {
        v.index("choice").ok_or_else(|| "nothing chosen".to_owned())
    });
    (Box::new(dialog), rx)
}

#[derive(Debug, Default)]
struct ProgressState {
    message: String,
    done: u64,
    total: Option<u64>,
    finished: bool,
}

/// Updates a [`ProgressDialog`] from the task doing the work.
#[derive(Debug, Clone)]
pub(crate) struct ProgressHandle {
    state: Arc<Mutex<ProgressState>>,
    cancel: CancellationToken,
}

impl ProgressHandle {
    pub(crate) fn update(&self, message: impl Into<String>, done: u64, total: Option<u64>) {
        if let Ok(mut s) = self.state.lock() {
            s.message = message.into();
            s.done = done;
            s.total = total;
        }
    }

    /// Close the dialog.
    pub(crate) fn finish(&self) {
        if let Ok(mut s) = self.state.lock() {
            s.finished = true;
        }
    }

    /// Cancelled by the user.
    pub(crate) fn cancel_token(&self) -> &CancellationToken {
        &self.cancel
    }
}

/// A message, a progress bar and Cancel (recursive delete, search, import).
/// Cancel (or `Esc`) fires the handle's cancellation token and closes.
pub(crate) struct ProgressDialog {
    title: String,
    state: Arc<Mutex<ProgressState>>,
    cancel: CancellationToken,
    buttons: ButtonRow,
}

impl ProgressDialog {
    pub(crate) fn new(title: &str) -> (Self, ProgressHandle) {
        let state = Arc::new(Mutex::new(ProgressState::default()));
        let cancel = CancellationToken::new();
        let handle = ProgressHandle {
            state: Arc::clone(&state),
            cancel: cancel.clone(),
        };
        (
            Self {
                title: title.to_owned(),
                state,
                cancel,
                buttons: ButtonRow::new(&["Cancel"], 0),
            },
            handle,
        )
    }
}

impl Modal for ProgressDialog {
    fn draw(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let (message, ratio, label) = match self.state.lock() {
            Ok(s) => {
                let ratio = s
                    .total
                    .filter(|t| *t > 0)
                    .map_or(0.0, |t| (s.done as f64 / t as f64).clamp(0.0, 1.0));
                let label = match s.total {
                    Some(t) => format!("{} / {t}", s.done),
                    None => s.done.to_string(),
                };
                (s.message.clone(), ratio, label)
            }
            Err(_) => (String::new(), 0.0, String::new()),
        };
        if let Some(inner) = dialog_frame(frame, area, &self.title, 50, 5, theme) {
            frame.render_widget(
                Paragraph::new(Line::raw(message)),
                Rect::new(inner.x, inner.y, inner.width, 1),
            );
            frame.render_widget(
                Gauge::default()
                    .ratio(ratio)
                    .label(label)
                    .gauge_style(theme.selection),
                Rect::new(inner.x, inner.y + 2, inner.width, 1),
            );
            self.buttons.draw(
                frame,
                Rect::new(inner.x, inner.y + 4, inner.width, 1),
                true,
                theme,
            );
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> ModalOutcome {
        if matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
            self.cancel.cancel();
            return ModalOutcome::Close;
        }
        ModalOutcome::Keep
    }

    fn is_done(&self) -> bool {
        self.state.lock().is_ok_and(|s| s.finished)
    }
}
