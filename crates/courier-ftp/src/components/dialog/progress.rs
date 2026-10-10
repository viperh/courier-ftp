//! `progress`: a dialog for a long operation. Not drawn until `show_after` (300 ms),
//! closes on [`ProgressHandle::finish`], *Cancel*/`Esc` cancels the token and shows
//! `Cancelling…` until `finish()`.

use std::{borrow::Cow, time::Duration};

use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};
use tokio::{sync::watch, time::Instant};
use tokio_util::sync::CancellationToken;

use super::{Dialog, DialogSize, DialogStep, FIT_MAX_W, FIT_MIN_W, widget_cx, wrap_text};
use crate::{
    action::Action,
    components::{
        DrawCx,
        widgets::{Button, ButtonRole, ButtonRow, Widget, WidgetOutcome},
    },
    keymap::chord::KeyChord,
    ui::text::{sanitize, width},
};

/// Options of [`progress`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProgressOpts {
    /// Not drawn before this (300 ms).
    pub show_after: Duration,
    /// Has a *Cancel* button (true).
    pub cancellable: bool,
}

impl Default for ProgressOpts {
    fn default() -> Self {
        Self {
            show_after: Duration::from_millis(300),
            cancellable: true,
        }
    }
}

/// What the operation reports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ProgressState {
    /// Current step.
    pub message: String,
    /// Units done.
    pub done: u64,
    /// Units in total, when known (determinate bar).
    pub total: Option<u64>,
    /// The operation ended.
    pub finished: bool,
}

/// The operation's side of a progress dialog.
#[derive(Debug, Clone)]
pub(crate) struct ProgressHandle {
    tx: watch::Sender<ProgressState>,
}

impl ProgressHandle {
    /// Replaces the message.
    pub(crate) fn set_message(&self, m: String) {
        self.tx.send_modify(|s| s.message = m);
    }

    /// Reports progress.
    pub(crate) fn set_progress(&self, done: u64, total: Option<u64>) {
        self.tx.send_modify(|s| {
            s.done = done;
            s.total = total;
        });
    }

    /// The operation ended: the dialog closes.
    pub(crate) fn finish(&self) {
        self.tx.send_modify(|s| s.finished = true);
    }
}

/// The dialog of [`progress`].
#[derive(Debug)]
pub(crate) struct ProgressDialog {
    title: String,
    rx: watch::Receiver<ProgressState>,
    cancel: CancellationToken,
    opts: ProgressOpts,
    opened: Instant,
    cancelling: bool,
    buttons: ButtonRow,
}

impl ProgressDialog {
    /// Cancel was pressed and the operation has not finished yet.
    pub(crate) fn is_cancelling(&self) -> bool {
        self.cancelling
    }

    fn do_cancel(&mut self) -> DialogStep<()> {
        if self.opts.cancellable && !self.cancelling {
            self.cancel.cancel();
            self.cancelling = true;
        }
        DialogStep::Continue
    }

    fn state(&self) -> ProgressState {
        self.rx.borrow().clone()
    }
}

/// A progress dialog for an operation that `cancel` stops; the operation reports
/// through the returned handle.
pub(crate) fn progress(
    title: &str,
    message: &str,
    cancel: CancellationToken,
    opts: ProgressOpts,
) -> (ProgressDialog, ProgressHandle) {
    let (tx, rx) = watch::channel(ProgressState {
        message: message.to_owned(),
        ..ProgressState::default()
    });
    let buttons = if opts.cancellable {
        vec![Button::new("cancel", "Cancel", ButtonRole::Normal)]
    } else {
        Vec::new()
    };
    (
        ProgressDialog {
            title: title.to_owned(),
            rx,
            cancel,
            opts,
            opened: Instant::now(),
            cancelling: false,
            buttons: ButtonRow::new(buttons),
        },
        ProgressHandle { tx },
    )
}

impl Dialog for ProgressDialog {
    type Output = ();

    fn kind(&self) -> &'static str {
        "progress"
    }

    fn title(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.title)
    }

    fn size(&self, _screen: Rect) -> DialogSize {
        DialogSize::Fit {
            min_w: FIT_MIN_W,
            max_w: FIT_MAX_W,
        }
    }

    fn measure(&self, max_width: u16) -> (u16, u16) {
        let s = self.state();
        let w = u16::try_from(width(&sanitize(&s.message)) + 2)
            .unwrap_or(u16::MAX)
            .clamp(36, max_width.max(1))
            .min(max_width);
        let lines = u16::try_from(wrap_text(&s.message, w).len()).unwrap_or(1);
        (w, lines + 4)
    }

    fn handle_key(&mut self, key: KeyChord) -> DialogStep<()> {
        match self.buttons.handle_key(key) {
            WidgetOutcome::Activated => self.do_cancel(),
            WidgetOutcome::Ignored => match self.buttons.mnemonic(key, true) {
                Some(_) => self.do_cancel(),
                None => DialogStep::Ignored,
            },
            _ => DialogStep::Continue,
        }
    }

    fn handle_action(&mut self, action: &Action) -> DialogStep<()> {
        match action {
            // Never closes by itself: only `finish()` does.
            Action::DialogCancel | Action::DialogSubmit => self.do_cancel(),
            Action::NextField | Action::PrevField => DialogStep::Continue,
            _ => DialogStep::Ignored,
        }
    }

    fn poll(&mut self, _now: Instant) -> DialogStep<()> {
        if self.rx.borrow().finished {
            DialogStep::Close(Some(()))
        } else {
            DialogStep::Continue
        }
    }

    fn is_visible(&self, now: Instant) -> bool {
        !self.rx.borrow().finished && now.duration_since(self.opened) >= self.opts.show_after
    }

    fn render(&mut self, frame: &mut Frame, area: Rect, cx: &DrawCx) {
        let s = self.state();
        let msg = if self.cancelling {
            "Cancelling…".to_owned()
        } else {
            s.message.clone()
        };
        let mut lines: Vec<Line> = wrap_text(&msg, area.width)
            .into_iter()
            .map(Line::from)
            .collect();
        lines.push(Line::default());
        let w = usize::from(area.width);
        let bar_style = cx.theme.style("progress_bar");
        let bar = match s.total {
            Some(total) if total > 0 => {
                let pct = (u128::from(s.done.min(total)) * 100 / u128::from(total)) as usize;
                let label = format!(" {pct:>3}%");
                let bw = w.saturating_sub(label.len());
                let full = bw * pct / 100;
                Line::from(vec![
                    Span::styled(cx.symbols.bar_full.repeat(full), bar_style),
                    Span::raw(cx.symbols.bar_empty.repeat(bw - full)),
                    Span::raw(label),
                ])
            }
            _ => {
                // A block moving back and forth, and the spinner.
                let elapsed = cx.now.duration_since(self.opened).as_millis();
                let spin = cx.symbols.spinner_frame(elapsed);
                let bw = w.saturating_sub(2);
                let block = 4.min(bw);
                let span = (bw - block).max(1);
                let step = usize::try_from(elapsed / 100).unwrap_or(0) % (2 * span);
                let pos = if step < span { step } else { 2 * span - step };
                let pos = pos.min(bw - block);
                Line::from(vec![
                    Span::raw(cx.symbols.bar_empty.repeat(pos)),
                    Span::styled(cx.symbols.bar_full.repeat(block), bar_style),
                    Span::raw(cx.symbols.bar_empty.repeat(bw - block - pos)),
                    Span::raw(format!(" {spin}")),
                ])
            }
        };
        lines.push(bar);
        let rows = area.height.saturating_sub(2);
        lines.truncate(usize::from(rows));
        frame.render_widget(
            Paragraph::new(lines),
            Rect {
                height: rows,
                ..area
            },
        );
        if area.height > 0 && !self.buttons.buttons().is_empty() {
            let r = Rect {
                y: area.bottom() - 1,
                height: 1,
                ..area
            };
            self.buttons.render(
                frame,
                r,
                &widget_cx(cx, cx.focused && !self.cancelling, !self.cancelling),
            );
        }
    }
}
