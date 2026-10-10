//! Dialogs (T52): the [`Dialog`] trait, its type erasure ([`AnyDialog`]), the adapter
//! that puts a dialog on the [`ModalStack`](super::modal::ModalStack), sizing and the
//! shared frame drawing (dimmed background, border, title, "too small" fallback).
//!
//! Results come back either over a `oneshot` channel (`ModalStack::push`, core
//! prompts) or mapped to an [`Action`] (`ModalStack::push_then`). A dialog that is
//! dropped without closing (`close_all`, depth limit) delivers `None`.

#![allow(
    dead_code,
    unused_imports,
    reason = "framework: parts are used only by the dialogs of T53–T71"
)]

use std::borrow::Cow;

use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
};
use tokio::{
    sync::{mpsc::UnboundedSender, oneshot},
    time::Instant,
};

use super::{Component, DrawCx, KeyOutcome, modal::Modal, widgets::WidgetCx};
use crate::{
    action::Action,
    app::Mode,
    keymap::chord::KeyChord,
    ui::text::{sanitize, truncate_to_width, width},
};

pub(crate) mod form;
pub(crate) mod progress;
pub(crate) mod standard;

#[cfg(test)]
mod app_tests;
#[cfg(test)]
mod snapshot_tests;
#[cfg(test)]
mod tests;

pub(crate) use form::{
    FieldId, FieldValue, FieldWidget, Form, FormBuilder, FormDialog, FormField, FormValues,
    TabbedForm,
};
pub(crate) use progress::{ProgressHandle, ProgressOpts, progress};
pub(crate) use standard::{
    ChoiceOption, ConfirmOpts, MessageLevel, choose, confirm, error, error_report, message,
    problems, prompt_password, prompt_text, text_viewer,
};

/// Smallest screen a dialog is drawn on; below it shows [`TOO_SMALL`].
pub(crate) const MIN_SCREEN: (u16, u16) = (30, 8);
/// Shown instead of a dialog on a too small screen.
pub(crate) const TOO_SMALL: &str = "Terminal too small for this dialog";
/// Width bounds of message-style dialogs.
pub(crate) const FIT_MIN_W: u16 = 40;
/// Width bounds of message-style dialogs.
pub(crate) const FIT_MAX_W: u16 = 76;

/// The actions of the `Dialog` key table a dialog handles.
pub(crate) const DIALOG_ACTIONS: &[Action] = &[
    Action::DialogSubmit,
    Action::DialogCancel,
    Action::DialogSave,
    Action::NextField,
    Action::PrevField,
    Action::NextFormTab,
    Action::PrevFormTab,
];

/// How big a dialog is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DialogSize {
    /// Content width + 4 clamped to `min_w..=min(max_w, screen − 4)`; content height +
    /// 2, at most screen height − 2.
    Fit {
        /// Minimum width.
        min_w: u16,
        /// Maximum width.
        max_w: u16,
    },
    /// Exactly this big (too small when the screen is smaller).
    Fixed {
        /// Width.
        w: u16,
        /// Height.
        h: u16,
    },
    /// A share of the screen.
    Percent {
        /// Width percent.
        w: u8,
        /// Height percent.
        h: u8,
    },
    /// The whole screen (unlock view T60, search view T65).
    FullScreen,
}

/// What a dialog did with a key, action, paste or poll.
pub(crate) enum DialogStep<T> {
    /// Used; stay open.
    Continue,
    /// Not used (keys then go to the `Dialog` key table).
    Ignored,
    /// Close with a result; `None` = cancelled.
    Close(Option<T>),
    /// Open another dialog on top (e.g. "Discard changes?").
    Push(Box<dyn AnyDialog>),
}

impl<T> std::fmt::Debug for DialogStep<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Continue => f.write_str("Continue"),
            Self::Ignored => f.write_str("Ignored"),
            Self::Close(r) => write!(f, "Close({})", if r.is_some() { "Some" } else { "None" }),
            Self::Push(d) => write!(f, "Push({})", d.kind()),
        }
    }
}

/// A modal dialog.
pub(crate) trait Dialog: Send + 'static {
    /// The result.
    type Output: Send + 'static;

    /// Short kind name for logs (`confirm`); never the title (it may hold paths).
    fn kind(&self) -> &'static str {
        "dialog"
    }

    /// Title (sanitised when drawn).
    fn title(&self) -> Cow<'_, str>;

    /// Size rule.
    fn size(&self, screen: Rect) -> DialogSize;

    /// Preferred content size (inside border and padding) for `Fit`, given the widest
    /// content allowed.
    fn measure(&self, max_width: u16) -> (u16, u16) {
        (max_width, 3)
    }

    /// A key, before the `Dialog` key table.
    fn handle_key(&mut self, key: KeyChord) -> DialogStep<Self::Output>;

    /// Actions from the `Dialog` key table (`DialogSubmit`, `DialogCancel`, …).
    fn handle_action(&mut self, action: &Action) -> DialogStep<Self::Output>;

    /// Bracketed paste.
    fn handle_paste(&mut self, text: &str) -> DialogStep<Self::Output> {
        let _ = text;
        DialogStep::Ignored
    }

    /// Every tick (4 Hz) and on `Action::Wake`: timers, progress, withdrawn prompts.
    fn poll(&mut self, now: Instant) -> DialogStep<Self::Output> {
        let _ = now;
        DialogStep::Continue
    }

    /// Draws the content into `area` (inside the border and padding).
    fn render(&mut self, frame: &mut Frame, area: Rect, cx: &DrawCx);

    /// Unsaved edits: `Esc` asks "Discard changes?" first.
    fn is_dirty(&self) -> bool {
        false
    }

    /// Drawn at all (`progress` hides itself for its first 300 ms).
    fn is_visible(&self, now: Instant) -> bool {
        let _ = now;
        true
    }

    /// A status-line message to show (paste cut, completion failed), taken once.
    fn take_notice(&mut self) -> Option<String> {
        None
    }
}

/// What a type-erased dialog did.
pub(crate) enum AnyStep {
    /// Used; stays open.
    Continue,
    /// Not used.
    Ignored,
    /// Closed (the result was delivered).
    Closed,
    /// Open this dialog on top.
    Push(Box<dyn AnyDialog>),
}

/// A dialog with its result sink, type-erased for the stack.
pub(crate) trait AnyDialog: Send {
    /// Kind name for logs.
    fn kind(&self) -> &'static str;
    /// See [`Dialog::handle_key`].
    fn handle_key(&mut self, key: KeyChord) -> AnyStep;
    /// See [`Dialog::handle_action`]; also runs the discard guard.
    fn handle_action(&mut self, action: &Action) -> AnyStep;
    /// See [`Dialog::handle_paste`].
    fn handle_paste(&mut self, text: &str) -> AnyStep;
    /// See [`Dialog::poll`].
    fn poll(&mut self, now: Instant) -> AnyStep;
    /// Draws the frame and the content on `screen`.
    fn render(&mut self, frame: &mut Frame, screen: Rect, cx: &DrawCx);
    /// See [`Dialog::is_visible`].
    fn is_visible(&self, now: Instant) -> bool;
    /// See [`Dialog::take_notice`].
    fn take_notice(&mut self) -> Option<String>;
}

type ThenFn<T> = Box<dyn FnOnce(Option<T>) -> Option<Action> + Send>;

/// Where a result goes.
enum Sink<T> {
    Channel(oneshot::Sender<Option<T>>),
    Then(ThenFn<T>, UnboundedSender<Action>),
}

impl<T> Sink<T> {
    fn deliver(self, result: Option<T>) {
        match self {
            Self::Channel(tx) => {
                let _ = tx.send(result);
            }
            Self::Then(f, tx) => {
                if let Some(a) = f(result) {
                    let _ = tx.send(a);
                }
            }
        }
    }
}

/// A dialog and its sink.
struct Host<D: Dialog> {
    dialog: D,
    sink: Option<Sink<D::Output>>,
    discard: Option<oneshot::Receiver<Option<bool>>>,
}

impl<D: Dialog> Drop for Host<D> {
    fn drop(&mut self) {
        if let Some(s) = self.sink.take() {
            s.deliver(None);
        }
    }
}

impl<D: Dialog> Host<D> {
    fn step(&mut self, s: DialogStep<D::Output>) -> AnyStep {
        match s {
            DialogStep::Continue => AnyStep::Continue,
            DialogStep::Ignored => AnyStep::Ignored,
            DialogStep::Push(d) => AnyStep::Push(d),
            DialogStep::Close(r) => {
                if let Some(sink) = self.sink.take() {
                    sink.deliver(r);
                }
                AnyStep::Closed
            }
        }
    }
}

/// The "Discard changes?" question of a dirty dialog.
fn discard_dialog() -> impl Dialog<Output = bool> {
    confirm(
        "Discard changes?",
        "Your changes will be lost.",
        ConfirmOpts::danger("Discard"),
    )
}

impl<D: Dialog> AnyDialog for Host<D> {
    fn kind(&self) -> &'static str {
        self.dialog.kind()
    }

    fn handle_key(&mut self, key: KeyChord) -> AnyStep {
        let s = self.dialog.handle_key(key);
        self.step(s)
    }

    fn handle_action(&mut self, action: &Action) -> AnyStep {
        if matches!(action, Action::DialogCancel) && self.dialog.is_dirty() {
            let (d, rx) = hosted(discard_dialog());
            self.discard = Some(rx);
            return AnyStep::Push(d);
        }
        let s = self.dialog.handle_action(action);
        if matches!(s, DialogStep::Ignored) && matches!(action, Action::DialogCancel) {
            return self.step(DialogStep::Close(None));
        }
        self.step(s)
    }

    fn handle_paste(&mut self, text: &str) -> AnyStep {
        let s = self.dialog.handle_paste(text);
        self.step(s)
    }

    fn poll(&mut self, now: Instant) -> AnyStep {
        if let Some(rx) = &mut self.discard {
            match rx.try_recv() {
                Ok(Some(true)) => {
                    self.discard = None;
                    return self.step(DialogStep::Close(None));
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
                _ => self.discard = None,
            }
        }
        let s = self.dialog.poll(now);
        self.step(s)
    }

    fn render(&mut self, frame: &mut Frame, screen: Rect, cx: &DrawCx) {
        let size = self.dialog.size(screen);
        let dialog = &self.dialog;
        let Some(r) = dialog_rect(size, screen, |w| dialog.measure(w)) else {
            draw_too_small(frame, screen, cx);
            return;
        };
        let title = self.dialog.title();
        let inner = draw_frame(frame, r, &title, cx);
        if inner.width > 0 && inner.height > 0 {
            self.dialog.render(frame, inner, cx);
        }
    }

    fn is_visible(&self, now: Instant) -> bool {
        self.dialog.is_visible(now)
    }

    fn take_notice(&mut self) -> Option<String> {
        self.dialog.take_notice()
    }
}

/// Wraps a dialog whose result arrives on the returned receiver (used for dialogs that
/// open dialogs, like the discard guard).
pub(crate) fn hosted<D: Dialog>(
    d: D,
) -> (Box<dyn AnyDialog>, oneshot::Receiver<Option<D::Output>>) {
    let (tx, rx) = oneshot::channel();
    (
        Box::new(Host {
            dialog: d,
            sink: Some(Sink::Channel(tx)),
            discard: None,
        }),
        rx,
    )
}

/// Wraps a dialog whose result is mapped to an action sent on `tx`.
pub(crate) fn hosted_then<D: Dialog>(
    d: D,
    then: impl FnOnce(Option<D::Output>) -> Option<Action> + Send + 'static,
    tx: UnboundedSender<Action>,
) -> Box<dyn AnyDialog> {
    Box::new(Host {
        dialog: d,
        sink: Some(Sink::Then(Box::new(then), tx)),
        discard: None,
    })
}

/// Where a dialog of `size` goes on `screen`; `None` when the screen is smaller than
/// 30×8 or than the dialog's own minimum (`Fit::min_w`, `Fixed`).
pub(crate) fn dialog_rect(
    size: DialogSize,
    screen: Rect,
    measure: impl Fn(u16) -> (u16, u16),
) -> Option<Rect> {
    if screen.width < MIN_SCREEN.0 || screen.height < MIN_SCREEN.1 {
        return None;
    }
    let (w, h) = match size {
        DialogSize::FullScreen => return Some(screen),
        DialogSize::Fixed { w, h } => {
            if w > screen.width || h > screen.height {
                return None;
            }
            (w, h)
        }
        DialogSize::Percent { w, h } => (
            (u32::from(screen.width) * u32::from(w.min(100)) / 100)
                .try_into()
                .unwrap_or(screen.width)
                .max(MIN_SCREEN.0)
                .min(screen.width),
            (u32::from(screen.height) * u32::from(h.min(100)) / 100)
                .try_into()
                .unwrap_or(screen.height)
                .max(MIN_SCREEN.1)
                .min(screen.height),
        ),
        DialogSize::Fit { min_w, max_w } => {
            if min_w > screen.width {
                // The dialog's own minimum.
                return None;
            }
            let max_w = max_w.min(screen.width.saturating_sub(4)).max(min_w);
            let (cw, ch) = measure(max_w.saturating_sub(4));
            let w = cw.saturating_add(4).clamp(min_w, max_w);
            let h = ch.saturating_add(2).min(screen.height.saturating_sub(2));
            (w, h)
        }
    };
    Some(Rect {
        x: screen.x + (screen.width - w) / 2,
        y: screen.y + (screen.height - h) / 2,
        width: w,
        height: h,
    })
}

/// Clears `r`, draws the dialog border and title; returns the content area (inside
/// the border, one column of padding left and right).
pub(crate) fn draw_frame(frame: &mut Frame, r: Rect, title: &str, cx: &DrawCx) -> Rect {
    frame.render_widget(Clear, r);
    let border = cx.theme.style("dialog_border");
    let title = sanitize(title);
    let max = usize::from(r.width.saturating_sub(4));
    let shown = truncate_to_width(&title, max, cx.symbols.ellipsis).into_owned();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(cx.symbols.border)
        .border_style(border)
        .title(Line::from(vec![
            Span::styled(" ", border),
            Span::styled(shown, cx.theme.style("dialog_title")),
            Span::styled(" ", border),
        ]));
    let inner = block.inner(r);
    frame.render_widget(block, r);
    Rect {
        x: inner.x.saturating_add(1),
        width: inner.width.saturating_sub(2),
        ..inner
    }
}

/// The fallback on a too small screen: the message, centred, over a cleared screen.
pub(crate) fn draw_too_small(frame: &mut Frame, screen: Rect, cx: &DrawCx) {
    frame.render_widget(Clear, screen);
    if screen.width == 0 || screen.height == 0 {
        return;
    }
    let lines: Vec<Line> = wrap_text(TOO_SMALL, screen.width)
        .into_iter()
        .map(|l| Line::from(Span::styled(l, cx.theme.style("dialog_title"))))
        .collect();
    let h = u16::try_from(lines.len())
        .unwrap_or(u16::MAX)
        .min(screen.height);
    let r = Rect {
        y: screen.y + (screen.height - h) / 2,
        height: h,
        ..screen
    };
    frame.render_widget(
        Paragraph::new(lines).alignment(ratatui::layout::Alignment::Center),
        r,
    );
}

/// Adds `DIM` to every cell (the background of the top dialog).
pub(crate) fn dim_screen(frame: &mut Frame) {
    let dim = Style::default().add_modifier(Modifier::DIM);
    for cell in &mut frame.buffer_mut().content {
        cell.set_style(dim);
    }
}

/// Wraps `text` at word boundaries to `max` display columns (sanitised; words longer
/// than a line are split). Each `\n` starts a new line.
pub(crate) fn wrap_text(text: &str, max: u16) -> Vec<String> {
    use unicode_width::UnicodeWidthChar;
    let max = usize::from(max.max(1));
    let mut out = Vec::new();
    for para in text.split('\n') {
        let para = sanitize(para.strip_suffix('\r').unwrap_or(para)).into_owned();
        let mut line = String::new();
        let mut lw = 0;
        for word in para.split(' ') {
            let ww = width(word);
            if lw > 0 && lw + 1 + ww <= max {
                line.push(' ');
                line.push_str(word);
                lw += 1 + ww;
                continue;
            }
            if lw > 0 {
                out.push(std::mem::take(&mut line));
                lw = 0;
            }
            if ww <= max {
                word.clone_into(&mut line);
                lw = ww;
                continue;
            }
            // A word longer than a line is split.
            for c in word.chars() {
                let cw = c.width().unwrap_or(0);
                if lw > 0 && lw + cw > max {
                    out.push(std::mem::take(&mut line));
                    lw = 0;
                }
                line.push(c);
                lw += cw;
            }
        }
        out.push(line);
    }
    out
}

/// The display width of the widest line of `text` (sanitised).
pub(crate) fn text_width(text: &str) -> usize {
    text.split('\n')
        .map(|l| width(&sanitize(l)))
        .max()
        .unwrap_or(0)
}

/// A widget context from a draw context.
pub(crate) fn widget_cx<'a>(cx: &DrawCx<'a>, focused: bool, enabled: bool) -> WidgetCx<'a> {
    WidgetCx {
        theme: cx.theme,
        symbols: cx.symbols,
        focused,
        enabled,
        now: cx.now,
    }
}

/// Puts a type-erased dialog on the modal stack (a [`Modal`]).
pub(crate) struct DialogModal {
    inner: Box<dyn AnyDialog>,
    done: bool,
    push: Option<Box<dyn AnyDialog>>,
}

impl std::fmt::Debug for DialogModal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DialogModal")
            .field("kind", &self.inner.kind())
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl DialogModal {
    /// Wraps `inner`.
    pub(crate) fn new(inner: Box<dyn AnyDialog>) -> Self {
        Self {
            inner,
            done: false,
            push: None,
        }
    }

    /// Kind of the wrapped dialog.
    pub(crate) fn kind(&self) -> &'static str {
        self.inner.kind()
    }

    /// Applies a step; returns whether it was used.
    fn apply(&mut self, s: AnyStep) -> bool {
        match s {
            AnyStep::Continue => true,
            AnyStep::Ignored => false,
            AnyStep::Closed => {
                self.done = true;
                true
            }
            AnyStep::Push(d) => {
                self.push = Some(d);
                true
            }
        }
    }

    fn notice(&mut self) -> Option<Action> {
        self.inner.take_notice().map(Action::StatusMessage)
    }
}

impl Component for DialogModal {
    fn key_mode(&self) -> Mode {
        Mode::Dialog
    }

    fn handle_key(&mut self, key: KeyChord) -> color_eyre::Result<KeyOutcome> {
        let s = self.inner.handle_key(key);
        if self.apply(s) {
            Ok(KeyOutcome::Consumed(self.notice()))
        } else {
            Ok(KeyOutcome::Ignored)
        }
    }

    fn handle_paste(&mut self, text: &str) -> color_eyre::Result<KeyOutcome> {
        let s = self.inner.handle_paste(text);
        if self.apply(s) {
            Ok(KeyOutcome::Consumed(self.notice()))
        } else {
            Ok(KeyOutcome::Ignored)
        }
    }

    fn handled_actions(&self) -> &'static [Action] {
        DIALOG_ACTIONS
    }

    fn update(&mut self, action: &Action) -> color_eyre::Result<Option<Action>> {
        let s = self.inner.handle_action(action);
        if !self.apply(s) && matches!(action, Action::Quit) {
            // Not the quit confirmation: quit (or ask) from the app.
            return Ok(Some(Action::Quit));
        }
        Ok(self.notice())
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect, cx: &DrawCx) -> color_eyre::Result<()> {
        self.inner.render(frame, area, cx);
        Ok(())
    }
}

impl Modal for DialogModal {
    fn is_done(&self) -> bool {
        self.done
    }

    fn take_push(&mut self) -> Option<Box<dyn AnyDialog>> {
        self.push.take()
    }

    fn poll(&mut self, now: Instant) -> Option<Action> {
        if self.done {
            return None;
        }
        let s = self.inner.poll(now);
        self.apply(s);
        self.notice()
    }

    fn dims_background(&self) -> bool {
        true
    }

    fn is_visible(&self, now: Instant) -> bool {
        self.inner.is_visible(now)
    }

    fn dialog_kind(&self) -> Option<&'static str> {
        Some(self.inner.kind())
    }
}
