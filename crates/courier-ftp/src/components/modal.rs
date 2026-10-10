//! The modal stack: the help overlay, dialogs (T52) and the unlock view (T60). The top
//! modal gets every key; nothing below it sees one. Every modal is polled on each
//! tick and on `Action::Wake`.

use ratatui::{Frame, layout::Rect};
use tokio::{
    sync::{mpsc::UnboundedSender, oneshot},
    time::Instant,
};
use tracing::{debug, warn};

use super::{
    Component, DrawCx,
    dialog::{AnyDialog, Dialog, DialogModal, dim_screen, hosted, hosted_then},
};
use crate::action::Action;

/// Modals open at most; a further push is refused (its result is `None`).
pub(crate) const MAX_DEPTH: usize = 8;

/// A component shown on the modal stack.
pub(crate) trait Modal: Component {
    /// The modal wants to be closed (checked after every key and action).
    fn is_done(&self) -> bool;

    /// A dialog this modal wants opened on top of itself.
    fn take_push(&mut self) -> Option<Box<dyn AnyDialog>> {
        None
    }

    /// Timers and async results (every tick and on `Action::Wake`); may return a
    /// status message.
    fn poll(&mut self, now: Instant) -> Option<Action> {
        let _ = now;
        None
    }

    /// Everything below this modal is drawn dimmed.
    fn dims_background(&self) -> bool {
        false
    }

    /// Drawn at all (a progress dialog hides itself at first).
    fn is_visible(&self, now: Instant) -> bool {
        let _ = now;
        true
    }

    /// Holds unsaved edits (a dirty form; T60 discards them on lock).
    fn is_dirty(&self) -> bool {
        false
    }

    #[cfg_attr(not(test), allow(dead_code, reason = "used by tests and T53–T71"))]
    /// The kind of dialog shown (`confirm`), for tests and logs.
    fn dialog_kind(&self) -> Option<&'static str> {
        None
    }
}

/// Open modals, bottom first.
pub(crate) struct ModalStack {
    stack: Vec<Box<dyn Modal>>,
    action_tx: UnboundedSender<Action>,
}

impl std::fmt::Debug for ModalStack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModalStack")
            .field("len", &self.stack.len())
            .finish()
    }
}

impl ModalStack {
    /// An empty stack; `push_then` results go to `action_tx`.
    pub(crate) fn new(action_tx: UnboundedSender<Action>) -> Self {
        Self {
            stack: Vec::new(),
            action_tx,
        }
    }

    /// Opens a non-dialog modal (help overlay) on top.
    pub(crate) fn push_modal(&mut self, modal: Box<dyn Modal>) {
        if self.stack.len() >= MAX_DEPTH {
            warn!("modal stack full, not opening another modal");
            return;
        }
        self.stack.push(modal);
    }

    #[cfg_attr(not(test), allow(dead_code, reason = "used by tests and T53–T71"))]
    /// Opens `d`; its result arrives on the receiver (cancel → `None`).
    pub(crate) fn push<D: Dialog>(&mut self, d: D) -> oneshot::Receiver<Option<D::Output>> {
        let (any, rx) = hosted(d);
        self.push_any(any);
        rx
    }

    /// Opens `d`; its result is mapped by `then` to an action sent on the action
    /// channel.
    pub(crate) fn push_then<D: Dialog>(
        &mut self,
        d: D,
        then: impl FnOnce(Option<D::Output>) -> Option<Action> + Send + 'static,
    ) {
        let any = hosted_then(d, then, self.action_tx.clone());
        self.push_any(any);
    }

    /// Opens a type-erased dialog. Refused beyond [`MAX_DEPTH`] (dropping it delivers
    /// `None`).
    pub(crate) fn push_any(&mut self, d: Box<dyn AnyDialog>) -> bool {
        if self.stack.len() >= MAX_DEPTH {
            warn!("dialog refused: {MAX_DEPTH} modals are open");
            return false;
        }
        debug!("dialog opened: {}", d.kind());
        self.stack.push(Box::new(DialogModal::new(d)));
        true
    }

    /// Any open modal holds unsaved edits.
    pub(crate) fn any_dirty(&self) -> bool {
        self.stack.iter().any(|m| m.is_dirty())
    }

    /// No modal is open.
    pub(crate) fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    #[cfg_attr(not(test), allow(dead_code, reason = "used by tests and T53–T71"))]
    /// Number of open modals.
    pub(crate) fn len(&self) -> usize {
        self.stack.len()
    }

    #[cfg_attr(not(test), allow(dead_code, reason = "used by tests and T53–T71"))]
    /// Number of open modals (spec name).
    pub(crate) fn depth(&self) -> usize {
        self.stack.len()
    }

    #[cfg_attr(not(test), allow(dead_code, reason = "used by tests and T53–T71"))]
    /// Kinds of the open dialogs, bottom first (`None` for other modals).
    pub(crate) fn kinds(&self) -> Vec<Option<&'static str>> {
        self.stack.iter().map(|m| m.dialog_kind()).collect()
    }

    /// Closes everything (quit, vault lock): every pending receiver gets `None`.
    pub(crate) fn close_all(&mut self) {
        // Top first, so results arrive in stack order.
        while self.stack.pop().is_some() {}
    }

    /// The top modal.
    pub(crate) fn top_mut(&mut self) -> Option<&mut (dyn Modal + 'static)> {
        self.stack.last_mut().map(|b| &mut **b)
    }

    /// The top modal.
    pub(crate) fn top(&self) -> Option<&(dyn Modal + 'static)> {
        self.stack.last().map(|b| &**b)
    }

    /// Opens the dialogs modals asked for and closes the modals that are done; a
    /// modal uncovered by a close is polled at once (so it sees the result of the
    /// dialog it opened). Returns true if anything changed.
    pub(crate) fn close_done(&mut self) -> bool {
        let mut changed = false;
        for _ in 0..(MAX_DEPTH * 4) {
            let mut step = false;
            let pushes: Vec<_> = self
                .stack
                .iter_mut()
                .filter_map(|m| m.take_push())
                .collect();
            for d in pushes {
                self.push_any(d);
                step = true;
            }
            let before = self.stack.len();
            self.stack.retain(|m| !m.is_done());
            if self.stack.len() != before {
                step = true;
                let now = Instant::now();
                if let Some(top) = self.stack.last_mut()
                    && let Some(a) = top.poll(now)
                {
                    let _ = self.action_tx.send(a);
                }
            }
            if !step {
                break;
            }
            changed = true;
        }
        changed
    }

    /// Polls every modal (tick, `Action::Wake`); returns their status messages.
    pub(crate) fn poll_all(&mut self, now: Instant) -> Vec<Action> {
        let out: Vec<Action> = self.stack.iter_mut().filter_map(|m| m.poll(now)).collect();
        self.close_done();
        out
    }

    /// Draws every visible modal, bottom first; only the top one is focused, and the
    /// screen under the top dialog is dimmed.
    pub(crate) fn draw(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        cx: &DrawCx,
    ) -> color_eyre::Result<()> {
        let now = cx.now;
        let top = self.stack.iter().rposition(|m| m.is_visible(now));
        for (i, m) in self.stack.iter_mut().enumerate() {
            if !m.is_visible(now) {
                continue;
            }
            let focused = Some(i) == top;
            if focused && m.dims_background() {
                dim_screen(frame);
            }
            let cx = DrawCx { focused, ..*cx };
            m.draw(frame, area, &cx)?;
        }
        Ok(())
    }
}
