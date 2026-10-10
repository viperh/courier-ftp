//! The modal stack: the help overlay, the quit confirmation, dialogs (T52) and the
//! unlock view (T60). The top modal gets every key; nothing below it sees one.

use ratatui::{Frame, layout::Rect};

use super::{Component, DrawCx};

/// A component shown on the modal stack.
pub(crate) trait Modal: Component {
    /// The modal wants to be closed (checked after every key and action).
    fn is_done(&self) -> bool;
}

/// Open modals, bottom first.
#[derive(Default)]
pub(crate) struct ModalStack {
    stack: Vec<Box<dyn Modal>>,
}

impl std::fmt::Debug for ModalStack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModalStack")
            .field("len", &self.stack.len())
            .finish()
    }
}

impl ModalStack {
    /// Opens `modal` on top.
    pub(crate) fn push(&mut self, modal: Box<dyn Modal>) {
        self.stack.push(modal);
    }

    /// No modal is open.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by tests and T52"))]
    pub(crate) fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    /// Number of open modals.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by tests and T52"))]
    pub(crate) fn len(&self) -> usize {
        self.stack.len()
    }

    /// The top modal.
    pub(crate) fn top_mut(&mut self) -> Option<&mut (dyn Modal + 'static)> {
        self.stack.last_mut().map(|b| &mut **b)
    }

    /// The top modal.
    pub(crate) fn top(&self) -> Option<&(dyn Modal + 'static)> {
        self.stack.last().map(|b| &**b)
    }

    /// Closes the modals that are done. Returns true if any was closed.
    pub(crate) fn close_done(&mut self) -> bool {
        let before = self.stack.len();
        self.stack.retain(|m| !m.is_done());
        before != self.stack.len()
    }

    /// Draws every modal, bottom first; only the top one is focused.
    pub(crate) fn draw(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        cx: &DrawCx,
    ) -> color_eyre::Result<()> {
        let n = self.stack.len();
        for (i, m) in self.stack.iter_mut().enumerate() {
            let cx = DrawCx {
                focused: i + 1 == n,
                ..*cx
            };
            m.draw(frame, area, &cx)?;
        }
        Ok(())
    }
}
