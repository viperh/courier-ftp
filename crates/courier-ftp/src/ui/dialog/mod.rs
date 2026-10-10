//! Dialogs and forms (T52): reusable widgets, a form model with focus
//! traversal and validation, and the standard dialogs every feature uses.
//!
//! Every widget implements [`Field`]. A [`Form`] holds fields in order, moves
//! focus with `Tab`/`Shift-Tab`, validates, and turns the values into a typed
//! result. A [`FormDialog`] puts a form on the modal stack and returns the
//! result through a `oneshot`, so callers (including core prompts, T04) can
//! await it.

// The framework is used piece by piece as the dialogs that need it land
// (quickconnect T58, Site Manager T59, file operations T62, trust prompts
// T69). Remove this once everything is used outside tests.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        unused_imports,
        reason = "widgets for T58/T59/T62/T68/T69 dialogs"
    )
)]

mod buttons;
mod choice;
mod form;
mod list;
mod standard;
mod text;

use std::collections::HashMap;

pub(crate) use buttons::ButtonRow;
pub(crate) use choice::{Checkbox, RadioGroup, Select, TriState, TriStateCheckbox};
use crossterm::event::KeyEvent;
pub(crate) use form::{Form, FormDialog, TabbedForm, dialog_frame_styled};
pub(crate) use list::ListView;
use ratatui::{Frame, layout::Rect};
use secrecy::SecretString;
pub(crate) use standard::{
    ProgressDialog, choose, confirm, error, message, prompt_password, prompt_text,
};
pub(crate) use text::{Completer, LocalPathCompleter, NumberInput, PathInput, TextInput};

use super::theme::Theme;

/// What a field did with a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FieldOutcome {
    /// The key was used.
    Consumed,
    /// Not for this field; the form may use it (Tab, Enter, Esc…).
    Ignored,
}

/// A field's value, as collected by [`Form::values`].
#[derive(Debug, Clone)]
pub(crate) enum FieldValue {
    Text(String),
    Secret(SecretString),
    Number(i64),
    Bool(bool),
    Tri(TriState),
    Index(usize),
}

/// One widget in a form.
pub(crate) trait Field: Send {
    /// The label shown left of the field.
    fn label(&self) -> &str;
    /// Rows the field needs.
    fn height(&self) -> u16 {
        1
    }
    /// Handle a key while focused.
    fn handle_key(&mut self, key: KeyEvent) -> FieldOutcome;
    /// Insert pasted text (bracketed paste). Most fields ignore it.
    fn handle_paste(&mut self, _text: &str) {}
    /// Draw into `area` (the label is drawn by the form).
    fn draw(&self, frame: &mut Frame, area: Rect, focused: bool, theme: &Theme);
    /// Draw anything that overlaps other fields (an open dropdown), after the
    /// whole form is drawn.
    fn draw_overlay(&self, _frame: &mut Frame, _area: Rect, _theme: &Theme) {}
    /// The current value.
    fn value(&self) -> FieldValue;
    /// A validation error to show under the field, if any.
    fn error(&self) -> Option<String> {
        None
    }
    /// Show validation errors from now on (the form calls this on submit).
    fn touch(&mut self) {}
    /// Whether the field is busy with a key sequence of its own (an open
    /// dropdown), so `Enter`/`Esc` must not submit or cancel the form.
    fn is_capturing(&self) -> bool {
        false
    }
}

/// The values of a submitted form, by field key.
#[derive(Debug, Default)]
pub(crate) struct FormValues(pub(crate) HashMap<String, FieldValue>);

impl FormValues {
    pub(crate) fn text(&self, key: &str) -> String {
        match self.0.get(key) {
            Some(FieldValue::Text(s)) => s.clone(),
            _ => String::new(),
        }
    }

    pub(crate) fn secret(&self, key: &str) -> Option<SecretString> {
        match self.0.get(key) {
            Some(FieldValue::Secret(s)) => Some(s.clone()),
            _ => None,
        }
    }

    pub(crate) fn number(&self, key: &str) -> Option<i64> {
        match self.0.get(key) {
            Some(FieldValue::Number(n)) => Some(*n),
            _ => None,
        }
    }

    pub(crate) fn bool(&self, key: &str) -> bool {
        matches!(self.0.get(key), Some(FieldValue::Bool(true)))
    }

    pub(crate) fn tri(&self, key: &str) -> Option<TriState> {
        match self.0.get(key) {
            Some(FieldValue::Tri(t)) => Some(*t),
            _ => None,
        }
    }

    pub(crate) fn index(&self, key: &str) -> Option<usize> {
        match self.0.get(key) {
            Some(FieldValue::Index(i)) => Some(*i),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
