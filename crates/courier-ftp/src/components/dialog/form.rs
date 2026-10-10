//! Forms: labelled fields with validation, visibility, dirty tracking and scrolling
//! ([`Form`]); a form in a dialog ([`FormDialog`]) and several pages of forms
//! ([`TabbedForm`]).

use std::{borrow::Cow, collections::BTreeMap, collections::HashMap, fmt};

use courier_ftp_core::secret::SecretString;
use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Position, Rect},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};
use tokio::time::Instant;

use super::{Dialog, DialogSize, DialogStep, FIT_MAX_W, FIT_MIN_W, widget_cx};
use crate::{
    action::Action,
    components::{
        DrawCx,
        widgets::{
            Button, ButtonRole, ButtonRow, Checkbox, ListView, Notice, NumberInput, PathInput,
            RadioGroup, SecretInput, Select, TextArea, TextInput, TriState, TriStateCheckbox,
            Widget, WidgetOutcome,
        },
    },
    keymap::chord::{KeyChord, Mods},
    ui::text::{sanitize, truncate_to_width, width},
};

/// A field's identifier (unique in a form; across pages of a tabbed form).
pub(crate) type FieldId = &'static str;

/// Widest label column (labels are cut with `…`).
const MAX_LABEL: usize = 24;
/// Preferred widget width for `Fit` sizing.
const WIDGET_W: usize = 36;

/// The widget of a field.
pub(crate) enum FieldWidget {
    /// Single-line text.
    Text(TextInput),
    /// Password.
    Secret(SecretInput),
    /// Integer.
    Number(NumberInput),
    /// Checkbox.
    Check(Checkbox),
    /// Tri-state checkbox.
    Tri(TriStateCheckbox),
    /// Drop-down.
    Select(Select<String>),
    /// Radio buttons.
    Radio(RadioGroup),
    /// Path with completion.
    Path(PathInput),
    /// Multi-line text.
    Area(TextArea),
    /// List with checkboxes or marks.
    List(ListView<String>),
    /// Anything else (no value in [`FormValues`]).
    Custom(Box<dyn Widget + Send>),
}

impl fmt::Debug for FieldWidget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Text(_) => "Text",
            Self::Secret(_) => "Secret",
            Self::Number(_) => "Number",
            Self::Check(_) => "Check",
            Self::Tri(_) => "Tri",
            Self::Select(_) => "Select",
            Self::Radio(_) => "Radio",
            Self::Path(_) => "Path",
            Self::Area(_) => "Area",
            Self::List(_) => "List",
            Self::Custom(_) => "Custom",
        };
        f.write_str(name)
    }
}

impl FieldWidget {
    /// The widget.
    pub(crate) fn widget(&self) -> &dyn Widget {
        match self {
            Self::Text(w) => w,
            Self::Secret(w) => w,
            Self::Number(w) => w,
            Self::Check(w) => w,
            Self::Tri(w) => w,
            Self::Select(w) => w,
            Self::Radio(w) => w,
            Self::Path(w) => w,
            Self::Area(w) => w,
            Self::List(w) => w,
            Self::Custom(w) => w.as_ref(),
        }
    }

    /// The widget.
    pub(crate) fn widget_mut(&mut self) -> &mut dyn Widget {
        match self {
            Self::Text(w) => w,
            Self::Secret(w) => w,
            Self::Number(w) => w,
            Self::Check(w) => w,
            Self::Tri(w) => w,
            Self::Select(w) => w,
            Self::Radio(w) => w,
            Self::Path(w) => w,
            Self::Area(w) => w,
            Self::List(w) => w,
            Self::Custom(w) => w.as_mut(),
        }
    }

    fn value(&self) -> Option<FieldValue> {
        Some(match self {
            Self::Text(w) => FieldValue::Text(w.value().to_owned()),
            Self::Secret(w) => FieldValue::Secret(w.snapshot()),
            Self::Number(w) => FieldValue::Number(w.value()),
            Self::Check(w) => FieldValue::Bool(w.checked),
            Self::Tri(w) => FieldValue::Tri(w.state),
            Self::Select(w) => FieldValue::Choice(w.index()),
            Self::Radio(w) => FieldValue::Choice(w.value()),
            Self::Path(w) => FieldValue::Text(w.value().to_owned()),
            Self::Area(w) => FieldValue::Lines(w.value()),
            Self::List(w) => FieldValue::Checked(w.checked()),
            Self::Custom(_) => return None,
        })
    }

    /// Runs the widget's own validator; the error message, if any.
    fn validate(&mut self) -> Option<String> {
        match self {
            Self::Text(w) => (!w.validate()).then(|| w.error().unwrap_or_default().to_owned()),
            Self::Number(w) => (!w.validate()).then(|| w.error().unwrap_or_default().to_owned()),
            Self::Path(w) => {
                let t = w.input_mut();
                (!t.validate()).then(|| t.error().unwrap_or_default().to_owned())
            }
            _ => None,
        }
    }
}

/// The value of a field.
pub(crate) enum FieldValue {
    /// Text and path fields.
    Text(String),
    /// Password fields (a copy; zeroed on drop).
    Secret(SecretString),
    /// Number fields.
    Number(Option<i64>),
    /// Checkboxes.
    Bool(bool),
    /// Tri-state checkboxes.
    Tri(TriState),
    /// Selects and radio groups: the option index.
    Choice(usize),
    /// Multi-line text.
    Lines(String),
    /// Lists: the checkbox of every item.
    Checked(Vec<bool>),
}

impl fmt::Debug for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(t) => write!(f, "Text({t:?})"),
            Self::Secret(_) => f.write_str("Secret(****)"),
            Self::Number(n) => write!(f, "Number({n:?})"),
            Self::Bool(b) => write!(f, "Bool({b})"),
            Self::Tri(t) => write!(f, "Tri({t:?})"),
            Self::Choice(c) => write!(f, "Choice({c})"),
            Self::Lines(l) => write!(f, "Lines({l:?})"),
            Self::Checked(c) => write!(f, "Checked({c:?})"),
        }
    }
}

impl FieldValue {
    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Text(a), Self::Text(b)) | (Self::Lines(a), Self::Lines(b)) => a == b,
            (Self::Secret(a), Self::Secret(b)) => a.ct_eq(b),
            (Self::Number(a), Self::Number(b)) => a == b,
            (Self::Bool(a), Self::Bool(b)) => a == b,
            (Self::Tri(a), Self::Tri(b)) => a == b,
            (Self::Choice(a), Self::Choice(b)) => a == b,
            (Self::Checked(a), Self::Checked(b)) => a == b,
            _ => false,
        }
    }
}

/// Every field's value (visible and hidden fields).
#[derive(Debug, Default)]
pub(crate) struct FormValues {
    map: BTreeMap<FieldId, FieldValue>,
}

impl FormValues {
    /// The value of `id`.
    pub(crate) fn get(&self, id: FieldId) -> Option<&FieldValue> {
        self.map.get(id)
    }

    /// Text of a text, path or multi-line field ("" otherwise).
    pub(crate) fn text(&self, id: FieldId) -> &str {
        match self.map.get(id) {
            Some(FieldValue::Text(t) | FieldValue::Lines(t)) => t,
            _ => "",
        }
    }

    /// A password field.
    pub(crate) fn secret(&self, id: FieldId) -> Option<&SecretString> {
        match self.map.get(id) {
            Some(FieldValue::Secret(s)) => Some(s),
            _ => None,
        }
    }

    /// A number field.
    pub(crate) fn number(&self, id: FieldId) -> Option<i64> {
        match self.map.get(id) {
            Some(FieldValue::Number(n)) => *n,
            _ => None,
        }
    }

    /// A checkbox.
    pub(crate) fn bool(&self, id: FieldId) -> bool {
        matches!(self.map.get(id), Some(FieldValue::Bool(true)))
    }

    /// A tri-state checkbox.
    pub(crate) fn tri(&self, id: FieldId) -> Option<TriState> {
        match self.map.get(id) {
            Some(FieldValue::Tri(t)) => Some(*t),
            _ => None,
        }
    }

    /// A select or radio group (0 otherwise).
    pub(crate) fn choice(&self, id: FieldId) -> usize {
        match self.map.get(id) {
            Some(FieldValue::Choice(c)) => *c,
            _ => 0,
        }
    }

    /// A list's checkboxes.
    pub(crate) fn checked(&self, id: FieldId) -> &[bool] {
        match self.map.get(id) {
            Some(FieldValue::Checked(c)) => c,
            _ => &[],
        }
    }

    fn extend(&mut self, other: Self) {
        self.map.extend(other.map);
    }
}

/// One field of a form.
pub(crate) struct FormField {
    /// Identifier.
    pub id: FieldId,
    /// Label (left column).
    pub label: String,
    /// Shown dim on the last body row while focused.
    pub help: Option<String>,
    /// The widget.
    pub widget: FieldWidget,
    /// Hidden fields keep their value but are not validated nor focusable.
    pub visible: bool,
    /// `Err(reason)`: disabled, the reason is shown, not focusable.
    pub enabled: Result<(), String>,
}

impl fmt::Debug for FormField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FormField")
            .field("id", &self.id)
            .field("widget", &self.widget)
            .field("visible", &self.visible)
            .field("enabled", &self.enabled.is_ok())
            .finish_non_exhaustive()
    }
}

type CrossFn = Box<dyn Fn(&FormValues) -> Vec<(FieldId, String)> + Send>;
type ChangeFn = Box<dyn FnMut(&mut Form, FieldId) + Send>;

/// Labelled fields (see the module docs). Focus index `fields.len()` is the button row
/// of the dialog the form is in.
pub(crate) struct Form {
    fields: Vec<FormField>,
    focus: usize,
    errors: HashMap<FieldId, String>,
    initial: Vec<(FieldId, FieldValue)>,
    cross: Option<CrossFn>,
    on_change: Option<ChangeFn>,
    scroll: usize,
    /// Where the focused widget was drawn last (for its overlay).
    overlay_at: Option<Rect>,
}

impl fmt::Debug for Form {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Form")
            .field("fields", &self.fields)
            .field("focus", &self.focus)
            .field("errors", &self.errors)
            .finish_non_exhaustive()
    }
}

/// Builds a [`Form`].
#[derive(Default)]
pub(crate) struct FormBuilder {
    fields: Vec<FormField>,
    cross: Option<CrossFn>,
    on_change: Option<ChangeFn>,
}

impl fmt::Debug for FormBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FormBuilder")
            .field("fields", &self.fields)
            .finish_non_exhaustive()
    }
}

impl FormBuilder {
    /// Adds a field.
    #[must_use]
    pub(crate) fn field(mut self, id: FieldId, label: &str, widget: FieldWidget) -> Self {
        self.fields.push(FormField {
            id,
            label: label.to_owned(),
            help: None,
            widget,
            visible: true,
            enabled: Ok(()),
        });
        self
    }

    /// Help text of the last field.
    #[must_use]
    pub(crate) fn help(mut self, text: &str) -> Self {
        if let Some(f) = self.fields.last_mut() {
            f.help = Some(text.to_owned());
        }
        self
    }

    /// Validates several fields together on submit.
    #[must_use]
    pub(crate) fn cross_validate(
        mut self,
        f: impl Fn(&FormValues) -> Vec<(FieldId, String)> + Send + 'static,
    ) -> Self {
        self.cross = Some(Box::new(f));
        self
    }

    /// Called after any field changes (show/hide fields by protocol, T59).
    #[must_use]
    pub(crate) fn on_change(mut self, f: impl FnMut(&mut Form, FieldId) + Send + 'static) -> Self {
        self.on_change = Some(Box::new(f));
        self
    }

    /// The form, focus on the first field.
    pub(crate) fn build(self) -> Form {
        let mut form = Form {
            fields: self.fields,
            focus: 0,
            errors: HashMap::new(),
            initial: Vec::new(),
            cross: self.cross,
            on_change: self.on_change,
            scroll: 0,
            overlay_at: None,
        };
        form.initial = form
            .fields
            .iter()
            .filter_map(|f| f.widget.value().map(|v| (f.id, v)))
            .collect();
        form.focus = form.first_focusable().unwrap_or(form.fields.len());
        form
    }
}

/// Rows of one laid-out field.
struct Placed {
    index: usize,
    top: usize,
    widget_rows: usize,
    extra_row: bool,
}

impl Form {
    /// A builder.
    pub(crate) fn builder() -> FormBuilder {
        FormBuilder::default()
    }

    /// Every field's value.
    pub(crate) fn values(&self) -> FormValues {
        FormValues {
            map: self
                .fields
                .iter()
                .filter_map(|f| f.widget.value().map(|v| (f.id, v)))
                .collect(),
        }
    }

    /// The fields.
    pub(crate) fn fields(&self) -> &[FormField] {
        &self.fields
    }

    /// Field `id`.
    pub(crate) fn field(&self, id: FieldId) -> Option<&FormField> {
        self.fields.iter().find(|f| f.id == id)
    }

    /// Field `id`.
    pub(crate) fn field_mut(&mut self, id: FieldId) -> Option<&mut FormField> {
        self.fields.iter_mut().find(|f| f.id == id)
    }

    fn index(&self, id: FieldId) -> Option<usize> {
        self.fields.iter().position(|f| f.id == id)
    }

    /// Shows or hides `id`; a hidden focused field passes the focus on.
    pub(crate) fn set_visible(&mut self, id: FieldId, visible: bool) {
        if let Some(i) = self.index(id) {
            self.fields[i].visible = visible;
            if !visible {
                self.errors.remove(id);
            }
            self.fix_focus();
        }
    }

    /// Enables `id`, or disables it with a reason.
    pub(crate) fn set_enabled(&mut self, id: FieldId, enabled: Result<(), String>) {
        if let Some(i) = self.index(id) {
            self.fields[i].enabled = enabled;
            self.fix_focus();
        }
    }

    /// Sets or clears the error shown under `id`.
    pub(crate) fn set_error(&mut self, id: FieldId, msg: Option<String>) {
        match msg {
            Some(m) => {
                self.errors.insert(id, m);
            }
            None => {
                self.errors.remove(id);
            }
        }
    }

    /// The error shown under `id`.
    pub(crate) fn error(&self, id: FieldId) -> Option<&str> {
        self.errors.get(id).map(String::as_str)
    }

    /// Any field shows an error.
    pub(crate) fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Some value differs from the initial one.
    pub(crate) fn is_dirty(&self) -> bool {
        self.fields.iter().any(|f| {
            let Some(now) = f.widget.value() else {
                return false;
            };
            self.initial
                .iter()
                .find(|(id, _)| *id == f.id)
                .is_none_or(|(_, init)| !init.same(&now))
        })
    }

    fn focusable(&self, i: usize) -> bool {
        self.fields
            .get(i)
            .is_some_and(|f| f.visible && f.enabled.is_ok())
    }

    fn first_focusable(&self) -> Option<usize> {
        (0..self.fields.len()).find(|&i| self.focusable(i))
    }

    fn fix_focus(&mut self) {
        if self.focus < self.fields.len() && !self.focusable(self.focus) {
            self.focus = (self.focus..self.fields.len())
                .find(|&i| self.focusable(i))
                .unwrap_or(self.fields.len());
        }
    }

    /// The focused field (`None` on the button row).
    pub(crate) fn focused_id(&self) -> Option<FieldId> {
        self.fields.get(self.focus).map(|f| f.id)
    }

    /// The button row has the focus.
    pub(crate) fn on_buttons(&self) -> bool {
        self.focus >= self.fields.len()
    }

    /// Focuses `id` when it can take the focus.
    pub(crate) fn focus_field(&mut self, id: FieldId) -> bool {
        match self.index(id) {
            Some(i) if self.focusable(i) => {
                self.focus = i;
                true
            }
            _ => false,
        }
    }

    /// Focuses the button row.
    pub(crate) fn focus_buttons(&mut self) {
        self.focus = self.fields.len();
    }

    /// Runs the validator of field `i` (focus leaves it).
    fn validate_field(&mut self, i: usize) {
        if !self.focusable(i) {
            return;
        }
        let f = &mut self.fields[i];
        let id = f.id;
        match f.widget.validate() {
            Some(e) => {
                self.errors.insert(id, e);
            }
            None => {
                self.errors.remove(id);
            }
        }
    }

    /// Moves the focus over the focusable fields and the button row, wrapping; the
    /// field left is validated.
    pub(crate) fn move_focus(&mut self, forward: bool) {
        let n = self.fields.len() + 1;
        let old = self.focus;
        if old < self.fields.len() {
            self.validate_field(old);
        }
        let mut i = old.min(n - 1);
        for _ in 0..n {
            i = if forward {
                (i + 1) % n
            } else {
                (i + n - 1) % n
            };
            if i == self.fields.len() || self.focusable(i) {
                break;
            }
        }
        self.focus = i;
    }

    /// Runs field validators, then the cross-field validator; focuses the first error.
    pub(crate) fn validate(&mut self) -> bool {
        self.errors.clear();
        for i in 0..self.fields.len() {
            self.validate_field(i);
        }
        if let Some(cross) = &self.cross {
            let values = self.values();
            for (id, msg) in cross(&values) {
                if self.index(id).is_some_and(|i| self.focusable(i)) {
                    self.errors.entry(id).or_insert(msg);
                }
            }
        }
        self.focus_first_error();
        self.errors.is_empty()
    }

    /// Focuses the first field (in order) that shows an error.
    pub(crate) fn focus_first_error(&mut self) -> bool {
        if let Some(i) = (0..self.fields.len())
            .find(|&i| self.errors.contains_key(self.fields[i].id) && self.focusable(i))
        {
            self.focus = i;
            return true;
        }
        false
    }

    fn changed(&mut self, id: FieldId) {
        if let Some(mut f) = self.on_change.take() {
            f(self, id);
            if self.on_change.is_none() {
                self.on_change = Some(f);
            }
        }
    }

    /// A key for the focused field; `↑`/`↓` move between fields when the widget does
    /// not use them.
    pub(crate) fn handle_key(&mut self, key: KeyChord) -> WidgetOutcome {
        let Some(f) = self.fields.get_mut(self.focus) else {
            return WidgetOutcome::Ignored;
        };
        let id = f.id;
        let o = f.widget.widget_mut().handle_key(key);
        if o == WidgetOutcome::Changed {
            self.changed(id);
        }
        if o == WidgetOutcome::Ignored && key.mods == Mods::NONE {
            match key.code {
                KeyCode::Down => {
                    self.move_focus(true);
                    return WidgetOutcome::Consumed;
                }
                KeyCode::Up => {
                    self.move_focus(false);
                    return WidgetOutcome::Consumed;
                }
                _ => {}
            }
        }
        o
    }

    /// A paste for the focused field.
    pub(crate) fn handle_paste(&mut self, text: &str) -> WidgetOutcome {
        let Some(f) = self.fields.get_mut(self.focus) else {
            return WidgetOutcome::Ignored;
        };
        let id = f.id;
        let o = f.widget.widget_mut().handle_paste(text);
        if o == WidgetOutcome::Changed {
            self.changed(id);
        }
        o
    }

    /// The focused widget types plain letters.
    pub(crate) fn focused_is_text(&self) -> bool {
        self.fields
            .get(self.focus)
            .is_some_and(|f| f.widget.widget().is_text())
    }

    /// Polls every widget; applies `NextField` notices. Returns whether anything
    /// changed.
    pub(crate) fn poll(&mut self) -> bool {
        let mut changed = false;
        for f in &mut self.fields {
            changed |= f.widget.widget_mut().poll();
        }
        changed
    }

    /// A status message from the focused widget (a `NextField` notice moves on).
    pub(crate) fn take_notice(&mut self) -> Option<String> {
        let mut out = None;
        for i in 0..self.fields.len() {
            match self.fields[i].widget.widget_mut().take_notice() {
                Some(Notice::Status(s)) => out = Some(s),
                Some(Notice::NextField) if i == self.focus => self.move_focus(true),
                _ => {}
            }
        }
        out
    }

    fn label_width(&self) -> usize {
        self.fields
            .iter()
            .filter(|f| f.visible)
            .map(|f| width(&sanitize(&f.label)))
            .max()
            .unwrap_or(0)
            .min(MAX_LABEL)
            + 2
    }

    fn layout(&self, widget_w: u16) -> (Vec<Placed>, usize) {
        let mut out = Vec::new();
        let mut top = 0;
        for (i, f) in self.fields.iter().enumerate() {
            if !f.visible {
                continue;
            }
            let widget_rows = usize::from(f.widget.widget().height(widget_w).max(1));
            let extra_row = self.errors.contains_key(f.id) || f.enabled.is_err();
            out.push(Placed {
                index: i,
                top,
                widget_rows,
                extra_row,
            });
            top += widget_rows + usize::from(extra_row);
        }
        (out, top)
    }

    /// Preferred (width, height) of the field area.
    pub(crate) fn measure(&self, max_width: u16) -> (u16, u16) {
        let lw = self.label_width();
        let w = (lw + 2 + WIDGET_W).min(usize::from(max_width));
        let widget_w = u16::try_from(w.saturating_sub(lw + 2)).unwrap_or(1);
        let (_, rows) = self.layout(widget_w);
        let errs = self
            .fields
            .iter()
            .filter(|f| f.visible && f.enabled.is_ok())
            .map(|f| width(&sanitize(f.help.as_deref().unwrap_or(""))))
            .max()
            .unwrap_or(0);
        (
            u16::try_from(w.max(errs.min(usize::from(max_width)))).unwrap_or(max_width),
            u16::try_from(rows).unwrap_or(u16::MAX),
        )
    }

    /// Draws the fields into `body` (scrolled so the focused field is fully visible,
    /// `▲`/`▼` on the right border) and the focused field's help on `help_row`.
    pub(crate) fn render(
        &mut self,
        frame: &mut Frame,
        body: Rect,
        help_row: Option<Rect>,
        cx: &DrawCx,
    ) {
        if body.width == 0 || body.height == 0 {
            return;
        }
        let lw = self.label_width();
        let label_w = u16::try_from(lw).unwrap_or(u16::MAX).min(body.width / 2);
        let widget_x = body.x + label_w + 2;
        let widget_w = body.width.saturating_sub(label_w + 2).max(1);
        let (placed, total) = self.layout(widget_w);
        let rows = usize::from(body.height);
        // Scroll so the focused field (label, widget, error line) is fully visible.
        if let Some(p) = placed.iter().find(|p| p.index == self.focus) {
            let end = p.top + p.widget_rows + usize::from(p.extra_row);
            if p.top < self.scroll {
                self.scroll = p.top;
            } else if end > self.scroll + rows {
                self.scroll = end.saturating_sub(rows).min(p.top);
            }
        }
        self.scroll = self.scroll.min(total.saturating_sub(rows));
        let scroll = self.scroll;
        let ell = cx.symbols.ellipsis;
        let mut overlay = None;
        for p in &placed {
            let f = &self.fields[p.index];
            let focused = p.index == self.focus && cx.focused;
            let field_rows = p.widget_rows + usize::from(p.extra_row);
            if p.top + field_rows <= scroll || p.top >= scroll + rows {
                continue;
            }
            let row_y = |r: usize| -> Option<u16> {
                (r >= scroll && r < scroll + rows)
                    .then(|| body.y + u16::try_from(r - scroll).unwrap_or(0))
            };
            // Label (on the widget's first row).
            if let Some(y) = row_y(p.top) {
                let label = truncate_to_width(
                    &sanitize(&f.label),
                    usize::from(label_w).saturating_sub(2),
                    ell,
                )
                .into_owned();
                let pad = usize::from(label_w).saturating_sub(2 + width(&label));
                let (marker, style) = if focused {
                    (
                        cx.symbols.focus_marker,
                        cx.theme.style("field_label_focused"),
                    )
                } else {
                    (" ", cx.theme.style("field_label"))
                };
                let style = if f.enabled.is_err() {
                    style.patch(cx.theme.style("field_help"))
                } else {
                    style
                };
                frame.render_widget(
                    Paragraph::new(Line::from(vec![
                        Span::styled(marker.to_owned(), style),
                        Span::styled(label, style),
                        Span::raw(" ".repeat(pad + 1)),
                        Span::styled(cx.symbols.separator.to_owned(), cx.theme.style("border")),
                        Span::raw(" "),
                    ])),
                    Rect::new(body.x, y, label_w + 2, 1),
                );
            }
            // Widget: the visible part of its rows.
            let first = p.top.max(scroll);
            let last = (p.top + p.widget_rows).min(scroll + rows);
            if first < last
                && let Some(y) = row_y(first)
            {
                let area = Rect::new(
                    widget_x,
                    y,
                    widget_w,
                    u16::try_from(last - first).unwrap_or(1),
                );
                let wcx = widget_cx(cx, focused, f.enabled.is_ok());
                let w = f.widget.widget();
                w.render(frame, area, &wcx);
                if focused {
                    overlay = Some(area);
                    if let Some(pos) = w.cursor(area) {
                        frame.set_cursor_position(Position::new(pos.x, pos.y));
                    }
                }
            }
            // Error or disabled reason.
            if p.extra_row
                && let Some(y) = row_y(p.top + p.widget_rows)
            {
                let (text, style) = match (self.errors.get(f.id), &f.enabled) {
                    (Some(e), _) => (format!("! {}", sanitize(e)), cx.theme.style("field_error")),
                    (None, Err(reason)) => {
                        (sanitize(reason).into_owned(), cx.theme.style("field_help"))
                    }
                    (None, Ok(())) => (String::new(), Style::default()),
                };
                let t = truncate_to_width(&text, usize::from(widget_w), ell).into_owned();
                frame.render_widget(
                    Paragraph::new(Line::from(Span::styled(t, style))),
                    Rect::new(widget_x, y, widget_w, 1),
                );
            }
        }
        // Scroll markers on the right border.
        let marker_x = body.right().saturating_add(1);
        if marker_x < frame.area().right() {
            let style = cx.theme.style("dialog_border");
            if scroll > 0 {
                frame.render_widget(
                    Paragraph::new(Span::styled(cx.symbols.scroll_up, style)),
                    Rect::new(marker_x, body.y, 1, 1),
                );
            }
            if scroll + rows < total {
                frame.render_widget(
                    Paragraph::new(Span::styled(cx.symbols.scroll_down, style)),
                    Rect::new(marker_x, body.bottom() - 1, 1, 1),
                );
            }
        }
        if let Some(help_row) = help_row
            && let Some(f) = self.fields.get(self.focus)
            && let Some(help) = &f.help
        {
            let t =
                truncate_to_width(&sanitize(help), usize::from(help_row.width), ell).into_owned();
            frame.render_widget(
                Paragraph::new(Span::styled(t, cx.theme.style("field_help"))),
                help_row,
            );
        }
        self.overlay_at = overlay;
    }

    /// Draws the focused widget's popup (an open `Select`, completion candidates) on
    /// top of everything; call after the rest of the dialog is drawn.
    pub(crate) fn render_overlay(&self, frame: &mut Frame, cx: &DrawCx) {
        if let (Some(area), Some(f)) = (self.overlay_at, self.fields.get(self.focus)) {
            let wcx = widget_cx(cx, true, true);
            f.widget
                .widget()
                .render_overlay(frame, area, frame.area(), &wcx);
        }
    }
}

type MapFn<T> = Box<dyn Fn(&FormValues) -> Result<T, Vec<(FieldId, String)>> + Send>;

/// A form (or several pages of forms) in a dialog with *OK* / *Cancel*; `map` turns
/// the values into the typed result or field errors.
pub(crate) struct FormDialog<T> {
    title: String,
    kind: &'static str,
    pages: Vec<(String, Form)>,
    active: usize,
    buttons: ButtonRow,
    map: MapFn<T>,
    tabbed: bool,
    guard: bool,
    min_w: u16,
}

impl<T> fmt::Debug for FormDialog<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FormDialog")
            .field("kind", &self.kind)
            .field("pages", &self.pages.len())
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

fn ok_cancel(ok: &str, cancel: &str) -> ButtonRow {
    ButtonRow::new(vec![
        Button::new("ok", ok, ButtonRole::Default),
        Button::new("cancel", cancel, ButtonRole::Normal),
    ])
}

impl<T: Send + 'static> FormDialog<T> {
    /// A dialog for `form`.
    pub(crate) fn new(
        title: &str,
        form: Form,
        map: impl Fn(&FormValues) -> Result<T, Vec<(FieldId, String)>> + Send + 'static,
    ) -> Self {
        Self {
            title: title.to_owned(),
            kind: "form",
            pages: vec![(String::new(), form)],
            active: 0,
            buttons: ok_cancel("OK", "Cancel"),
            map: Box::new(map),
            tabbed: false,
            guard: true,
            min_w: FIT_MIN_W,
        }
    }

    /// Button labels (default "OK" / "Cancel").
    #[must_use]
    pub(crate) fn buttons(mut self, ok: &str, cancel: &str) -> Self {
        self.buttons = ok_cancel(ok, cancel);
        self
    }

    /// Kind name for logs (`site_editor`).
    #[must_use]
    pub(crate) fn kind(mut self, kind: &'static str) -> Self {
        self.kind = kind;
        self
    }

    /// Whether `Esc` on a dirty form asks "Discard changes?" (default on; prompts
    /// turn it off).
    #[must_use]
    pub(crate) fn discard_guard(mut self, on: bool) -> Self {
        self.guard = on;
        self
    }

    /// The page shown.
    pub(crate) fn form(&self) -> &Form {
        &self.pages[self.active].1
    }

    /// The page shown.
    pub(crate) fn form_mut(&mut self) -> &mut Form {
        &mut self.pages[self.active].1
    }

    /// Page `i`.
    pub(crate) fn page(&self, i: usize) -> Option<&Form> {
        self.pages.get(i).map(|p| &p.1)
    }

    /// Index of the page shown.
    pub(crate) fn active_page(&self) -> usize {
        self.active
    }

    fn values(&self) -> FormValues {
        let mut v = FormValues::default();
        for (_, f) in &self.pages {
            v.extend(f.values());
        }
        v
    }

    fn submit(&mut self) -> DialogStep<T> {
        let mut first_bad = None;
        for (i, (_, f)) in self.pages.iter_mut().enumerate() {
            if !f.validate() && first_bad.is_none() {
                first_bad = Some(i);
            }
        }
        if let Some(i) = first_bad {
            self.active = i;
            return DialogStep::Continue;
        }
        match (self.map)(&self.values()) {
            Ok(t) => DialogStep::Close(Some(t)),
            Err(errors) => {
                let mut first = None;
                for (id, msg) in errors {
                    if let Some(p) = self.pages.iter().position(|(_, f)| f.field(id).is_some()) {
                        self.pages[p].1.set_error(id, Some(msg));
                        first = Some(first.map_or(p, |q: usize| q.min(p)));
                    }
                }
                if let Some(p) = first {
                    self.active = p;
                    self.pages[p].1.focus_first_error();
                }
                DialogStep::Continue
            }
        }
    }

    fn press(&mut self, i: usize) -> DialogStep<T> {
        self.buttons.set_focus(i);
        match self.buttons.buttons().get(i).map(|b| b.id) {
            Some("ok") => self.submit(),
            Some(_) => DialogStep::Close(None),
            None => DialogStep::Continue,
        }
    }

    fn switch_page(&mut self, forward: bool) -> DialogStep<T> {
        let n = self.pages.len();
        if !self.tabbed || n < 2 {
            return DialogStep::Ignored;
        }
        self.active = if forward {
            (self.active + 1) % n
        } else {
            (self.active + n - 1) % n
        };
        DialogStep::Continue
    }

    fn header(&self, cx: &DrawCx) -> Line<'static> {
        let mut spans = Vec::new();
        for (i, (name, _)) in self.pages.iter().enumerate() {
            if i > 0 {
                spans.push(Span::raw("  "));
            }
            let name = sanitize(name).into_owned();
            if i == self.active {
                spans.push(Span::styled(
                    format!("[{name}]"),
                    cx.theme.style("field_label_focused"),
                ));
            } else {
                spans.push(Span::styled(name, cx.theme.style("field_label")));
            }
        }
        Line::from(spans)
    }
}

impl<T: Send + 'static> Dialog for FormDialog<T> {
    type Output = T;

    fn kind(&self) -> &'static str {
        self.kind
    }

    fn title(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.title)
    }

    fn size(&self, _screen: Rect) -> DialogSize {
        DialogSize::Fit {
            min_w: self.min_w,
            max_w: FIT_MAX_W,
        }
    }

    fn measure(&self, max_width: u16) -> (u16, u16) {
        let (mut w, mut h) = (0u16, 0u16);
        for (_, f) in &self.pages {
            let (fw, fh) = f.measure(max_width);
            w = w.max(fw);
            h = h.max(fh);
        }
        let bw = u16::try_from(self.buttons.total_width()).unwrap_or(u16::MAX);
        let tabs = if self.tabbed {
            let t: usize = self.pages.iter().map(|(n, _)| width(n) + 4).sum();
            w = w.max(u16::try_from(t).unwrap_or(u16::MAX));
            2
        } else {
            0
        };
        (w.max(bw).min(max_width), h.saturating_add(2 + tabs))
    }

    fn handle_key(&mut self, key: KeyChord) -> DialogStep<T> {
        let form = &mut self.pages[self.active].1;
        if !form.on_buttons() {
            let plain = !form.focused_is_text();
            if form.handle_key(key).is_used() {
                return DialogStep::Continue;
            }
            return match self.buttons.mnemonic(key, plain) {
                Some(i) => self.press(i),
                None => DialogStep::Ignored,
            };
        }
        match self.buttons.handle_key(key) {
            WidgetOutcome::Activated => self.press(self.buttons.focused()),
            WidgetOutcome::Ignored => match self.buttons.mnemonic(key, true) {
                Some(i) => self.press(i),
                None if key.code == KeyCode::Up && key.mods == Mods::NONE => {
                    self.pages[self.active].1.move_focus(false);
                    DialogStep::Continue
                }
                None => DialogStep::Ignored,
            },
            _ => DialogStep::Continue,
        }
    }

    fn handle_action(&mut self, action: &Action) -> DialogStep<T> {
        match action {
            Action::DialogSubmit => {
                if self.form().on_buttons() {
                    self.press(self.buttons.focused())
                } else {
                    match self.buttons.default_index() {
                        Some(i) => self.press(i),
                        None => self.submit(),
                    }
                }
            }
            Action::DialogSave => self.submit(),
            Action::NextField => {
                self.form_mut().move_focus(true);
                DialogStep::Continue
            }
            Action::PrevField => {
                self.form_mut().move_focus(false);
                DialogStep::Continue
            }
            Action::NextFormTab => self.switch_page(true),
            Action::PrevFormTab => self.switch_page(false),
            _ => DialogStep::Ignored,
        }
    }

    fn handle_paste(&mut self, text: &str) -> DialogStep<T> {
        if self.form_mut().handle_paste(text).is_used() {
            DialogStep::Continue
        } else {
            DialogStep::Ignored
        }
    }

    fn poll(&mut self, _now: Instant) -> DialogStep<T> {
        for (_, f) in &mut self.pages {
            f.poll();
        }
        DialogStep::Continue
    }

    fn render(&mut self, frame: &mut Frame, area: Rect, cx: &DrawCx) {
        let mut body = area;
        if self.tabbed && body.height > 0 {
            let header = self.header(cx);
            frame.render_widget(Paragraph::new(header), Rect { height: 1, ..body });
            body.y += 1;
            body.height -= 1;
            if body.height > 3 {
                body.y += 1;
                body.height -= 1;
            }
        }
        let buttons_row = (body.height > 0).then(|| Rect {
            y: body.bottom() - 1,
            height: 1,
            ..body
        });
        body.height = body.height.saturating_sub(1);
        let help_row = (body.height > 1).then(|| Rect {
            y: body.bottom() - 1,
            height: 1,
            ..body
        });
        if help_row.is_some() {
            body.height -= 1;
        }
        let on_buttons = self.form().on_buttons();
        self.pages[self.active].1.render(frame, body, help_row, cx);
        if let Some(r) = buttons_row {
            let wcx = widget_cx(cx, cx.focused && on_buttons, true);
            self.buttons.render(frame, r, &wcx);
        }
        if cx.focused {
            self.pages[self.active].1.render_overlay(frame, cx);
        }
    }

    fn is_dirty(&self) -> bool {
        self.guard && self.pages.iter().any(|(_, f)| f.is_dirty())
    }

    fn take_notice(&mut self) -> Option<String> {
        self.form_mut().take_notice()
    }
}

/// Several pages of forms under a tab header (`[General]  Advanced`).
/// `NextFormTab`/`PrevFormTab` switch pages; submit validates every page and shows the
/// first page with an error. Focus is kept per page.
#[derive(Debug)]
pub(crate) struct TabbedForm<T>(FormDialog<T>);

impl<T: Send + 'static> TabbedForm<T> {
    /// A tabbed dialog over `pages` (name, form).
    pub(crate) fn new(
        title: &str,
        pages: Vec<(&str, Form)>,
        map: impl Fn(&FormValues) -> Result<T, Vec<(FieldId, String)>> + Send + 'static,
    ) -> Self {
        let mut d = FormDialog::new(title, Form::builder().build(), map).kind("tabbed_form");
        d.pages = pages.into_iter().map(|(n, f)| (n.to_owned(), f)).collect();
        if d.pages.is_empty() {
            d.pages.push((String::new(), Form::builder().build()));
        }
        d.tabbed = true;
        d.min_w = 60;
        Self(d)
    }

    /// Button labels (default "OK" / "Cancel").
    #[must_use]
    pub(crate) fn buttons(self, ok: &str, cancel: &str) -> Self {
        Self(self.0.buttons(ok, cancel))
    }

    /// The dialog inside.
    pub(crate) fn inner(&self) -> &FormDialog<T> {
        &self.0
    }

    /// The dialog inside.
    pub(crate) fn inner_mut(&mut self) -> &mut FormDialog<T> {
        &mut self.0
    }
}

impl<T: Send + 'static> Dialog for TabbedForm<T> {
    type Output = T;

    fn kind(&self) -> &'static str {
        Dialog::kind(&self.0)
    }
    fn title(&self) -> Cow<'_, str> {
        self.0.title()
    }
    fn size(&self, screen: Rect) -> DialogSize {
        self.0.size(screen)
    }
    fn measure(&self, max_width: u16) -> (u16, u16) {
        self.0.measure(max_width)
    }
    fn handle_key(&mut self, key: KeyChord) -> DialogStep<T> {
        self.0.handle_key(key)
    }
    fn handle_action(&mut self, action: &Action) -> DialogStep<T> {
        self.0.handle_action(action)
    }
    fn handle_paste(&mut self, text: &str) -> DialogStep<T> {
        self.0.handle_paste(text)
    }
    fn poll(&mut self, now: Instant) -> DialogStep<T> {
        self.0.poll(now)
    }
    fn render(&mut self, frame: &mut Frame, area: Rect, cx: &DrawCx) {
        self.0.render(frame, area, cx);
    }
    fn is_dirty(&self) -> bool {
        self.0.is_dirty()
    }
    fn take_notice(&mut self) -> Option<String> {
        self.0.take_notice()
    }
}
