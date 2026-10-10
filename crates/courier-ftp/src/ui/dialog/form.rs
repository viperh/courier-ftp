//! [`Form`], [`TabbedForm`] and [`FormDialog`].

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};
use tokio::sync::oneshot;

use super::{ButtonRow, Field, FieldOutcome, FormValues};
use crate::ui::{
    modal::{Modal, ModalOutcome, centered},
    theme::Theme,
};

/// What a form did with a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FormOutcome {
    Keep,
    /// Every field is valid and the user confirmed.
    Submit,
    Cancel,
    /// `Tab` past the last field of a form without buttons (inside a
    /// [`TabbedForm`]).
    LeaveForward,
    /// `Shift-Tab` before the first field of a form without buttons.
    LeaveBackward,
    /// Nobody used the key (a [`TabbedForm`] may: `[`/`]`).
    Unhandled,
}

type FormValidator = Box<dyn Fn(&FormValues) -> Result<(), String> + Send>;

/// Fields in order, optionally followed by a button row. The first button
/// submits, the others cancel. Inside the form `Tab`/`Shift-Tab` (and `↓`/`↑`
/// when the field doesn't use them) move between fields; `Enter` submits;
/// `Esc` cancels.
pub(crate) struct Form {
    fields: Vec<(String, Box<dyn Field>)>,
    /// `0..fields.len()` is a field; `fields.len()` is the button row.
    focus: usize,
    buttons: Option<ButtonRow>,
    validator: Option<FormValidator>,
    error: Option<String>,
}

impl Form {
    /// A form with these buttons (`&[]` for none).
    pub(crate) fn new(buttons: &[&str]) -> Self {
        Self {
            fields: Vec::new(),
            focus: 0,
            buttons: (!buttons.is_empty()).then(|| ButtonRow::new(buttons, 0)),
            validator: None,
            error: None,
        }
    }

    /// Add a field under `key` (the name its value is collected under).
    pub(crate) fn field(mut self, key: &str, field: impl Field + 'static) -> Self {
        self.fields.push((key.to_owned(), Box::new(field)));
        self
    }

    /// A check over all values, run on submit after the per-field checks.
    pub(crate) fn validate_with(
        mut self,
        validator: impl Fn(&FormValues) -> Result<(), String> + Send + 'static,
    ) -> Self {
        self.validator = Some(Box::new(validator));
        self
    }

    pub(crate) fn values(&self) -> FormValues {
        FormValues(
            self.fields
                .iter()
                .map(|(k, f)| (k.clone(), f.value()))
                .collect(),
        )
    }

    pub(crate) fn set_error(&mut self, error: Option<String>) {
        self.error = error;
    }

    pub(crate) fn focused_field_mut(&mut self) -> Option<&mut Box<dyn Field>> {
        self.fields.get_mut(self.focus).map(|(_, f)| f)
    }

    pub(crate) fn focused_key(&self) -> Option<&str> {
        self.fields.get(self.focus).map(|(k, _)| k.as_str())
    }

    fn slots(&self) -> usize {
        self.fields.len() + usize::from(self.buttons.is_some())
    }

    /// Focus the first slot (`backward`: the last).
    pub(crate) fn enter(&mut self, backward: bool) {
        self.focus = if backward {
            self.slots().saturating_sub(1)
        } else {
            0
        };
    }

    fn step(&mut self, forward: bool) -> FormOutcome {
        let slots = self.slots();
        if slots == 0 {
            return if forward {
                FormOutcome::LeaveForward
            } else {
                FormOutcome::LeaveBackward
            };
        }
        if self.buttons.is_none() {
            if forward && self.focus + 1 >= slots {
                return FormOutcome::LeaveForward;
            }
            if !forward && self.focus == 0 {
                return FormOutcome::LeaveBackward;
            }
        }
        self.focus = if forward {
            (self.focus + 1) % slots
        } else {
            (self.focus + slots - 1) % slots
        };
        FormOutcome::Keep
    }

    /// Validate everything; on failure focus the first bad field.
    pub(crate) fn check(&mut self) -> bool {
        for (_, f) in &mut self.fields {
            f.touch();
        }
        if let Some(i) = self.fields.iter().position(|(_, f)| f.error().is_some()) {
            self.focus = i;
            self.error = Some("Please fix the marked field.".to_owned());
            return false;
        }
        if let Some(v) = &self.validator
            && let Err(e) = v(&self.values())
        {
            self.error = Some(e);
            return false;
        }
        self.error = None;
        true
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> FormOutcome {
        let on_field = self.focus < self.fields.len();
        if on_field {
            let field = &mut self.fields[self.focus].1;
            let capturing = field.is_capturing();
            if field.handle_key(key) == FieldOutcome::Consumed || capturing {
                return FormOutcome::Keep;
            }
        }
        if key.modifiers.contains(KeyModifiers::ALT)
            && let Some(buttons) = &mut self.buttons
            && let Some(pressed) = buttons.handle_key(key)
        {
            return self.press(pressed);
        }
        match key.code {
            KeyCode::Tab | KeyCode::Down => self.step(true),
            KeyCode::BackTab | KeyCode::Up => self.step(false),
            KeyCode::Esc => FormOutcome::Cancel,
            KeyCode::Enter if on_field => self.press(0),
            _ if !on_field => match self.buttons.as_mut().and_then(|b| b.handle_key(key)) {
                Some(pressed) => self.press(pressed),
                None => FormOutcome::Keep,
            },
            _ => FormOutcome::Unhandled,
        }
    }

    fn press(&mut self, button: usize) -> FormOutcome {
        if button != 0 {
            return FormOutcome::Cancel;
        }
        if self.check() {
            FormOutcome::Submit
        } else {
            FormOutcome::Keep
        }
    }

    pub(crate) fn handle_paste(&mut self, text: &str) {
        if let Some((_, f)) = self.fields.get_mut(self.focus) {
            f.handle_paste(text);
        }
    }

    fn label_width(&self) -> u16 {
        let w = self
            .fields
            .iter()
            .map(|(_, f)| f.label().chars().count())
            .max()
            .unwrap_or(0);
        u16::try_from(w).unwrap_or(u16::MAX).saturating_add(2)
    }

    /// Rows of each field (including its error line).
    fn field_rows(&self) -> Vec<u16> {
        self.fields
            .iter()
            .map(|(_, f)| f.height() + u16::from(f.error().is_some()))
            .collect()
    }

    /// Rows the form wants.
    pub(crate) fn height(&self) -> u16 {
        let fields: u16 = self.field_rows().iter().sum();
        let buttons = if self.buttons.is_some() { 2 } else { 0 };
        fields + buttons + u16::from(self.error.is_some())
    }

    pub(crate) fn draw(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let rows = self.field_rows();
        let label_w = self.label_width().min(area.width / 2);
        // Scroll so the focused field is visible.
        let focus_top: u16 = rows.iter().take(self.focus).sum();
        let focus_rows = rows.get(self.focus).copied().unwrap_or(2);
        let scroll = (focus_top + focus_rows).saturating_sub(area.height);
        let mut y = area.y;
        let bottom = area.bottom();
        let mut overlay: Option<(usize, Rect)> = None;
        for (i, ((_, field), h)) in self.fields.iter().zip(&rows).enumerate() {
            let top: u16 = rows.iter().take(i).sum();
            if top < scroll {
                continue;
            }
            if y + field.height() > bottom {
                break;
            }
            let focused = i == self.focus;
            let label_style = if focused { theme.title } else { theme.dim };
            frame.render_widget(
                Paragraph::new(Span::styled(field.label().to_owned(), label_style)),
                Rect::new(area.x, y, label_w, 1),
            );
            let field_area = Rect::new(
                area.x + label_w,
                y,
                area.width.saturating_sub(label_w),
                field.height(),
            );
            field.draw(frame, field_area, focused, theme);
            if focused {
                overlay = Some((i, field_area));
            }
            if let Some(err) = field.error()
                && y + field.height() < bottom
            {
                frame.render_widget(
                    Paragraph::new(Span::styled(err, theme.error)),
                    Rect::new(field_area.x, y + field.height(), field_area.width, 1),
                );
            }
            y += h;
        }
        if let Some(buttons) = &self.buttons
            && y + 1 < bottom
        {
            buttons.draw(
                frame,
                Rect::new(area.x, y + 1, area.width, 1),
                self.focus == self.fields.len(),
                theme,
            );
            y += 2;
        }
        if let Some(err) = &self.error
            && y < bottom
        {
            frame.render_widget(
                Paragraph::new(Span::styled(err.clone(), theme.error)),
                Rect::new(area.x, y, area.width, 1),
            );
        }
        if let Some((i, rect)) = overlay {
            self.fields[i].1.draw_overlay(frame, rect, theme);
        }
    }
}

/// Several forms under tab headers (Site Manager tabs, settings sections)
/// sharing one button row. `Ctrl-PageUp`/`Ctrl-PageDown`, or `[`/`]` when the
/// field doesn't use them, switch tabs.
pub(crate) struct TabbedForm {
    tabs: Vec<(String, Form)>,
    current: usize,
    on_buttons: bool,
    buttons: ButtonRow,
    error: Option<String>,
}

impl TabbedForm {
    /// `tabs` should be forms created with `Form::new(&[])`.
    pub(crate) fn new(tabs: Vec<(&str, Form)>, buttons: &[&str]) -> Self {
        Self {
            tabs: tabs.into_iter().map(|(t, f)| (t.to_owned(), f)).collect(),
            current: 0,
            on_buttons: false,
            buttons: ButtonRow::new(buttons, 0),
            error: None,
        }
    }

    pub(crate) fn current_tab(&self) -> usize {
        self.current
    }

    fn switch(&mut self, forward: bool) {
        let n = self.tabs.len().max(1);
        self.current = if forward {
            (self.current + 1) % n
        } else {
            (self.current + n - 1) % n
        };
        self.on_buttons = false;
        if let Some((_, f)) = self.tabs.get_mut(self.current) {
            f.enter(false);
        }
    }

    pub(crate) fn values(&self) -> FormValues {
        let mut all = FormValues::default();
        for (_, f) in &self.tabs {
            all.0.extend(f.values().0);
        }
        all
    }

    fn check(&mut self) -> bool {
        for i in 0..self.tabs.len() {
            if !self.tabs[i].1.check() {
                self.current = i;
                self.on_buttons = false;
                self.error = Some(format!(
                    "Please fix the marked field on “{}”.",
                    self.tabs[i].0
                ));
                return false;
            }
        }
        self.error = None;
        true
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> FormOutcome {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::PageDown if ctrl => {
                self.switch(true);
                return FormOutcome::Keep;
            }
            KeyCode::PageUp if ctrl => {
                self.switch(false);
                return FormOutcome::Keep;
            }
            _ => {}
        }
        if self.on_buttons {
            return match key.code {
                KeyCode::Tab => {
                    self.on_buttons = false;
                    if let Some((_, f)) = self.tabs.get_mut(self.current) {
                        f.enter(false);
                    }
                    FormOutcome::Keep
                }
                KeyCode::BackTab => {
                    self.on_buttons = false;
                    if let Some((_, f)) = self.tabs.get_mut(self.current) {
                        f.enter(true);
                    }
                    FormOutcome::Keep
                }
                KeyCode::Esc => FormOutcome::Cancel,
                KeyCode::Char('[') => {
                    self.switch(false);
                    FormOutcome::Keep
                }
                KeyCode::Char(']') => {
                    self.switch(true);
                    FormOutcome::Keep
                }
                _ => match self.buttons.handle_key(key) {
                    Some(0) => {
                        if self.check() {
                            FormOutcome::Submit
                        } else {
                            FormOutcome::Keep
                        }
                    }
                    Some(_) => FormOutcome::Cancel,
                    None => FormOutcome::Keep,
                },
            };
        }
        let Some((_, form)) = self.tabs.get_mut(self.current) else {
            return FormOutcome::Cancel;
        };
        match form.handle_key(key) {
            FormOutcome::Keep => FormOutcome::Keep,
            // `[`/`]` reach here only when the focused field didn't use them
            // (a text field types them).
            FormOutcome::Unhandled => {
                match key.code {
                    KeyCode::Char('[') => self.switch(false),
                    KeyCode::Char(']') => self.switch(true),
                    _ => {}
                }
                FormOutcome::Keep
            }
            FormOutcome::LeaveForward | FormOutcome::LeaveBackward => {
                self.on_buttons = true;
                FormOutcome::Keep
            }
            FormOutcome::Submit => {
                if self.check() {
                    FormOutcome::Submit
                } else {
                    FormOutcome::Keep
                }
            }
            FormOutcome::Cancel => FormOutcome::Cancel,
        }
    }

    pub(crate) fn handle_paste(&mut self, text: &str) {
        if !self.on_buttons
            && let Some((_, f)) = self.tabs.get_mut(self.current)
        {
            f.handle_paste(text);
        }
    }

    pub(crate) fn height(&self) -> u16 {
        let tallest = self.tabs.iter().map(|(_, f)| f.height()).max().unwrap_or(0);
        tallest + 4 + u16::from(self.error.is_some())
    }

    pub(crate) fn draw(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let mut spans = Vec::new();
        for (i, (title, _)) in self.tabs.iter().enumerate() {
            let style = if i == self.current {
                theme.selection
            } else {
                theme.dim
            };
            spans.push(Span::styled(format!(" {title} "), style));
            spans.push(Span::raw(" "));
        }
        frame.render_widget(
            Paragraph::new(Line::from(spans)),
            Rect::new(area.x, area.y, area.width, 1),
        );
        let body_height = area
            .height
            .saturating_sub(4 + u16::from(self.error.is_some()));
        if let Some((_, f)) = self.tabs.get(self.current) {
            f.draw(
                frame,
                Rect::new(area.x, area.y + 2, area.width, body_height),
                theme,
            );
        }
        let y = area.y + 2 + body_height;
        if y < area.bottom() {
            self.buttons.draw(
                frame,
                Rect::new(area.x, y + 1, area.width, 1),
                self.on_buttons,
                theme,
            );
        }
        if let Some(err) = &self.error
            && y + 2 < area.bottom()
        {
            frame.render_widget(
                Paragraph::new(Span::styled(err.clone(), theme.error)),
                Rect::new(area.x, y + 2, area.width, 1),
            );
        }
    }
}

/// A form or a tabbed form, as a dialog body.
pub(crate) enum Body {
    Form(Form),
    Tabbed(TabbedForm),
}

impl From<Form> for Body {
    fn from(f: Form) -> Self {
        Body::Form(f)
    }
}

impl From<TabbedForm> for Body {
    fn from(f: TabbedForm) -> Self {
        Body::Tabbed(f)
    }
}

impl Body {
    fn handle_key(&mut self, key: KeyEvent) -> FormOutcome {
        match self {
            Body::Form(f) => match f.handle_key(key) {
                // A lone form without buttons wraps around.
                FormOutcome::LeaveForward => {
                    f.enter(false);
                    FormOutcome::Keep
                }
                FormOutcome::LeaveBackward => {
                    f.enter(true);
                    FormOutcome::Keep
                }
                FormOutcome::Unhandled => FormOutcome::Keep,
                other => other,
            },
            Body::Tabbed(t) => t.handle_key(key),
        }
    }

    fn handle_paste(&mut self, text: &str) {
        match self {
            Body::Form(f) => f.handle_paste(text),
            Body::Tabbed(t) => t.handle_paste(text),
        }
    }

    fn values(&self) -> FormValues {
        match self {
            Body::Form(f) => f.values(),
            Body::Tabbed(t) => t.values(),
        }
    }

    fn set_error(&mut self, error: String) {
        match self {
            Body::Form(f) => f.set_error(Some(error)),
            Body::Tabbed(t) => t.error = Some(error),
        }
    }

    fn height(&self) -> u16 {
        match self {
            Body::Form(f) => f.height(),
            Body::Tabbed(t) => t.height(),
        }
    }

    fn draw(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        match self {
            Body::Form(f) => f.draw(frame, area, theme),
            Body::Tabbed(t) => t.draw(frame, area, theme),
        }
    }
}

type Submit<T> = Box<dyn FnMut(&FormValues) -> Result<T, String> + Send>;

/// A form on the modal stack. On submit the values go through `on_submit`;
/// its `Ok` value is sent to the receiver and the dialog closes, its `Err`
/// is shown and the dialog stays. Cancelling (or dropping the dialog) sends
/// `None` / closes the channel.
pub(crate) struct FormDialog<T: Send + 'static> {
    title: String,
    width: u16,
    body: Body,
    on_submit: Submit<T>,
    reply: Option<oneshot::Sender<Option<T>>>,
}

impl<T: Send + 'static> FormDialog<T> {
    pub(crate) fn new(
        title: impl Into<String>,
        width: u16,
        body: impl Into<Body>,
        on_submit: impl FnMut(&FormValues) -> Result<T, String> + Send + 'static,
    ) -> (Self, oneshot::Receiver<Option<T>>) {
        let (tx, rx) = oneshot::channel();
        (
            Self {
                title: title.into(),
                width,
                body: body.into(),
                on_submit: Box::new(on_submit),
                reply: Some(tx),
            },
            rx,
        )
    }

    fn finish(&mut self, value: Option<T>) {
        if let Some(reply) = self.reply.take() {
            let _ = reply.send(value);
        }
    }
}

/// The smallest area a dialog can be drawn in.
const MIN_DIALOG: (u16, u16) = (20, 5);

/// Draw a dialog frame and return the inner area, or `None` (after drawing
/// a notice) when the terminal is too small.
pub(crate) fn dialog_frame(
    frame: &mut Frame,
    screen: Rect,
    title: &str,
    width: u16,
    inner_height: u16,
    theme: &Theme,
) -> Option<Rect> {
    if screen.width < MIN_DIALOG.0 || screen.height < MIN_DIALOG.1 {
        frame.render_widget(Clear, screen);
        frame.render_widget(
            Paragraph::new("terminal too small").style(theme.error),
            screen,
        );
        return None;
    }
    let rect = centered(
        screen,
        width.saturating_add(2),
        inner_height.saturating_add(2),
    );
    let block = Block::bordered()
        .title(format!(" {title} "))
        .border_style(theme.focused_border);
    let inner = block.inner(rect);
    frame.render_widget(Clear, rect);
    frame.render_widget(block, rect);
    Some(inner)
}

impl<T: Send + 'static> Modal for FormDialog<T> {
    fn draw(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        if let Some(inner) = dialog_frame(
            frame,
            area,
            &self.title,
            self.width,
            self.body.height(),
            theme,
        ) {
            self.body.draw(frame, inner, theme);
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> ModalOutcome {
        match self.body.handle_key(key) {
            FormOutcome::Submit => match (self.on_submit)(&self.body.values()) {
                Ok(value) => {
                    self.finish(Some(value));
                    ModalOutcome::Close
                }
                Err(e) => {
                    self.body.set_error(e);
                    ModalOutcome::Keep
                }
            },
            FormOutcome::Cancel => {
                self.finish(None);
                ModalOutcome::Close
            }
            _ => ModalOutcome::Keep,
        }
    }

    fn handle_paste(&mut self, text: &str) {
        self.body.handle_paste(text);
    }
}
