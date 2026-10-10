//! Standard dialogs: `confirm`, `message`, `error`, `error_report`, `prompt_text`,
//! `prompt_password`, `choose`, `text_viewer` and `problems`.

use std::borrow::Cow;

use courier_ftp_core::secret::SecretString;
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{
    Dialog, DialogSize, DialogStep, FIT_MAX_W, FIT_MIN_W, FieldWidget, Form, FormDialog,
    text_width, widget_cx, wrap_text,
};
use crate::{
    action::Action,
    components::{
        DrawCx,
        widgets::{
            Button, ButtonRole, ButtonRow, SecretInput, TextInput, TextView, Validator, Widget,
            WidgetOutcome,
        },
    },
    keymap::chord::KeyChord,
};

/// Lines of an error's cause chain shown at most.
const MAX_DETAIL_LINES: usize = 50;

/// Options of [`confirm`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfirmOpts {
    /// Label of the "yes" button.
    pub yes: String,
    /// Label of the "no" button.
    pub no: String,
    /// `Enter` (and the initial focus) is "yes".
    pub default_yes: bool,
    /// Destructive: "yes" is drawn as danger, the default is "no".
    pub danger: bool,
}

impl Default for ConfirmOpts {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfirmOpts {
    /// "OK" / "Cancel", default OK, not dangerous.
    pub(crate) fn new() -> Self {
        Self {
            yes: "OK".to_owned(),
            no: "Cancel".to_owned(),
            default_yes: true,
            danger: false,
        }
    }

    /// `yes` / "Cancel"; default and initial focus: Cancel.
    pub(crate) fn danger(yes: &str) -> Self {
        Self {
            yes: yes.to_owned(),
            no: "Cancel".to_owned(),
            default_yes: false,
            danger: true,
        }
    }
}

/// Text above a row of buttons; shared by confirm, message, error and choose.
#[derive(Debug)]
struct ButtonBox {
    title: String,
    text: String,
    buttons: ButtonRow,
}

impl ButtonBox {
    fn measure(&self, max_width: u16) -> (u16, u16) {
        let tw = u16::try_from(text_width(&self.text)).unwrap_or(u16::MAX);
        let bw = u16::try_from(self.buttons.total_width()).unwrap_or(u16::MAX);
        let w = tw.max(bw).min(max_width).max(1);
        let lines = u16::try_from(wrap_text(&self.text, w).len()).unwrap_or(u16::MAX);
        (w, lines.saturating_add(2))
    }

    /// Button index pressed by `key` (row keys, mnemonics with or without Alt), or
    /// `Some(None)` when the key was used otherwise.
    fn key(&mut self, key: KeyChord) -> Option<Option<usize>> {
        match self.buttons.handle_key(key) {
            WidgetOutcome::Activated => Some(Some(self.buttons.focused())),
            WidgetOutcome::Ignored => self.buttons.mnemonic(key, true).map(Some),
            _ => Some(None),
        }
    }

    /// Focus movement and the default button for dialog-table actions.
    fn action(&mut self, action: &Action) -> Option<Option<usize>> {
        match action {
            Action::NextField => {
                if !self.buttons.move_focus(true) {
                    self.buttons.set_focus(0);
                }
                Some(None)
            }
            Action::PrevField => {
                if !self.buttons.move_focus(false) {
                    self.buttons.set_focus(usize::MAX);
                }
                Some(None)
            }
            Action::DialogSubmit => Some(Some(self.buttons.focused())),
            _ => None,
        }
    }

    fn render(&self, frame: &mut Frame, area: Rect, cx: &DrawCx, extra: &[String]) {
        let mut lines: Vec<Line> = wrap_text(&self.text, area.width)
            .into_iter()
            .map(Line::from)
            .collect();
        for e in extra {
            lines.extend(wrap_text(e, area.width).into_iter().map(Line::from));
        }
        let text_rows = area.height.saturating_sub(2);
        lines.truncate(usize::from(text_rows));
        frame.render_widget(
            Paragraph::new(lines),
            Rect {
                height: text_rows,
                ..area
            },
        );
        if area.height > 0 {
            let r = Rect {
                y: area.bottom() - 1,
                height: 1,
                ..area
            };
            self.buttons
                .render(frame, r, &widget_cx(cx, cx.focused, true));
        }
    }
}

/// A yes/no question (see [`confirm`]).
#[derive(Debug)]
pub(crate) struct ConfirmDialog {
    inner: ButtonBox,
    confirm_on_quit: bool,
}

impl ConfirmDialog {
    /// The `Quit` action (pressed again) answers "yes" (the quit confirmation).
    #[must_use]
    pub(crate) fn confirm_on_quit(mut self) -> Self {
        self.confirm_on_quit = true;
        self
    }

    /// Index of the focused button (0 = yes, 1 = no).
    pub(crate) fn focused(&self) -> usize {
        self.inner.buttons.focused()
    }

    fn result(i: Option<usize>) -> DialogStep<bool> {
        match i {
            Some(i) => DialogStep::Close(Some(i == 0)),
            None => DialogStep::Continue,
        }
    }
}

/// A yes/no question. `true` only for yes; `Esc` → `None`. A `danger` confirm has the
/// default and initial focus on "no", so `Enter` never confirms it by accident.
pub(crate) fn confirm(title: &str, text: &str, opts: ConfirmOpts) -> ConfirmDialog {
    let yes_role = if opts.danger {
        ButtonRole::Danger
    } else if opts.default_yes {
        ButtonRole::Default
    } else {
        ButtonRole::Normal
    };
    let no_role = if opts.default_yes && !opts.danger {
        ButtonRole::Normal
    } else {
        ButtonRole::Default
    };
    ConfirmDialog {
        inner: ButtonBox {
            title: title.to_owned(),
            text: text.to_owned(),
            buttons: ButtonRow::new(vec![
                Button::new("yes", &opts.yes, yes_role),
                Button::new("no", &opts.no, no_role),
            ]),
        },
        confirm_on_quit: false,
    }
}

impl Dialog for ConfirmDialog {
    type Output = bool;

    fn kind(&self) -> &'static str {
        "confirm"
    }

    fn title(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.inner.title)
    }

    fn size(&self, _screen: Rect) -> DialogSize {
        DialogSize::Fit {
            min_w: FIT_MIN_W,
            max_w: FIT_MAX_W,
        }
    }

    fn measure(&self, max_width: u16) -> (u16, u16) {
        self.inner.measure(max_width)
    }

    fn handle_key(&mut self, key: KeyChord) -> DialogStep<bool> {
        match self.inner.key(key) {
            Some(i) => Self::result(i),
            None => DialogStep::Ignored,
        }
    }

    fn handle_action(&mut self, action: &Action) -> DialogStep<bool> {
        if self.confirm_on_quit && matches!(action, Action::Quit) {
            return DialogStep::Close(Some(true));
        }
        match self.inner.action(action) {
            Some(i) => Self::result(i),
            None => DialogStep::Ignored,
        }
    }

    fn render(&mut self, frame: &mut Frame, area: Rect, cx: &DrawCx) {
        self.inner.render(frame, area, cx, &[]);
    }
}

/// Severity of a [`message`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageLevel {
    /// Information.
    Info,
    /// Something to know.
    Warning,
    /// Something failed.
    Error,
}

impl MessageLevel {
    fn prefix(self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Warning => "Warning",
            Self::Error => "Error",
        }
    }
}

/// A message with *OK* (and *Details* for errors with causes).
#[derive(Debug)]
pub(crate) struct MessageDialog {
    inner: ButtonBox,
    kind: &'static str,
    details: Vec<String>,
    expanded: bool,
}

impl MessageDialog {
    /// The cause lines are shown.
    pub(crate) fn is_expanded(&self) -> bool {
        self.expanded
    }

    fn press(&mut self, i: Option<usize>) -> DialogStep<()> {
        match i
            .and_then(|i| self.inner.buttons.buttons().get(i))
            .map(|b| b.id)
        {
            Some("details") => {
                self.expanded = !self.expanded;
                DialogStep::Continue
            }
            Some(_) => DialogStep::Close(Some(())),
            None => DialogStep::Continue,
        }
    }

    fn shown_details(&self) -> &[String] {
        if self.expanded { &self.details } else { &[] }
    }
}

/// A message; the title is prefixed `Info:`/`Warning:`/`Error:` so the level reads
/// without colour.
pub(crate) fn message(title: &str, text: &str, level: MessageLevel) -> MessageDialog {
    MessageDialog {
        inner: ButtonBox {
            title: format!("{}: {title}", level.prefix()),
            text: text.to_owned(),
            buttons: ButtonRow::new(vec![Button::new("ok", "OK", ButtonRole::Default)]),
        },
        kind: "message",
        details: Vec::new(),
        expanded: false,
    }
}

fn error_dialog(context: &str, chain: Vec<String>) -> MessageDialog {
    let mut it = chain.into_iter();
    let top = it.next().unwrap_or_default();
    let details: Vec<String> = it
        .take(MAX_DETAIL_LINES)
        .map(|c| format!("Caused by: {c}"))
        .collect();
    let mut buttons = vec![Button::new("ok", "OK", ButtonRole::Default)];
    if !details.is_empty() {
        buttons.push(Button::new("details", "Details", ButtonRole::Normal));
    }
    let text = if context.is_empty() {
        top
    } else {
        format!("{context}: {top}")
    };
    MessageDialog {
        inner: ButtonBox {
            title: "Error".to_owned(),
            text,
            buttons: ButtonRow::new(buttons),
        },
        kind: "error",
        details,
        expanded: false,
    }
}

/// An error and its `source()` chain (behind *Details*).
pub(crate) fn error(context: &str, err: &(dyn std::error::Error + 'static)) -> MessageDialog {
    let mut chain = Vec::new();
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        chain.push(e.to_string());
        if chain.len() > MAX_DETAIL_LINES {
            break;
        }
        cur = e.source();
    }
    error_dialog(context, chain)
}

/// A `color_eyre` report and its chain (behind *Details*).
pub(crate) fn error_report(context: &str, report: &color_eyre::Report) -> MessageDialog {
    let chain = report
        .chain()
        .take(MAX_DETAIL_LINES + 1)
        .map(ToString::to_string)
        .collect();
    error_dialog(context, chain)
}

impl Dialog for MessageDialog {
    type Output = ();

    fn kind(&self) -> &'static str {
        self.kind
    }

    fn title(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.inner.title)
    }

    fn size(&self, _screen: Rect) -> DialogSize {
        DialogSize::Fit {
            min_w: FIT_MIN_W,
            max_w: FIT_MAX_W,
        }
    }

    fn measure(&self, max_width: u16) -> (u16, u16) {
        let (mut w, mut h) = self.inner.measure(max_width);
        for d in self.shown_details() {
            let dw = u16::try_from(text_width(d))
                .unwrap_or(u16::MAX)
                .min(max_width);
            w = w.max(dw);
        }
        for d in self.shown_details() {
            h = h.saturating_add(u16::try_from(wrap_text(d, w).len()).unwrap_or(1));
        }
        (w, h)
    }

    fn handle_key(&mut self, key: KeyChord) -> DialogStep<()> {
        match self.inner.key(key) {
            Some(i) => self.press(i),
            None => DialogStep::Ignored,
        }
    }

    fn handle_action(&mut self, action: &Action) -> DialogStep<()> {
        match self.inner.action(action) {
            Some(i) => self.press(i),
            None => DialogStep::Ignored,
        }
    }

    fn render(&mut self, frame: &mut Frame, area: Rect, cx: &DrawCx) {
        let details = self.shown_details().to_vec();
        self.inner.render(frame, area, cx, &details);
    }
}

/// One option of [`choose`].
#[derive(Debug, Clone)]
pub(crate) struct ChoiceOption {
    /// Button label.
    pub label: String,
    /// Mnemonic letter (default: none).
    pub mnemonic: Option<char>,
    /// Role (the first `Safe` option has the initial focus).
    pub role: ButtonRole,
}

impl ChoiceOption {
    /// An option whose mnemonic is its first letter.
    pub(crate) fn new(label: &str, role: ButtonRole) -> Self {
        Self {
            label: label.to_owned(),
            mnemonic: label
                .chars()
                .find(|c| c.is_alphanumeric())
                .map(|c| c.to_ascii_lowercase()),
            role,
        }
    }
}

/// One of several buttons (see [`choose`]).
#[derive(Debug)]
pub(crate) struct ChooseDialog {
    inner: ButtonBox,
}

impl ChooseDialog {
    /// Index of the focused option.
    pub(crate) fn focused(&self) -> usize {
        self.inner.buttons.focused()
    }
}

/// One button per option, in order; initial focus and default: the first `Safe`
/// option, else the first. Result: the option index.
pub(crate) fn choose(title: &str, text: &str, options: Vec<ChoiceOption>) -> ChooseDialog {
    let first = options
        .iter()
        .position(|o| o.role == ButtonRole::Safe)
        .unwrap_or(0);
    let buttons = options
        .into_iter()
        .map(|o| Button {
            id: "",
            label: o.label,
            mnemonic: o.mnemonic.map(|c| c.to_ascii_lowercase()),
            role: o.role,
        })
        .collect();
    let mut row = ButtonRow::new(buttons);
    row.set_focus(first);
    ChooseDialog {
        inner: ButtonBox {
            title: title.to_owned(),
            text: text.to_owned(),
            buttons: row,
        },
    }
}

impl Dialog for ChooseDialog {
    type Output = usize;

    fn kind(&self) -> &'static str {
        "choose"
    }

    fn title(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.inner.title)
    }

    fn size(&self, _screen: Rect) -> DialogSize {
        DialogSize::Fit {
            min_w: FIT_MIN_W,
            max_w: FIT_MAX_W,
        }
    }

    fn measure(&self, max_width: u16) -> (u16, u16) {
        self.inner.measure(max_width)
    }

    fn handle_key(&mut self, key: KeyChord) -> DialogStep<usize> {
        match self.inner.key(key) {
            Some(Some(i)) => DialogStep::Close(Some(i)),
            Some(None) => DialogStep::Continue,
            None => DialogStep::Ignored,
        }
    }

    fn handle_action(&mut self, action: &Action) -> DialogStep<usize> {
        match self.inner.action(action) {
            Some(Some(i)) => DialogStep::Close(Some(i)),
            Some(None) => DialogStep::Continue,
            None => DialogStep::Ignored,
        }
    }

    fn render(&mut self, frame: &mut Frame, area: Rect, cx: &DrawCx) {
        self.inner.render(frame, area, cx, &[]);
    }
}

/// A one-field text prompt; the result is the text exactly as typed (not trimmed).
pub(crate) fn prompt_text(
    title: &str,
    label: &str,
    initial: &str,
    validate: Option<Validator>,
) -> FormDialog<String> {
    let mut input = TextInput::new(initial);
    if let Some(v) = validate {
        input = input.validator(v);
    }
    let form = Form::builder()
        .field("value", label, FieldWidget::Text(input))
        .build();
    FormDialog::new(title, form, |v| Ok(v.text("value").to_owned()))
        .kind("prompt_text")
        .discard_guard(false)
}

/// A one-field password prompt (empty allowed).
pub(crate) fn prompt_password(title: &str, label: &str) -> FormDialog<SecretString> {
    let form = Form::builder()
        .field("value", label, FieldWidget::Secret(SecretInput::new()))
        .build();
    FormDialog::new(title, form, |v| {
        Ok(v.secret("value").map_or_else(
            || SecretString::from(""),
            |s| SecretString::from(s.expose()),
        ))
    })
    .kind("prompt_password")
    .discard_guard(false)
}

/// Read-only text with *Close* (see [`text_viewer`]).
#[derive(Debug)]
pub(crate) struct TextViewerDialog {
    title: String,
    kind: &'static str,
    view: TextView,
    buttons: ButtonRow,
}

impl TextViewerDialog {
    /// The viewer.
    pub(crate) fn view(&self) -> &TextView {
        &self.view
    }
}

/// Read-only text (sanitised, up to 1 000 000 lines) with *Close*.
pub(crate) fn text_viewer(title: &str, text: String) -> TextViewerDialog {
    TextViewerDialog {
        title: title.to_owned(),
        kind: "text_viewer",
        view: TextView::new(&text),
        buttons: ButtonRow::new(vec![Button::new("close", "Close", ButtonRole::Default)]),
    }
}

/// Startup configuration problems collected by T50/T51.
pub(crate) fn problems(lines: Vec<String>) -> TextViewerDialog {
    let n = lines.len();
    let s = if n == 1 { "" } else { "s" };
    let mut d = text_viewer(&format!("{n} configuration problem{s}"), lines.join("\n"));
    d.kind = "problems";
    d
}

impl Dialog for TextViewerDialog {
    type Output = ();

    fn kind(&self) -> &'static str {
        self.kind
    }

    fn title(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.title)
    }

    fn size(&self, _screen: Rect) -> DialogSize {
        DialogSize::Percent { w: 90, h: 80 }
    }

    fn handle_key(&mut self, key: KeyChord) -> DialogStep<()> {
        if self.view.handle_key(key).is_used() {
            return DialogStep::Continue;
        }
        match self.buttons.handle_key(key) {
            WidgetOutcome::Activated => DialogStep::Close(Some(())),
            WidgetOutcome::Ignored => match self.buttons.mnemonic(key, !self.view.is_text()) {
                Some(_) => DialogStep::Close(Some(())),
                None => DialogStep::Ignored,
            },
            _ => DialogStep::Continue,
        }
    }

    fn handle_action(&mut self, action: &Action) -> DialogStep<()> {
        match action {
            Action::DialogSubmit => DialogStep::Close(Some(())),
            Action::NextField | Action::PrevField => DialogStep::Continue,
            _ => DialogStep::Ignored,
        }
    }

    fn render(&mut self, frame: &mut Frame, area: Rect, cx: &DrawCx) {
        let view_h = area.height.saturating_sub(2);
        self.view.render(
            frame,
            Rect {
                height: view_h,
                ..area
            },
            &widget_cx(cx, cx.focused, true),
        );
        if area.height > 0 {
            let r = Rect {
                y: area.bottom() - 1,
                height: 1,
                ..area
            };
            self.buttons
                .render(frame, r, &widget_cx(cx, cx.focused, true));
            if area.height > 1 {
                let total = self.view.lines().len();
                let (row, _) = self.view.scroll();
                let pos = format!("{}/{total}", (row + 1).min(total));
                let w = u16::try_from(pos.len()).unwrap_or(0).min(area.width);
                frame.render_widget(
                    Paragraph::new(Span::styled(pos, cx.theme.style("field_help"))),
                    Rect::new(area.right() - w, area.bottom() - 1, w, 1),
                );
            }
        }
    }
}
