//! SSH keyboard-interactive prompts (T69 §5; T20 produces them): one field per
//! server prompt, masked unless the server allows echo.

use std::fmt;

use courier_ftp_core::{
    events::{KbdInteractivePrompt, PromptResponse},
    secret::SecretString,
};
use ratatui::{
    Frame,
    layout::{Position, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
};
use zeroize::Zeroizing;

use super::{
    PromptDialog, Step,
    layout::{Body, BodyCx, Btn, K, Row, classify, clean, clean_multiline, step_focus, wrap},
};
use crate::{
    components::widgets::{Notice, SecretInput, TextInput, Widget, WidgetCx},
    keymap::chord::KeyChord,
    ui::text::{truncate_to_width, width},
};

/// Instruction lines shown at once (more scroll with `PgUp`/`PgDn`).
pub(crate) const INSTRUCTION_LINES: usize = 8;
/// Widest label column.
pub(crate) const LABEL_CAP: usize = 28;
/// Narrowest input.
const MIN_INPUT: usize = 20;

enum Field {
    Masked(SecretInput),
    Plain(TextInput),
}

impl Field {
    fn widget(&self) -> &dyn Widget {
        match self {
            Self::Masked(s) => s,
            Self::Plain(t) => t,
        }
    }

    fn widget_mut(&mut self) -> &mut dyn Widget {
        match self {
            Self::Masked(s) => s,
            Self::Plain(t) => t,
        }
    }

    fn take(&mut self) -> SecretString {
        match self {
            Self::Masked(s) => s.take(),
            Self::Plain(t) => {
                let v = Zeroizing::new(t.value().to_owned());
                t.set_value("");
                SecretString::from(v.as_str())
            }
        }
    }
}

/// The keyboard-interactive dialog.
pub(crate) struct KbdDialog {
    host: String,
    name: String,
    instructions: Vec<String>,
    labels: Vec<String>,
    fields: Vec<Field>,
    /// Field index, then OK (`n`), Cancel (`n + 1`).
    focus: usize,
    instr_scroll: usize,
}

impl fmt::Debug for KbdDialog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KbdDialog")
            .field("fields", &self.fields.len())
            .field("answers", &format_args!("[REDACTED]"))
            .field("focus", &self.focus)
            .finish_non_exhaustive()
    }
}

impl KbdDialog {
    /// The dialog for `p`.
    pub(crate) fn new(p: &KbdInteractivePrompt) -> Self {
        let fields = p
            .prompts
            .iter()
            .map(|f| {
                if f.echo {
                    Field::Plain(TextInput::new("").max_chars(1024))
                } else {
                    Field::Masked(SecretInput::new())
                }
            })
            .collect();
        Self {
            host: clean(&p.host),
            name: clean(&p.name),
            instructions: vec![clean_multiline(p.instructions.trim_end())],
            labels: p.prompts.iter().map(|f| clean(f.text.trim_end())).collect(),
            fields,
            focus: 0,
            instr_scroll: 0,
        }
    }

    fn ok_index(&self) -> usize {
        self.fields.len()
    }

    fn submit(&mut self) -> Step {
        let answers = self.fields.iter_mut().map(Field::take).collect();
        Step::Answer(PromptResponse::Answers(answers))
    }

    fn label_width(&self) -> usize {
        self.labels
            .iter()
            .map(|l| width(l))
            .max()
            .unwrap_or(0)
            .min(LABEL_CAP)
    }

    fn instruction_lines(&self, width: usize) -> Vec<String> {
        let text = self.instructions.join("\n");
        if text.trim().is_empty() {
            return Vec::new();
        }
        wrap(&text, width)
    }
}

impl PromptDialog for KbdDialog {
    fn kind(&self) -> &'static str {
        "keyboard_interactive"
    }

    fn title(&self, _unicode: bool) -> String {
        format!("Authentication: {}", self.host)
    }

    fn handle_key(&mut self, key: KeyChord) -> Step {
        let n = self.fields.len() + 2;
        match classify(key) {
            K::Esc | K::Alt('c') => return Step::Answer(PromptResponse::Cancel),
            K::Alt('o') => return self.submit(),
            K::Tab => self.focus = step_focus(self.focus, n, true, |_| true),
            K::BackTab => self.focus = step_focus(self.focus, n, false, |_| true),
            K::Enter => {
                if self.focus + 1 < self.ok_index() {
                    self.focus += 1;
                } else if self.focus == self.ok_index() + 1 {
                    return Step::Answer(PromptResponse::Cancel);
                } else {
                    return self.submit();
                }
            }
            K::PageDown => self.instr_scroll += INSTRUCTION_LINES,
            K::PageUp => self.instr_scroll = self.instr_scroll.saturating_sub(INSTRUCTION_LINES),
            K::Left if self.focus == self.ok_index() + 1 => self.focus = self.ok_index(),
            K::Right if self.focus == self.ok_index() => self.focus = self.ok_index() + 1,
            _ => {
                if let Some(f) = self.fields.get_mut(self.focus) {
                    f.widget_mut().handle_key(key);
                }
            }
        }
        Step::Continue
    }

    fn handle_paste(&mut self, text: &str) {
        if let Some(f) = self.fields.get_mut(self.focus) {
            f.widget_mut().handle_paste(text);
        }
    }

    fn take_notice(&mut self) -> Option<String> {
        self.fields
            .iter_mut()
            .find_map(|f| match f.widget_mut().take_notice() {
                Some(Notice::Status(s)) => Some(s),
                _ => None,
            })
    }

    fn body(&self, w: u16, cx: &BodyCx) -> Body {
        let w = usize::from(w);
        let mut b = Body::default();
        if !self.name.trim().is_empty() {
            b.para(&self.name, w, Style::default().add_modifier(Modifier::BOLD));
        }
        let lines = self.instruction_lines(w.saturating_sub(2).max(1));
        if !lines.is_empty() {
            let max_scroll = lines.len().saturating_sub(INSTRUCTION_LINES);
            let top = self.instr_scroll.min(max_scroll);
            let shown = &lines[top..(top + INSTRUCTION_LINES).min(lines.len())];
            let last = shown.len() - 1;
            for (i, l) in shown.iter().enumerate() {
                let mut spans = vec![Span::raw(l.clone())];
                let marker = if i == 0 && top > 0 {
                    Some(cx.symbols.scroll_up)
                } else if i == last && top < max_scroll {
                    Some(cx.symbols.scroll_down)
                } else {
                    None
                };
                if let Some(m) = marker {
                    let pad = w.saturating_sub(width(l) + 1);
                    spans.push(Span::raw(" ".repeat(pad)));
                    spans.push(Span::styled(m, cx.theme.style("field_help")));
                }
                b.line(Line::from(spans));
            }
        }
        b.blank();
        let lw = self.label_width();
        let input_w = w.saturating_sub(lw + 1 + 2 + 2).max(MIN_INPUT);
        for (i, label) in self.labels.iter().enumerate() {
            let shown = truncate_to_width(label, lw, cx.symbols.ellipsis).into_owned();
            let pad = lw.saturating_sub(width(&shown));
            let focused = self.focus == i;
            let style = if focused {
                cx.theme.style("field_label_focused")
            } else {
                Style::default()
            };
            let row = b.push(Row::Input {
                label: Line::from(vec![
                    Span::styled(shown, style),
                    Span::raw(" ".repeat(pad + 1)),
                ]),
                field: i,
                width: u16::try_from(input_w).unwrap_or(u16::MAX),
                focused,
                enabled: true,
                suffix: None,
            });
            if focused {
                b.focus_row = row;
            }
        }
        if !self.labels.is_empty() {
            b.blank();
        }
        let ok = self.ok_index();
        let row = b.push(Row::Buttons(vec![
            Btn::new("OK", self.focus == ok),
            Btn::new("Cancel", self.focus == ok + 1),
        ]));
        if self.focus >= ok {
            b.focus_row = row;
        }
        b
    }

    fn draw_input(
        &self,
        frame: &mut Frame,
        field: usize,
        area: Rect,
        cx: &WidgetCx,
    ) -> Option<Position> {
        let f = self.fields.get(field)?.widget();
        f.render(frame, area, cx);
        f.cursor(area)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

    use super::*;
    use crate::components::prompts::tests::{k, kbd_prompt};

    #[test]
    fn enter_advances_then_submits_in_order() {
        let mut d = KbdDialog::new(&kbd_prompt(
            &[("Password:", false), ("Verification code:", true)],
            "",
        ));
        for c in "pw1".chars() {
            d.handle_key(KeyChord::char(c));
        }
        assert!(matches!(d.handle_key(k("enter")), Step::Continue));
        assert_eq!(d.focus, 1);
        for c in "123456".chars() {
            d.handle_key(KeyChord::char(c));
        }
        match d.handle_key(k("enter")) {
            Step::Answer(PromptResponse::Answers(a)) => {
                let v: Vec<&str> = a.iter().map(|s| s.expose()).collect();
                assert_eq!(v, ["pw1", "123456"]);
            }
            other => panic!("unexpected {other:?}"),
        }
        // No fields: Enter answers with no answers.
        let mut d = KbdDialog::new(&kbd_prompt(&[], "Press OK"));
        assert!(matches!(
            d.handle_key(k("enter")),
            Step::Answer(PromptResponse::Answers(a)) if a.is_empty()
        ));
        let mut d = KbdDialog::new(&kbd_prompt(&[("Code:", true)], ""));
        assert!(matches!(
            d.handle_key(k("esc")),
            Step::Answer(PromptResponse::Cancel)
        ));
    }
}
