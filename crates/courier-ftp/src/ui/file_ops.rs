//! Dialogs of the file operations (T62): FileZilla's "File attributes"
//! (chmod) dialog with tri-state checkboxes and a numeric field, the custom
//! command line with its history, and the texts of the delete and
//! overwrite questions.

use courier_ftp_core::{
    model::Entry,
    transfer::recursive::{ApplyTo, ChmodSpec},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};
use tokio::sync::oneshot;

use super::{
    Side,
    dialog::{ButtonRow, Field, FieldOutcome, TextInput, TriState, dialog_frame},
    modal::{Modal, ModalOutcome},
    theme::Theme,
};

/// `1 file`, `3 directories`.
pub(crate) fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// `2 files and 1 directory`, `1 file`.
pub(crate) fn count_text(files: usize, dirs: usize) -> String {
    match (files, dirs) {
        (f, 0) => plural(f, "file", "files"),
        (0, d) => plural(d, "directory", "directories"),
        (f, d) => format!(
            "{} and {}",
            plural(f, "file", "files"),
            plural(d, "directory", "directories")
        ),
    }
}

/// Up to `max` names, one per line, then `…and N more`.
fn name_list(names: &[String], max: usize) -> String {
    let mut out: Vec<String> = names.iter().take(max).map(|n| format!("  {n}")).collect();
    if names.len() > max {
        out.push(format!("  …and {} more", names.len() - max));
    }
    out.join("\n")
}

/// The delete confirmation: "Really delete 2 files and 1 directory from the
/// server?" with the first few names.
pub(crate) fn delete_question(side: Side, entries: &[Entry]) -> String {
    let dirs = entries
        .iter()
        .filter(|e| e.is_dir_like() && !e.kind.is_symlink())
        .count();
    let files = entries.len() - dirs;
    let place = match side {
        Side::Local => "this computer",
        Side::Remote => "the server",
    };
    let names: Vec<String> = entries
        .iter()
        .map(|e| {
            if e.is_dir_like() && !e.kind.is_symlink() {
                format!("{}/", e.name)
            } else {
                e.name.clone()
            }
        })
        .collect();
    let mut text = format!(
        "Really delete {} from {place}?\n{}",
        count_text(files, dirs),
        name_list(&names, 5)
    );
    if dirs > 0 {
        text.push_str("\nDirectories are deleted with everything in them.");
    }
    text
}

/// The overwrite question of a rename or move.
pub(crate) fn overwrite_question(names: &[String]) -> String {
    if let [one] = names {
        format!("{one} already exists. Replace it?")
    } else {
        format!(
            "{} files already exist:\n{}\nReplace them?",
            names.len(),
            name_list(names, 5)
        )
    }
}

/// The nine rwx bits, owner read first.
const BITS: [u32; 9] = [
    0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001,
];
const ROWS: [&str; 3] = [
    "Owner permissions:",
    "Group permissions:",
    "Public permissions:",
];
const COLS: [&str; 3] = ["Read", "Write", "Execute"];
const APPLY: [(ApplyTo, &str); 3] = [
    (ApplyTo::All, "All"),
    (ApplyTo::FilesOnly, "Files only"),
    (ApplyTo::DirsOnly, "Directories only"),
];
const WIDTH: u16 = 58;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Grid(usize),
    Numeric,
    Recurse,
    ApplyTo,
    Buttons,
}

/// FileZilla's "File attributes" dialog.
///
/// Each of the nine bits is on, off or (with several entries whose modes
/// differ, or an unknown mode) "unchanged". The numeric field mirrors the
/// boxes: one octal digit per triplet, `x` where a triplet is not fully
/// known; typing three digits (or `x`) sets the boxes. Directories in the
/// selection add "Recurse into subdirectories" and, when recursing, which
/// entries to change. Bits outside rwx (setuid, setgid, sticky) are always
/// left as they are.
pub(crate) struct ChmodDialog {
    subject: String,
    bits: [TriState; 9],
    /// Whether "unchanged" is offered (several entries, or unknown modes).
    tristate: bool,
    numeric: String,
    has_dirs: bool,
    recurse: bool,
    apply_to: usize,
    focus: Focus,
    buttons: ButtonRow,
    error: Option<String>,
    reply: Option<oneshot::Sender<Option<ChmodSpec>>>,
}

impl ChmodDialog {
    /// The dialog for `entries` (the selection). `None` from the receiver:
    /// cancelled.
    pub(crate) fn new(entries: &[Entry]) -> (Self, oneshot::Receiver<Option<ChmodSpec>>) {
        let modes: Vec<Option<u32>> = entries
            .iter()
            .map(|e| e.permissions.as_ref().and_then(|p| p.bits()))
            .collect();
        let mut bits = [TriState::Unchanged; 9];
        for (i, bit) in BITS.iter().enumerate() {
            let mut states = modes.iter().map(|m| m.map(|m| m & bit != 0));
            let first = states.next().flatten();
            if let Some(first) = first
                && states.all(|s| s == Some(first))
            {
                bits[i] = if first { TriState::On } else { TriState::Off };
            }
        }
        let tristate = bits.contains(&TriState::Unchanged);
        let subject = match entries {
            [one] => format!("Permissions of {}", one.name),
            many => format!(
                "Permissions of {}",
                plural(many.len(), "entry", "selected entries")
            ),
        };
        let (tx, rx) = oneshot::channel();
        let mut dialog = Self {
            subject,
            bits,
            tristate,
            numeric: String::new(),
            has_dirs: entries
                .iter()
                .any(|e| e.is_dir_like() && !e.kind.is_symlink()),
            recurse: false,
            apply_to: 0,
            focus: Focus::Grid(0),
            buttons: ButtonRow::new(&["OK", "Cancel"], 0),
            error: None,
            reply: Some(tx),
        };
        dialog.numeric = dialog.digits();
        (dialog, rx)
    }

    /// The numeric value of the boxes (`x` for a triplet not fully known).
    fn digits(&self) -> String {
        self.bits
            .chunks(3)
            .map(|triplet| {
                let mut digit = 0;
                for (state, value) in triplet.iter().zip([4, 2, 1]) {
                    match state {
                        TriState::On => digit += value,
                        TriState::Off => {}
                        TriState::Unchanged => return 'x',
                    }
                }
                char::from(b'0' + digit)
            })
            .collect()
    }

    /// Set the boxes from three typed digits; an error for anything else.
    fn apply_numeric(&mut self) -> Result<(), String> {
        let chars: Vec<char> = self.numeric.chars().collect();
        let valid = chars.len() == 3
            && chars
                .iter()
                .all(|c| matches!(c, '0'..='7') || (self.tristate && *c == 'x'));
        if !valid {
            return Err(if self.tristate {
                "Enter three digits 0–7, or x to leave a group unchanged".to_owned()
            } else {
                "Enter three digits 0–7".to_owned()
            });
        }
        for (t, c) in chars.iter().enumerate() {
            for (k, value) in [4, 2, 1].into_iter().enumerate() {
                self.bits[t * 3 + k] = match c.to_digit(8) {
                    Some(d) if d & value != 0 => TriState::On,
                    Some(_) => TriState::Off,
                    None => TriState::Unchanged,
                };
            }
        }
        Ok(())
    }

    /// What OK sets.
    pub(crate) fn spec(&self) -> ChmodSpec {
        let mut spec = ChmodSpec {
            mode: 0,
            mask: 0,
            recurse: self.has_dirs && self.recurse,
            apply_to: if self.has_dirs && self.recurse {
                APPLY[self.apply_to].0
            } else {
                ApplyTo::All
            },
        };
        for (bit, state) in BITS.iter().zip(self.bits) {
            spec.set_bit(
                *bit,
                match state {
                    TriState::On => Some(true),
                    TriState::Off => Some(false),
                    TriState::Unchanged => None,
                },
            );
        }
        spec
    }

    fn order(&self) -> Vec<Focus> {
        let mut v = vec![Focus::Grid(0), Focus::Numeric];
        if self.has_dirs {
            v.push(Focus::Recurse);
            if self.recurse {
                v.push(Focus::ApplyTo);
            }
        }
        v.push(Focus::Buttons);
        v
    }

    fn step(&mut self, forward: bool) {
        if self.focus == Focus::Numeric && self.apply_numeric().is_err() {
            // Leaving a half-typed value: show the boxes' value again.
            self.numeric = self.digits();
        }
        let order = self.order();
        let at = order
            .iter()
            .position(|f| {
                matches!((f, self.focus), (Focus::Grid(_), Focus::Grid(_))) || *f == self.focus
            })
            .unwrap_or(0);
        let n = order.len();
        let next = if forward {
            (at + 1) % n
        } else {
            (at + n - 1) % n
        };
        self.focus = order[next];
    }

    fn cycle(&mut self, i: usize) {
        self.bits[i] = match (self.bits[i], self.tristate) {
            (TriState::Off, _) => TriState::On,
            (TriState::On, true) => TriState::Unchanged,
            (TriState::On, false) | (TriState::Unchanged, _) => TriState::Off,
        };
        self.numeric = self.digits();
    }

    fn finish(&mut self, ok: bool) -> ModalOutcome {
        if ok {
            if self.focus == Focus::Numeric
                && let Err(e) = self.apply_numeric()
            {
                self.error = Some(e);
                return ModalOutcome::Keep;
            }
            let spec = self.spec();
            if spec.mask == 0 {
                self.error = Some("Nothing to change: every box is \"unchanged\"".to_owned());
                return ModalOutcome::Keep;
            }
            if let Some(tx) = self.reply.take() {
                let _ = tx.send(Some(spec));
            }
        } else if let Some(tx) = self.reply.take() {
            let _ = tx.send(None);
        }
        ModalOutcome::Close
    }

    fn mark(&self, state: TriState) -> &'static str {
        match state {
            TriState::On => "[x]",
            TriState::Off => "[ ]",
            TriState::Unchanged => "[-]",
        }
    }
}

impl Modal for ChmodDialog {
    fn draw(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let mut lines: Vec<Line> = vec![Line::raw(self.subject.clone()), Line::raw("")];
        let focus_style = |focused: bool| {
            if focused {
                theme.selection
            } else {
                Style::new()
            }
        };
        for (r, label) in ROWS.iter().enumerate() {
            let mut spans = vec![Span::styled(format!("{label:<20}"), theme.dim)];
            for (c, col) in COLS.iter().enumerate() {
                let i = r * 3 + c;
                spans.push(Span::styled(
                    self.mark(self.bits[i]),
                    focus_style(self.focus == Focus::Grid(i)),
                ));
                spans.push(Span::raw(format!(" {col:<9}")));
            }
            lines.push(Line::from(spans));
        }
        lines.push(Line::raw(""));
        let numeric = if self.focus == Focus::Numeric {
            Span::styled(format!("{:<3}", self.numeric), theme.selection)
        } else {
            Span::raw(self.numeric.clone())
        };
        let mut spans = vec![Span::styled(format!("{:<20}", "Numeric value:"), theme.dim)];
        spans.push(numeric);
        if self.tristate {
            spans.push(Span::styled("   x = unchanged", theme.dim));
        }
        lines.push(Line::from(spans));
        if self.has_dirs {
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                Span::styled(
                    if self.recurse { "[x]" } else { "[ ]" },
                    focus_style(self.focus == Focus::Recurse),
                ),
                Span::raw(" Recurse into subdirectories"),
            ]));
            let mut spans = vec![Span::raw("    ")];
            for (i, (_, label)) in APPLY.iter().enumerate() {
                let mark = if i == self.apply_to { "(•)" } else { "( )" };
                let style = if !self.recurse {
                    theme.dim
                } else {
                    focus_style(self.focus == Focus::ApplyTo && i == self.apply_to)
                };
                spans.push(Span::styled(format!("{mark} {label}"), style));
                spans.push(Span::raw("  "));
            }
            lines.push(Line::from(spans));
        }
        lines.push(Line::raw(""));
        let buttons_row = lines.len() as u16;
        lines.push(Line::raw(""));
        if let Some(e) = &self.error {
            lines.push(Line::styled(e.clone(), theme.error));
        }
        let height = lines.len() as u16;
        if let Some(inner) = dialog_frame(frame, area, "File attributes", WIDTH, height, theme) {
            frame.render_widget(Paragraph::new(lines), inner);
            if buttons_row < inner.height {
                self.buttons.draw(
                    frame,
                    Rect::new(inner.x, inner.y + buttons_row, inner.width, 1),
                    self.focus == Focus::Buttons,
                    theme,
                );
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> ModalOutcome {
        self.error = None;
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        match key.code {
            KeyCode::Esc => return self.finish(false),
            KeyCode::Tab => self.step(true),
            KeyCode::BackTab => self.step(false),
            KeyCode::Char('o') if alt => return self.finish(true),
            KeyCode::Char('c') if alt => return self.finish(false),
            KeyCode::Enter if self.focus != Focus::Buttons => return self.finish(true),
            _ => match self.focus {
                Focus::Grid(i) => match key.code {
                    KeyCode::Char(' ') => self.cycle(i),
                    KeyCode::Left | KeyCode::Char('h') if i % 3 > 0 => {
                        self.focus = Focus::Grid(i - 1);
                    }
                    KeyCode::Right | KeyCode::Char('l') if i % 3 < 2 => {
                        self.focus = Focus::Grid(i + 1);
                    }
                    KeyCode::Up | KeyCode::Char('k') if i >= 3 => self.focus = Focus::Grid(i - 3),
                    KeyCode::Down | KeyCode::Char('j') if i < 6 => {
                        self.focus = Focus::Grid(i + 3);
                    }
                    KeyCode::Down | KeyCode::Char('j') => self.step(true),
                    _ => {}
                },
                Focus::Numeric => match key.code {
                    KeyCode::Char(c @ ('0'..='7' | 'x' | 'X')) if self.numeric.len() < 3 => {
                        self.numeric.push(c.to_ascii_lowercase());
                        if self.numeric.len() == 3
                            && let Err(e) = self.apply_numeric()
                        {
                            self.error = Some(e);
                        }
                    }
                    KeyCode::Backspace => {
                        self.numeric.pop();
                    }
                    KeyCode::Up => self.step(false),
                    KeyCode::Down => self.step(true),
                    _ => {}
                },
                Focus::Recurse => match key.code {
                    KeyCode::Char(' ') => self.recurse = !self.recurse,
                    KeyCode::Up => self.step(false),
                    KeyCode::Down => self.step(true),
                    _ => {}
                },
                Focus::ApplyTo => match key.code {
                    KeyCode::Left => self.apply_to = self.apply_to.saturating_sub(1),
                    KeyCode::Right => self.apply_to = (self.apply_to + 1).min(APPLY.len() - 1),
                    KeyCode::Up => self.step(false),
                    KeyCode::Down => self.step(true),
                    _ => {}
                },
                Focus::Buttons => {
                    if let Some(pressed) = self.buttons.handle_key(key) {
                        return self.finish(pressed == 0);
                    }
                }
            },
        }
        ModalOutcome::Keep
    }
}

/// `:`: one raw command for the server (FileZilla's "Enter custom
/// command"). Up and Down walk through the commands sent before (oldest
/// first in `history`); Enter sends, Esc cancels.
pub(crate) struct CommandDialog {
    input: TextInput,
    history: Vec<String>,
    /// Where in `history` Up/Down are (`history.len()`: the new line).
    at: usize,
    /// The line being typed before walking the history.
    draft: String,
    reply: Option<oneshot::Sender<Option<String>>>,
}

impl CommandDialog {
    pub(crate) fn new(history: Vec<String>) -> (Self, oneshot::Receiver<Option<String>>) {
        let (tx, rx) = oneshot::channel();
        let at = history.len();
        (
            Self {
                input: TextInput::new("Command:"),
                history,
                at,
                draft: String::new(),
                reply: Some(tx),
            },
            rx,
        )
    }

    fn recall(&mut self, older: bool) {
        if self.at == self.history.len() {
            self.draft = self.input.text();
        }
        let at = if older {
            self.at.checked_sub(1)
        } else {
            Some(self.at + 1).filter(|a| *a <= self.history.len())
        };
        let Some(at) = at else {
            return;
        };
        self.at = at;
        let text = self.history.get(at).cloned().unwrap_or(self.draft.clone());
        self.input.set_value(&text);
    }

    fn close(&mut self, answer: Option<String>) -> ModalOutcome {
        if let Some(tx) = self.reply.take() {
            let _ = tx.send(answer);
        }
        ModalOutcome::Close
    }
}

impl Modal for CommandDialog {
    fn draw(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let Some(inner) = dialog_frame(frame, area, "Custom command", 60, 3, theme) else {
            return;
        };
        let label = "Command: ";
        frame.render_widget(
            Paragraph::new(Span::styled(label, theme.dim)),
            Rect::new(inner.x, inner.y, inner.width, 1),
        );
        let w = label.len() as u16;
        self.input.draw(
            frame,
            Rect::new(inner.x + w, inner.y, inner.width.saturating_sub(w), 1),
            true,
            theme,
        );
        frame.render_widget(
            Paragraph::new(Span::styled(
                "Enter sends · ↑/↓ history · Esc cancels",
                theme.dim,
            )),
            Rect::new(inner.x, inner.y + 2, inner.width, 1),
        );
    }

    fn handle_key(&mut self, key: KeyEvent) -> ModalOutcome {
        match key.code {
            KeyCode::Esc => self.close(None),
            KeyCode::Enter => {
                let text = self.input.text().trim().to_owned();
                if text.is_empty() {
                    ModalOutcome::Keep
                } else {
                    self.close(Some(text))
                }
            }
            KeyCode::Up => {
                self.recall(true);
                ModalOutcome::Keep
            }
            KeyCode::Down => {
                self.recall(false);
                ModalOutcome::Keep
            }
            _ => {
                if self.input.handle_key(key) == FieldOutcome::Consumed {
                    self.at = self.history.len();
                }
                ModalOutcome::Keep
            }
        }
    }

    fn handle_paste(&mut self, text: &str) {
        self.input.handle_paste(text);
    }
}

#[cfg(test)]
mod tests;
