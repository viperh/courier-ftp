//! The file-exists prompt (T42, T69 §6): source and target side by side,
//! a radio list of actions, a *new name* field for Rename, and the "apply
//! to all" options.
//!
//! - `↑`/`↓` pick the action while the list has focus; `Tab`/`Shift-Tab`
//!   move between the list, the name field (only while Rename is picked),
//!   the checkboxes and the buttons; `Space` toggles a checkbox.
//! - `Enter` answers *OK* (or presses the highlighted button); `Esc` and
//!   *Cancel* answer *Skip* for this file. Plain letters never press a
//!   button (they type into the name field); `Alt-O` / `Alt-C` do.
//! - "Always use this action" remembers the answer for the session; ticking
//!   "Apply to current queue only" limits it to the current queue run, and
//!   the other two to the same direction / server. The three are greyed out
//!   until "Always" is ticked.

use courier_ftp_core::{
    events::{ApplyTo, FileExistsAnswer, PromptResponse},
    model::{Direction, Entry, LocalPath, Precision, RemotePath, Timestamp},
    settings::ExistsAction,
    transfer::numbered_name,
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
    dialog::{ButtonRow, Field, TextInput, dialog_frame_styled},
    modal::{Modal, ModalOutcome},
    status::human_bytes,
    theme::Theme,
};

/// The actions offered, in order.
const ACTIONS: [(ExistsAction, &str); 7] = [
    (ExistsAction::Overwrite, "Overwrite"),
    (
        ExistsAction::OverwriteIfNewer,
        "Overwrite if source is newer",
    ),
    (
        ExistsAction::OverwriteIfSizeDiffers,
        "Overwrite if size differs",
    ),
    (
        ExistsAction::OverwriteIfNewerOrSizeDiffers,
        "Overwrite if newer or size differs",
    ),
    (ExistsAction::Resume, "Resume"),
    (ExistsAction::Rename, "Rename to"),
    (ExistsAction::Skip, "Skip"),
];
const RENAME: usize = 5;

/// Focus slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Actions,
    Name,
    Always,
    QueueOnly,
    DirectionOnly,
    ServerOnly,
    Buttons,
}

const SLOTS: [Slot; 7] = [
    Slot::Actions,
    Slot::Name,
    Slot::Always,
    Slot::QueueOnly,
    Slot::DirectionOnly,
    Slot::ServerOnly,
    Slot::Buttons,
];

/// The modal; see the module docs.
pub(crate) struct FileExistsDialog {
    direction: Direction,
    source: Entry,
    target: Entry,
    local: LocalPath,
    remote: RemotePath,
    selected: usize,
    name: TextInput,
    always: bool,
    queue_only: bool,
    direction_only: bool,
    server_only: bool,
    focus: Slot,
    buttons: ButtonRow,
    error: Option<String>,
    unicode: bool,
    reply: Option<oneshot::Sender<PromptResponse>>,
}

impl FileExistsDialog {
    pub(crate) fn new(
        direction: Direction,
        source: Entry,
        target: Entry,
        local: LocalPath,
        remote: RemotePath,
        unicode: bool,
        reply: oneshot::Sender<PromptResponse>,
    ) -> Self {
        let name = TextInput::new("").with_value(&numbered_name(&target.name, 1));
        Self {
            direction,
            source,
            target,
            local,
            remote,
            selected: 0,
            name,
            always: false,
            queue_only: false,
            direction_only: false,
            server_only: false,
            focus: Slot::Actions,
            buttons: ButtonRow::new(&["OK", "Cancel"], 0),
            error: None,
            unicode,
            reply: Some(reply),
        }
    }

    fn enabled(&self, slot: Slot) -> bool {
        match slot {
            Slot::Name => self.selected == RENAME,
            Slot::QueueOnly | Slot::DirectionOnly | Slot::ServerOnly => self.always,
            _ => true,
        }
    }

    fn step(&mut self, forward: bool) {
        let n = SLOTS.len();
        let mut i = SLOTS.iter().position(|s| *s == self.focus).unwrap_or(0);
        for _ in 0..n {
            i = if forward {
                (i + 1) % n
            } else {
                (i + n - 1) % n
            };
            if self.enabled(SLOTS[i]) {
                break;
            }
        }
        self.focus = SLOTS[i];
    }

    fn toggle(&mut self) {
        match self.focus {
            Slot::Always => self.always = !self.always,
            Slot::QueueOnly => self.queue_only = !self.queue_only,
            Slot::DirectionOnly => self.direction_only = !self.direction_only,
            Slot::ServerOnly => self.server_only = !self.server_only,
            _ => {}
        }
    }

    fn send(&mut self, answer: FileExistsAnswer) -> ModalOutcome {
        if let Some(reply) = self.reply.take() {
            let _ = reply.send(PromptResponse::FileExists(answer));
        }
        ModalOutcome::Close
    }

    /// The answer for the current choices, or an error to show.
    fn answer(&self) -> Result<FileExistsAnswer, String> {
        let action = ACTIONS[self.selected].0;
        let new_name = if self.selected == RENAME {
            let name = self.name.text();
            let name = name.trim();
            if name.contains(['/', '\\', '\0']) || name == "." || name == ".." {
                return Err("The new name must be a file name, without / or \\.".into());
            }
            (!name.is_empty()).then(|| name.to_owned())
        } else {
            None
        };
        Ok(FileExistsAnswer {
            action,
            apply_to: match (self.always, self.queue_only) {
                (false, _) => ApplyTo::Once,
                (true, true) => ApplyTo::AllInQueue,
                (true, false) => ApplyTo::AllInSession,
            },
            same_direction_only: self.always && self.direction_only,
            same_server_only: self.always && self.server_only,
            new_name,
        })
    }

    fn ok(&mut self) -> ModalOutcome {
        match self.answer() {
            Ok(a) => self.send(a),
            Err(e) => {
                self.error = Some(e);
                self.focus = Slot::Name;
                ModalOutcome::Keep
            }
        }
    }

    fn cancel(&mut self) -> ModalOutcome {
        self.send(FileExistsAnswer::once(ExistsAction::Skip))
    }

    fn press(&mut self, button: usize) -> ModalOutcome {
        if button == 0 {
            self.ok()
        } else {
            self.cancel()
        }
    }

    fn sides(&self) -> [(&'static str, String, &Entry); 2] {
        let local = self.local.to_display();
        let remote = self.remote.as_str().to_owned();
        match self.direction {
            Direction::Download => [
                ("Source (server)", remote, &self.source),
                ("Target (local)", local, &self.target),
            ],
            Direction::Upload => [
                ("Source (local)", local, &self.source),
                ("Target (server)", remote, &self.target),
            ],
        }
    }
}

/// `2026-05-01 12:00:30 UTC`, at the timestamp's precision and offset.
fn format_time(t: &Timestamp) -> String {
    let d = t.time;
    let date = format!("{:04}-{:02}-{:02}", d.year(), u8::from(d.month()), d.day());
    let time = match t.precision {
        Precision::Day => return date,
        Precision::Minute => format!("{:02}:{:02}", d.hour(), d.minute()),
        Precision::Second | Precision::Millis => {
            format!("{:02}:{:02}:{:02}", d.hour(), d.minute(), d.second())
        }
    };
    let offset = d.offset();
    let zone = if offset.is_utc() {
        "UTC".to_owned()
    } else {
        let (h, m, _) = offset.as_hms();
        format!("{:+03}:{:02}", h, m.unsigned_abs())
    };
    format!("{date} {time} {zone}")
}

/// `text` shortened from the left to `width` characters (`…/dir/file`).
fn ellipsize_left(text: &str, width: usize, unicode: bool) -> String {
    let n = text.chars().count();
    if n <= width {
        return text.to_owned();
    }
    let dots = if unicode { "…" } else { "..." };
    let keep = width.saturating_sub(dots.chars().count());
    let tail: String = text.chars().skip(n - keep).collect();
    format!("{dots}{tail}")
}

impl Modal for FileExistsDialog {
    fn draw(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let width = 72u16.min(area.width.saturating_sub(4)).max(20);
        let w = usize::from(width);
        const INTRO: (&str, &str) = ("The target file already exists.", "What do you want to do?");
        let mut lines: Vec<Line> = if INTRO.0.len() + 1 + INTRO.1.len() <= w {
            vec![Line::raw(format!("{} {}", INTRO.0, INTRO.1))]
        } else {
            vec![Line::raw(INTRO.0), Line::raw(INTRO.1)]
        };
        lines.push(Line::raw(""));
        let label_w = 17;
        let value_w = w.saturating_sub(label_w).max(1);
        let size_differs = self.source.size != self.target.size;
        let source_newer = match (&self.source.modified, &self.target.modified) {
            (Some(s), Some(t)) => s.cmp_coarse(t) == std::cmp::Ordering::Greater,
            _ => false,
        };
        for (i, (label, path, entry)) in self.sides().into_iter().enumerate() {
            lines.push(Line::from(vec![
                Span::styled(format!("{label:<label_w$}"), theme.title),
                Span::raw(ellipsize_left(&path, value_w, self.unicode)),
            ]));
            let size = entry.size.map_or_else(
                || "size unknown".to_owned(),
                |s| format!("{} ({s} bytes)", human_bytes(s)),
            );
            let time = entry
                .modified
                .as_ref()
                .map_or_else(|| "time unknown".to_owned(), format_time);
            // Highlight what differs on the target row.
            let size_style = if i == 1 && size_differs {
                theme.error
            } else {
                Style::new()
            };
            let time_style = if i == 0 && source_newer {
                theme.title
            } else {
                Style::new()
            };
            lines.push(Line::from(vec![
                Span::raw(" ".repeat(label_w)),
                Span::styled(size, size_style),
            ]));
            lines.push(Line::from(vec![
                Span::raw(" ".repeat(label_w)),
                Span::styled(time, time_style),
            ]));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled("Action:", theme.dim));
        let (on, off) = if self.unicode {
            ("(•)", "( )")
        } else {
            ("(*)", "( )")
        };
        let mut name_row = 0u16;
        for (i, (_, label)) in ACTIONS.iter().enumerate() {
            let mark = if i == self.selected { on } else { off };
            let style = if i == self.selected && self.focus == Slot::Actions {
                theme.selection
            } else {
                Style::new()
            };
            if i == RENAME {
                name_row = u16::try_from(lines.len()).unwrap_or(u16::MAX);
            }
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(format!("{mark} {label}"), style),
            ]));
        }
        lines.push(Line::raw(""));
        let check = |checked: bool, enabled: bool| match (enabled, checked) {
            (false, _) => "[-]",
            (true, true) => "[x]",
            (true, false) => "[ ]",
        };
        let direction_label = match self.direction {
            Direction::Download => "Apply only to downloads",
            Direction::Upload => "Apply only to uploads",
        };
        let boxes = [
            (Slot::Always, self.always, "Always use this action", 0),
            (
                Slot::QueueOnly,
                self.queue_only,
                "Apply to current queue only",
                4,
            ),
            (Slot::DirectionOnly, self.direction_only, direction_label, 4),
            (
                Slot::ServerOnly,
                self.server_only,
                "Apply only to this server",
                4,
            ),
        ];
        for (slot, checked, label, indent) in boxes {
            let enabled = self.enabled(slot);
            let mark_style = if self.focus == slot {
                theme.selection
            } else {
                Style::new()
            };
            let label_style = if enabled { Style::new() } else { theme.dim };
            lines.push(Line::from(vec![
                Span::raw(" ".repeat(indent)),
                Span::styled(check(checked, enabled), mark_style),
                Span::raw(" "),
                Span::styled(label, label_style),
            ]));
        }
        if let Some(err) = &self.error {
            lines.push(Line::styled(err.clone(), theme.error));
        }
        let to_u16 = |n: usize| u16::try_from(n).unwrap_or(u16::MAX);
        let height = to_u16(lines.len()) + 2;
        let Some(inner) = dialog_frame_styled(
            frame,
            area,
            "Target file exists",
            width,
            height,
            theme,
            theme.focused_border,
        ) else {
            return;
        };
        frame.render_widget(Paragraph::new(lines), inner);
        // The name field sits right of "Rename to".
        let label_end = 2 + 4 + "Rename to".len() as u16 + 1;
        if self.selected == RENAME && name_row < inner.height {
            let x = inner.x + label_end;
            let field = Rect::new(x, inner.y + name_row, inner.right().saturating_sub(x), 1);
            self.name
                .draw(frame, field, self.focus == Slot::Name, theme);
        }
        self.buttons.draw(
            frame,
            Rect::new(inner.x, inner.bottom().saturating_sub(1), inner.width, 1),
            self.focus == Slot::Buttons,
            theme,
        );
    }

    fn handle_key(&mut self, key: KeyEvent) -> ModalOutcome {
        if key.modifiers.contains(KeyModifiers::ALT) {
            if let Some(i) = self.buttons.handle_key(key) {
                return self.press(i);
            }
            return ModalOutcome::Keep;
        }
        match (self.focus, key.code) {
            (_, KeyCode::Esc) => return self.cancel(),
            (_, KeyCode::Tab) => self.step(true),
            (_, KeyCode::BackTab) => self.step(false),
            (Slot::Buttons, _) => {
                if let Some(i) = self.buttons.handle_key(key) {
                    return self.press(i);
                }
            }
            (_, KeyCode::Enter) => return self.ok(),
            (Slot::Actions, KeyCode::Up) => self.selected = self.selected.saturating_sub(1),
            (Slot::Actions, KeyCode::Down) => {
                self.selected = (self.selected + 1).min(ACTIONS.len() - 1);
            }
            (Slot::Name, _) => {
                self.name.handle_key(key);
                self.error = None;
            }
            (_, KeyCode::Char(' ')) => self.toggle(),
            (_, KeyCode::Down) => self.step(true),
            (_, KeyCode::Up) => self.step(false),
            _ => {}
        }
        ModalOutcome::Keep
    }

    fn handle_paste(&mut self, text: &str) {
        if self.focus == Slot::Name {
            self.name.handle_paste(text);
        }
    }

    fn is_done(&self) -> bool {
        // The core stopped waiting (the transfer was cancelled).
        self.reply.as_ref().is_none_or(|r| r.is_closed())
    }
}

#[cfg(test)]
mod tests;
