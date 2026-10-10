//! "Target file already exists" (T69 §6; T42 produces the prompt).

use courier_ftp_core::{
    events::{ApplyTo, FileExistsPrompt, PromptResponse},
    model::{Direction, Entry},
    settings::ExistsAction,
};
use ratatui::{
    Frame,
    layout::{Position, Rect},
    style::Style,
    text::{Line, Span},
};

use super::{
    PromptDialog, PromptEnv, Step,
    layout::{
        Body, BodyCx, Btn, K, Row, checkbox, classify, clean, middle_truncate, radio, step_focus,
    },
};
use crate::{
    components::{
        file_list::format::{format_modified, format_size},
        widgets::{Notice, TextInput, Widget, WidgetCx},
    },
    keymap::chord::KeyChord,
};

/// The radio choices: action, label, mnemonic.
const CHOICES: [(ExistsAction, &str, char); 7] = [
    (ExistsAction::Overwrite, "Overwrite", 'o'),
    (
        ExistsAction::OverwriteIfNewer,
        "Overwrite if the source is newer",
        'n',
    ),
    (
        ExistsAction::OverwriteIfSizeDiffers,
        "Overwrite if the size differs",
        'z',
    ),
    (
        ExistsAction::OverwriteIfNewerOrSizeDiffers,
        "Overwrite if newer or the size differs",
        'b',
    ),
    (ExistsAction::Resume, "Resume", 'r'),
    (ExistsAction::Rename, "Rename to:", 'm'),
    (ExistsAction::Skip, "Skip", 's'),
];

const RESUME: usize = 4;
const RENAME: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Radio,
    Name,
    All,
    OnlyDir,
    Ok,
    Cancel,
}

const FOCUS: [Focus; 6] = [
    Focus::Radio,
    Focus::Name,
    Focus::All,
    Focus::OnlyDir,
    Focus::Ok,
    Focus::Cancel,
];

/// The file-exists dialog.
#[derive(Debug)]
pub(crate) struct FileExistsDialog {
    p: FileExistsPrompt,
    source: (String, String),
    target: (String, String),
    choice: usize,
    name: TextInput,
    all: bool,
    only_dir: bool,
    focus: Focus,
}

fn size_and_date(e: &Entry, env: &PromptEnv) -> (String, String) {
    let size = e.size.map_or_else(
        || "?".to_owned(),
        |b| format_size(b, env.size_format, env.thousands),
    );
    let modified = e
        .modified
        .as_ref()
        .map_or_else(|| "?".to_owned(), |t| format_modified(t, &env.dates, false));
    (clean(&size), clean(&modified))
}

impl FileExistsDialog {
    /// The dialog for `p`, with sizes and dates formatted per `env`.
    pub(crate) fn new(p: FileExistsPrompt, env: &PromptEnv) -> Self {
        let name = TextInput::new(&clean(
            p.suggested_name.as_deref().unwrap_or(&p.target.name),
        ));
        Self {
            source: size_and_date(&p.source, env),
            target: size_and_date(&p.target, env),
            p,
            choice: 0,
            name,
            all: false,
            only_dir: false,
            focus: Focus::Radio,
        }
    }

    fn choice_enabled(&self, i: usize) -> bool {
        i != RESUME || self.p.can_resume
    }

    fn enabled(&self, f: Focus) -> bool {
        match f {
            Focus::Name => self.choice == RENAME,
            Focus::OnlyDir => self.all,
            _ => true,
        }
    }

    /// Why the rename field's value cannot be used.
    fn name_error(&self) -> Option<&'static str> {
        if self.choice != RENAME {
            return None;
        }
        let v = self.name.value();
        if v.trim().is_empty() {
            Some("enter a name")
        } else if v.contains(['/', '\\']) {
            Some("no / or \\ allowed")
        } else if v == self.p.target.name {
            Some("that is the existing name")
        } else {
            None
        }
    }

    fn select(&mut self, i: usize) {
        if self.choice_enabled(i) {
            self.choice = i;
        }
    }

    fn move_choice(&mut self, forward: bool) {
        let mut i = self.choice;
        loop {
            let next = if forward { i + 1 } else { i.wrapping_sub(1) };
            if next >= CHOICES.len() {
                return;
            }
            i = next;
            if self.choice_enabled(i) {
                self.choice = i;
                return;
            }
        }
    }

    fn move_focus(&mut self, forward: bool) {
        let cur = FOCUS.iter().position(|f| *f == self.focus).unwrap_or(0);
        self.focus = FOCUS[step_focus(cur, FOCUS.len(), forward, |i| self.enabled(FOCUS[i]))];
    }

    fn toggle_all(&mut self) {
        self.all = !self.all;
        if !self.all {
            self.only_dir = false;
            if self.focus == Focus::OnlyDir {
                self.focus = Focus::All;
            }
        }
    }

    fn submit(&mut self) -> Step {
        if self.name_error().is_some() {
            self.focus = Focus::Name;
            return Step::Continue;
        }
        let action = CHOICES[self.choice].0;
        let apply_to = match (self.all, self.only_dir) {
            (false, _) => ApplyTo::Once,
            (true, false) => ApplyTo::AllInQueue,
            (true, true) => ApplyTo::AllForDirection,
        };
        let new_name = (action == ExistsAction::Rename).then(|| self.name.value().to_owned());
        Step::Answer(PromptResponse::FileExists {
            action,
            apply_to,
            new_name,
        })
    }

    fn mnemonic(&mut self, c: char) {
        if let Some(i) = CHOICES.iter().position(|x| x.2 == c) {
            self.select(i);
            if i == RENAME && self.choice == RENAME {
                self.focus = Focus::Name;
            } else if self.focus == Focus::Name {
                self.focus = Focus::Radio;
            }
            return;
        }
        match c {
            'a' => self.toggle_all(),
            'd' if self.all => self.only_dir = !self.only_dir,
            _ => {}
        }
    }

    /// Sets the rename field (tests).
    #[cfg(test)]
    pub(crate) fn set_name(&mut self, v: &str) {
        self.name.set_value(v);
    }
}

impl PromptDialog for FileExistsDialog {
    fn kind(&self) -> &'static str {
        "file_exists"
    }

    fn title(&self, _unicode: bool) -> String {
        "Target file already exists".to_owned()
    }

    fn handle_key(&mut self, key: KeyChord) -> Step {
        let k = classify(key);
        match k {
            K::Esc | K::Alt('c') => return Step::Answer(PromptResponse::Cancel),
            K::Tab => self.move_focus(true),
            K::BackTab => self.move_focus(false),
            K::Enter => {
                return if self.focus == Focus::Cancel {
                    Step::Answer(PromptResponse::Cancel)
                } else {
                    self.submit()
                };
            }
            K::Alt('k') => return self.submit(),
            K::Alt(c) => self.mnemonic(c),
            _ if self.focus == Focus::Name => {
                self.name.handle_key(key);
            }
            K::Up | K::Plain('k') if self.focus == Focus::Radio => self.move_choice(false),
            K::Down | K::Plain('j') if self.focus == Focus::Radio => self.move_choice(true),
            K::Space if self.focus == Focus::All => self.toggle_all(),
            K::Space if self.focus == Focus::OnlyDir => self.only_dir = !self.only_dir,
            K::Left if self.focus == Focus::Cancel => self.focus = Focus::Ok,
            K::Right if self.focus == Focus::Ok => self.focus = Focus::Cancel,
            K::Plain(c) => self.mnemonic(c.to_ascii_lowercase()),
            _ => {}
        }
        if !self.enabled(self.focus) {
            self.focus = Focus::Radio;
        }
        Step::Continue
    }

    fn handle_paste(&mut self, text: &str) {
        if self.focus == Focus::Name {
            self.name.handle_paste(text);
        }
    }

    fn take_notice(&mut self) -> Option<String> {
        match self.name.take_notice() {
            Some(Notice::Status(s)) => Some(s),
            _ => None,
        }
    }

    fn body(&self, width: u16, cx: &BodyCx) -> Body {
        let w = usize::from(width);
        let mut b = Body::default();
        let path_w = w.saturating_sub(10).max(4);
        let verb = match self.p.direction {
            Direction::Download => "Download",
            Direction::Upload => "Upload",
        };
        let ell = cx.symbols.ellipsis;
        b.text(
            format!(
                "{verb:<8}  {}",
                middle_truncate(&clean(&self.p.source_path), path_w, ell)
            ),
            Style::default(),
        );
        b.text(
            format!(
                "{:>8}  {}",
                "to",
                middle_truncate(&clean(&self.p.target_path), path_w, ell)
            ),
            Style::default(),
        );
        b.blank();
        let label = cx.theme.style("field_help");
        b.line(Line::from(vec![
            Span::raw(" ".repeat(super::layout::LABEL_W)),
            Span::styled(format!("{:<14}{}", "Size", "Modified"), label),
        ]));
        for (name, (size, date)) in [("Source:", &self.source), ("Target:", &self.target)] {
            b.text(
                format!("{}{size:<14}{date}", super::layout::pad_label(name)),
                Style::default(),
            );
        }
        b.blank();
        for (i, (_, text, _)) in CHOICES.iter().enumerate() {
            let focused = self.focus == Focus::Radio && self.choice == i;
            let line = radio(text, self.choice == i, focused, self.choice_enabled(i), cx);
            if i == RENAME {
                let mut label: Vec<Span<'static>> = line.spans;
                label.push(Span::raw(" "));
                let enabled = self.choice == RENAME;
                let row = b.push(Row::Input {
                    label: Line::from(label),
                    field: 0,
                    width: u16::try_from(w.saturating_sub(18 + 22).clamp(10, 30)).unwrap_or(30),
                    focused: self.focus == Focus::Name,
                    enabled,
                    suffix: self.name_error().map(|e| Span::styled(e, cx.danger())),
                });
                if self.focus == Focus::Name || focused {
                    b.focus_row = row;
                }
            } else {
                let row = b.line(line);
                if focused {
                    b.focus_row = row;
                }
            }
        }
        b.blank();
        let row = b.line(checkbox(
            "Use this action for all remaining conflicts in this queue",
            self.all,
            self.focus == Focus::All,
            true,
            cx.theme,
        ));
        if self.focus == Focus::All {
            b.focus_row = row;
        }
        let dir = match self.p.direction {
            Direction::Download => "Only for downloads",
            Direction::Upload => "Only for uploads",
        };
        let mut only = checkbox(
            dir,
            self.only_dir,
            self.focus == Focus::OnlyDir,
            self.all,
            cx.theme,
        );
        only.spans.insert(0, Span::raw("    "));
        let row = b.line(only);
        if self.focus == Focus::OnlyDir {
            b.focus_row = row;
        }
        b.blank();
        let row = b.push(Row::Buttons(vec![
            Btn::new("OK", self.focus == Focus::Ok),
            Btn::new("Cancel", self.focus == Focus::Cancel),
        ]));
        if matches!(self.focus, Focus::Ok | Focus::Cancel) {
            b.focus_row = row;
        }
        b
    }

    fn draw_input(
        &self,
        frame: &mut Frame,
        _field: usize,
        area: Rect,
        cx: &WidgetCx,
    ) -> Option<Position> {
        self.name.render(frame, area, cx);
        self.name.cursor(area)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

    use super::*;
    use crate::components::prompts::tests::{file_exists_prompt, k};

    fn dialog(can_resume: bool) -> FileExistsDialog {
        FileExistsDialog::new(
            file_exists_prompt(Direction::Download, can_resume),
            &PromptEnv::default(),
        )
    }

    fn answer(step: Step) -> Option<(ExistsAction, ApplyTo, Option<String>)> {
        match step {
            Step::Answer(PromptResponse::FileExists {
                action,
                apply_to,
                new_name,
            }) => Some((action, apply_to, new_name)),
            Step::Answer(other) => panic!("unexpected {other:?}"),
            Step::Continue => None,
        }
    }

    #[test]
    fn answer_mapping_table() {
        for (i, (action, _, key)) in CHOICES.iter().enumerate() {
            for (all, only, apply) in [
                (false, false, ApplyTo::Once),
                (true, false, ApplyTo::AllInQueue),
                (true, true, ApplyTo::AllForDirection),
                // "Only for…" without "all" is impossible: it stays off.
                (false, true, ApplyTo::Once),
            ] {
                let mut d = dialog(true);
                d.handle_key(KeyChord::char(*key));
                assert_eq!(d.choice, i);
                if i == RENAME {
                    assert_eq!(d.focus, Focus::Name);
                    d.handle_key(k("tab"));
                }
                if all {
                    d.handle_key(k("alt-a"));
                }
                if only {
                    d.handle_key(k("alt-d"));
                }
                let (a, scope, name) = answer(d.handle_key(k("enter"))).expect("answered");
                assert_eq!(a, *action);
                assert_eq!(scope, apply, "{action:?} all={all} only={only}");
                if *action == ExistsAction::Rename {
                    assert_eq!(name.as_deref(), Some("index (1).html"));
                } else {
                    assert_eq!(name, None);
                }
            }
        }
        // j/k move the selection; Esc cancels.
        let mut d = dialog(true);
        d.handle_key(k("j"));
        d.handle_key(k("down"));
        assert_eq!(d.choice, 2);
        d.handle_key(k("k"));
        assert_eq!(d.choice, 1);
        assert!(matches!(
            d.handle_key(k("esc")),
            Step::Answer(PromptResponse::Cancel)
        ));
    }

    #[test]
    fn resume_disabled_and_rename_validation() {
        let mut d = dialog(false);
        d.handle_key(k("r"));
        assert_eq!(d.choice, 0, "Resume cannot be selected");
        for _ in 0..4 {
            d.handle_key(k("down"));
        }
        assert_eq!(d.choice, RENAME, "↓ skips Resume");
        d.handle_key(k("up"));
        assert_eq!(d.choice, 3);

        let mut d = dialog(true);
        d.handle_key(k("m"));
        for bad in ["", "  ", "a/b", "a\\b", "index.html"] {
            d.set_name(bad);
            assert!(d.name_error().is_some(), "{bad:?}");
            assert_eq!(answer(d.handle_key(k("enter"))), None, "{bad:?} blocks OK");
            assert_eq!(d.focus, Focus::Name);
        }
        d.set_name("index-old.html");
        assert_eq!(
            answer(d.handle_key(k("enter"))),
            Some((
                ExistsAction::Rename,
                ApplyTo::Once,
                Some("index-old.html".to_owned())
            ))
        );
    }
}
