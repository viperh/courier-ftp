//! The query form (T65 §1): where to search, the conditions (the T67
//! condition rows), how they combine, case sensitivity and the result type.

use std::path::PathBuf;

use courier_ftp_core::{
    filters::{AppliesTo, Condition, MatchMode, StringOp},
    model::{LocalPath, RemotePath},
    search::{SearchQuery, SearchRoot},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::ui::{
    Side,
    dialog::{ButtonRow, Checkbox, Field, FieldOutcome, FieldValue, Select, TextInput},
    filters::CondRow,
    theme::Theme,
};

const SIDES: [(Side, &str); 2] = [(Side::Local, "Local"), (Side::Remote, "Remote")];
const MATCH_MODES: [(MatchMode, &str); 2] = [
    (MatchMode::All, "All conditions"),
    (MatchMode::Any, "Any condition"),
];
const TYPES: [(AppliesTo, &str); 3] = [
    (AppliesTo::Files, "Files"),
    (AppliesTo::Dirs, "Directories"),
    (AppliesTo::Both, "Files and directories"),
];
const COND_BUTTONS: [&str; 2] = ["Add condition", "Remove condition"];
const BUTTONS: [&str; 3] = ["Search", "Results", "Close"];
/// Width of the labels.
const LABEL_WIDTH: u16 = 12;
/// Widths of the condition columns before the value.
const COND_WIDTHS: [u16; 2] = [12, 17];

fn labels<T>(table: &[(T, &str)]) -> Vec<String> {
    table.iter().map(|(_, l)| (*l).to_owned()).collect()
}

fn index_of<T: PartialEq>(table: &[(T, &str)], value: &T) -> usize {
    table.iter().position(|(v, _)| v == value).unwrap_or(0)
}

fn pick<T: Copy>(table: &[(T, &str)], i: usize) -> T {
    table.get(i).unwrap_or(&table[0]).0
}

fn side_index(side: Side) -> usize {
    index_of(&SIDES, &side)
}

/// A focusable place in the form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Slot {
    Side,
    Dir,
    Match,
    Case,
    Type,
    /// Condition row, column (type, operator, value).
    Cond(usize, usize),
    CondButtons,
    Buttons,
}

/// What the form did with a key.
pub(super) enum FormOutcome {
    Keep,
    /// *Search*: a valid query.
    Search(SearchQuery),
    /// *Results*: back to the results of the last search.
    ShowResults,
    /// *Close* or `Esc`.
    Close,
}

/// The query form.
pub(crate) struct QueryForm {
    side: Select,
    dir: TextInput,
    match_mode: Select,
    case: Checkbox,
    kind: Select,
    conds: Vec<CondRow>,
    cond_buttons: ButtonRow,
    buttons: ButtonRow,
    focus: Slot,
    /// The condition row last focused (for *Remove condition*).
    last_cond: usize,
    /// The current directory of each side's pane (native form for local),
    /// put in the directory field when the side changes.
    dirs: [String; 2],
    /// What is wrong with the query.
    error: Option<String>,
}

fn empty_name_condition() -> Condition {
    Condition::Name {
        op: StringOp::Contains,
        value: String::new(),
    }
}

impl QueryForm {
    /// A form searching `side`, starting in that side's directory, with one
    /// empty "Filename contains" condition.
    pub(super) fn new(side: Side, dirs: [String; 2]) -> Self {
        let dir = dirs[side_index(side)].clone();
        Self {
            side: Select::new("", labels(&SIDES), side_index(side)),
            dir: TextInput::new("").with_value(&dir),
            match_mode: Select::new("", labels(&MATCH_MODES), 0),
            case: Checkbox::new("", false),
            kind: Select::new("", labels(&TYPES), index_of(&TYPES, &AppliesTo::Both)),
            conds: vec![CondRow::new(&empty_name_condition())],
            cond_buttons: ButtonRow::new(&COND_BUTTONS, 0),
            buttons: ButtonRow::new(&BUTTONS, 0),
            focus: Slot::Cond(0, 2),
            last_cond: 0,
            dirs,
            error: None,
        }
    }

    /// The side searched.
    pub(super) fn side(&self) -> Side {
        pick(&SIDES, self.side.selected())
    }

    #[cfg(test)]
    pub(super) fn focus(&self) -> Slot {
        self.focus
    }

    #[cfg(test)]
    pub(super) fn dir_text(&self) -> String {
        self.dir.text()
    }

    #[cfg(test)]
    pub(super) fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// The panes' directories changed (the form is shown again): search
    /// `side` from its current directory.
    pub(super) fn reopen(&mut self, side: Side, dirs: [String; 2]) {
        self.dirs = dirs;
        self.side = Select::new("", labels(&SIDES), side_index(side));
        let dir = self.dirs[side_index(side)].clone();
        self.dir.set_value(&dir);
        self.error = None;
    }

    fn slots(&self) -> Vec<Slot> {
        let mut slots = vec![Slot::Side, Slot::Dir, Slot::Match, Slot::Case, Slot::Type];
        for r in 0..self.conds.len() {
            slots.extend((0..3).map(|c| Slot::Cond(r, c)));
        }
        slots.extend([Slot::CondButtons, Slot::Buttons]);
        slots
    }

    fn step(&mut self, forward: bool) {
        let slots = self.slots();
        let n = slots.len();
        let i = slots.iter().position(|s| *s == self.focus).unwrap_or(0);
        self.focus = if forward {
            slots[(i + 1) % n]
        } else {
            slots[(i + n - 1) % n]
        };
        if let Slot::Cond(r, _) = self.focus {
            self.last_cond = r;
        }
    }

    fn field_mut(&mut self, slot: Slot) -> Option<&mut dyn Field> {
        Some(match slot {
            Slot::Side => &mut self.side,
            Slot::Dir => &mut self.dir,
            Slot::Match => &mut self.match_mode,
            Slot::Case => &mut self.case,
            Slot::Type => &mut self.kind,
            Slot::Cond(r, c) => self.conds.get_mut(r)?.col_mut(c),
            Slot::CondButtons | Slot::Buttons => return None,
        })
    }

    fn field(&self, slot: Slot) -> Option<&dyn Field> {
        Some(match slot {
            Slot::Side => &self.side,
            Slot::Dir => &self.dir,
            Slot::Match => &self.match_mode,
            Slot::Case => &self.case,
            Slot::Type => &self.kind,
            Slot::Cond(r, c) => self.conds.get(r)?.col(c),
            Slot::CondButtons | Slot::Buttons => return None,
        })
    }

    fn add_condition(&mut self) {
        self.conds.push(CondRow::new(&empty_name_condition()));
        let row = self.conds.len() - 1;
        self.focus = Slot::Cond(row, 2);
        self.last_cond = row;
    }

    /// Remove condition `row` (`None`: the last focused one).
    fn remove_condition(&mut self, row: Option<usize>) {
        if self.conds.is_empty() {
            return;
        }
        let row = row.unwrap_or(self.last_cond).min(self.conds.len() - 1);
        self.conds.remove(row);
        let left = self.conds.len();
        self.last_cond = row.min(left.saturating_sub(1));
        if let Slot::Cond(_, c) = self.focus {
            self.focus = if left == 0 {
                Slot::CondButtons
            } else {
                Slot::Cond(self.last_cond, c)
            };
        }
    }

    /// The query, or what is wrong with it (the bad field gets focus).
    pub(super) fn query(&mut self) -> Result<SearchQuery, String> {
        let text = self.dir.text();
        let text = text.trim();
        let root = match self.side() {
            Side::Local => {
                let path = PathBuf::from(text);
                if text.is_empty() || !path.is_absolute() {
                    self.focus = Slot::Dir;
                    return Err("Enter the full path of a local directory.".into());
                }
                SearchRoot::Local(LocalPath::new(path))
            }
            Side::Remote => {
                if !text.starts_with('/') {
                    self.focus = Slot::Dir;
                    return Err("Enter the full path of a remote directory (/…).".into());
                }
                SearchRoot::Remote(RemotePath::new(text))
            }
        };
        let mut conditions = Vec::new();
        for (i, row) in self.conds.iter().enumerate() {
            match row.condition() {
                Ok(c) => conditions.push(c),
                Err(e) => {
                    self.focus = Slot::Cond(i, 2);
                    self.last_cond = i;
                    return Err(format!("Condition {}: {e}.", i + 1));
                }
            }
        }
        let query = SearchQuery {
            root,
            conditions,
            match_mode: pick(&MATCH_MODES, self.match_mode.selected()),
            case_sensitive: matches!(self.case.value(), FieldValue::Bool(true)),
            search_type: pick(&TYPES, self.kind.selected()),
        };
        query.validate().map_err(|e| e.to_string())?;
        Ok(query)
    }

    fn submit(&mut self) -> FormOutcome {
        match self.query() {
            Ok(query) => {
                self.error = None;
                FormOutcome::Search(query)
            }
            Err(e) => {
                self.error = Some(e);
                FormOutcome::Keep
            }
        }
    }

    pub(super) fn handle_paste(&mut self, text: &str) {
        let focus = self.focus;
        if let Some(field) = self.field_mut(focus) {
            field.handle_paste(text);
        }
    }

    pub(super) fn handle_key(&mut self, key: KeyEvent) -> FormOutcome {
        let focus = self.focus;
        // Alt + S/R/C presses Search, Results, Close from anywhere (an open
        // dropdown keeps its keys).
        if key.modifiers.contains(KeyModifiers::ALT)
            && !self.field(focus).is_some_and(Field::is_capturing)
            && let KeyCode::Char(_) = key.code
        {
            let mut buttons = self.buttons.clone();
            return match buttons.handle_key(key) {
                Some(0) => self.submit(),
                Some(1) => FormOutcome::ShowResults,
                Some(_) => FormOutcome::Close,
                None => FormOutcome::Keep,
            };
        }
        if let Some(capturing) = self.field(focus).map(Field::is_capturing) {
            let side_before = self.side.selected();
            let kind_before = match focus {
                Slot::Cond(r, 0) => self.conds.get(r).map(CondRow::kind),
                _ => None,
            };
            let used = self
                .field_mut(focus)
                .is_some_and(|f| f.handle_key(key) == FieldOutcome::Consumed);
            if used || capturing {
                if let (Slot::Cond(r, 0), Some(before)) = (focus, kind_before)
                    && let Some(row) = self.conds.get_mut(r)
                    && row.kind() != before
                {
                    row.retype();
                }
                if self.side.selected() != side_before {
                    let dir = self.dirs[self.side.selected().min(1)].clone();
                    self.dir.set_value(&dir);
                }
                return FormOutcome::Keep;
            }
        }
        match key.code {
            KeyCode::Esc => return FormOutcome::Close,
            KeyCode::Tab => {
                self.step(true);
                return FormOutcome::Keep;
            }
            KeyCode::BackTab => {
                self.step(false);
                return FormOutcome::Keep;
            }
            _ => {}
        }
        match focus {
            Slot::CondButtons | Slot::Buttons => self.button_key(focus, key),
            Slot::Cond(r, c) => {
                match key.code {
                    KeyCode::Up if r > 0 => self.focus = Slot::Cond(r - 1, c),
                    KeyCode::Up => self.focus = Slot::Type,
                    KeyCode::Down if r + 1 < self.conds.len() => {
                        self.focus = Slot::Cond(r + 1, c);
                    }
                    KeyCode::Down => self.focus = Slot::CondButtons,
                    KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        self.remove_condition(Some(r));
                    }
                    KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        self.add_condition();
                    }
                    KeyCode::Enter => return self.submit(),
                    _ => {}
                }
                if let Slot::Cond(r, _) = self.focus {
                    self.last_cond = r;
                }
                FormOutcome::Keep
            }
            _ => match key.code {
                KeyCode::Down => {
                    self.step(true);
                    FormOutcome::Keep
                }
                KeyCode::Up => {
                    self.step(false);
                    FormOutcome::Keep
                }
                KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.add_condition();
                    FormOutcome::Keep
                }
                KeyCode::Enter => self.submit(),
                _ => FormOutcome::Keep,
            },
        }
    }

    fn button_key(&mut self, slot: Slot, key: KeyEvent) -> FormOutcome {
        match key.code {
            KeyCode::Down => {
                self.step(true);
                return FormOutcome::Keep;
            }
            KeyCode::Up => {
                self.step(false);
                return FormOutcome::Keep;
            }
            _ => {}
        }
        let row = match slot {
            Slot::CondButtons => &mut self.cond_buttons,
            _ => &mut self.buttons,
        };
        let Some(pressed) = row.handle_key(key) else {
            return FormOutcome::Keep;
        };
        match (slot, pressed) {
            (Slot::CondButtons, 0) => self.add_condition(),
            (Slot::CondButtons, _) => self.remove_condition(None),
            (_, 0) => return self.submit(),
            (_, 1) => return FormOutcome::ShowResults,
            _ => return FormOutcome::Close,
        }
        FormOutcome::Keep
    }

    /// Draw into `area` (inside the view's frame); `note` is shown when the
    /// query has no problem.
    pub(super) fn draw(&self, frame: &mut Frame, area: Rect, note: Option<&str>, theme: &Theme) {
        if area.height < 8 || area.width < 30 {
            return;
        }
        let mut overlay: Option<(Slot, Rect)> = None;
        let field_x = area.x + LABEL_WIDTH;
        let field_w = area.width.saturating_sub(LABEL_WIDTH);
        let mut y = area.y;
        for (slot, label, field) in [
            (Slot::Side, "Search in", &self.side as &dyn Field),
            (Slot::Dir, "Directory", &self.dir),
            (Slot::Match, "Match", &self.match_mode),
            (Slot::Case, "Case", &self.case),
            (Slot::Type, "Find", &self.kind),
        ] {
            let focused = self.focus == slot;
            frame.render_widget(
                Paragraph::new(Span::styled(
                    label,
                    if focused { theme.title } else { theme.dim },
                )),
                Rect::new(area.x, y, LABEL_WIDTH, 1),
            );
            let rect = Rect::new(field_x, y, field_w, 1);
            field.draw(frame, rect, focused, theme);
            if slot == Slot::Case {
                frame.render_widget(
                    Paragraph::new("case-sensitive"),
                    Rect::new(field_x + 4, y, field_w.saturating_sub(4), 1),
                );
            }
            if focused {
                overlay = Some((slot, rect));
            }
            y += 1;
        }
        y += 1;
        frame.render_widget(
            Paragraph::new(Span::styled("Conditions", theme.dim)),
            Rect::new(area.x, y, area.width, 1),
        );
        y += 1;
        // Bottom rows: condition buttons, a blank line, the note, the buttons.
        let buttons_y = area.bottom() - 1;
        let note_y = area.bottom() - 2;
        let cond_buttons_y = area.bottom().saturating_sub(4);
        let visible = usize::from(cond_buttons_y.saturating_sub(y)).max(1);
        let focus_row = match self.focus {
            Slot::Cond(r, _) => r,
            _ => self.last_cond,
        };
        let first = focus_row.saturating_sub(visible - 1);
        if self.conds.is_empty() {
            frame.render_widget(
                Paragraph::new(Span::styled(
                    "No conditions: everything of the chosen type matches",
                    theme.dim,
                )),
                Rect::new(area.x, y, area.width, 1),
            );
        }
        let widths = [
            COND_WIDTHS[0],
            COND_WIDTHS[1],
            area.width
                .saturating_sub(COND_WIDTHS[0] + COND_WIDTHS[1] + 2),
        ];
        for (r, row) in self.conds.iter().enumerate().skip(first).take(visible) {
            let bad = row.condition().is_err();
            let mut x = area.x;
            for (c, width) in widths.iter().enumerate() {
                let slot = Slot::Cond(r, c);
                let rect = Rect::new(x, y, *width, 1);
                let focused = self.focus == slot;
                row.col(c).draw(frame, rect, focused, theme);
                if c == 2 && bad && !focused && self.error.is_some() {
                    frame.buffer_mut().set_style(rect, theme.error);
                }
                if focused {
                    overlay = Some((slot, rect));
                }
                x += width + 1;
            }
            y += 1;
        }
        self.cond_buttons.draw(
            frame,
            Rect::new(area.x, cond_buttons_y, area.width, 1),
            self.focus == Slot::CondButtons,
            theme,
        );
        let hint = match self.focus {
            Slot::Cond(..) => "Ctrl-n adds a condition · Ctrl-d removes this one · Enter searches",
            _ => "Tab moves · Enter or Alt-s searches · Esc closes",
        };
        let line = match (&self.error, note) {
            (Some(e), _) => Line::from(Span::styled(e.clone(), theme.error)),
            (None, Some(n)) => Line::from(Span::styled(n.to_owned(), theme.key_hint)),
            (None, None) => Line::from(Span::styled(hint, theme.dim)),
        };
        frame.render_widget(
            Paragraph::new(line),
            Rect::new(area.x, note_y, area.width, 1),
        );
        self.buttons.draw(
            frame,
            Rect::new(area.x, buttons_y, area.width, 1),
            self.focus == Slot::Buttons,
            theme,
        );
        if let Some((slot, rect)) = overlay
            && let Some(field) = self.field(slot)
        {
            field.draw_overlay(frame, rect, theme);
        }
    }
}
