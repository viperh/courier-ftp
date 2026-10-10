//! The filter editor (T67 §2, §3): the list of filters on the left, the
//! selected filter's settings and conditions on the right.
//!
//! The widgets of the selected filter are the source of truth while it is
//! selected; every key that changes one writes the filter back
//! ([`FilterEditor::commit`]) and re-checks it, so an invalid regular
//! expression shows its error at once. A filter with a problem can't be
//! left (another filter selected) and blocks *OK*.

use courier_ftp_core::filters::{
    AppliesTo, Condition, DateOp, FileAttribute, Filter, FilterScope, MatchMode, NumOp, PermBit,
    StringOp, builtin_filters,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};
use time::{Date, Month, OffsetDateTime};

use crate::ui::{
    dialog::{ButtonRow, Checkbox, Field, FieldOutcome, FieldValue, Select, TextInput},
    theme::Theme,
};

/// Inner height of the editor's frame.
pub(super) const HEIGHT: u16 = 20;

/// Inner width of the editor's frame on a screen `screen` columns wide:
/// wider screens show longer filter names.
pub(super) fn width(screen: u16) -> u16 {
    screen.saturating_sub(4).clamp(60, 100)
}
/// Width of the labels of the filter's settings.
const LABEL_WIDTH: u16 = 13;

const KINDS: [&str; 6] = [
    "Filename",
    "Path",
    "Size",
    "Date",
    "Permission",
    "Attribute",
];
const STRING_OPS: [(StringOp, &str); 7] = [
    (StringOp::Contains, "contains"),
    (StringOp::NotContains, "doesn't contain"),
    (StringOp::Equals, "equals"),
    (StringOp::NotEquals, "not equals"),
    (StringOp::BeginsWith, "begins with"),
    (StringOp::EndsWith, "ends with"),
    (StringOp::Matches, "matches regex"),
];
const NUM_OPS: [(NumOp, &str); 4] = [
    (NumOp::Greater, "greater than"),
    (NumOp::Equals, "equals"),
    (NumOp::NotEquals, "not equals"),
    (NumOp::Less, "less than"),
];
const DATE_OPS: [(DateOp, &str); 4] = [
    (DateOp::Before, "before"),
    (DateOp::Equals, "on"),
    (DateOp::NotEquals, "not on"),
    (DateOp::After, "after"),
];
const PERM_BITS: [(PermBit, &str); 12] = [
    (PermBit::OwnerRead, "owner read"),
    (PermBit::OwnerWrite, "owner write"),
    (PermBit::OwnerExecute, "owner execute"),
    (PermBit::GroupRead, "group read"),
    (PermBit::GroupWrite, "group write"),
    (PermBit::GroupExecute, "group execute"),
    (PermBit::OtherRead, "other read"),
    (PermBit::OtherWrite, "other write"),
    (PermBit::OtherExecute, "other execute"),
    (PermBit::Setuid, "setuid"),
    (PermBit::Setgid, "setgid"),
    (PermBit::Sticky, "sticky"),
];
const ATTRIBUTES: [(FileAttribute, &str); 2] = [
    (FileAttribute::Hidden, "hidden"),
    (FileAttribute::ReadOnly, "read-only"),
];
const SET_CHOICES: [&str; 2] = ["is set", "is not set"];
const APPLIES_TO: [(AppliesTo, &str); 3] = [
    (AppliesTo::Both, "Files and directories"),
    (AppliesTo::Files, "Files"),
    (AppliesTo::Dirs, "Directories"),
];
const MATCH_MODES: [(MatchMode, &str); 4] = [
    (MatchMode::All, "All conditions"),
    (MatchMode::Any, "Any condition"),
    (MatchMode::None, "None of the conditions"),
    (MatchMode::NotAll, "Not all conditions"),
];
const SCOPES: [(FilterScope, &str); 3] = [
    (FilterScope::Both, "Local and remote"),
    (FilterScope::LocalOnly, "Local only"),
    (FilterScope::RemoteOnly, "Remote only"),
];

fn labels<T>(table: &[(T, &str)]) -> Vec<String> {
    table.iter().map(|(_, l)| (*l).to_owned()).collect()
}

fn index_of<T: PartialEq>(table: &[(T, &str)], value: &T) -> usize {
    table.iter().position(|(v, _)| v == value).unwrap_or(0)
}

fn pick<T: Copy>(table: &[(T, &str)], i: usize) -> T {
    table.get(i).unwrap_or(&table[0]).0
}

/// `2024-03-10`.
pub(super) fn format_date(value: OffsetDateTime) -> String {
    let d = value.date();
    format!("{:04}-{:02}-{:02}", d.year(), u8::from(d.month()), d.day())
}

/// A `YYYY-MM-DD` date, as midnight UTC.
pub(super) fn parse_date(text: &str) -> Option<OffsetDateTime> {
    let mut parts = text.trim().split('-');
    let year: i32 = parts.next()?.parse().ok()?;
    let month: u8 = parts.next()?.parse().ok()?;
    let day: u8 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    let date = Date::from_calendar_date(year, Month::try_from(month).ok()?, day).ok()?;
    Some(date.midnight().assume_utc())
}

/// The useful part of a regex error: its last `error: …` line.
fn regex_error(value: &str) -> Option<String> {
    let probe = Filter {
        name: "probe".into(),
        applies_to: AppliesTo::Both,
        match_mode: MatchMode::All,
        case_sensitive: false,
        conditions: vec![Condition::Name {
            op: StringOp::Matches,
            value: value.to_owned(),
        }],
        scope: FilterScope::Both,
    };
    let message = probe.validate().err()?.to_string();
    let last = message
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    Some(last.strip_prefix("error: ").unwrap_or(last).to_owned())
}

/// The value part of a condition row.
enum ValueWidget {
    Text(TextInput),
    Choice(Select),
}

impl ValueWidget {
    fn field(&self) -> &dyn Field {
        match self {
            ValueWidget::Text(t) => t,
            ValueWidget::Choice(s) => s,
        }
    }

    fn field_mut(&mut self) -> &mut dyn Field {
        match self {
            ValueWidget::Text(t) => t,
            ValueWidget::Choice(s) => s,
        }
    }

    fn text(&self) -> String {
        match self {
            ValueWidget::Text(t) => t.text(),
            ValueWidget::Choice(_) => String::new(),
        }
    }

    fn index(&self) -> usize {
        match self {
            ValueWidget::Text(_) => 0,
            ValueWidget::Choice(s) => s.selected(),
        }
    }
}

/// One condition row: type, operator, value.
struct CondRow {
    kind: Select,
    op: Select,
    value: ValueWidget,
}

impl CondRow {
    fn new(condition: &Condition) -> Self {
        let (kind, op_labels, op, value) = match condition {
            Condition::Name { op, value } | Condition::Path { op, value } => (
                usize::from(matches!(condition, Condition::Path { .. })),
                labels(&STRING_OPS),
                index_of(&STRING_OPS, op),
                ValueWidget::Text(TextInput::new("").with_value(value)),
            ),
            Condition::Size { op, value } => (
                2,
                labels(&NUM_OPS),
                index_of(&NUM_OPS, op),
                ValueWidget::Text(TextInput::new("").with_value(&value.to_string())),
            ),
            Condition::Date { op, value } => (
                3,
                labels(&DATE_OPS),
                index_of(&DATE_OPS, op),
                ValueWidget::Text(TextInput::new("").with_value(&format_date(*value))),
            ),
            Condition::Permission { bit, set } => (
                4,
                labels(&PERM_BITS),
                index_of(&PERM_BITS, bit),
                ValueWidget::Choice(set_select(*set)),
            ),
            Condition::Attribute { attr, set } => (
                5,
                labels(&ATTRIBUTES),
                index_of(&ATTRIBUTES, attr),
                ValueWidget::Choice(set_select(*set)),
            ),
        };
        Self {
            kind: Select::new("", KINDS.iter().map(|k| (*k).to_owned()).collect(), kind),
            op: Select::new("", op_labels, op),
            value,
        }
    }

    /// The condition, or what is wrong with it.
    fn condition(&self) -> Result<Condition, String> {
        let op = self.op.selected();
        let text = self.value.text();
        match self.kind.selected() {
            k @ (0 | 1) => {
                let op = pick(&STRING_OPS, op);
                if text.is_empty() {
                    return Err("enter a value".into());
                }
                if op == StringOp::Matches
                    && let Some(e) = regex_error(&text)
                {
                    return Err(format!("invalid regular expression: {e}"));
                }
                Ok(if k == 0 {
                    Condition::Name { op, value: text }
                } else {
                    Condition::Path { op, value: text }
                })
            }
            2 => Ok(Condition::Size {
                op: pick(&NUM_OPS, op),
                value: text
                    .trim()
                    .parse()
                    .map_err(|_| "the size is a whole number of bytes".to_owned())?,
            }),
            3 => Ok(Condition::Date {
                op: pick(&DATE_OPS, op),
                value: parse_date(&text).ok_or("enter the date as YYYY-MM-DD")?,
            }),
            4 => Ok(Condition::Permission {
                bit: pick(&PERM_BITS, op),
                set: self.value.index() == 0,
            }),
            _ => Ok(Condition::Attribute {
                attr: pick(&ATTRIBUTES, op),
                set: self.value.index() == 0,
            }),
        }
    }

    /// The type was changed: a fresh operator and value of the new type
    /// (the text stays between Filename and Path).
    fn retype(&mut self) {
        let text = self.value.text();
        let kind = self.kind.selected();
        let fresh = match kind {
            0 => Condition::Name {
                op: StringOp::Contains,
                value: text,
            },
            1 => Condition::Path {
                op: StringOp::Contains,
                value: text,
            },
            2 => Condition::Size {
                op: NumOp::Greater,
                value: 0,
            },
            3 => Condition::Date {
                op: DateOp::Before,
                value: OffsetDateTime::now_utc().date().midnight().assume_utc(),
            },
            4 => Condition::Permission {
                bit: PermBit::OwnerExecute,
                set: true,
            },
            _ => Condition::Attribute {
                attr: FileAttribute::Hidden,
                set: true,
            },
        };
        *self = CondRow::new(&fresh);
    }

    fn col(&self, col: usize) -> &dyn Field {
        match col {
            0 => &self.kind,
            1 => &self.op,
            _ => self.value.field(),
        }
    }

    fn col_mut(&mut self, col: usize) -> &mut dyn Field {
        match col {
            0 => &mut self.kind,
            1 => &mut self.op,
            _ => self.value.field_mut(),
        }
    }
}

fn set_select(set: bool) -> Select {
    Select::new(
        "",
        SET_CHOICES.iter().map(|s| (*s).to_owned()).collect(),
        usize::from(!set),
    )
}

/// The widgets of the selected filter.
struct Widgets {
    name: TextInput,
    applies_to: Select,
    match_mode: Select,
    case: Checkbox,
    scope: Select,
    conds: Vec<CondRow>,
}

impl Widgets {
    fn new(f: &Filter) -> Self {
        Self {
            name: TextInput::new("Name:").with_value(&f.name),
            applies_to: Select::new(
                "Applies to:",
                labels(&APPLIES_TO),
                index_of(&APPLIES_TO, &f.applies_to),
            ),
            match_mode: Select::new(
                "Match:",
                labels(&MATCH_MODES),
                index_of(&MATCH_MODES, &f.match_mode),
            ),
            case: Checkbox::new("Case:", f.case_sensitive),
            scope: Select::new("Use on:", labels(&SCOPES), index_of(&SCOPES, &f.scope)),
            conds: f.conditions.iter().map(CondRow::new).collect(),
        }
    }
}

/// A focusable place in the editor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Slot {
    List,
    Name,
    AppliesTo,
    Match,
    Case,
    Scope,
    /// Condition row, column (type, operator, value).
    Cond(usize, usize),
    CondButtons,
    ListButtons,
    MainButtons,
}

/// What the editor did with a key.
pub(super) enum EditorOutcome {
    Keep,
    Cancel,
    /// *OK*: the new filter list, and the filters renamed (old, new name).
    Done {
        filters: Vec<Filter>,
        renames: Vec<(String, String)>,
    },
}

const LIST_BUTTONS: [&str; 5] = ["New", "Copy", "Rename", "Delete", "Restore defaults"];
const COND_BUTTONS: [&str; 2] = ["Add condition", "Remove condition"];
const MAIN_BUTTONS: [&str; 2] = ["OK", "Cancel"];

/// The filter editor.
pub(super) struct FilterEditor {
    filters: Vec<Filter>,
    /// The name each filter had when the editor opened (`None`: added here).
    origins: Vec<Option<String>>,
    selected: usize,
    w: Option<Widgets>,
    focus: Slot,
    /// The condition row last focused (for *Remove condition*).
    last_cond: usize,
    list_buttons: ButtonRow,
    cond_buttons: ButtonRow,
    main_buttons: ButtonRow,
    /// What is wrong with the selected filter.
    issues: Vec<String>,
    /// A message for the user (`true`: an error).
    note: Option<(String, bool)>,
}

/// `base`, or `base (2)`, `base (3)`… — the first name not in `filters`.
fn unique_name(filters: &[Filter], base: &str) -> String {
    let taken = |n: &str| filters.iter().any(|f| f.name == n);
    if !taken(base) {
        return base.to_owned();
    }
    (2..)
        .map(|i| format!("{base} ({i})"))
        .find(|n| !taken(n))
        .unwrap_or_else(|| base.to_owned())
}

impl FilterEditor {
    pub(super) fn new(filters: &[Filter]) -> Self {
        let mut editor = Self {
            filters: filters.to_vec(),
            origins: filters.iter().map(|f| Some(f.name.clone())).collect(),
            selected: 0,
            w: None,
            focus: Slot::List,
            last_cond: 0,
            list_buttons: ButtonRow::new(&LIST_BUTTONS, 0),
            cond_buttons: ButtonRow::new(&COND_BUTTONS, 0),
            main_buttons: ButtonRow::new(&MAIN_BUTTONS, 0),
            issues: Vec::new(),
            note: None,
        };
        editor.load();
        editor
    }

    #[cfg(test)]
    pub(super) fn focus(&self) -> Slot {
        self.focus
    }

    #[cfg(test)]
    pub(super) fn filters(&self) -> &[Filter] {
        &self.filters
    }

    #[cfg(test)]
    pub(super) fn selected(&self) -> usize {
        self.selected
    }

    /// The first problem of the selected filter, as shown.
    #[cfg(test)]
    pub(super) fn issue(&self) -> Option<&str> {
        self.issues.first().map(String::as_str)
    }

    /// Build the widgets for the selected filter.
    fn load(&mut self) {
        self.selected = self.selected.min(self.filters.len().saturating_sub(1));
        self.w = self.filters.get(self.selected).map(Widgets::new);
        self.last_cond = 0;
        self.check();
    }

    /// Write the widgets back into the selected filter and check it.
    fn commit(&mut self) {
        let Some(w) = &mut self.w else {
            return;
        };
        let Some(f) = self.filters.get_mut(self.selected) else {
            return;
        };
        f.name = w.name.text();
        f.applies_to = pick(&APPLIES_TO, w.applies_to.selected());
        f.match_mode = pick(&MATCH_MODES, w.match_mode.selected());
        f.scope = pick(&SCOPES, w.scope.selected());
        f.case_sensitive = matches!(w.case.value(), FieldValue::Bool(true));
        f.conditions = w.conds.iter().filter_map(|c| c.condition().ok()).collect();
        self.check();
    }

    /// Collect what is wrong with the selected filter.
    fn check(&mut self) {
        self.issues.clear();
        let (Some(w), Some(f)) = (&self.w, self.filters.get(self.selected)) else {
            return;
        };
        let name = w.name.text();
        if name.trim().is_empty() {
            self.issues.push("Enter a name for the filter.".into());
        } else if self
            .filters
            .iter()
            .enumerate()
            .any(|(i, other)| i != self.selected && other.name == f.name)
        {
            self.issues
                .push(format!("Another filter is already called “{name}”."));
        }
        for (i, row) in w.conds.iter().enumerate() {
            if let Err(e) = row.condition() {
                self.issues.push(format!("Condition {}: {e}.", i + 1));
            }
        }
    }

    fn is_builtin(name: &str) -> bool {
        builtin_filters().iter().any(|b| b.name == name)
    }

    fn slots(&self) -> Vec<Slot> {
        let mut slots = vec![Slot::List];
        if let Some(w) = &self.w {
            slots.extend([
                Slot::Name,
                Slot::AppliesTo,
                Slot::Match,
                Slot::Case,
                Slot::Scope,
            ]);
            for r in 0..w.conds.len() {
                slots.extend((0..3).map(|c| Slot::Cond(r, c)));
            }
            slots.push(Slot::CondButtons);
        }
        slots.extend([Slot::ListButtons, Slot::MainButtons]);
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
        let w = self.w.as_mut()?;
        Some(match slot {
            Slot::Name => &mut w.name,
            Slot::AppliesTo => &mut w.applies_to,
            Slot::Match => &mut w.match_mode,
            Slot::Case => &mut w.case,
            Slot::Scope => &mut w.scope,
            Slot::Cond(r, c) => w.conds.get_mut(r)?.col_mut(c),
            _ => return None,
        })
    }

    fn field(&self, slot: Slot) -> Option<&dyn Field> {
        let w = self.w.as_ref()?;
        Some(match slot {
            Slot::Name => &w.name,
            Slot::AppliesTo => &w.applies_to,
            Slot::Match => &w.match_mode,
            Slot::Case => &w.case,
            Slot::Scope => &w.scope,
            Slot::Cond(r, c) => w.conds.get(r)?.col(c),
            _ => return None,
        })
    }

    /// Select another filter, unless the current one has a problem.
    fn select(&mut self, i: usize) {
        if i == self.selected || self.filters.is_empty() {
            return;
        }
        if let Some(issue) = self.issues.first() {
            self.note = Some((format!("Fix this filter first: {issue}"), true));
            return;
        }
        self.selected = i.min(self.filters.len() - 1);
        self.note = None;
        self.load();
    }

    fn add(&mut self) {
        if self.blocked() {
            return;
        }
        let name = unique_name(&self.filters, "New filter");
        self.filters.push(Filter {
            name,
            applies_to: AppliesTo::Both,
            match_mode: MatchMode::All,
            case_sensitive: false,
            conditions: Vec::new(),
            scope: FilterScope::Both,
        });
        self.origins.push(None);
        self.selected = self.filters.len() - 1;
        self.load();
        self.add_condition();
        self.focus = Slot::Name;
        self.note = None;
    }

    fn copy(&mut self) {
        if self.blocked() {
            return;
        }
        let Some(f) = self.filters.get(self.selected) else {
            return;
        };
        let mut copy = f.clone();
        copy.name = unique_name(&self.filters, &format!("{} (copy)", f.name));
        self.filters.push(copy);
        self.origins.push(None);
        self.selected = self.filters.len() - 1;
        self.load();
        self.focus = Slot::Name;
    }

    fn delete(&mut self) {
        if self.filters.is_empty() {
            return;
        }
        let name = self.filters.remove(self.selected).name;
        self.origins.remove(self.selected);
        self.load();
        self.focus = Slot::List;
        self.note = Some((format!("Deleted “{name}”"), false));
    }

    fn restore_defaults(&mut self) {
        for builtin in builtin_filters() {
            match self.filters.iter_mut().find(|f| f.name == builtin.name) {
                Some(existing) => *existing = builtin,
                None => {
                    self.filters.push(builtin);
                    self.origins.push(None);
                }
            }
        }
        self.load();
        self.note = Some(("Built-in filters restored".into(), false));
    }

    fn add_condition(&mut self) {
        let Some(w) = &mut self.w else {
            return;
        };
        w.conds.push(CondRow::new(&Condition::Name {
            op: StringOp::Contains,
            value: String::new(),
        }));
        let row = w.conds.len() - 1;
        self.focus = Slot::Cond(row, 2);
        self.last_cond = row;
        self.commit();
    }

    /// Remove condition `row` (`None`: the last one).
    fn remove_condition(&mut self, row: Option<usize>) {
        let Some(w) = &mut self.w else {
            return;
        };
        if w.conds.is_empty() {
            return;
        }
        let row = row.unwrap_or(w.conds.len() - 1).min(w.conds.len() - 1);
        w.conds.remove(row);
        let left = w.conds.len();
        self.last_cond = row.min(left.saturating_sub(1));
        if let Slot::Cond(_, c) = self.focus {
            self.focus = if left == 0 {
                Slot::CondButtons
            } else {
                Slot::Cond(self.last_cond, c)
            };
        }
        self.commit();
    }

    /// The current filter has a problem: say so (for actions that would
    /// leave it).
    fn blocked(&mut self) -> bool {
        match self.issues.first() {
            Some(issue) => {
                self.note = Some((format!("Fix this filter first: {issue}"), true));
                true
            }
            None => false,
        }
    }

    /// *OK*: every filter must be valid and the names unique.
    fn ok(&mut self) -> EditorOutcome {
        self.commit();
        if self.blocked() {
            return EditorOutcome::Keep;
        }
        for (i, f) in self.filters.iter().enumerate() {
            let problem = f.validate().err().map(|e| e.to_string()).or_else(|| {
                self.filters[..i]
                    .iter()
                    .any(|o| o.name == f.name)
                    .then(|| format!("Two filters are called “{}”.", f.name))
            });
            if let Some(problem) = problem {
                self.selected = i;
                self.load();
                self.note = Some((problem, true));
                return EditorOutcome::Keep;
            }
        }
        let renames = self
            .origins
            .iter()
            .zip(&self.filters)
            .filter_map(|(o, f)| {
                o.as_ref()
                    .filter(|o| **o != f.name)
                    .map(|o| (o.clone(), f.name.clone()))
            })
            .collect();
        EditorOutcome::Done {
            filters: self.filters.clone(),
            renames,
        }
    }

    fn press_list_button(&mut self, i: usize) {
        match i {
            0 => self.add(),
            1 => self.copy(),
            2 => {
                if !self.filters.is_empty() {
                    self.focus = Slot::Name;
                }
            }
            3 => self.delete(),
            _ => self.restore_defaults(),
        }
    }

    pub(super) fn handle_paste(&mut self, text: &str) {
        let focus = self.focus;
        if let Some(field) = self.field_mut(focus) {
            field.handle_paste(text);
            self.commit();
        }
    }

    pub(super) fn handle_key(&mut self, key: KeyEvent) -> EditorOutcome {
        let focus = self.focus;
        // A field first (an open dropdown takes every key).
        if let Some(capturing) = self.field(focus).map(|f| f.is_capturing()) {
            let kind_before = match focus {
                Slot::Cond(r, 0) => self
                    .w
                    .as_ref()
                    .and_then(|w| w.conds.get(r))
                    .map(|c| c.kind.selected()),
                _ => None,
            };
            let used = self
                .field_mut(focus)
                .is_some_and(|f| f.handle_key(key) == FieldOutcome::Consumed);
            if used || capturing {
                if let (Slot::Cond(r, 0), Some(before)) = (focus, kind_before)
                    && let Some(row) = self.w.as_mut().and_then(|w| w.conds.get_mut(r))
                    && row.kind.selected() != before
                {
                    row.retype();
                }
                self.commit();
                return EditorOutcome::Keep;
            }
        }
        match key.code {
            KeyCode::Esc => return EditorOutcome::Cancel,
            KeyCode::Tab => {
                self.step(true);
                return EditorOutcome::Keep;
            }
            KeyCode::BackTab => {
                self.step(false);
                return EditorOutcome::Keep;
            }
            _ => {}
        }
        match focus {
            Slot::List => self.list_key(key),
            Slot::CondButtons | Slot::ListButtons | Slot::MainButtons => {
                self.button_key(focus, key)
            }
            Slot::Cond(r, c) => {
                let rows = self.w.as_ref().map_or(0, |w| w.conds.len());
                match key.code {
                    KeyCode::Up if r > 0 => self.focus = Slot::Cond(r - 1, c),
                    KeyCode::Up => self.focus = Slot::Scope,
                    KeyCode::Down if r + 1 < rows => self.focus = Slot::Cond(r + 1, c),
                    KeyCode::Down => self.focus = Slot::CondButtons,
                    KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        self.remove_condition(Some(r));
                    }
                    KeyCode::Enter => return self.ok(),
                    _ => {}
                }
                if let Slot::Cond(r, _) = self.focus {
                    self.last_cond = r;
                }
                EditorOutcome::Keep
            }
            _ => match key.code {
                KeyCode::Down => {
                    self.step(true);
                    EditorOutcome::Keep
                }
                KeyCode::Up => {
                    self.step(false);
                    EditorOutcome::Keep
                }
                KeyCode::Enter => self.ok(),
                _ => EditorOutcome::Keep,
            },
        }
    }

    fn list_key(&mut self, key: KeyEvent) -> EditorOutcome {
        let last = self.filters.len().saturating_sub(1);
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.select(self.selected.saturating_sub(1)),
            KeyCode::Down | KeyCode::Char('j') => self.select((self.selected + 1).min(last)),
            KeyCode::PageUp => self.select(self.selected.saturating_sub(10)),
            KeyCode::PageDown => self.select((self.selected + 10).min(last)),
            KeyCode::Home | KeyCode::Char('g') => self.select(0),
            KeyCode::End | KeyCode::Char('G') => self.select(last),
            KeyCode::Char('n') | KeyCode::Insert => self.add(),
            KeyCode::Char('c') => self.copy(),
            KeyCode::Char('r') | KeyCode::F(2) => self.press_list_button(2),
            KeyCode::Char('d') | KeyCode::Delete => self.delete(),
            KeyCode::Enter => return self.ok(),
            _ => {}
        }
        EditorOutcome::Keep
    }

    fn button_key(&mut self, slot: Slot, key: KeyEvent) -> EditorOutcome {
        match key.code {
            KeyCode::Down => {
                self.step(true);
                return EditorOutcome::Keep;
            }
            KeyCode::Up => {
                self.step(false);
                return EditorOutcome::Keep;
            }
            _ => {}
        }
        let row = match slot {
            Slot::CondButtons => &mut self.cond_buttons,
            Slot::ListButtons => &mut self.list_buttons,
            _ => &mut self.main_buttons,
        };
        let Some(pressed) = row.handle_key(key) else {
            return EditorOutcome::Keep;
        };
        match (slot, pressed) {
            (Slot::CondButtons, 0) => self.add_condition(),
            (Slot::CondButtons, _) => self.remove_condition(None),
            (Slot::ListButtons, i) => self.press_list_button(i),
            (_, 0) => return self.ok(),
            _ => return EditorOutcome::Cancel,
        }
        EditorOutcome::Keep
    }

    /// Draw into the inner area of the editor's frame.
    pub(super) fn draw(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let h = area.height;
        if h < 8 {
            return;
        }
        // Bottom rows: note, list buttons, main buttons.
        let list_buttons_y = area.bottom() - 2;
        let main_buttons_y = area.bottom() - 1;
        let note_y = area.bottom() - 3;
        let body_h = h - 3;

        // Left: the filter list.
        let list_width = (area.width * 2 / 5).max(24).min(area.width);
        let list = Rect::new(area.x, area.y, list_width, body_h);
        frame.render_widget(
            Paragraph::new(Span::styled(
                "Filters",
                if self.focus == Slot::List {
                    theme.title
                } else {
                    theme.dim
                },
            )),
            Rect::new(list.x, list.y, list.width, 1),
        );
        let rows = usize::from(body_h.saturating_sub(1)).max(1);
        let start = self.selected.saturating_sub(rows - 1);
        let width = usize::from(list.width);
        let lines: Vec<Line> = self
            .filters
            .iter()
            .enumerate()
            .skip(start)
            .take(rows)
            .map(|(i, f)| {
                let tag = if Self::is_builtin(&f.name) {
                    " (built-in)"
                } else {
                    ""
                };
                let room = width.saturating_sub(2 + tag.chars().count());
                let mut name: String = f.name.chars().take(room).collect();
                if f.name.chars().count() > room && room > 0 {
                    name.pop();
                    name.push('…');
                }
                let marker = if i == self.selected { "> " } else { "  " };
                let style = if i == self.selected {
                    if self.focus == Slot::List {
                        theme.selection
                    } else {
                        theme.title
                    }
                } else {
                    ratatui::style::Style::new()
                };
                Line::from(vec![
                    Span::styled(format!("{marker}{name}"), style),
                    Span::styled(tag, theme.dim),
                ])
            })
            .collect();
        let lines = if lines.is_empty() {
            vec![Line::styled("  (no filters)", theme.dim)]
        } else {
            lines
        };
        frame.render_widget(
            Paragraph::new(lines),
            Rect::new(list.x, list.y + 1, list.width, body_h.saturating_sub(1)),
        );

        // Right: the selected filter.
        let rx = area.x + list_width + 2;
        let rw = area.right().saturating_sub(rx);
        let mut overlay: Option<(Slot, Rect)> = None;
        if let Some(w) = &self.w {
            let mut y = area.y;
            let field_x = rx + LABEL_WIDTH;
            let field_w = rw.saturating_sub(LABEL_WIDTH);
            for (slot, label, field) in [
                (Slot::Name, "Name", &w.name as &dyn Field),
                (Slot::AppliesTo, "Applies to", &w.applies_to),
                (Slot::Match, "Match", &w.match_mode),
                (Slot::Case, "Case", &w.case),
                (Slot::Scope, "Use on", &w.scope),
            ] {
                let focused = self.focus == slot;
                frame.render_widget(
                    Paragraph::new(Span::styled(
                        label,
                        if focused { theme.title } else { theme.dim },
                    )),
                    Rect::new(rx, y, LABEL_WIDTH, 1),
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
                Rect::new(rx, y, rw, 1),
            );
            y += 1;
            // Rows for conditions: up to the condition buttons.
            let cond_buttons_y = note_y.saturating_sub(1);
            let visible = usize::from(cond_buttons_y.saturating_sub(y)).max(1);
            let focus_row = match self.focus {
                Slot::Cond(r, _) => r,
                _ => self.last_cond,
            };
            let first = focus_row.saturating_sub(visible - 1);
            if w.conds.is_empty() {
                frame.render_widget(
                    Paragraph::new(Span::styled("No conditions: matches nothing", theme.dim)),
                    Rect::new(rx, y, rw, 1),
                );
            }
            let widths = [12u16, 17, rw.saturating_sub(31)];
            for (r, row) in w.conds.iter().enumerate().skip(first).take(visible) {
                let bad = row.condition().is_err();
                let mut x = rx;
                for (c, width) in widths.iter().enumerate() {
                    let slot = Slot::Cond(r, c);
                    let rect = Rect::new(x, y, *width, 1);
                    let focused = self.focus == slot;
                    row.col(c).draw(frame, rect, focused, theme);
                    if c == 2 && bad && !focused {
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
                Rect::new(rx, cond_buttons_y, rw, 1),
                self.focus == Slot::CondButtons,
                theme,
            );
        } else {
            frame.render_widget(
                Paragraph::new(Span::styled("Press n to add a filter.", theme.dim)),
                Rect::new(rx, area.y, rw, 1),
            );
        }

        let hint = match self.focus {
            Slot::List => Some("n new · c copy · r rename · d delete · Enter OK · Esc cancel"),
            Slot::Cond(..) => Some("Ctrl-d removes this condition"),
            _ => None,
        };
        let note = self
            .issues
            .first()
            .map(|i| (i.clone(), true))
            .or_else(|| self.note.clone())
            .or_else(|| hint.map(|h| (h.to_owned(), false)));
        if let Some((text, error)) = note {
            frame.render_widget(
                Paragraph::new(Span::styled(
                    text,
                    if error { theme.error } else { theme.dim },
                )),
                Rect::new(area.x, note_y, area.width, 1),
            );
        }
        self.list_buttons.draw(
            frame,
            Rect::new(area.x, list_buttons_y, area.width, 1),
            self.focus == Slot::ListButtons,
            theme,
        );
        self.main_buttons.draw(
            frame,
            Rect::new(area.x, main_buttons_y, area.width, 1),
            self.focus == Slot::MainButtons,
            theme,
        );
        if let Some((slot, rect)) = overlay
            && let Some(field) = self.field(slot)
        {
            field.draw_overlay(frame, rect, theme);
        }
    }
}
