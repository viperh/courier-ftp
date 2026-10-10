//! Filters UI (T67): FileZilla's "Directory listing filters" dialog and the
//! filter editor.
//!
//! The dialog works on a copy of the `filters` settings. *Apply* and *OK*
//! send the copy as [`Action::SetFilters`]: the screen re-filters both panes
//! at once (the status bar indicator follows) and the app saves the settings
//! file (T05 `save_user`). *Cancel* drops what wasn't applied.
//!
//! - Two checklists, *Local filters* and *Remote filters*, enable each
//!   filter per side in the active filter set. A filter limited to one side
//!   shows `[-]` on the other.
//! - The filter set dropdown switches sets; *Save as…* copies the current
//!   set under a new name, *Delete* removes it (not "Default").
//! - *Edit filter rules…* opens the [`editor`] in the same dialog; renaming
//!   a filter there renames it in every set, deleting it removes it.
//! - "Apply filters to transfers" (`filters.apply_to_transfers`, T43):
//!   recursive operations skip filtered entries.

mod editor;
#[cfg(test)]
mod tests;

use std::collections::HashMap;

use courier_ftp_core::filters::{DEFAULT_SET, FilterSet, FilterSettings, Side};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};
use tokio::sync::mpsc::UnboundedSender;

use self::editor::{EditorOutcome, FilterEditor};
use super::{
    dialog::{ButtonRow, Checkbox, Field, FieldOutcome, FieldValue, Select, TextInput},
    modal::{Modal, ModalOutcome},
    theme::Theme,
};
use crate::{action::Action, ui::dialog::dialog_frame};

/// Inner width of the dialog.
const WIDTH: u16 = 74;
/// Filter rows shown before the checklists scroll.
const MAX_ROWS: usize = 12;

const BUTTONS: [&str; 5] = ["OK", "Apply", "Edit filter rules…", "Toggle all", "Cancel"];
const SET_BUTTONS: [&str; 2] = ["Save as…", "Delete"];

/// A focusable place in the dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Slot {
    Set,
    SetButtons,
    Column(Side),
    Transfers,
    Buttons,
}

const SLOTS: [Slot; 6] = [
    Slot::Set,
    Slot::SetButtons,
    Slot::Column(Side::Local),
    Slot::Column(Side::Remote),
    Slot::Transfers,
    Slot::Buttons,
];

/// What is shown over the checklists.
enum Sub {
    /// The filter editor.
    Editor(Box<FilterEditor>),
    /// Typing the name for *Save as…*.
    SaveSet(TextInput),
}

/// The "Directory listing filters" dialog.
pub(crate) struct FiltersDialog {
    work: FilterSettings,
    set: Select,
    set_buttons: ButtonRow,
    /// Cursor row of each checklist.
    cursor: [usize; 2],
    transfers: Checkbox,
    buttons: ButtonRow,
    focus: Slot,
    sub: Option<Sub>,
    /// A message for the user (`true`: an error).
    note: Option<(String, bool)>,
    tx: Option<UnboundedSender<Action>>,
}

fn col(side: Side) -> usize {
    match side {
        Side::Local => 0,
        Side::Remote => 1,
    }
}

impl FiltersDialog {
    /// A dialog over `settings`; the result goes to `tx` as
    /// [`Action::SetFilters`].
    pub(crate) fn new(settings: &FilterSettings, tx: Option<UnboundedSender<Action>>) -> Self {
        let mut work = settings.clone();
        if work.sets.is_empty() {
            work.sets.push(FilterSet {
                name: DEFAULT_SET.to_owned(),
                enabled_local: Vec::new(),
                enabled_remote: Vec::new(),
            });
        }
        if !work.sets.iter().any(|s| s.name == work.active_set) {
            work.active_set = work.sets[0].name.clone();
        }
        let transfers = Checkbox::new("", work.apply_to_transfers);
        let mut dialog = Self {
            set: Select::new("", Vec::new(), 0),
            work,
            set_buttons: ButtonRow::new(&SET_BUTTONS, 0),
            cursor: [0, 0],
            transfers,
            buttons: ButtonRow::new(&BUTTONS, 0),
            focus: Slot::Column(Side::Local),
            sub: None,
            note: None,
            tx,
        };
        dialog.refresh_sets();
        dialog
    }

    /// The settings as edited so far.
    #[cfg(test)]
    pub(crate) fn settings(&self) -> &FilterSettings {
        &self.work
    }

    #[cfg(test)]
    pub(crate) fn focus(&self) -> Slot {
        self.focus
    }

    #[cfg(test)]
    fn editor(&self) -> Option<&FilterEditor> {
        match &self.sub {
            Some(Sub::Editor(e)) => Some(e),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn note(&self) -> Option<&str> {
        self.note.as_ref().map(|(n, _)| n.as_str())
    }

    /// Rebuild the set dropdown from the sets.
    fn refresh_sets(&mut self) {
        let names: Vec<String> = self.work.sets.iter().map(|s| s.name.clone()).collect();
        let current = names
            .iter()
            .position(|n| *n == self.work.active_set)
            .unwrap_or(0);
        self.set = Select::new("", names, current);
    }

    fn active_mut(&mut self) -> Option<&mut FilterSet> {
        let name = self.work.active_set.clone();
        self.work.sets.iter_mut().find(|s| s.name == name)
    }

    fn enabled(&self, side: Side, name: &str) -> bool {
        self.work.active().is_some_and(|s| {
            match side {
                Side::Local => &s.enabled_local,
                Side::Remote => &s.enabled_remote,
            }
            .iter()
            .any(|n| n == name)
        })
    }

    fn set_enabled(&mut self, side: Side, name: &str, on: bool) {
        let Some(set) = self.active_mut() else {
            return;
        };
        let list = match side {
            Side::Local => &mut set.enabled_local,
            Side::Remote => &mut set.enabled_remote,
        };
        list.retain(|n| n != name);
        if on {
            list.push(name.to_owned());
        }
    }

    /// Space in a checklist.
    fn toggle(&mut self, side: Side) {
        let Some(f) = self.work.filters.get(self.cursor[col(side)]) else {
            return;
        };
        let name = f.name.clone();
        if !f.scope.allows(side) {
            let only = if side == Side::Local {
                "remote"
            } else {
                "local"
            };
            self.note = Some((format!("“{name}” is for {only} files only."), true));
            return;
        }
        let on = !self.enabled(side, &name);
        self.set_enabled(side, &name, on);
        self.note = None;
    }

    /// *Toggle all*: everything on (both sides, where allowed), or off when
    /// it all is on already.
    fn toggle_all(&mut self) {
        let allowed: Vec<(Side, String)> = self
            .work
            .filters
            .iter()
            .flat_map(|f| {
                [Side::Local, Side::Remote]
                    .into_iter()
                    .filter(|s| f.scope.allows(*s))
                    .map(|s| (s, f.name.clone()))
            })
            .collect();
        let all_on = allowed.iter().all(|(s, n)| self.enabled(*s, n));
        for (side, name) in allowed {
            self.set_enabled(side, &name, !all_on);
        }
        self.note = None;
    }

    fn save_set(&mut self, name: &str) -> Result<(), String> {
        let name = name.trim();
        if name.is_empty() {
            return Err("Enter a name for the filter set.".into());
        }
        if self.work.sets.iter().any(|s| s.name == name) {
            return Err(format!("There is already a filter set called “{name}”."));
        }
        let mut set = self.work.active().cloned().unwrap_or(FilterSet {
            name: String::new(),
            enabled_local: Vec::new(),
            enabled_remote: Vec::new(),
        });
        set.name = name.to_owned();
        self.work.sets.push(set);
        self.work.active_set = name.to_owned();
        self.refresh_sets();
        self.note = Some((format!("Saved filter set “{name}”"), false));
        Ok(())
    }

    fn delete_set(&mut self) {
        let name = self.work.active_set.clone();
        if name == DEFAULT_SET || self.work.sets.len() <= 1 {
            self.note = Some((
                format!("The “{DEFAULT_SET}” filter set can't be deleted."),
                true,
            ));
            return;
        }
        self.work.sets.retain(|s| s.name != name);
        self.work.active_set = self
            .work
            .sets
            .iter()
            .find(|s| s.name == DEFAULT_SET)
            .unwrap_or(&self.work.sets[0])
            .name
            .clone();
        self.refresh_sets();
        self.note = Some((format!("Deleted filter set “{name}”"), false));
    }

    /// The editor's OK: take its filters, renaming and dropping set
    /// entries to match.
    fn take_filters(
        &mut self,
        filters: Vec<courier_ftp_core::filters::Filter>,
        renames: Vec<(String, String)>,
    ) {
        let renames: HashMap<String, String> = renames.into_iter().collect();
        let exists = |n: &str| filters.iter().any(|f| f.name == n);
        let renamed: Vec<String> = renames.values().cloned().collect();
        let map = |list: &mut Vec<String>| {
            let mut out: Vec<String> = Vec::new();
            for n in list.iter() {
                let new = match renames.get(n) {
                    Some(new) => new.clone(),
                    // A name now used by a renamed filter meant the old one.
                    None if renamed.contains(n) => continue,
                    None => n.clone(),
                };
                if exists(&new) && !out.contains(&new) {
                    out.push(new);
                }
            }
            *list = out;
        };
        for set in &mut self.work.sets {
            map(&mut set.enabled_local);
            map(&mut set.enabled_remote);
        }
        self.work.filters = filters;
        let last = self.work.filters.len().saturating_sub(1);
        self.cursor = [self.cursor[0].min(last), self.cursor[1].min(last)];
    }

    /// Check the filters before applying them.
    fn validate(&self) -> Result<(), String> {
        for f in &self.work.filters {
            if let Err(e) = f.validate() {
                return Err(format!("{e} (fix it under Edit filter rules…)"));
            }
        }
        Ok(())
    }

    /// Send the filters to the screen; `false` (with a note) when invalid.
    fn apply(&mut self) -> bool {
        if let Err(e) = self.validate() {
            self.note = Some((e, true));
            return false;
        }
        self.work.apply_to_transfers = matches!(self.transfers.value(), FieldValue::Bool(true));
        if let Some(tx) = &self.tx {
            let _ = tx.send(Action::SetFilters(Box::new(self.work.clone())));
        }
        self.note = Some(("Filters applied".into(), false));
        true
    }

    fn step(&mut self, forward: bool) {
        let n = SLOTS.len();
        let i = SLOTS.iter().position(|s| *s == self.focus).unwrap_or(0);
        self.focus = if forward {
            SLOTS[(i + 1) % n]
        } else {
            SLOTS[(i + n - 1) % n]
        };
    }

    fn press(&mut self, button: usize) -> ModalOutcome {
        match button {
            0 => {
                if self.apply() {
                    return ModalOutcome::Close;
                }
            }
            1 => {
                self.apply();
            }
            2 => {
                self.note = None;
                self.sub = Some(Sub::Editor(Box::new(FilterEditor::new(&self.work.filters))));
            }
            3 => self.toggle_all(),
            _ => return ModalOutcome::Close,
        }
        ModalOutcome::Keep
    }

    fn column_key(&mut self, side: Side, key: KeyEvent) -> ModalOutcome {
        let c = col(side);
        let last = self.work.filters.len().saturating_sub(1);
        match key.code {
            KeyCode::Up | KeyCode::Char('k') if self.cursor[c] == 0 => self.step(false),
            KeyCode::Up | KeyCode::Char('k') => self.cursor[c] -= 1,
            KeyCode::Down | KeyCode::Char('j') if self.cursor[c] >= last => self.step(true),
            KeyCode::Down | KeyCode::Char('j') => self.cursor[c] += 1,
            KeyCode::Home => self.cursor[c] = 0,
            KeyCode::End => self.cursor[c] = last,
            KeyCode::Left | KeyCode::Right | KeyCode::Char('h') | KeyCode::Char('l') => {
                let other = side.other();
                self.cursor[col(other)] = self.cursor[c];
                self.focus = Slot::Column(other);
            }
            KeyCode::Char(' ') => self.toggle(side),
            KeyCode::Enter => return self.press(0),
            _ => {}
        }
        ModalOutcome::Keep
    }

    fn sub_key(&mut self, key: KeyEvent) -> ModalOutcome {
        match self.sub.as_mut() {
            Some(Sub::Editor(editor)) => match editor.handle_key(key) {
                EditorOutcome::Keep => {}
                EditorOutcome::Cancel => self.sub = None,
                EditorOutcome::Done { filters, renames } => {
                    self.sub = None;
                    self.take_filters(filters, renames);
                    self.note = Some((
                        "Filter rules changed; Apply or OK to use them".into(),
                        false,
                    ));
                }
            },
            Some(Sub::SaveSet(input)) => match key.code {
                KeyCode::Esc => self.sub = None,
                KeyCode::Enter => {
                    let name = input.text();
                    match self.save_set(&name) {
                        Ok(()) => self.sub = None,
                        Err(e) => self.note = Some((e, true)),
                    }
                }
                _ => {
                    input.handle_key(key);
                }
            },
            None => {}
        }
        ModalOutcome::Keep
    }

    fn draw_main(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let mut y = area.y;
        let label = |focused: bool| if focused { theme.title } else { theme.dim };
        frame.render_widget(
            Paragraph::new(Span::styled("Filter set", label(self.focus == Slot::Set))),
            Rect::new(area.x, y, 12, 1),
        );
        let set_rect = Rect::new(area.x + 12, y, 28, 1);
        self.set
            .draw(frame, set_rect, self.focus == Slot::Set, theme);
        self.set_buttons.draw(
            frame,
            Rect::new(area.x + 40, y, area.width.saturating_sub(40), 1),
            self.focus == Slot::SetButtons,
            theme,
        );
        y += 2;
        let half = area.width / 2;
        for (side, x, title) in [
            (Side::Local, area.x, "Local filters"),
            (Side::Remote, area.x + half, "Remote filters"),
        ] {
            let focused = self.focus == Slot::Column(side);
            frame.render_widget(
                Paragraph::new(Span::styled(title, label(focused))),
                Rect::new(x, y, half, 1),
            );
            let rows = self.rows();
            let cursor = self.cursor[col(side)];
            let start = cursor.saturating_sub(rows.saturating_sub(1));
            let width = usize::from(half.saturating_sub(1));
            let lines: Vec<Line> = self
                .work
                .filters
                .iter()
                .enumerate()
                .skip(start)
                .take(rows)
                .map(|(i, f)| {
                    let allowed = f.scope.allows(side);
                    let mark = if !allowed {
                        "[-]"
                    } else if self.enabled(side, &f.name) {
                        "[x]"
                    } else {
                        "[ ]"
                    };
                    let text: String = format!("{mark} {}", f.name).chars().take(width).collect();
                    let style = if focused && i == cursor {
                        theme.selection
                    } else if !allowed {
                        theme.dim
                    } else {
                        ratatui::style::Style::new()
                    };
                    Line::styled(text, style)
                })
                .collect();
            frame.render_widget(
                Paragraph::new(lines),
                Rect::new(
                    x,
                    y + 1,
                    half.saturating_sub(1),
                    u16::try_from(rows).unwrap_or(1),
                ),
            );
        }
        y += 1 + u16::try_from(self.rows()).unwrap_or(1) + 1;
        let focused = self.focus == Slot::Transfers;
        self.transfers
            .draw(frame, Rect::new(area.x, y, 3, 1), focused, theme);
        frame.render_widget(
            Paragraph::new(Span::styled(
                "Apply filters to transfers: recursive operations skip filtered entries",
                label(focused),
            )),
            Rect::new(area.x + 4, y, area.width.saturating_sub(4), 1),
        );
        y += 2;
        self.buttons.draw(
            frame,
            Rect::new(area.x, y, area.width, 1),
            self.focus == Slot::Buttons,
            theme,
        );
        y += 1;
        if let Some(Sub::SaveSet(input)) = &self.sub {
            frame.render_widget(
                Paragraph::new("Name of the new filter set:"),
                Rect::new(area.x, y, 28, 1),
            );
            input.draw(
                frame,
                Rect::new(area.x + 28, y, area.width.saturating_sub(28), 1),
                true,
                theme,
            );
            y += 1;
        }
        if let Some((text, error)) = &self.note {
            frame.render_widget(
                Paragraph::new(Span::styled(
                    text.clone(),
                    if *error { theme.error } else { theme.dim },
                )),
                Rect::new(area.x, y, area.width, 1),
            );
        }
        if self.focus == Slot::Set && self.sub.is_none() {
            self.set.draw_overlay(frame, set_rect, theme);
        }
    }

    fn rows(&self) -> usize {
        self.work.filters.len().clamp(1, MAX_ROWS)
    }

    fn height(&self) -> u16 {
        // Set row, blank, header, rows, blank, transfers, blank, buttons,
        // (new set name,) note.
        let naming = matches!(self.sub, Some(Sub::SaveSet(_)));
        u16::try_from(self.rows()).unwrap_or(1) + 8 + u16::from(naming)
    }
}

impl Modal for FiltersDialog {
    fn draw(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        if let Some(Sub::Editor(editor)) = &self.sub {
            let height = editor::HEIGHT.min(area.height.saturating_sub(2));
            if let Some(inner) = dialog_frame(
                frame,
                area,
                "Filter rules",
                editor::width(area.width),
                height,
                theme,
            ) {
                editor.draw(frame, inner, theme);
            }
            return;
        }
        if let Some(inner) = dialog_frame(
            frame,
            area,
            "Directory listing filters",
            WIDTH,
            self.height(),
            theme,
        ) {
            self.draw_main(frame, inner, theme);
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> ModalOutcome {
        if self.sub.is_some() {
            return self.sub_key(key);
        }
        // An open dropdown takes every key.
        if self.focus == Slot::Set {
            let capturing = self.set.is_capturing();
            let before = self.set.selected();
            if self.set.handle_key(key) == FieldOutcome::Consumed || capturing {
                if self.set.selected() != before
                    && let Some(set) = self.work.sets.get(self.set.selected())
                {
                    self.work.active_set = set.name.clone();
                    self.note = None;
                }
                return ModalOutcome::Keep;
            }
        }
        if self.focus == Slot::Transfers && self.transfers.handle_key(key) == FieldOutcome::Consumed
        {
            return ModalOutcome::Keep;
        }
        match key.code {
            KeyCode::Esc => return ModalOutcome::Close,
            KeyCode::Tab => {
                self.step(true);
                return ModalOutcome::Keep;
            }
            KeyCode::BackTab => {
                self.step(false);
                return ModalOutcome::Keep;
            }
            _ => {}
        }
        match self.focus {
            Slot::Column(side) => self.column_key(side, key),
            Slot::SetButtons | Slot::Buttons => {
                match key.code {
                    KeyCode::Up => self.step(false),
                    KeyCode::Down => self.step(true),
                    _ => {}
                }
                let pressed = if self.focus == Slot::SetButtons {
                    self.set_buttons.handle_key(key).map(|b| (true, b))
                } else {
                    self.buttons.handle_key(key).map(|b| (false, b))
                };
                match pressed {
                    Some((true, 0)) => {
                        self.note = None;
                        self.sub = Some(Sub::SaveSet(TextInput::new("")));
                        ModalOutcome::Keep
                    }
                    Some((true, _)) => {
                        self.delete_set();
                        ModalOutcome::Keep
                    }
                    Some((false, b)) => self.press(b),
                    None => ModalOutcome::Keep,
                }
            }
            Slot::Set | Slot::Transfers => {
                match key.code {
                    KeyCode::Up => self.step(false),
                    KeyCode::Down => self.step(true),
                    KeyCode::Enter => return self.press(0),
                    _ => {}
                }
                ModalOutcome::Keep
            }
        }
    }

    fn handle_paste(&mut self, text: &str) {
        match self.sub.as_mut() {
            Some(Sub::Editor(editor)) => editor.handle_paste(text),
            Some(Sub::SaveSet(input)) => input.handle_paste(text),
            None => {}
        }
    }
}
