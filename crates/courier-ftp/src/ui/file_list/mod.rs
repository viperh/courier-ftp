//! The file list pane (T53), used for both the local and the remote side: a
//! sortable, filterable, multi-select list with an address bar.
//!
//! Rendering is virtualised: only the visible rows are formatted, and sorting
//! and filtering run when the data changes, never while drawing. Directory
//! changes are requested with [`Action::ListDir`] and applied when the listing
//! arrives ([`FileList::listing_loaded`]); a failed listing leaves the pane in
//! the directory it was in.

mod format;
mod sort;

use std::collections::{HashMap, HashSet};

use courier_ftp_core::{
    backend::Listing,
    filters::{FilterEngine, QuickFilter},
    local::{display_native, local_to_remote},
    model::{Entry, EntryKind, RemotePath},
    settings::{Column, Settings, SizeFormat},
};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};
pub(crate) use sort::{SortKey, SortOrder};
use time::UtcOffset;
use tokio::sync::mpsc::UnboundedSender;

use super::{
    Side,
    dialog::{
        Checkbox, Completer, Field, Form, FormDialog, LocalPathCompleter, PathInput, prompt_text,
    },
    modal::Modal,
    panes::{block, spinner_frame},
    theme::Theme,
};
use crate::action::Action;

/// What the pane wants done besides changing itself.
pub(crate) enum Effect {
    Action(Action),
    Modal(Box<dyn Modal>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum History {
    Push,
    Back,
    Forward,
    Stay,
}

#[derive(Debug, Clone)]
struct Pending {
    dir: RemotePath,
    focus: Option<String>,
    history: History,
}

#[derive(Debug, Clone)]
struct Quick {
    text: String,
    editing: bool,
}

/// Display settings the list needs.
#[derive(Debug, Clone)]
struct Display {
    size_format: SizeFormat,
    separators: bool,
    date_format: String,
    time_format: String,
    offset: UtcOffset,
    columns: Vec<Column>,
    /// Width of a formatted modification time.
    date_width: usize,
}

#[derive(Debug, Clone, Copy, Default)]
struct Totals {
    files: usize,
    dirs: usize,
    bytes: u64,
}

/// Completes names from the current listing (remote side).
struct ListingCompleter {
    dir: String,
    names: Vec<(String, bool)>,
}

impl Completer for ListingCompleter {
    fn complete(&self, prefix: &str) -> Vec<String> {
        let base = if self.dir.ends_with('/') {
            self.dir.clone()
        } else {
            format!("{}/", self.dir)
        };
        let Some(partial) = prefix.strip_prefix(&base) else {
            return Vec::new();
        };
        self.names
            .iter()
            .filter(|(n, _)| n.starts_with(partial) && !partial.contains('/'))
            .map(|(n, dir)| format!("{base}{n}{}", if *dir { "/" } else { "" }))
            .collect()
    }
}

/// One side's file list.
pub(crate) struct FileList {
    pub(crate) side: Side,
    pub(crate) dir: Option<RemotePath>,
    entries: Vec<Entry>,
    /// Sorted, filtered indices into `entries`.
    view: Vec<usize>,
    /// Row index; row 0 is `..` when the directory has a parent.
    cursor: usize,
    scroll: usize,
    selected: HashSet<String>,
    /// Visual mode: the anchor row and the selection before it started.
    visual: Option<(usize, HashSet<String>)>,
    sort: SortOrder,
    show_hidden: bool,
    quick: Option<Quick>,
    filters: FilterEngine,
    pub(crate) busy: bool,
    error: Option<String>,
    pending: Option<Pending>,
    back: Vec<RemotePath>,
    forward: Vec<RemotePath>,
    remembered: HashMap<RemotePath, String>,
    address: Option<PathInput>,
    display: Display,
    totals: Totals,
    /// Name → index into `entries`, for the shown entries.
    index: HashMap<String, usize>,
    rows: usize,
    /// Remote side: the server shown in the title (`alice@host`), set while
    /// connecting and connected.
    server: Option<String>,
}

impl FileList {
    pub(crate) fn new(side: Side, settings: &Settings, filters: FilterEngine) -> Self {
        let ui = &settings.interface;
        Self {
            side,
            dir: None,
            entries: Vec::new(),
            view: Vec::new(),
            cursor: 0,
            scroll: 0,
            selected: HashSet::new(),
            visual: None,
            sort: SortOrder {
                dirs_first: ui.dirs_first,
                case_sensitive: ui.sort_case_sensitive,
                natural: ui.natural_sort,
                ..SortOrder::default()
            },
            show_hidden: match side {
                Side::Local => ui.show_hidden_local,
                Side::Remote => true,
            },
            quick: None,
            filters,
            busy: false,
            error: None,
            pending: None,
            back: Vec::new(),
            forward: Vec::new(),
            remembered: HashMap::new(),
            address: None,
            display: Display {
                size_format: ui.size_format,
                separators: ui.thousands_separator,
                date_format: ui.date_format.clone(),
                time_format: ui.time_format.clone(),
                offset: UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC),
                columns: match side {
                    Side::Local => ui.columns.local.clone(),
                    Side::Remote => ui.columns.remote.clone(),
                },
                date_width: format::date(
                    &courier_ftp_core::model::Timestamp::new(
                        time::macros::datetime!(2000-12-31 23:59:59 UTC),
                        courier_ftp_core::model::Precision::Second,
                    ),
                    &ui.date_format,
                    &ui.time_format,
                    UtcOffset::UTC,
                )
                .chars()
                .count(),
            },
            totals: Totals::default(),
            index: HashMap::new(),
            rows: 1,
            server: None,
        }
    }

    /// Remote side: a connection to `server` is being opened.
    pub(crate) fn connecting(&mut self, server: String) {
        self.disconnected(None);
        self.server = Some(server);
        self.busy = true;
    }

    /// Remote side: back to "not connected", with the reason when a
    /// connection failed.
    pub(crate) fn disconnected(&mut self, error: Option<String>) {
        self.dir = None;
        self.entries.clear();
        self.view.clear();
        self.index.clear();
        self.cursor = 0;
        self.scroll = 0;
        self.selected.clear();
        self.visual = None;
        self.quick = None;
        self.busy = false;
        self.error = error;
        self.pending = None;
        self.back.clear();
        self.forward.clear();
        self.remembered.clear();
        self.address = None;
        self.totals = Totals::default();
        self.server = None;
    }

    /// Use this offset for times instead of the local one (tests).
    #[cfg(test)]
    pub(crate) fn set_offset(&mut self, offset: UtcOffset) {
        self.display.offset = offset;
    }

    #[cfg(test)]
    pub(crate) fn columns(&self) -> &[Column] {
        &self.display.columns
    }

    pub(crate) fn is_typing(&self) -> bool {
        self.address.is_some() || self.quick.as_ref().is_some_and(|q| q.editing)
    }

    pub(crate) fn is_editing_address(&self) -> bool {
        self.address.is_some()
    }

    /// Whether filters or the quick filter hide entries (status bar, title).
    pub(crate) fn is_filtered(&self) -> bool {
        self.filters.is_active() || self.quick.as_ref().is_some_and(|q| !q.text.is_empty())
    }

    fn has_parent(&self) -> bool {
        self.dir.as_ref().is_some_and(|d| !d.is_root())
    }

    fn row_count(&self) -> usize {
        self.view.len() + usize::from(self.has_parent())
    }

    /// The entry at a row (`None` for `..`).
    fn entry_at(&self, row: usize) -> Option<&Entry> {
        let offset = usize::from(self.has_parent());
        row.checked_sub(offset)
            .and_then(|i| self.view.get(i))
            .map(|&i| &self.entries[i])
    }

    /// The entry under the cursor.
    pub(crate) fn current(&self) -> Option<&Entry> {
        self.entry_at(self.cursor)
    }

    /// The names of the selected entries, or the entry under the cursor.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "file operations use it from T62")
    )]
    pub(crate) fn targets(&self) -> Vec<String> {
        if self.selected.is_empty() {
            self.current()
                .map(|e| vec![e.name.clone()])
                .unwrap_or_default()
        } else {
            let mut v: Vec<String> = self.selected.iter().cloned().collect();
            v.sort();
            v
        }
    }

    /// Re-filter and re-sort, keeping the cursor on the same entry.
    fn rebuild(&mut self, focus: Option<String>) {
        let keep = focus.or_else(|| self.current().map(|e| e.name.clone()));
        let dir = self.dir.clone().unwrap_or_default();
        let quick = self.quick.as_ref().map(|q| QuickFilter::new(&q.text));
        self.view = (0..self.entries.len())
            .filter(|&i| {
                let e = &self.entries[i];
                if e.hidden && !self.show_hidden {
                    return false;
                }
                if quick.as_ref().is_some_and(|q| !q.keeps(&e.name)) {
                    return false;
                }
                let path = if dir.is_root() {
                    format!("/{}", e.name)
                } else {
                    format!("{dir}/{}", e.name)
                };
                !self.filters.excluded(e, &path)
            })
            .collect();
        let sort = self.sort;
        let entries = &self.entries;
        self.view
            .sort_by(|&a, &b| sort.compare(&entries[a], &entries[b]));
        let mut totals = Totals::default();
        for &i in &self.view {
            let e = &self.entries[i];
            if e.is_dir_like() {
                totals.dirs += 1;
            } else {
                totals.files += 1;
                totals.bytes += e.size.unwrap_or(0);
            }
        }
        self.totals = totals;
        self.index = self
            .view
            .iter()
            .map(|&i| (self.entries[i].name.clone(), i))
            .collect();
        let index = &self.index;
        self.selected.retain(|n| index.contains_key(n));
        // The remembered entry may be gone (filtered out, deleted): then the
        // first entry, not `..`, so typing a filter lands on a match.
        let first_entry = usize::from(self.has_parent() && !self.view.is_empty());
        self.cursor = match keep {
            Some(name) => self.row_of(&name).unwrap_or(first_entry),
            None => 0,
        }
        .min(self.row_count().saturating_sub(1));
    }

    fn row_of(&self, name: &str) -> Option<usize> {
        self.view
            .iter()
            .position(|&i| self.entries[i].name == name)
            .map(|p| p + usize::from(self.has_parent()))
    }

    /// Ask for a listing of `dir`; it is applied when it arrives.
    fn navigate(
        &mut self,
        dir: RemotePath,
        focus: Option<String>,
        history: History,
        force: bool,
    ) -> Option<Effect> {
        self.pending = Some(Pending {
            dir: dir.clone(),
            focus,
            history,
        });
        self.busy = true;
        Some(Effect::Action(Action::ListDir {
            side: self.side,
            dir,
            force,
        }))
    }

    /// A listing arrived (or failed). Returns an error to log, if any.
    pub(crate) fn listing_loaded(&mut self, result: &Result<Listing, String>) -> Option<Action> {
        self.busy = false;
        let pending = self.pending.take();
        match result {
            Ok(listing) => {
                let old = self.dir.clone();
                let same_dir = old.as_ref() == Some(&listing.dir);
                let previous = self.current().map(|e| e.name.clone());
                if let (Some(old), Some(entry)) = (&old, self.current()) {
                    self.remembered.insert(old.clone(), entry.name.clone());
                }
                let history = pending.as_ref().map_or(History::Stay, |p| p.history);
                if let Some(old) = old.filter(|_| !same_dir) {
                    match history {
                        History::Push => {
                            self.back.push(old);
                            self.forward.clear();
                        }
                        History::Back => self.forward.push(old),
                        History::Forward => self.back.push(old),
                        History::Stay => {}
                    }
                }
                let focus = pending
                    .and_then(|p| p.focus)
                    .or_else(|| self.remembered.get(&listing.dir).cloned());
                if !same_dir {
                    self.selected.clear();
                    self.visual = None;
                    self.quick = None;
                    self.scroll = 0;
                }
                self.dir = Some(listing.dir.clone());
                self.entries = listing.entries.clone();
                // The old view indexes the old entries.
                self.view.clear();
                self.error = None;
                self.rebuild(if same_dir { focus.or(previous) } else { focus });
                None
            }
            Err(e) => {
                let target = pending.map(|p| p.dir.to_string()).unwrap_or_default();
                self.error = Some(e.clone());
                Some(Action::Error(format!("{target}: {e}")))
            }
        }
    }

    fn move_cursor(&mut self, delta: isize) {
        let last = self.row_count().saturating_sub(1);
        self.cursor = self.cursor.saturating_add_signed(delta).min(last);
        self.extend_visual();
    }

    fn extend_visual(&mut self) {
        let Some((anchor, base)) = &self.visual else {
            return;
        };
        let (lo, hi) = (*anchor.min(&self.cursor), *anchor.max(&self.cursor));
        let mut selected = base.clone();
        for row in lo..=hi {
            if let Some(e) = self.entry_at(row) {
                selected.insert(e.name.clone());
            }
        }
        self.selected = selected;
    }

    fn select_matching(&mut self, pattern: &str, select: bool) {
        let q = QuickFilter::new(pattern);
        let names: Vec<String> = self
            .view
            .iter()
            .map(|&i| &self.entries[i])
            .filter(|e| q.keeps(&e.name))
            .map(|e| e.name.clone())
            .collect();
        for n in names {
            if select {
                self.selected.insert(n);
            } else {
                self.selected.remove(&n);
            }
        }
    }

    /// Apply an action meant for this pane.
    pub(crate) fn update(
        &mut self,
        action: &Action,
        tx: Option<&UnboundedSender<Action>>,
    ) -> Option<Effect> {
        let page = self.rows.max(1) as isize;
        match action {
            Action::CursorDown => self.move_cursor(1),
            Action::CursorUp => self.move_cursor(-1),
            Action::PageDown => self.move_cursor(page),
            Action::PageUp => self.move_cursor(-page),
            Action::HalfPageDown => self.move_cursor(page / 2),
            Action::HalfPageUp => self.move_cursor(-(page / 2)),
            Action::Top => {
                self.cursor = 0;
                self.extend_visual();
            }
            Action::Bottom => {
                self.cursor = self.row_count().saturating_sub(1);
                self.extend_visual();
            }
            Action::ParentDir => {
                let dir = self.dir.clone()?;
                let parent = dir.parent()?;
                return self.navigate(
                    parent,
                    dir.file_name().map(str::to_owned),
                    History::Push,
                    false,
                );
            }
            Action::Open => {
                let dir = self.dir.clone()?;
                match self.current() {
                    None if self.has_parent() => return self.update(&Action::ParentDir, tx),
                    None => {}
                    Some(e) if e.is_dir_like() => {
                        let target = dir.join(&e.name).ok()?;
                        return self.navigate(target, None, History::Push, false);
                    }
                    // A file: FileZilla's double-click transfers it (T62).
                    Some(_) => return Some(Effect::Action(Action::Copy)),
                }
            }
            Action::Refresh => {
                let dir = self.dir.clone()?;
                let focus = self.current().map(|e| e.name.clone());
                return self.navigate(dir, focus, History::Stay, true);
            }
            Action::HistoryBack => {
                let dir = self.back.pop()?;
                return self.navigate(dir, None, History::Back, false);
            }
            Action::HistoryForward => {
                let dir = self.forward.pop()?;
                return self.navigate(dir, None, History::Forward, false);
            }
            Action::ToggleSelect => {
                if let Some(name) = self.current().map(|e| e.name.clone())
                    && !self.selected.remove(&name)
                {
                    self.selected.insert(name);
                }
                self.move_cursor(1);
            }
            Action::VisualSelect => {
                self.visual = match self.visual {
                    Some(_) => None,
                    None => Some((self.cursor, self.selected.clone())),
                };
                self.extend_visual();
            }
            Action::SelectAll => {
                self.selected = self
                    .view
                    .iter()
                    .map(|&i| self.entries[i].name.clone())
                    .collect();
            }
            Action::InvertSelection => {
                let all: HashSet<String> = self
                    .view
                    .iter()
                    .map(|&i| self.entries[i].name.clone())
                    .collect();
                self.selected = all.difference(&self.selected).cloned().collect();
            }
            Action::SelectPattern | Action::DeselectPattern => {
                let select = matches!(action, Action::SelectPattern);
                let title = if select { "Select" } else { "Deselect" };
                let (modal, rx) = prompt_text(title, "Pattern (* and ? allowed)", "*");
                if let Some(tx) = tx.cloned() {
                    let side = self.side;
                    tokio::spawn(async move {
                        if let Ok(Some(pattern)) = rx.await {
                            let _ = tx.send(Action::ApplyPattern {
                                side,
                                pattern,
                                select,
                            });
                        }
                    });
                }
                return Some(Effect::Modal(modal));
            }
            Action::ApplyPattern {
                pattern, select, ..
            } => self.select_matching(pattern, *select),
            Action::SortName => self.resort(SortKey::Name),
            Action::SortSize => self.resort(SortKey::Size),
            Action::SortModified => self.resort(SortKey::Modified),
            Action::SortPermissions => self.resort(SortKey::Permissions),
            Action::SortOwner => self.resort(SortKey::Owner),
            Action::ToggleHidden => {
                self.show_hidden = !self.show_hidden;
                self.rebuild(None);
            }
            Action::QuickFilter => {
                self.quick = Some(Quick {
                    text: self.quick.take().map(|q| q.text).unwrap_or_default(),
                    editing: true,
                });
            }
            Action::EditAddress => {
                let dir = self.dir.clone()?;
                self.address = Some(self.address_input(&dir));
            }
            Action::ColumnMenu => return Some(Effect::Modal(self.column_menu(tx))),
            Action::SetColumns { columns, .. } => self.display.columns = columns.clone(),
            _ => {}
        }
        None
    }

    fn resort(&mut self, key: SortKey) {
        self.sort.by(key);
        self.rebuild(None);
    }

    fn address_input(&self, dir: &RemotePath) -> PathInput {
        match self.side {
            Side::Local => {
                let mut text = display_native(dir);
                if !text.ends_with(std::path::MAIN_SEPARATOR) {
                    text.push(std::path::MAIN_SEPARATOR);
                }
                PathInput::new("", Box::new(LocalPathCompleter)).with_value(&text)
            }
            Side::Remote => {
                let names = self
                    .entries
                    .iter()
                    .map(|e| (e.name.clone(), e.is_dir_like()))
                    .collect();
                let completer = ListingCompleter {
                    dir: dir.to_string(),
                    names,
                };
                let text = if dir.is_root() {
                    "/".to_owned()
                } else {
                    format!("{dir}/")
                };
                PathInput::new("", Box::new(completer)).with_value(&text)
            }
        }
    }

    fn column_menu(&self, tx: Option<&UnboundedSender<Action>>) -> Box<dyn Modal> {
        const ALL: [(Column, &str); 5] = [
            (Column::Size, "Size"),
            (Column::Type, "Type"),
            (Column::Modified, "Modified"),
            (Column::Permissions, "Permissions"),
            (Column::Owner, "Owner/Group"),
        ];
        let mut form = Form::new(&["OK", "Cancel"]);
        for (col, label) in ALL {
            form = form.field(
                label,
                Checkbox::new(label, self.display.columns.contains(&col)),
            );
        }
        let (dialog, rx) = FormDialog::new("Columns", 36, form, |v| {
            let mut cols = vec![Column::Name];
            cols.extend(ALL.iter().filter(|(_, l)| v.bool(l)).map(|(c, _)| *c));
            Ok(cols)
        });
        if let Some(tx) = tx.cloned() {
            let side = self.side;
            tokio::spawn(async move {
                if let Ok(Some(columns)) = rx.await {
                    let _ = tx.send(Action::SetColumns { side, columns });
                }
            });
        }
        Box::new(dialog)
    }

    /// Keys while typing the quick filter or the address. Returns `None` when
    /// the pane isn't typing.
    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> Option<Option<Effect>> {
        if let Some(input) = &mut self.address {
            return Some(match key.code {
                KeyCode::Esc => {
                    self.address = None;
                    None
                }
                KeyCode::Enter => {
                    let text = input.text();
                    self.address = None;
                    let target = match self.side {
                        Side::Local => local_to_remote(std::path::Path::new(text.trim())),
                        Side::Remote => {
                            Ok(self.dir.clone().unwrap_or_default().join_path(text.trim()))
                        }
                    };
                    match target {
                        Ok(dir) => self.navigate(dir, None, History::Push, false),
                        Err(e) => Some(Effect::Action(Action::Error(e.to_string()))),
                    }
                }
                _ => {
                    // Tab with nothing to complete is ignored: stay in the field.
                    input.handle_key(key);
                    None
                }
            });
        }
        let quick = self.quick.as_mut().filter(|q| q.editing)?;
        match key.code {
            KeyCode::Esc => {
                self.quick = None;
                self.rebuild(None);
            }
            KeyCode::Enter => {
                quick.editing = false;
                if quick.text.is_empty() {
                    self.quick = None;
                }
            }
            KeyCode::Backspace => {
                quick.text.pop();
                self.rebuild(None);
                self.skip_parent_row();
            }
            KeyCode::Char(c)
                if key
                    .modifiers
                    .difference(crossterm::event::KeyModifiers::SHIFT)
                    .is_empty() =>
            {
                quick.text.push(c);
                self.rebuild(None);
                self.skip_parent_row();
            }
            _ => {}
        }
        Some(None)
    }

    /// While filtering, the cursor belongs on a match rather than on `..`.
    fn skip_parent_row(&mut self) {
        if self.cursor == 0 && self.has_parent() && !self.view.is_empty() {
            self.cursor = 1;
        }
    }

    /// Paste into the address bar while it is open.
    pub(crate) fn handle_paste(&mut self, text: &str) {
        if let Some(input) = &mut self.address {
            input.handle_paste(text);
        }
    }

    fn title_place(&self) -> String {
        match (&self.dir, self.side) {
            (Some(d), Side::Local) => display_native(d),
            (Some(d), Side::Remote) => match &self.server {
                Some(server) => format!("{server} {d}"),
                None => d.to_string(),
            },
            (None, Side::Remote) => match &self.server {
                Some(server) => format!("connecting to {server}"),
                None => "not connected".to_owned(),
            },
            (None, Side::Local) => String::new(),
        }
    }

    pub(crate) fn draw(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        focused: bool,
        tick: u64,
        theme: &Theme,
    ) {
        let label = match self.side {
            Side::Local => "Local",
            Side::Remote => "Remote",
        };
        let mut title = vec![Span::styled(
            format!(" {label}: {} ", self.title_place()),
            theme.title,
        )];
        if self.is_filtered() {
            title.push(Span::styled("(filtered) ", theme.key_hint));
        }
        if self.busy {
            title.push(Span::raw(format!("{} ", spinner_frame(tick))));
        }
        let outer = block(Line::from(title), focused, theme);
        let inner = outer.inner(area);
        frame.render_widget(outer, area);
        if inner.height == 0 || inner.width == 0 {
            return;
        }

        if self.dir.is_none() && self.side == Side::Remote {
            let mut lines = if self.busy {
                vec![Line::raw("Connecting…")]
            } else {
                vec![
                    Line::raw("Not connected to any server."),
                    Line::styled("Ctrl-s: Site Manager · Ctrl-k: quickconnect", theme.dim),
                ]
            };
            if let Some(err) = &self.error {
                lines.push(Line::raw(""));
                lines.push(Line::styled(format!("⚠ {err}"), theme.error));
            }
            frame.render_widget(
                Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: false }),
                inner,
            );
            return;
        }

        let mut y = inner.y;
        let bottom = inner.bottom();
        // Address bar while editing.
        if let Some(input) = &self.address {
            input.draw(frame, Rect::new(inner.x, y, inner.width, 1), true, theme);
            y += 1;
        }
        if let Some(err) = &self.error
            && y < bottom
        {
            frame.render_widget(
                Paragraph::new(Line::styled(format!("⚠ {err}"), theme.error)),
                Rect::new(inner.x, y, inner.width, 1),
            );
            y += 1;
        }
        let footer_rows = u16::from(inner.height > 3);
        if y + footer_rows >= bottom {
            return;
        }
        let columns = self.fit_columns(usize::from(inner.width));
        // Header.
        frame.render_widget(
            Paragraph::new(self.header_line(&columns, usize::from(inner.width), theme)),
            Rect::new(inner.x, y, inner.width, 1),
        );
        y += 1;
        let list_rows = usize::from(bottom.saturating_sub(y + footer_rows));
        self.rows = list_rows.max(1);
        // Keep the cursor visible.
        if self.cursor < self.scroll {
            self.scroll = self.cursor;
        } else if self.cursor >= self.scroll + self.rows {
            self.scroll = self.cursor + 1 - self.rows;
        }
        let total_rows = self.row_count();
        let mut lines = Vec::with_capacity(list_rows);
        if total_rows == 0 || (total_rows == 1 && self.has_parent() && self.view.is_empty()) {
            if self.has_parent() {
                lines.push(self.row_line(0, &columns, usize::from(inner.width), focused, theme));
            }
            let empty = if self.is_filtered() {
                "(no matches)"
            } else {
                "(empty)"
            };
            lines.push(Line::styled(empty, theme.dim));
        } else {
            for row in self.scroll..(self.scroll + list_rows).min(total_rows) {
                lines.push(self.row_line(row, &columns, usize::from(inner.width), focused, theme));
            }
        }
        frame.render_widget(
            Paragraph::new(lines),
            Rect::new(inner.x, y, inner.width, list_rows as u16),
        );
        if footer_rows > 0 {
            frame.render_widget(
                Paragraph::new(self.footer_line(theme)),
                Rect::new(inner.x, bottom - 1, inner.width, 1),
            );
        }
    }

    /// The columns that fit in `width`, dropping the least important first
    /// (Owner, Type, Permissions, Modified, Size).
    fn fit_columns(&self, width: usize) -> Vec<Column> {
        const DROP_ORDER: [Column; 5] = [
            Column::Owner,
            Column::Type,
            Column::Permissions,
            Column::Modified,
            Column::Size,
        ];
        let mut cols: Vec<Column> = self
            .display
            .columns
            .iter()
            .copied()
            .filter(|c| *c != Column::Name)
            .collect();
        let min_name = 16;
        let needed = |cols: &[Column]| -> usize {
            cols.iter()
                .map(|c| self.column_width(*c) + 1)
                .sum::<usize>()
                + 2
                + min_name
        };
        for drop in DROP_ORDER {
            if needed(&cols) <= width {
                break;
            }
            cols.retain(|c| *c != drop);
        }
        cols
    }

    fn column_width(&self, c: Column) -> usize {
        match c {
            Column::Name => 0,
            Column::Size => match self.display.size_format {
                SizeFormat::Bytes => 14,
                _ => 9,
            },
            Column::Type => 14,
            Column::Modified => self.display.date_width,
            Column::Permissions => 10,
            Column::Owner => 15,
        }
    }

    fn header_line(&self, columns: &[Column], width: usize, theme: &Theme) -> Line<'static> {
        let arrow = |k: SortKey| {
            if self.sort.key == k {
                if self.sort.descending { "▼" } else { "▲" }
            } else {
                ""
            }
        };
        let name_width = self.name_width(columns, width);
        let mut s = format!("  {:<name_width$}", format!("Name{}", arrow(SortKey::Name)));
        for c in columns {
            let w = self.column_width(*c);
            let label = match c {
                Column::Size => format!("Size{}", arrow(SortKey::Size)),
                Column::Type => "Type".to_owned(),
                Column::Modified => format!("Modified{}", arrow(SortKey::Modified)),
                Column::Permissions => format!("Perms{}", arrow(SortKey::Permissions)),
                Column::Owner => format!("Owner{}", arrow(SortKey::Owner)),
                Column::Name => continue,
            };
            if *c == Column::Size {
                s.push_str(&format!(" {label:>w$}"));
            } else {
                s.push_str(&format!(" {label:<w$}"));
            }
        }
        Line::styled(s, theme.dim.add_modifier(Modifier::BOLD))
    }

    fn name_width(&self, columns: &[Column], width: usize) -> usize {
        let fixed: usize = columns.iter().map(|c| self.column_width(*c) + 1).sum();
        width.saturating_sub(fixed + 2).max(1)
    }

    fn row_line(
        &self,
        row: usize,
        columns: &[Column],
        width: usize,
        focused: bool,
        theme: &Theme,
    ) -> Line<'static> {
        let name_width = self.name_width(columns, width);
        let at_cursor = row == self.cursor;
        let cursor_style = if focused {
            theme.selection
        } else {
            Style::new().add_modifier(Modifier::UNDERLINED)
        };
        let Some(entry) = self.entry_at(row) else {
            let style = if at_cursor {
                cursor_style
            } else {
                Style::new()
            };
            return Line::styled(
                format!("  {:<width$}", "..", width = width.saturating_sub(2)),
                style,
            );
        };
        let selected = self.selected.contains(&entry.name);
        let mut base = if entry.is_dir_like() {
            theme.dir
        } else if entry.hidden {
            theme.dim
        } else {
            Style::new()
        };
        if selected {
            base = base.patch(theme.key_hint).add_modifier(Modifier::BOLD);
        }
        if at_cursor {
            base = base.patch(cursor_style);
        }
        let mut name = entry.name.clone();
        if entry.is_dir_like() {
            name.push('/');
        }
        let link = match &entry.kind {
            EntryKind::Symlink {
                target: Some(t), ..
            } => format!(" → {t}"),
            _ => String::new(),
        };
        let marker = if selected { "* " } else { "  " };
        let mut spans = vec![Span::styled(marker.to_owned(), base)];
        let name_len = name.chars().count();
        if name_len >= name_width {
            let cut: String = name.chars().take(name_width.saturating_sub(1)).collect();
            spans.push(Span::styled(format!("{cut}…"), base));
        } else {
            spans.push(Span::styled(name, base));
            let room = name_width - name_len;
            let link: String = link.chars().take(room).collect();
            let pad = room - link.chars().count();
            spans.push(Span::styled(link, base.patch(theme.dim)));
            spans.push(Span::styled(" ".repeat(pad), base));
        }
        for c in columns {
            let w = self.column_width(*c);
            let cell = match c {
                Column::Size => {
                    let s = if entry.is_dir_like() {
                        String::new()
                    } else {
                        entry
                            .size
                            .map(|n| {
                                format::size(n, self.display.size_format, self.display.separators)
                            })
                            .unwrap_or_default()
                    };
                    format!(" {s:>w$}")
                }
                Column::Type => format!(" {:<w$.w$}", format::kind(entry)),
                Column::Modified => {
                    let s = entry
                        .modified
                        .as_ref()
                        .map(|t| {
                            format::date(
                                t,
                                &self.display.date_format,
                                &self.display.time_format,
                                self.display.offset,
                            )
                        })
                        .unwrap_or_default();
                    format!(" {s:<w$.w$}")
                }
                Column::Permissions => {
                    let s = entry
                        .permissions
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_default();
                    format!(" {s:<w$.w$}")
                }
                Column::Owner => {
                    let s = match (&entry.owner, &entry.group) {
                        (Some(o), Some(g)) => format!("{o} {g}"),
                        (Some(o), None) => o.clone(),
                        _ => String::new(),
                    };
                    format!(" {s:<w$.w$}")
                }
                Column::Name => continue,
            };
            spans.push(Span::styled(
                cell,
                if at_cursor {
                    base
                } else {
                    base.remove_modifier(Modifier::BOLD)
                },
            ));
        }
        Line::from(spans)
    }

    fn footer_line(&self, theme: &Theme) -> Line<'static> {
        if let Some(q) = &self.quick
            && q.editing
        {
            return Line::styled(format!("/{}▏", q.text), theme.key_hint);
        }
        let plural =
            |n: usize, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
        let size = |b: u64| format::size(b, self.display.size_format, self.display.separators);
        let text = if self.selected.is_empty() {
            let t = self.totals;
            format!(
                "{} and {}. Total size: {}",
                plural(t.files, "file", "files"),
                plural(t.dirs, "directory", "directories"),
                size(t.bytes)
            )
        } else {
            let (mut files, mut dirs, mut bytes) = (0, 0, 0);
            for e in self
                .selected
                .iter()
                .filter_map(|n| self.index.get(n))
                .map(|&i| &self.entries[i])
            {
                if e.is_dir_like() {
                    dirs += 1;
                } else {
                    files += 1;
                    bytes += e.size.unwrap_or(0);
                }
            }
            format!(
                "Selected {} and {}. Total size: {}",
                plural(files, "file", "files"),
                plural(dirs, "directory", "directories"),
                size(bytes)
            )
        };
        let mut spans = vec![Span::styled(text, theme.dim)];
        if let Some(q) = &self.quick {
            spans.push(Span::styled(
                format!("  filter: {}", q.text),
                theme.key_hint,
            ));
        }
        if self.visual.is_some() {
            spans.push(Span::styled("  -- VISUAL --", theme.key_hint));
        }
        Line::from(spans)
    }
}

#[cfg(test)]
mod tests;
