//! The bookmarks menu (T64, `Ctrl-b`): the global bookmarks and the
//! connected site's bookmarks in two sections, filtered by a fuzzy search.
//! `Enter` applies the selected bookmark, `a` adds the directories shown now,
//! `e` edits, `x` deletes, `J`/`K` move a bookmark within its section.
//!
//! Like the Site Manager (T59) the menu is owned by the
//! [`MainScreen`](super::MainScreen), asks the app for every change with a
//! [`BookmarkOp`] ([`BookmarksMenu::take_requests`]) and gets the result back
//! ([`BookmarksMenu::apply_reply`]); its add/edit form and the delete
//! confirmation are standard dialogs on a private overlay. Keys are fixed,
//! like the dialogs'.

#[cfg(test)]
mod tests;

use courier_ftp_core::{
    model::{LocalPath, RemotePath, item::ItemId},
    sites::{Bookmark, BookmarkTarget, SiteError},
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
    dialog::{
        Checkbox, Form, FormDialog, LocalPathCompleter, PathInput, RadioGroup, TextInput, confirm,
        dialog_frame_styled,
    },
    modal::{Modal, ModalOutcome},
    site_manager::score,
    theme::Theme,
};
use crate::bookmarks::{BookmarkOp, BookmarkOutcome, BookmarksReply};

/// Keys of the menu, shown at the bottom.
pub(crate) const HINTS: &str =
    "Enter go · a add · e edit · x delete · J/K move · / search · Esc close";

/// Shown in the site section of a quickconnect session.
pub(crate) const QUICKCONNECT_NOTE: &str = "Save this connection as a site to use site bookmarks";

/// Shown in the site section when nothing is connected.
pub(crate) const NOT_CONNECTED_NOTE: &str = "Connect to a saved site to use its bookmarks";

/// What the menu knows about the main window when it opens.
#[derive(Debug, Clone, Default)]
pub(crate) struct MenuContext {
    /// The saved site the remote pane is connected to: id and name.
    pub(crate) site: Option<(ItemId, String)>,
    /// Connected through quickconnect: no site bookmarks.
    pub(crate) quickconnect: bool,
    /// The directories shown now (native local path, remote path), which
    /// "add" fills in.
    pub(crate) local_dir: Option<String>,
    pub(crate) remote_dir: Option<String>,
}

/// One row of the list.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Row {
    Header(String),
    Note(String),
    Item(ItemId),
}

type Then = Box<dyn FnOnce(&mut BookmarksMenu) + Send>;

/// A dialog of the menu and what to do with its answer.
struct Overlay {
    modal: Box<dyn Modal>,
    then: Then,
}

/// The bookmarks menu. See the module docs.
pub(crate) struct BookmarksMenu {
    ctx: MenuContext,
    /// Every bookmark; `None` while loading.
    list: Option<Vec<Bookmark>>,
    /// The vault is locked: only a message.
    locked: bool,
    /// The vault was just unlocked and the sites are still loading: the
    /// bookmarks are read once they are ([`BookmarksMenu::sites_ready`]).
    waiting: bool,
    selected: Option<ItemId>,
    query: String,
    /// Typing the search.
    searching: bool,
    overlay: Option<Overlay>,
    busy: bool,
    /// The last result (text, is an error), shown instead of the hints.
    message: Option<(String, bool)>,
    requests: Vec<BookmarkOp>,
    /// The bookmark to apply once the menu closed.
    apply: Option<BookmarkTarget>,
    unlock_requested: bool,
    closed: bool,
}

impl BookmarksMenu {
    /// The menu, loading the bookmarks (the first [`BookmarkOp::Load`] is
    /// already requested).
    pub(crate) fn new(ctx: MenuContext) -> Self {
        let mut menu = Self {
            ctx,
            list: None,
            locked: false,
            waiting: false,
            selected: None,
            query: String::new(),
            searching: false,
            overlay: None,
            busy: false,
            message: None,
            requests: Vec::new(),
            apply: None,
            unlock_requested: false,
            closed: false,
        };
        menu.request(BookmarkOp::Load);
        menu
    }

    /// The vault is locked: bookmarks are hidden; `Enter` unlocks.
    pub(crate) fn locked(ctx: MenuContext) -> Self {
        let mut menu = Self::new(ctx);
        menu.requests.clear();
        menu.busy = false;
        menu.locked = true;
        menu
    }

    #[cfg(test)]
    pub(crate) fn is_locked(&self) -> bool {
        self.locked
    }

    /// The menu, waiting for the sites to load before reading the
    /// bookmarks (opened right after unlocking).
    pub(crate) fn waiting(ctx: MenuContext) -> Self {
        let mut menu = Self::new(ctx);
        menu.requests.clear();
        menu.busy = false;
        menu.waiting = true;
        menu
    }

    /// The vault was unlocked: wait for the sites.
    pub(crate) fn unlocked(&mut self) {
        if self.locked {
            self.locked = false;
            self.waiting = true;
        }
    }

    /// The sites (and with them the vault's bookmarks) are loaded: read the
    /// bookmarks if the menu is waiting for them.
    pub(crate) fn sites_ready(&mut self) {
        if self.waiting {
            self.waiting = false;
            self.request(BookmarkOp::Load);
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed
    }

    #[cfg(test)]
    pub(crate) fn is_busy(&self) -> bool {
        self.busy
    }

    /// The operations asked for since the last call.
    pub(crate) fn take_requests(&mut self) -> Vec<BookmarkOp> {
        std::mem::take(&mut self.requests)
    }

    /// The bookmark chosen with `Enter` (once).
    pub(crate) fn take_apply(&mut self) -> Option<BookmarkTarget> {
        self.apply.take()
    }

    /// Whether the user asked to unlock the vault (once).
    pub(crate) fn take_unlock_request(&mut self) -> bool {
        std::mem::take(&mut self.unlock_requested)
    }

    #[cfg(test)]
    pub(crate) fn selected(&self) -> Option<ItemId> {
        self.selected
    }

    #[cfg(test)]
    pub(crate) fn has_overlay(&self) -> bool {
        self.overlay.is_some()
    }

    fn request(&mut self, op: BookmarkOp) {
        self.busy = true;
        self.requests.push(op);
    }

    fn overlay<T: Send + 'static>(
        &mut self,
        modal: Box<dyn Modal>,
        rx: oneshot::Receiver<T>,
        then: impl FnOnce(&mut Self, T) + Send + 'static,
    ) {
        self.overlay = Some(Overlay {
            modal,
            then: Box::new(move |menu| {
                let mut rx = rx;
                if let Ok(answer) = rx.try_recv() {
                    then(menu, answer);
                }
            }),
        });
    }

    fn info(&mut self, text: impl Into<String>) {
        self.message = Some((text.into(), false));
    }

    fn error(&mut self, text: impl Into<String>) {
        self.message = Some((text.into(), true));
    }

    // ---- the list

    fn get(&self, id: ItemId) -> Option<&Bookmark> {
        self.list.as_ref()?.iter().find(|b| b.id == id)
    }

    /// The bookmarks of a scope in order, filtered (and, while searching,
    /// sorted) by the query.
    fn scope(&self, site: Option<ItemId>) -> Vec<&Bookmark> {
        let Some(list) = &self.list else {
            return Vec::new();
        };
        let mut scored: Vec<(i64, usize, &Bookmark)> = list
            .iter()
            .filter(|b| b.site_id == site)
            .enumerate()
            .filter_map(|(i, b)| score(&self.query, &b.name).map(|s| (s, i, b)))
            .collect();
        if !self.query.trim().is_empty() {
            scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        }
        scored.into_iter().map(|(_, _, b)| b).collect()
    }

    fn rows(&self) -> Vec<Row> {
        let mut rows = vec![Row::Header("Global bookmarks".to_owned())];
        let global = self.scope(None);
        if global.is_empty() {
            rows.push(Row::Note(self.empty_note().to_owned()));
        }
        rows.extend(global.iter().map(|b| Row::Item(b.id)));
        match &self.ctx.site {
            Some((id, name)) => {
                rows.push(Row::Header(format!("Bookmarks of site {name}")));
                let site = self.scope(Some(*id));
                if site.is_empty() {
                    rows.push(Row::Note(self.empty_note().to_owned()));
                }
                rows.extend(site.iter().map(|b| Row::Item(b.id)));
            }
            None => {
                rows.push(Row::Header("Site bookmarks".to_owned()));
                rows.push(Row::Note(
                    if self.ctx.quickconnect {
                        QUICKCONNECT_NOTE
                    } else {
                        NOT_CONNECTED_NOTE
                    }
                    .to_owned(),
                ));
            }
        }
        rows
    }

    fn empty_note(&self) -> &'static str {
        if self.query.trim().is_empty() {
            "None yet: a adds the directories shown now"
        } else {
            "No match"
        }
    }

    /// The selectable bookmarks, in display order.
    fn items(&self) -> Vec<ItemId> {
        self.rows()
            .into_iter()
            .filter_map(|r| match r {
                Row::Item(id) => Some(id),
                _ => None,
            })
            .collect()
    }

    /// Keep the selection on a shown bookmark (the first one otherwise).
    fn fix_selection(&mut self) {
        let items = self.items();
        if !self.selected.is_some_and(|id| items.contains(&id)) {
            self.selected = items.first().copied();
        }
    }

    fn move_selection(&mut self, delta: isize) {
        let items = self.items();
        if items.is_empty() {
            return;
        }
        let at = self
            .selected
            .and_then(|id| items.iter().position(|i| *i == id))
            .unwrap_or(0);
        let to = at.saturating_add_signed(delta).min(items.len() - 1);
        self.selected = Some(items[to]);
    }

    fn selected_bookmark(&self) -> Option<&Bookmark> {
        self.selected.and_then(|id| self.get(id))
    }

    // ---- commands

    fn apply_selected(&mut self) {
        match self.selected_bookmark() {
            Some(b) => {
                self.apply = Some(b.target());
                self.closed = true;
            }
            None => self.error("No bookmark selected"),
        }
    }

    fn add(&mut self) {
        let base = Bookmark::global("");
        let name = default_name(&self.ctx);
        let (dialog, rx) = editor_dialog(
            "Add bookmark",
            base,
            Some(self.ctx.site.as_ref().map(|(id, _)| *id)),
            &name,
            self.ctx.local_dir.as_deref().unwrap_or(""),
            self.ctx.remote_dir.as_deref().unwrap_or(""),
        );
        self.overlay(Box::new(dialog), rx, |menu, bookmark| {
            if let Some(b) = bookmark {
                menu.request(BookmarkOp::Add(Box::new(b)));
            }
        });
    }

    fn edit(&mut self) {
        let Some(b) = self.selected_bookmark().cloned() else {
            self.error("No bookmark selected");
            return;
        };
        if b.read_only {
            self.error("This bookmark comes from a newer courier-ftp and can't be edited here");
            return;
        }
        let local = b
            .effective_local_dir()
            .map(LocalPath::to_display)
            .unwrap_or_default();
        let remote = b
            .remote_dir
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default();
        let name = b.name.clone();
        let (dialog, rx) = editor_dialog("Edit bookmark", b, None, &name, &local, &remote);
        self.overlay(Box::new(dialog), rx, |menu, bookmark| {
            if let Some(b) = bookmark {
                menu.request(BookmarkOp::Edit(Box::new(b)));
            }
        });
    }

    fn delete(&mut self) {
        let Some(b) = self.selected_bookmark() else {
            self.error("No bookmark selected");
            return;
        };
        let id = b.id;
        let (modal, rx) = confirm(
            "Delete bookmark",
            &format!("Delete the bookmark “{}”?", b.name),
            false,
        );
        self.overlay(modal, rx, move |menu, yes| {
            if yes {
                menu.request(BookmarkOp::Delete(id));
            }
        });
    }

    /// `J` (`down`) / `K`: move the selected bookmark within its section.
    fn reorder(&mut self, down: bool) {
        if !self.query.trim().is_empty() {
            self.error("Clear the search to reorder bookmarks");
            return;
        }
        let Some(b) = self.selected_bookmark() else {
            self.error("No bookmark selected");
            return;
        };
        let id = b.id;
        let scope = self.scope(b.site_id);
        let Some(at) = scope.iter().position(|x| x.id == id) else {
            return;
        };
        let to = if down {
            at + 1
        } else {
            match at.checked_sub(1) {
                Some(to) => to,
                None => return,
            }
        };
        if to >= scope.len() {
            return;
        }
        self.request(BookmarkOp::Reorder { id, index: to });
    }

    // ---- replies

    /// An operation finished.
    pub(crate) fn apply_reply(&mut self, reply: &BookmarksReply) {
        self.busy = false;
        match &reply.bookmarks {
            Some(list) => self.list = Some(list.clone()),
            None if self.list.is_none() => self.locked = true,
            None => {}
        }
        match &reply.outcome {
            BookmarkOutcome::Loaded => {}
            BookmarkOutcome::Saved(id) => {
                self.selected = Some(*id);
                // A new bookmark may not match the search.
                if !self.items().contains(id) {
                    self.query.clear();
                }
                self.info("Saved");
            }
            BookmarkOutcome::Deleted => self.info("Deleted"),
            BookmarkOutcome::Moved(id) => self.selected = Some(*id),
            BookmarkOutcome::Failed(e) => self.error(e.clone()),
        }
        self.fix_selection();
    }

    // ---- keys

    /// Bracketed paste goes to the dialog or the search.
    pub(crate) fn handle_paste(&mut self, text: &str) {
        if let Some(o) = self.overlay.as_mut() {
            o.modal.handle_paste(text);
        } else if self.list.is_some() {
            self.searching = true;
            self.query.extend(text.chars().filter(|c| !c.is_control()));
            self.fix_selection();
        }
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) {
        if let Some(o) = self.overlay.as_mut() {
            if o.modal.handle_key(key) == ModalOutcome::Close
                && let Some(o) = self.overlay.take()
            {
                (o.then)(self);
            }
            return;
        }
        self.message = None;
        if self.locked {
            match key.code {
                KeyCode::Enter => self.unlock_requested = true,
                KeyCode::Esc | KeyCode::Char('q') => self.closed = true,
                _ => {}
            }
            return;
        }
        if self.list.is_none() || self.busy {
            if key.code == KeyCode::Esc {
                self.closed = true;
            }
            return;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Down => return self.move_selection(1),
            KeyCode::Up => return self.move_selection(-1),
            KeyCode::Char('n') if ctrl => return self.move_selection(1),
            KeyCode::Char('p') if ctrl => return self.move_selection(-1),
            KeyCode::PageDown => return self.move_selection(10),
            KeyCode::PageUp => return self.move_selection(-10),
            _ => {}
        }
        if self.searching {
            self.search_key(key);
            return;
        }
        match key.code {
            KeyCode::Esc if !self.query.is_empty() => {
                self.query.clear();
                self.fix_selection();
            }
            KeyCode::Esc | KeyCode::Char('q') => self.closed = true,
            KeyCode::Enter => self.apply_selected(),
            KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Home | KeyCode::Char('g') => self.move_selection(isize::MIN),
            KeyCode::End | KeyCode::Char('G') => self.move_selection(isize::MAX),
            KeyCode::Char('/') => self.searching = true,
            KeyCode::Char('a') => self.add(),
            KeyCode::Char('e') => self.edit(),
            KeyCode::Char('x') | KeyCode::Delete => self.delete(),
            KeyCode::Char('J') => self.reorder(true),
            KeyCode::Char('K') => self.reorder(false),
            _ => {}
        }
    }

    /// A key while typing the search: `Enter` applies the best match, `Esc`
    /// clears the search.
    fn search_key(&mut self, key: KeyEvent) {
        let plain = !key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
        match key.code {
            KeyCode::Esc => {
                self.searching = false;
                self.query.clear();
            }
            KeyCode::Enter => {
                self.searching = false;
                self.apply_selected();
            }
            KeyCode::Tab => self.searching = false,
            KeyCode::Backspace => {
                if self.query.pop().is_none() {
                    self.searching = false;
                }
            }
            KeyCode::Char('u') if !plain => self.query.clear(),
            KeyCode::Char(c) if plain => self.query.push(c),
            _ => return,
        }
        // The best match first.
        self.selected = None;
        self.fix_selection();
    }

    // ---- drawing

    pub(crate) fn draw(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let rows = if self.locked || self.list.is_none() {
            Vec::new()
        } else {
            self.rows()
        };
        let list_h = u16::try_from(rows.len()).unwrap_or(u16::MAX).clamp(3, 16);
        let width = area.width.saturating_sub(4).min(76);
        let height = if rows.is_empty() { 3 } else { list_h + 4 };
        let Some(inner) = dialog_frame_styled(
            frame,
            area,
            "Bookmarks",
            width,
            height,
            theme,
            theme.focused_border,
        ) else {
            if let Some(o) = self.overlay.as_mut() {
                o.modal.draw(frame, area, theme);
            }
            return;
        };
        let line = |y: u16| Rect::new(inner.x, inner.y + y, inner.width, 1);
        if self.locked {
            frame.render_widget(
                Paragraph::new(vec![
                    Line::styled("Bookmarks are kept in the vault.", theme.title),
                    Line::raw(""),
                    Line::styled("Enter unlocks it, Esc closes.", theme.dim),
                ]),
                inner,
            );
            return;
        }
        if self.list.is_none() {
            frame.render_widget(
                Paragraph::new(Span::styled("Loading bookmarks…", theme.dim)),
                line(0),
            );
            return;
        }
        // The search line.
        let search = if self.searching || !self.query.is_empty() {
            let cursor = if self.searching { "▏" } else { "" };
            Line::from(vec![
                Span::styled("Search: ", theme.title),
                Span::raw(format!("{}{cursor}", self.query)),
            ])
        } else {
            Line::styled("/ to search", theme.dim)
        };
        frame.render_widget(Paragraph::new(search), line(0));

        let list = Rect::new(inner.x, inner.y + 2, inner.width, list_h);
        let selected_row = rows
            .iter()
            .position(|r| matches!(r, Row::Item(id) if Some(*id) == self.selected));
        let height = usize::from(list_h);
        let start = selected_row.map_or(0, |s| (s + 1).saturating_sub(height));
        let name_w = self
            .list
            .iter()
            .flatten()
            .map(|b| b.name.chars().count())
            .max()
            .unwrap_or(0)
            .min(usize::from(inner.width) / 3);
        let lines: Vec<Line> = rows
            .iter()
            .enumerate()
            .skip(start)
            .take(height)
            .map(|(i, row)| match row {
                Row::Header(text) => Line::styled(text.clone(), theme.title),
                Row::Note(text) => Line::styled(format!("  {text}"), theme.dim),
                Row::Item(id) => {
                    let Some(b) = self.get(*id) else {
                        return Line::raw("");
                    };
                    let chosen = Some(i) == selected_row;
                    item_line(b, name_w, chosen, theme)
                }
            })
            .collect();
        frame.render_widget(Paragraph::new(lines), list);

        let (text, style) = match &self.message {
            Some((m, true)) => (m.clone(), theme.error),
            Some((m, false)) => (m.clone(), theme.title),
            None if self.busy => ("Working…".to_owned(), theme.dim),
            None if self.searching => (
                "Enter go · ↑/↓ choose · Tab stop typing · Esc clear".to_owned(),
                theme.dim,
            ),
            None => (HINTS.to_owned(), theme.dim),
        };
        frame.render_widget(
            Paragraph::new(Span::styled(text, style)),
            line(inner.height.saturating_sub(1)),
        );
        if let Some(o) = self.overlay.as_mut() {
            o.modal.draw(frame, area, theme);
        }
    }
}

/// One bookmark: its name, then where it goes and what it turns on.
fn item_line<'a>(b: &Bookmark, name_w: usize, chosen: bool, theme: &Theme) -> Line<'a> {
    let base = if chosen {
        theme.selection
    } else {
        Style::new()
    };
    let detail = if chosen { theme.selection } else { theme.dim };
    let mut parts = Vec::new();
    if let Some(local) = b.effective_local_dir() {
        parts.push(format!("local {}", local.to_display()));
    }
    if let Some(remote) = &b.remote_dir {
        parts.push(format!("remote {remote}"));
    }
    let mut flags = Vec::new();
    if b.sync_browsing {
        flags.push("sync");
    }
    if b.comparison {
        flags.push("compare");
    }
    if b.read_only {
        flags.push("read-only");
    }
    if !flags.is_empty() {
        parts.push(format!("[{}]", flags.join(", ")));
    }
    let marker = if chosen { "> " } else { "  " };
    Line::from(vec![
        Span::styled(format!("{marker}{:<name_w$}", b.name), base),
        Span::styled(format!("  {}", parts.join("  ")), detail),
    ])
}

/// The name "add" suggests: the last part of the remote directory, else of
/// the local one.
fn default_name(ctx: &MenuContext) -> String {
    let last = |s: &str| {
        s.trim_end_matches(['/', '\\'])
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or_default()
            .to_owned()
    };
    ctx.remote_dir
        .as_deref()
        .map(last)
        .filter(|n| !n.is_empty())
        .or_else(|| ctx.local_dir.as_deref().map(last))
        .filter(|n| !n.is_empty())
        .unwrap_or_default()
}

/// The add/edit form. `site` is `Some` when adding: `Some(Some(id))` offers
/// the choice between a global and a site bookmark (site `id`); editing
/// keeps the scope. Answers the bookmark to save.
fn editor_dialog(
    title: &str,
    base: Bookmark,
    site: Option<Option<ItemId>>,
    name: &str,
    local: &str,
    remote: &str,
) -> (FormDialog<Bookmark>, oneshot::Receiver<Option<Bookmark>>) {
    let mut form = Form::new(&["Save", "Cancel"]).field(
        "name",
        TextInput::new("Name:")
            .with_value(name)
            .with_validator(|v| {
                if v.trim().is_empty() {
                    Err("Enter a name".to_owned())
                } else {
                    Ok(())
                }
            }),
    );
    let site_choice = site.flatten();
    if site_choice.is_some() {
        form = form.field(
            "type",
            RadioGroup::new(
                "Type:",
                vec!["Global".to_owned(), "Site-specific".to_owned()],
                1,
            ),
        );
    }
    form = form
        .field(
            "local",
            PathInput::new("Local directory:", Box::new(LocalPathCompleter)).with_value(local),
        )
        .field(
            "remote",
            TextInput::new("Remote directory:").with_value(remote),
        )
        .field(
            "sync",
            Checkbox::new("Use synchronized browsing:", base.sync_browsing),
        )
        .field(
            "compare",
            Checkbox::new("Directory comparison:", base.comparison),
        );
    let adding = site.is_some();
    FormDialog::new(title, 64, form, move |v| {
        let mut b = base.clone();
        b.name = v.text("name").trim().to_owned();
        if adding {
            b.site_id = site_choice.filter(|_| v.index("type") == Some(1));
        }
        let local = v.text("local");
        let local = local.trim();
        let local =
            (!local.is_empty()).then(|| LocalPath::new(crate::diagnostics::expand_home(local)));
        // This device's override stays the one edited when there is one.
        if b.local_dir_override.is_some() {
            b.local_dir_override = local;
        } else {
            b.local_dir = local;
        }
        let remote = v.text("remote");
        let remote = remote.trim();
        b.remote_dir = (!remote.is_empty()).then(|| RemotePath::new(remote));
        b.sync_browsing = v.bool("sync");
        b.comparison = v.bool("compare");
        b.validate().map_err(|e| match e {
            SiteError::InvalidBookmark(why) => sentence(&why),
            other => other.to_string(),
        })?;
        Ok(b)
    })
}

/// `why` with a capital letter.
fn sentence(why: &str) -> String {
    let mut chars = why.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}
