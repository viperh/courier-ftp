//! The Site Manager screen (T59): the folder tree of saved sites on the
//! left, the site editor ([`editor`]) on the right, buttons at the bottom.
//!
//! The screen draws a [`Snapshot`] of the tree and asks the app for every
//! change with a [`SiteOp`] (taken with [`SiteManagerView::take_requests`]);
//! the app runs it on the `SiteManager` in the background and hands the
//! result back ([`SiteManagerView::apply_reply`]). Its own dialogs (name
//! prompts, confirmations, import/export) are standard dialogs kept on a
//! private overlay, so their answers are read as soon as they close.
//!
//! Keys are fixed, like the dialogs' (not in the keymap): see
//! [`TREE_HINTS`] and [`EDITOR_HINTS`].

mod editor;
mod picker;
#[cfg(test)]
mod tests;

use std::collections::HashSet;

use courier_ftp_core::{
    model::{
        Protocol,
        item::{CredentialOverride, ItemId, VaultId},
    },
    sites::{Site, SiteNode, SiteTree, export::ExportScope},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};
use secrecy::SecretString;
use tokio::sync::oneshot;

use editor::EditorKey;
pub(crate) use editor::FieldId;
pub(crate) use editor::color_style;
pub(crate) use picker::{score, site_paths, site_picker};

use super::{
    dialog::{
        ButtonRow, Form, FormDialog, LocalPathCompleter, PathInput, Select, TextInput, ask, choose,
        confirm, message, prompt_password, prompt_text,
    },
    modal::{Modal, ModalOutcome},
    theme::Theme,
};
use crate::sites::{
    ExportFormat, OverrideForm, SiteOp, SiteOutcome, SitesReply, Snapshot, VaultRoot,
};

pub(crate) use editor::Editor;
pub(crate) use editor::TextArea;

/// Keys of the tree, shown at the bottom.
pub(crate) const TREE_HINTS: &str = "n new · f folder · d dup · r rename · x delete · ^x/^v move · / search · Enter connect · Esc close";
/// Keys of the tree with team vault roots (T90).
pub(crate) const VAULT_TREE_HINTS: &str =
    "n new · f folder · x delete · c/m copy/move to vault · o my login · Enter connect · Esc close";
/// Keys of the editor, shown at the bottom.
pub(crate) const EDITOR_HINTS: &str =
    "Tab next field · [ ] or ^PgUp/^PgDn tabs · ^s save · Alt-c connect · Esc back to the tree";

const BUTTONS: [&str; 6] = ["Connect", "New tab", "Save", "Import…", "Export…", "Close"];

/// What the screen needs from the settings and the system.
#[derive(Debug, Clone, Default)]
pub(crate) struct ViewOpts {
    pub(crate) unicode: bool,
    /// `vault.store_passwords`.
    pub(crate) store_passwords: bool,
    /// The file the import dialog suggests (FileZilla's `sitemanager.xml`).
    pub(crate) import_default: String,
    /// The file the export dialog suggests.
    pub(crate) export_default: String,
}

/// Which part of the screen has the keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pane {
    Tree,
    Editor,
    Buttons,
}

/// Something to do once unsaved changes are saved or discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cmd {
    Select(Option<ItemId>),
    /// A vault root row (T90).
    SelectRoot(VaultId),
    Close,
    NewSite,
    NewFolder,
    Duplicate,
    Delete,
    Paste,
    Import,
    Export,
    /// Connect; `true`: in a new tab (T61).
    Connect(ItemId, bool),
}

type Then = Box<dyn FnOnce(&mut SiteManagerView) + Send>;

/// A row of the tree: a vault root (T90, only with team vaults) or a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Row {
    Root(VaultId),
    Node { depth: usize, id: ItemId },
}

impl Row {
    fn node(self) -> Option<ItemId> {
        match self {
            Self::Node { id, .. } => Some(id),
            Self::Root(_) => None,
        }
    }
}

/// A dialog of the Site Manager and what to do with its answer.
struct Overlay {
    modal: Box<dyn Modal>,
    then: Then,
}

/// The Site Manager screen. See the module docs.
pub(crate) struct SiteManagerView {
    opts: ViewOpts,
    /// `None` while the first load runs.
    snapshot: Option<Snapshot>,
    /// The vault is locked: only a message.
    locked: bool,
    cursor: usize,
    selected: Option<ItemId>,
    /// The vault roots (T90): empty without team vaults (a flat tree).
    vaults: Vec<VaultRoot>,
    /// Collapsed vault roots.
    collapsed: HashSet<VaultId>,
    /// A vault root row is selected (then `selected` is `None`).
    root: Option<VaultId>,
    focus: Pane,
    buttons: ButtonRow,
    editor: Option<Editor>,
    /// A site to add as new once the tree is loaded ("Save as site").
    prefill: Option<Site>,
    /// Cut with `Ctrl-x`, waiting for `Ctrl-v`.
    cut: Option<ItemId>,
    /// Typing a search (`/`).
    search: Option<String>,
    /// Renaming a row in place.
    rename: Option<(ItemId, TextInput)>,
    overlay: Option<Overlay>,
    /// An operation is running.
    busy: bool,
    /// The last result, shown instead of the key hints.
    message: Option<(String, bool)>,
    /// What to do after the running save succeeds.
    after_save: Option<Cmd>,
    requests: Vec<SiteOp>,
    /// The locked message's Enter: unlock the vault.
    unlock_requested: bool,
    closed: bool,
}

impl SiteManagerView {
    /// The screen over `snapshot` (`None`: still loading).
    pub(crate) fn new(snapshot: Option<Snapshot>, opts: ViewOpts) -> Self {
        let mut view = Self {
            opts,
            snapshot: None,
            locked: false,
            cursor: 0,
            selected: None,
            vaults: Vec::new(),
            collapsed: HashSet::new(),
            root: None,
            focus: Pane::Tree,
            buttons: ButtonRow::new(&BUTTONS, 0),
            editor: None,
            prefill: None,
            cut: None,
            search: None,
            rename: None,
            overlay: None,
            busy: false,
            message: None,
            after_save: None,
            requests: Vec::new(),
            unlock_requested: false,
            closed: false,
        };
        if let Some(snapshot) = snapshot {
            view.set_snapshot(snapshot);
        }
        view
    }

    /// The vault is locked and the user didn't unlock it.
    pub(crate) fn locked(opts: ViewOpts) -> Self {
        let mut view = Self::new(None, opts);
        view.locked = true;
        view
    }

    /// Whether this is the locked message.
    pub(crate) fn is_locked(&self) -> bool {
        self.locked
    }

    /// The vault was unlocked: wait for the tree.
    pub(crate) fn unlocked(&mut self, snapshot: Option<Snapshot>) {
        self.locked = false;
        if let Some(snapshot) = snapshot {
            self.set_snapshot(snapshot);
        }
    }

    /// Start with a new, unsaved site (quickconnect's "Save as site").
    pub(crate) fn with_new_site(mut self, site: Site) -> Self {
        self.prefill = Some(site);
        self.add_prefill();
        self
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed
    }

    /// Whether the user asked to unlock the vault (once).
    pub(crate) fn take_unlock_request(&mut self) -> bool {
        std::mem::take(&mut self.unlock_requested)
    }

    /// The operations asked for since the last call.
    pub(crate) fn take_requests(&mut self) -> Vec<SiteOp> {
        std::mem::take(&mut self.requests)
    }

    #[cfg(test)]
    pub(crate) fn editor(&self) -> Option<&Editor> {
        self.editor.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn editor_mut(&mut self) -> Option<&mut Editor> {
        self.editor.as_mut()
    }

    #[cfg(test)]
    pub(crate) fn selected(&self) -> Option<ItemId> {
        self.selected
    }

    #[cfg(test)]
    pub(crate) fn focus(&self) -> Pane {
        self.focus
    }

    #[cfg(test)]
    pub(crate) fn has_overlay(&self) -> bool {
        self.overlay.is_some()
    }

    #[cfg(test)]
    pub(crate) fn is_busy(&self) -> bool {
        self.busy
    }

    fn tree_ref(&self) -> Option<&SiteTree> {
        self.snapshot.as_ref().map(|s| &s.tree)
    }

    fn bookmarks_of(&self, id: ItemId) -> Vec<String> {
        self.snapshot
            .as_ref()
            .and_then(|s| s.bookmarks.get(&id).cloned())
            .unwrap_or_default()
    }

    /// The vaults to show as roots of the tree (T90): the personal vault
    /// and the team vaults, or nothing (a flat tree) without team vaults.
    pub(crate) fn set_vaults(&mut self, vaults: Vec<VaultRoot>) {
        if vaults == self.vaults {
            return;
        }
        self.vaults = vaults;
        if self
            .root
            .is_some_and(|v| !self.root_list().iter().any(|r| r.id == v))
        {
            self.root = None;
        }
        if let Some(vault) = self.editor.as_ref().map(|e| e.site.vault) {
            let lock = self.lock_note(vault);
            if let Some(ed) = self.editor.as_mut() {
                ed.set_vault_lock(lock);
            }
        }
        if self.selected.is_none() && self.root.is_none() {
            let rows = self.rows();
            self.select_row(rows.get(self.cursor).copied());
            self.rebuild_editor();
        }
        self.sync_cursor();
    }

    fn roots_mode(&self) -> bool {
        !self.vaults.is_empty()
    }

    fn personal(&self) -> Option<VaultId> {
        self.vaults.iter().find(|r| r.personal).map(|r| r.id)
    }

    /// The vault of `node` (an unsaved node without one: the personal).
    fn vault_of_node(&self, node: &SiteNode) -> Option<VaultId> {
        node.vault().or_else(|| self.personal())
    }

    /// The roots, with a fallback for vaults the list doesn't know yet.
    fn root_list(&self) -> Vec<VaultRoot> {
        let mut out = self.vaults.clone();
        if !self.roots_mode() {
            return out;
        }
        if let Some(tree) = self.tree_ref() {
            for n in tree.roots() {
                if let Some(v) = self.vault_of_node(n)
                    && !out.iter().any(|r| r.id == v)
                {
                    let id = v.to_string();
                    out.push(VaultRoot {
                        id: v,
                        name: format!("vault {}", id.chars().take(8).collect::<String>()),
                        personal: false,
                        read_only: false,
                    });
                }
            }
        }
        out
    }

    fn root_info(&self, vault: Option<VaultId>) -> Option<VaultRoot> {
        let vault = vault.or_else(|| self.personal())?;
        self.root_list().into_iter().find(|r| r.id == vault)
    }

    /// The vault root `vault` when it is read-only for this account.
    fn locked_vault(&self, vault: Option<VaultId>) -> Option<VaultRoot> {
        self.root_info(vault).filter(|r| r.read_only)
    }

    /// The editor's note for a site in vault `vault` when it is read-only.
    fn lock_note(&self, vault: Option<VaultId>) -> Option<String> {
        let root = self.locked_vault(vault)?;
        let lock = if self.opts.unicode { "🔒" } else { "[ro]" };
        Some(format!(
            "{lock} read-only ({} is shared with you for reading)",
            root.label()
        ))
    }

    /// The visible rows.
    fn rows(&self) -> Vec<Row> {
        fn push(node: &SiteNode, depth: usize, out: &mut Vec<Row>) {
            out.push(Row::Node {
                depth,
                id: node.id(),
            });
            if let SiteNode::Folder(f) = node
                && f.expanded
            {
                for c in &f.children {
                    push(c, depth + 1, out);
                }
            }
        }
        let Some(tree) = self.tree_ref() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        if !self.roots_mode() {
            for n in tree.roots() {
                push(n, 0, &mut out);
            }
            return out;
        }
        for root in self.root_list() {
            out.push(Row::Root(root.id));
            if self.collapsed.contains(&root.id) {
                continue;
            }
            for n in tree.roots() {
                if self.vault_of_node(n) == Some(root.id) {
                    push(n, 1, &mut out);
                }
            }
        }
        out
    }

    /// Select `row` (nothing for `None`).
    fn select_row(&mut self, row: Option<Row>) {
        match row {
            Some(Row::Root(v)) => {
                self.root = Some(v);
                self.selected = None;
            }
            Some(Row::Node { id, .. }) => {
                self.root = None;
                self.selected = Some(id);
            }
            None => {
                self.root = None;
                self.selected = None;
            }
        }
    }

    fn node(&self, id: ItemId) -> Option<&SiteNode> {
        self.tree_ref()?.get(id)
    }

    /// An editor for `site`, with the 🔒 note of a read-only team vault.
    fn new_editor(&self, site: Site, new: bool) -> Editor {
        let bookmarks = if new {
            Vec::new()
        } else {
            self.bookmarks_of(site.id)
        };
        let lock = self.lock_note(site.vault);
        let mut ed = Editor::new(site, new, self.opts.store_passwords, bookmarks);
        ed.set_vault_lock(lock);
        ed
    }

    fn info(&mut self, text: impl Into<String>) {
        self.message = Some((text.into(), false));
    }

    fn error(&mut self, text: impl Into<String>) {
        self.message = Some((text.into(), true));
    }

    fn request(&mut self, op: SiteOp) {
        if !matches!(op, SiteOp::Connect(_) | SiteOp::ConnectInNewTab(_)) {
            self.busy = true;
        }
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
            then: Box::new(move |view| {
                let mut rx = rx;
                if let Ok(answer) = rx.try_recv() {
                    then(view, answer);
                }
            }),
        });
    }

    // ---- tree state

    fn set_snapshot(&mut self, snapshot: Snapshot) {
        let expanded = self.tree_ref().map(SiteTree::expanded).unwrap_or_default();
        let pending = self
            .editor
            .as_ref()
            .filter(|e| e.is_new())
            .map(|e| e.site.clone());
        let mut snapshot = snapshot;
        for id in expanded {
            snapshot.tree.set_expanded(id, true);
        }
        if let Some(site) = pending
            && snapshot.tree.get(site.id).is_none()
        {
            let parent = site.parent;
            let _ = snapshot.tree.insert(parent, SiteNode::Site(Box::new(site)));
        }
        let first = self.snapshot.is_none();
        self.snapshot = Some(snapshot);
        // The editor follows what is stored.
        if let Some(ed) = self.editor.as_ref() {
            let id = ed.id();
            let stored = self.tree_ref().and_then(|t| t.site(id)).cloned();
            let bookmarks = self.bookmarks_of(id);
            match stored {
                Some(stored) if !ed.is_new() => {
                    let dirty = ed.is_dirty();
                    let fresh = (!dirty).then(|| self.new_editor(stored.clone(), false));
                    if let Some(ed) = self.editor.as_mut() {
                        if let Some(mut fresh) = fresh {
                            fresh.keep_place(ed);
                            *ed = fresh;
                        } else {
                            ed.tree_changed(&stored.name, stored.parent);
                            ed.set_bookmarks(bookmarks);
                        }
                    }
                }
                Some(_) => {}
                None => self.editor = None,
            }
        }
        if first {
            self.add_prefill();
        }
        if self.selected.is_some_and(|id| self.node(id).is_none()) {
            self.selected = None;
        }
        if self.selected.is_none() && self.root.is_none() {
            let rows = self.rows();
            let row = self.cursor.min(rows.len().saturating_sub(1));
            self.select_row(rows.get(row).copied());
            self.rebuild_editor();
        }
        self.sync_cursor();
    }

    /// Insert the "Save as site" site, once the tree is there.
    fn add_prefill(&mut self) {
        if self.tree_ref().is_none() {
            return;
        }
        let Some(mut site) = self.prefill.take() else {
            return;
        };
        if let Some(tree) = self.tree_ref() {
            site.name = tree.unique_name(None, &site.name);
        }
        site.parent = None;
        self.add_new_site(site);
    }

    /// Put an unsaved site in the tree and edit it.
    fn add_new_site(&mut self, site: Site) {
        let id = site.id;
        let parent = site.parent;
        let result = match self.snapshot.as_mut() {
            Some(s) => s.tree.insert(parent, SiteNode::Site(Box::new(site))),
            None => return,
        };
        if let Err(e) = result {
            self.error(e.to_string());
            return;
        }
        if let Some(tree) = self.snapshot.as_mut().map(|s| &mut s.tree) {
            tree.reveal(id);
        }
        let Some(site) = self.tree_ref().and_then(|t| t.site(id)).cloned() else {
            return;
        };
        self.selected = Some(id);
        self.root = None;
        if let Some(v) = site.vault {
            self.collapsed.remove(&v);
        }
        let mut editor = self.new_editor(site, true);
        editor.focus_field(FieldId::Host);
        self.editor = Some(editor);
        self.focus = Pane::Editor;
        self.sync_cursor();
    }

    /// Forget an unsaved new site.
    fn drop_new_site(&mut self) {
        if let Some(ed) = self.editor.take_if(|e| e.is_new()) {
            let id = ed.id();
            if let Some(s) = self.snapshot.as_mut() {
                s.tree.remove(id);
            }
            if self.selected == Some(id) {
                self.selected = None;
            }
        }
    }

    /// The editor for the selected node (none for a folder).
    fn rebuild_editor(&mut self) {
        let site = self
            .selected
            .and_then(|id| self.tree_ref().and_then(|t| t.site(id)))
            .cloned();
        self.editor = site.map(|s| self.new_editor(s, false));
    }

    fn sync_cursor(&mut self) {
        let rows = self.rows();
        let found = match (self.root, self.selected) {
            (Some(v), _) => rows.iter().position(|r| *r == Row::Root(v)),
            (None, Some(id)) => rows.iter().position(|r| r.node() == Some(id)),
            (None, None) => None,
        };
        if let Some(i) = found {
            self.cursor = i;
            return;
        }
        self.cursor = self.cursor.min(rows.len().saturating_sub(1));
    }

    fn dirty(&self) -> bool {
        self.editor.as_ref().is_some_and(Editor::is_dirty)
    }

    /// Where new entries go: the selected folder, the selected site's
    /// folder, or the top level of the selected vault root; with the vault
    /// (`None`: the personal vault, or a flat tree).
    fn context(&self) -> (Option<ItemId>, Option<VaultId>) {
        if let Some(v) = self.root {
            return (None, Some(v));
        }
        let Some(node) = self.selected.and_then(|id| self.node(id)) else {
            return (None, self.personal());
        };
        let vault = self.vault_of_node(node);
        if node.is_folder() {
            (Some(node.id()), vault)
        } else {
            (node.parent(), vault)
        }
    }

    /// Refuses (with a message) a change in a read-only team vault.
    fn refuse_locked(&mut self, vault: Option<VaultId>) -> bool {
        let Some(root) = self.locked_vault(vault) else {
            return false;
        };
        let lock = if self.opts.unicode { "🔒" } else { "[ro]" };
        self.error(format!(
            "{lock} {} is read-only for you: it can't be changed here",
            root.label()
        ));
        true
    }

    /// [`Self::refuse_locked`] for the vault of node `id`.
    fn refuse_locked_node(&mut self, id: ItemId) -> bool {
        let vault = self.node(id).and_then(|n| self.vault_of_node(n));
        self.roots_mode() && self.refuse_locked(vault)
    }

    // ---- commands

    /// Run `cmd`, asking first when unsaved changes would be lost.
    fn guarded(&mut self, cmd: Cmd) {
        let editing = self.editor.as_ref().map(Editor::id);
        let pending_new = self.editor.as_ref().is_some_and(Editor::is_new);
        let keeps_editor = match cmd {
            Cmd::Select(id) => id == editing,
            // Deleting the unsaved new site just drops it.
            Cmd::Delete => pending_new && self.selected == editing,
            Cmd::Import | Cmd::Export | Cmd::Connect(..) | Cmd::NewFolder => true,
            _ => false,
        };
        if keeps_editor || !self.dirty() {
            self.run(cmd);
            return;
        }
        let name = self
            .editor
            .as_ref()
            .map(|e| e.site.name.clone())
            .unwrap_or_default();
        let (modal, rx) = ask(
            "Unsaved changes",
            &format!("“{name}” has unsaved changes."),
            &["Save", "Discard", "Cancel"],
            0,
        );
        self.overlay(modal, rx, move |view, answer| match answer {
            Some(0) => view.save(Some(cmd)),
            Some(1) => {
                view.discard();
                view.run(cmd);
            }
            _ => {}
        });
    }

    fn discard(&mut self) {
        if self.editor.as_ref().is_some_and(Editor::is_new) {
            self.drop_new_site();
        } else {
            self.rebuild_editor();
        }
        self.sync_cursor();
    }

    fn run(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Select(id) => {
                self.root = None;
                if id != self.editor.as_ref().map(Editor::id) {
                    self.selected = id;
                    self.rebuild_editor();
                }
                self.sync_cursor();
            }
            Cmd::SelectRoot(v) => {
                self.root = Some(v);
                self.selected = None;
                self.editor = None;
                self.sync_cursor();
            }
            Cmd::Close => self.closed = true,
            Cmd::NewSite => self.new_site(),
            Cmd::NewFolder => self.new_folder(),
            Cmd::Duplicate => match self.selected {
                Some(id) => {
                    if !self.refuse_locked_node(id) {
                        self.request(SiteOp::Duplicate(id));
                    }
                }
                None => self.error("Nothing selected"),
            },
            Cmd::Delete => self.delete(),
            Cmd::Paste => self.paste(),
            Cmd::Import => self.import(),
            Cmd::Export => self.export(),
            Cmd::Connect(id, new_tab) => {
                self.request(if new_tab {
                    SiteOp::ConnectInNewTab(id)
                } else {
                    SiteOp::Connect(id)
                });
                self.closed = true;
            }
        }
    }

    fn new_site(&mut self) {
        let (parent, vault) = self.context();
        if self.refuse_locked(vault) {
            return;
        }
        let vault = vault.filter(|_| self.roots_mode());
        let suggested = self
            .tree_ref()
            .map(|t| t.unique_name(parent, "New site"))
            .unwrap_or_else(|| "New site".to_owned());
        let (modal, rx) = prompt_text("New site", "Name", &suggested);
        self.overlay(modal, rx, move |view, name| {
            if let Some(name) = name {
                let mut site = Site::new(name, Protocol::Sftp, "");
                site.parent = parent;
                site.vault = vault;
                view.add_new_site(site);
            }
        });
    }

    fn new_folder(&mut self) {
        let (parent, vault) = self.context();
        if self.refuse_locked(vault) {
            return;
        }
        let vault = vault.filter(|_| self.roots_mode());
        let suggested = self
            .tree_ref()
            .map(|t| t.unique_name(parent, "New folder"))
            .unwrap_or_else(|| "New folder".to_owned());
        let (modal, rx) = prompt_text("New folder", "Name", &suggested);
        self.overlay(modal, rx, move |view, name| {
            if let Some(name) = name {
                if let Some(v) = vault {
                    view.collapsed.remove(&v);
                }
                view.request(SiteOp::AddFolder {
                    parent,
                    name,
                    vault,
                });
            }
        });
    }

    fn delete(&mut self) {
        let Some(id) = self.selected else {
            self.error("Nothing selected");
            return;
        };
        if self
            .editor
            .as_ref()
            .is_some_and(|e| e.is_new() && e.id() == id)
        {
            self.drop_new_site();
            self.sync_cursor();
            let rows = self.rows();
            self.select_row(rows.get(self.cursor).copied());
            self.rebuild_editor();
            return;
        }
        if self.refuse_locked_node(id) {
            return;
        }
        let Some(node) = self.node(id) else {
            return;
        };
        let text = match node {
            SiteNode::Site(s) => format!("Delete the site “{}”?", s.name),
            SiteNode::Folder(f) => {
                let (folders, sites) = node.count();
                let folders = folders - 1;
                if folders == 0 && sites == 0 {
                    format!("Delete the empty folder “{}”?", f.name)
                } else {
                    format!(
                        "Delete the folder “{}” with {} and {}?",
                        f.name,
                        plural(folders, "folder"),
                        plural(sites, "site")
                    )
                }
            }
        };
        let (modal, rx) = confirm("Delete", &text, false);
        self.overlay(modal, rx, move |view, yes| {
            if yes {
                view.request(SiteOp::Delete(id));
            }
        });
    }

    fn cut(&mut self) {
        let Some(id) = self.selected else {
            return;
        };
        if self
            .editor
            .as_ref()
            .is_some_and(|e| e.is_new() && e.id() == id)
        {
            self.error("Save the new site first");
            return;
        }
        if self.refuse_locked_node(id) {
            return;
        }
        let name = self
            .node(id)
            .map(|n| n.name().to_owned())
            .unwrap_or_default();
        self.cut = Some(id);
        self.info(format!(
            "Cut “{name}”: select the target folder and press Ctrl-v"
        ));
    }

    fn paste(&mut self) {
        let Some(id) = self.cut.take() else {
            self.error("Nothing to paste: cut a site or folder with Ctrl-x first");
            return;
        };
        let (parent, vault) = self.context();
        if self.roots_mode() {
            let own = self.node(id).and_then(|n| self.vault_of_node(n));
            if own != vault {
                self.error(
                    "That is another vault: use c (copy to vault) or m (move to vault) instead",
                );
                return;
            }
            if self.refuse_locked(vault) {
                return;
            }
        }
        self.request(SiteOp::Move { id, parent });
    }

    /// "Copy to vault…" (`c`) / "Move to vault…" (`m`) of the selected
    /// site (T90): pick a writable vault.
    fn copy_to_vault(&mut self, remove: bool) {
        let what = if remove { "Move" } else { "Copy" };
        let Some(site) = self
            .selected
            .and_then(|id| self.tree_ref()?.site(id))
            .cloned()
        else {
            self.error(format!("Select a site to {}", what.to_lowercase()));
            return;
        };
        if self.editor.as_ref().is_some_and(|e| e.is_new()) {
            self.error("Save the new site first");
            return;
        }
        if !self.roots_mode() {
            self.error("There is no other vault: teams are set up in the sync panel");
            return;
        }
        if remove && self.refuse_locked(site.vault) {
            return;
        }
        let own = site.vault.or_else(|| self.personal());
        let targets: Vec<VaultRoot> = self
            .root_list()
            .into_iter()
            .filter(|r| Some(r.id) != own && !r.read_only)
            .collect();
        if targets.is_empty() {
            self.error("There is no other vault you can write to");
            return;
        }
        let labels = targets.iter().map(VaultRoot::label).collect();
        let (modal, rx) = choose(&format!("{what} “{}” to vault", site.name), labels);
        let id = site.id;
        self.overlay(modal, rx, move |view, picked: Option<usize>| {
            if let Some(target) = picked.and_then(|i| targets.get(i)) {
                view.collapsed.remove(&target.id);
                view.request(SiteOp::CopyToVault {
                    id,
                    vault: target.id,
                    remove,
                });
            }
        });
    }

    /// `o`: this member's own login for the selected team vault site
    /// (credential override, T89 §6).
    fn edit_override(&mut self) {
        let Some(site) = self
            .selected
            .and_then(|id| self.tree_ref()?.site(id))
            .cloned()
        else {
            self.error("Select a team vault site");
            return;
        };
        let team = self.roots_mode() && site.vault.is_some() && site.vault != self.personal();
        if !team {
            self.error("Your own login can only be set for sites in a team vault");
            return;
        }
        if self.editor.as_ref().is_some_and(|e| e.is_new()) {
            self.error("Save the new site first");
            return;
        }
        self.request(SiteOp::LoadOverride(site.id));
    }

    /// The override editor over `form`.
    fn override_dialog(&mut self, form: &OverrideForm) {
        use secrecy::ExposeSecret;
        let current = form.current.clone();
        let user = current
            .as_ref()
            .and_then(|o| o.user.clone())
            .unwrap_or_default();
        let password = current.as_ref().and_then(|o| o.password.clone());
        let passphrase = current.as_ref().and_then(|o| o.passphrase.clone());
        let key_index = current
            .as_ref()
            .and_then(|o| o.key_id)
            .and_then(|k| form.keys.iter().position(|(id, _)| *id == k))
            .map_or(0, |i| i + 1);
        let mut key_names = vec!["(none: the shared site's login)".to_owned()];
        key_names.extend(form.keys.iter().map(|(_, label)| label.clone()));
        let mut pw = TextInput::password("Password:");
        if let Some(p) = &password {
            pw = pw.with_value(p.expose_secret());
        }
        let mut pp = TextInput::password("Key passphrase:");
        if let Some(p) = &passphrase {
            pp = pp.with_value(p.expose_secret());
        }
        let ui = Form::new(&["Save", "Cancel"])
            .field(
                "user",
                TextInput::new("User:")
                    .with_value(&user)
                    .with_placeholder("the shared site's user"),
            )
            .field("password", pw)
            .field("key", Select::new("SSH key:", key_names, key_index))
            .field("passphrase", pp);
        let site = form.site;
        let keys: Vec<ItemId> = form.keys.iter().map(|(id, _)| *id).collect();
        let (dialog, rx) = FormDialog::new(
            format!("My login for “{}” (only on your devices)", form.site_name),
            64,
            ui,
            move |v| {
                let mut ov = CredentialOverride::new(site);
                let user = v.text("user").trim().to_owned();
                ov.user = (!user.is_empty()).then_some(user);
                ov.password = v
                    .secret("password")
                    .filter(|s| !s.expose_secret().is_empty());
                ov.key_id = v
                    .index("key")
                    .and_then(|i| i.checked_sub(1))
                    .and_then(|i| keys.get(i).copied());
                ov.passphrase = v
                    .secret("passphrase")
                    .filter(|s| !s.expose_secret().is_empty());
                Ok(ov)
            },
        );
        self.overlay(Box::new(dialog), rx, |view, ov| {
            if let Some(ov) = ov {
                view.request(SiteOp::SetOverride(Box::new(ov)));
            }
        });
    }

    fn start_rename(&mut self) {
        let Some(id) = self.selected else {
            return;
        };
        if self.refuse_locked_node(id) {
            return;
        }
        let Some(name) = self.node(id).map(|n| n.name().to_owned()) else {
            return;
        };
        self.rename = Some((id, TextInput::new("").with_value(&name)));
    }

    fn finish_rename(&mut self, id: ItemId, name: String) {
        let pending = self
            .editor
            .as_ref()
            .is_some_and(|e| e.is_new() && e.id() == id);
        if !pending {
            self.request(SiteOp::Rename { id, name });
            return;
        }
        let result = match self.snapshot.as_mut() {
            Some(s) => s.tree.rename(id, &name),
            None => return,
        };
        match result {
            Ok(()) => {
                let (name, parent) = match self.tree_ref().and_then(|t| t.site(id)) {
                    Some(s) => (s.name.clone(), s.parent),
                    None => return,
                };
                if let Some(ed) = self.editor.as_mut() {
                    ed.tree_changed(&name, parent);
                }
                self.sync_cursor();
            }
            Err(e) => self.error(e.to_string()),
        }
    }

    fn save(&mut self, after: Option<Cmd>) {
        let Some(ed) = self.editor.as_mut() else {
            self.error("Select a site to save");
            return;
        };
        let vault = ed.site.vault;
        if self.refuse_locked(vault) {
            return;
        }
        let Some(ed) = self.editor.as_mut() else {
            return;
        };
        if ed.site.read_only {
            self.error("This site comes from a newer courier-ftp and can't be edited here");
            return;
        }
        ed.touch();
        if let Some(e) = ed.widget_error() {
            self.error(format!("Can't save: {e}"));
            return;
        }
        let errors: Vec<String> = ed
            .issues()
            .into_iter()
            .filter(|i| i.is_error())
            .map(|i| i.message)
            .collect();
        if !errors.is_empty() {
            ed.focus_first_error();
            self.focus = Pane::Editor;
            self.error(format!("Can't save: {}", errors.join("; ")));
            return;
        }
        let site = ed.site.clone();
        self.after_save = after;
        self.request(SiteOp::Save(Box::new(site)));
    }

    /// Connect to the selected site (`new_tab`: in a new tab), saving first
    /// when it has changes.
    fn connect(&mut self, new_tab: bool) {
        let Some(id) = self.selected else {
            self.error("Select a site to connect to");
            return;
        };
        if self.node(id).is_some_and(SiteNode::is_folder) {
            self.error("Select a site to connect to");
            return;
        }
        if self.dirty() {
            self.save(Some(Cmd::Connect(id, new_tab)));
        } else {
            self.run(Cmd::Connect(id, new_tab));
        }
    }

    fn import(&mut self) {
        let form = Form::new(&["Import", "Cancel"]).field(
            "file",
            PathInput::new("File:", Box::new(LocalPathCompleter))
                .with_value(&self.opts.import_default),
        );
        let (dialog, rx) = FormDialog::new(
            "Import sites: FileZilla sitemanager.xml or a courier-ftp export",
            70,
            form,
            |v| {
                let file = v.text("file");
                if file.trim().is_empty() {
                    return Err("Choose a file".to_owned());
                }
                Ok(crate::diagnostics::expand_home(file.trim()))
            },
        );
        self.overlay(Box::new(dialog), rx, |view, path| {
            if let Some(path) = path {
                view.request(SiteOp::Import {
                    path,
                    passphrase: None,
                });
            }
        });
    }

    fn export(&mut self) {
        let mut scopes = Vec::new();
        let mut labels = Vec::new();
        if let Some(id) = self.selected
            && let Some(node) = self.node(id)
            && !self
                .editor
                .as_ref()
                .is_some_and(|e| e.is_new() && e.id() == id)
        {
            let path = self
                .tree_ref()
                .and_then(|t| t.path_of(id))
                .unwrap_or_default();
            if node.is_folder() {
                scopes.push(ExportScope::Folder(id));
                labels.push(format!("Folder {path}"));
            } else {
                scopes.push(ExportScope::Site(id));
                labels.push(format!("Site {path}"));
            }
        }
        scopes.push(ExportScope::All);
        labels.push("All sites".to_owned());
        let formats = [
            ExportFormat::Json,
            ExportFormat::Encrypted,
            ExportFormat::FileZilla,
        ];
        let form = Form::new(&["Export", "Cancel"])
            .field("scope", Select::new("What:", labels, 0))
            .field(
                "format",
                Select::new(
                    "Format:",
                    vec![
                        "courier-ftp JSON, without passwords".to_owned(),
                        "courier-ftp, encrypted, with passwords".to_owned(),
                        "FileZilla XML, without passwords".to_owned(),
                    ],
                    0,
                ),
            )
            .field(
                "file",
                PathInput::new("File:", Box::new(LocalPathCompleter))
                    .with_value(&self.opts.export_default),
            )
            .field("pass", TextInput::password("Passphrase:"))
            .field("repeat", TextInput::password("Repeat:"))
            .validate_with(|v| {
                if v.text("file").trim().is_empty() {
                    return Err("Choose a file".to_owned());
                }
                if v.index("format") == Some(1) {
                    use secrecy::ExposeSecret;
                    let pass = v.secret("pass");
                    let repeat = v.secret("repeat");
                    let pass = pass.as_ref().map(ExposeSecret::expose_secret);
                    if pass.is_none_or(str::is_empty) {
                        return Err("An encrypted export needs a passphrase".to_owned());
                    }
                    if pass != repeat.as_ref().map(ExposeSecret::expose_secret) {
                        return Err("The passphrases don't match".to_owned());
                    }
                }
                Ok(())
            });
        let (dialog, rx) = FormDialog::new("Export sites", 70, form, move |v| {
            let scope = scopes
                .get(v.index("scope").unwrap_or(0))
                .copied()
                .unwrap_or(ExportScope::All);
            let format = formats
                .get(v.index("format").unwrap_or(0))
                .copied()
                .unwrap_or(ExportFormat::Json);
            let passphrase = (format == ExportFormat::Encrypted)
                .then(|| v.secret("pass"))
                .flatten();
            Ok(SiteOp::Export {
                scope,
                format,
                path: crate::diagnostics::expand_home(v.text("file").trim()),
                passphrase,
            })
        });
        self.overlay(Box::new(dialog), rx, |view, op| {
            if let Some(op) = op {
                view.request(op);
            }
        });
    }

    // ---- replies

    /// An operation finished.
    pub(crate) fn apply_reply(&mut self, reply: &SitesReply) {
        self.busy = false;
        if let Some(snapshot) = &reply.snapshot {
            self.set_snapshot(snapshot.clone());
        } else if self.snapshot.is_none() && !matches!(reply.outcome, SiteOutcome::Loaded) {
            self.locked = true;
        }
        match &reply.outcome {
            SiteOutcome::Loaded => {}
            SiteOutcome::Saved { id, warnings } => {
                if let Some(ed) = self.editor.as_ref().filter(|e| e.id() == *id) {
                    let stored = self.tree_ref().and_then(|t| t.site(*id)).cloned();
                    if let Some(stored) = stored {
                        let mut fresh = self.new_editor(stored, false);
                        fresh.keep_place(ed);
                        self.editor = Some(fresh);
                    }
                }
                if warnings.is_empty() {
                    self.info("Saved");
                } else {
                    let text: Vec<&str> = warnings.iter().map(|w| w.message.as_str()).collect();
                    self.info(format!("Saved ({})", text.join("; ")));
                }
                if let Some(cmd) = self.after_save.take() {
                    self.run(cmd);
                }
            }
            SiteOutcome::Created(id) => {
                if let Some(s) = self.snapshot.as_mut() {
                    s.tree.reveal(*id);
                }
                self.run(Cmd::Select(Some(*id)));
            }
            SiteOutcome::Renamed => self.info("Renamed"),
            SiteOutcome::Moved => {
                if let (Some(id), Some(s)) = (self.selected, self.snapshot.as_mut()) {
                    s.tree.reveal(id);
                }
                self.sync_cursor();
                self.info("Moved");
            }
            SiteOutcome::Deleted(n) => {
                self.selected = None;
                let rows = self.rows();
                self.cursor = self.cursor.min(rows.len().saturating_sub(1));
                self.select_row(rows.get(self.cursor).copied());
                self.rebuild_editor();
                self.info(format!("Deleted {}", plural(*n, "item")));
            }
            SiteOutcome::CopiedToVault { id, moved } => {
                self.run(Cmd::Select(Some(*id)));
                let vault = self
                    .tree_ref()
                    .and_then(|t| t.site(*id))
                    .and_then(|s| s.vault);
                let label = self
                    .root_info(vault)
                    .map_or_else(|| "the vault".to_owned(), |r| r.label());
                self.info(if *moved {
                    format!("Moved to {label}")
                } else {
                    format!("Copied to {label}")
                });
            }
            SiteOutcome::Override(form) => self.override_dialog(form),
            SiteOutcome::OverrideSaved(true) => {
                self.info("Your own login for this site was saved (synced to your devices only)");
            }
            SiteOutcome::OverrideSaved(false) => {
                self.info("Your own login was removed: the shared site's login is used");
            }
            SiteOutcome::Imported(report) => {
                if let Some(root) = report.root {
                    if let Some(s) = self.snapshot.as_mut() {
                        s.tree.set_expanded(root, true);
                    }
                    self.run(Cmd::Select(Some(root)));
                }
                let mut text = report.summary();
                for s in report.skipped.iter().take(8) {
                    text.push_str(&format!("\n• {}: {}", s.path, s.reason));
                }
                if report.skipped.len() > 8 {
                    text.push_str(&format!("\n… and {} more", report.skipped.len() - 8));
                }
                self.info(report.summary());
                let (modal, rx) = message("Import", &text);
                self.overlay(modal, rx, |_, ()| {});
            }
            SiteOutcome::NeedPassphrase(path) => {
                let path = path.clone();
                let (modal, rx) = prompt_password("Encrypted export", "Passphrase");
                self.overlay(modal, rx, move |view, pass: Option<SecretString>| {
                    if let Some(passphrase) = pass {
                        view.request(SiteOp::Import {
                            path,
                            passphrase: Some(passphrase),
                        });
                    }
                });
            }
            SiteOutcome::Exported { path, sites } => {
                self.info(format!(
                    "Exported {} to {}",
                    plural(*sites, "site"),
                    path.display()
                ));
            }
            SiteOutcome::Failed(e) => {
                self.after_save = None;
                self.error(e.clone());
            }
        }
    }

    // ---- keys

    /// Bracketed paste goes to the focused field.
    pub(crate) fn handle_paste(&mut self, text: &str) {
        if let Some(o) = self.overlay.as_mut() {
            o.modal.handle_paste(text);
        } else if let Some((_, input)) = self.rename.as_mut() {
            use crate::ui::dialog::Field;
            input.handle_paste(text);
        } else if self.focus == Pane::Editor
            && let Some(ed) = self.editor.as_mut()
        {
            ed.handle_paste(text);
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
        if self.locked || self.snapshot.is_none() || self.busy {
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => self.closed = true,
                KeyCode::Enter if self.locked => self.unlock_requested = true,
                _ => {}
            }
            return;
        }
        if self.rename.is_some() {
            self.rename_key(key);
            return;
        }
        if self.search.is_some() {
            self.search_key(key);
            return;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        if ctrl && key.code == KeyCode::Char('s') {
            self.save(None);
            return;
        }
        if alt && let Some(i) = self.buttons.clone().handle_key(key) {
            self.press(i);
            return;
        }
        match self.focus {
            Pane::Tree => self.tree_key(key),
            Pane::Editor => self.editor_key(key),
            Pane::Buttons => self.buttons_key(key),
        }
    }

    fn press(&mut self, button: usize) {
        match button {
            0 => self.connect(false),
            1 => self.connect(true),
            2 => self.save(None),
            3 => self.guarded(Cmd::Import),
            4 => self.guarded(Cmd::Export),
            _ => self.guarded(Cmd::Close),
        }
    }

    fn move_to(&mut self, row: usize) {
        let rows = self.rows();
        if rows.is_empty() {
            return;
        }
        let row = row.min(rows.len() - 1);
        match rows[row] {
            Row::Node { id, .. } if Some(id) != self.selected || self.root.is_some() => {
                self.guarded(Cmd::Select(Some(id)));
            }
            Row::Root(v) if self.root != Some(v) => self.guarded(Cmd::SelectRoot(v)),
            _ => {}
        }
    }

    fn set_expanded(&mut self, id: ItemId, expanded: bool) {
        if let Some(s) = self.snapshot.as_mut() {
            s.tree.set_expanded(id, expanded);
        }
        self.sync_cursor();
    }

    fn set_root_expanded(&mut self, vault: VaultId, expanded: bool) {
        if expanded {
            self.collapsed.remove(&vault);
        } else {
            self.collapsed.insert(vault);
        }
        self.sync_cursor();
    }

    /// Keys on a vault root row.
    fn root_key(&mut self, vault: VaultId, key: KeyEvent) -> bool {
        let expanded = !self.collapsed.contains(&vault);
        match key.code {
            KeyCode::Right | KeyCode::Char('l') if expanded => self.move_to(self.cursor + 1),
            KeyCode::Right | KeyCode::Char('l') => self.set_root_expanded(vault, true),
            KeyCode::Left | KeyCode::Char('h') => self.set_root_expanded(vault, false),
            KeyCode::Char(' ') | KeyCode::Enter => self.set_root_expanded(vault, !expanded),
            KeyCode::Char('d' | 'r' | 'x' | 'c' | 'm' | 'o') | KeyCode::Delete | KeyCode::F(2) => {
                self.error("Select a site or folder in the vault");
            }
            _ => return false,
        }
        true
    }

    fn tree_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if !ctrl
            && let Some(vault) = self.root
            && self.root_key(vault, key)
        {
            return;
        }
        let rows = self.rows();
        let current = self
            .selected
            .and_then(|id| self.node(id))
            .map(|n| (n.id(), n.as_folder().map(|f| f.expanded), n.parent()));
        let top_vault = self
            .selected
            .and_then(|id| self.node(id))
            .filter(|n| n.parent().is_none() && self.roots_mode())
            .and_then(|n| self.vault_of_node(n));
        match key.code {
            KeyCode::Char('x') if ctrl => self.cut(),
            KeyCode::Char('v') if ctrl => self.guarded(Cmd::Paste),
            _ if ctrl => {}
            KeyCode::Char('c') => self.copy_to_vault(false),
            KeyCode::Char('m') => self.copy_to_vault(true),
            KeyCode::Char('o') => self.edit_override(),
            KeyCode::Down | KeyCode::Char('j') => self.move_to(self.cursor + 1),
            KeyCode::Up | KeyCode::Char('k') => self.move_to(self.cursor.saturating_sub(1)),
            KeyCode::PageDown => self.move_to(self.cursor + 10),
            KeyCode::PageUp => self.move_to(self.cursor.saturating_sub(10)),
            KeyCode::Home | KeyCode::Char('g') => self.move_to(0),
            KeyCode::End | KeyCode::Char('G') => self.move_to(rows.len().saturating_sub(1)),
            KeyCode::Right | KeyCode::Char('l') => match current {
                Some((id, Some(false), _)) => self.set_expanded(id, true),
                Some((_, Some(true), _)) => self.move_to(self.cursor + 1),
                Some((_, None, _)) => self.focus_editor(false),
                None => {}
            },
            KeyCode::Left | KeyCode::Char('h') => match current {
                Some((id, Some(true), _)) => self.set_expanded(id, false),
                Some((_, _, Some(parent))) => {
                    if let Some(i) = rows.iter().position(|r| r.node() == Some(parent)) {
                        self.move_to(i);
                    }
                }
                _ => {
                    if let Some(v) = top_vault
                        && let Some(i) = rows.iter().position(|r| *r == Row::Root(v))
                    {
                        self.move_to(i);
                    }
                }
            },
            KeyCode::Char(' ') => {
                if let Some((id, Some(expanded), _)) = current {
                    self.set_expanded(id, !expanded);
                }
            }
            KeyCode::Enter => match current {
                Some((id, Some(expanded), _)) => self.set_expanded(id, !expanded),
                Some(_) => self.connect(false),
                None => {}
            },
            KeyCode::Tab => self.focus_editor(false),
            KeyCode::BackTab => self.focus = Pane::Buttons,
            KeyCode::Esc => self.guarded(Cmd::Close),
            KeyCode::Char('n') => self.guarded(Cmd::NewSite),
            KeyCode::Char('f') => self.guarded(Cmd::NewFolder),
            KeyCode::Char('d') => self.guarded(Cmd::Duplicate),
            KeyCode::Char('r') | KeyCode::F(2) => self.start_rename(),
            KeyCode::Char('x') | KeyCode::Delete => self.guarded(Cmd::Delete),
            KeyCode::Char('/') => self.search = Some(String::new()),
            _ => {}
        }
    }

    fn focus_editor(&mut self, backward: bool) {
        match self.editor.as_mut() {
            Some(ed) => {
                if ed.focused().is_none() || backward {
                    ed.enter(backward);
                }
                self.focus = Pane::Editor;
            }
            None => self.focus = Pane::Buttons,
        }
    }

    fn editor_key(&mut self, key: KeyEvent) {
        let Some(ed) = self.editor.as_mut() else {
            self.focus = Pane::Tree;
            return;
        };
        if key.code == KeyCode::Esc && !ed.is_capturing() {
            self.focus = Pane::Tree;
            return;
        }
        match ed.handle_key(key) {
            EditorKey::Consumed | EditorKey::Unhandled => {}
            EditorKey::LeaveForward => self.focus = Pane::Buttons,
            EditorKey::LeaveBackward => self.focus = Pane::Tree,
        }
    }

    fn buttons_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Tab => self.focus = Pane::Tree,
            KeyCode::BackTab => self.focus_editor(true),
            KeyCode::Esc => self.focus = Pane::Tree,
            _ => {
                if let Some(i) = self.buttons.handle_key(key) {
                    self.press(i);
                }
            }
        }
    }

    fn rename_key(&mut self, key: KeyEvent) {
        use crate::ui::dialog::{Field, FieldOutcome};
        let Some((id, input)) = self.rename.as_mut() else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.rename = None,
            KeyCode::Enter => {
                let (id, name) = (*id, input.text());
                self.rename = None;
                self.finish_rename(id, name);
            }
            _ => {
                let _: FieldOutcome = input.handle_key(key);
            }
        }
    }

    /// Type-to-search: the first site or folder (in tree order) whose name
    /// contains the query is revealed and selected.
    fn search_key(&mut self, key: KeyEvent) {
        let Some(query) = self.search.as_mut() else {
            return;
        };
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                self.search = None;
                return;
            }
            KeyCode::Backspace => {
                query.pop();
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => query.push(c),
            _ => return,
        }
        let needle = query.to_lowercase();
        if needle.is_empty() {
            return;
        }
        let found = self.tree_ref().and_then(|t| {
            t.walk()
                .into_iter()
                .find(|n| n.name().to_lowercase().contains(&needle))
                .map(SiteNode::id)
        });
        match found {
            Some(id) => {
                if let Some(s) = self.snapshot.as_mut() {
                    s.tree.reveal(id);
                }
                let top = self
                    .tree_ref()
                    .and_then(|t| t.ancestors(id).last().copied())
                    .unwrap_or(id);
                if let Some(v) = self.node(top).and_then(|n| self.vault_of_node(n)) {
                    self.collapsed.remove(&v);
                }
                self.sync_cursor();
                self.guarded(Cmd::Select(Some(id)));
            }
            None => self.error("No match"),
        }
    }

    // ---- drawing

    pub(crate) fn draw(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        frame.render_widget(Clear, area);
        let outer = Block::bordered()
            .title(" Site Manager ")
            .border_style(theme.focused_border);
        let inner = outer.inner(area);
        frame.render_widget(outer, area);
        if inner.height < 4 || inner.width < 30 {
            frame.render_widget(
                Paragraph::new("terminal too small").style(theme.error),
                inner,
            );
            return;
        }
        if self.locked {
            frame.render_widget(
                Paragraph::new(vec![
                    Line::raw(""),
                    Line::styled("Unlock the vault to view sites.", theme.title).centered(),
                    Line::raw(""),
                    Line::styled(
                        "Sites are kept in the vault. Enter unlocks it, Esc closes.",
                        theme.dim,
                    )
                    .centered(),
                ]),
                inner,
            );
            return;
        }
        let [body, buttons, hints] = Layout::vertical([
            Constraint::Min(3),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(inner);
        let tree_w = (body.width * 35 / 100).max(24).min(body.width / 2);
        let [tree_area, editor_area] =
            Layout::horizontal([Constraint::Length(tree_w), Constraint::Min(10)]).areas(body);
        self.draw_tree(frame, tree_area, theme);
        self.draw_editor(frame, editor_area, theme);
        self.buttons
            .draw(frame, buttons, self.focus == Pane::Buttons, theme);
        let (text, style) = match &self.message {
            Some((m, true)) => (m.clone(), theme.error),
            Some((m, false)) => (m.clone(), theme.title),
            None if self.busy => ("Working…".to_owned(), theme.dim),
            None if self.snapshot.is_none() => ("Loading sites…".to_owned(), theme.dim),
            None => (
                match self.focus {
                    Pane::Editor => EDITOR_HINTS,
                    _ if self.roots_mode() => VAULT_TREE_HINTS,
                    _ => TREE_HINTS,
                }
                .to_owned(),
                theme.dim,
            ),
        };
        frame.render_widget(Paragraph::new(Span::styled(text, style)), hints);
        if let Some(o) = self.overlay.as_mut() {
            o.modal.draw(frame, area, theme);
        }
    }

    fn draw_tree(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let focused = self.focus == Pane::Tree;
        let block = Block::bordered()
            .title(" My Sites ")
            .border_style(if focused {
                theme.focused_border
            } else {
                theme.border
            });
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let Some(tree) = self.tree_ref() else {
            frame.render_widget(Paragraph::new(Line::styled("Loading…", theme.dim)), inner);
            return;
        };
        let mut list_area = inner;
        if let Some(query) = &self.search {
            list_area.height = list_area.height.saturating_sub(1);
            frame.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled("/", theme.key_hint),
                    Span::raw(query.clone()),
                    Span::styled(" ", theme.selection),
                ])),
                Rect::new(inner.x, inner.bottom().saturating_sub(1), inner.width, 1),
            );
        }
        if tree.is_empty() && !self.roots_mode() {
            frame.render_widget(
                Paragraph::new(vec![
                    Line::styled("No sites yet.", theme.dim),
                    Line::styled("n: new site", theme.dim),
                    Line::styled("Alt-i: import", theme.dim),
                ]),
                list_area,
            );
            return;
        }
        let rows = self.rows();
        let height = usize::from(list_area.height.max(1));
        let start = self.cursor.saturating_sub(height - 1);
        let (open, closed, dot, lock) = if self.opts.unicode {
            ("▾ ", "▸ ", "● ", " 🔒")
        } else {
            ("v ", "> ", "o ", " [ro]")
        };
        let dirty_id = self
            .editor
            .as_ref()
            .filter(|e| e.is_dirty())
            .map(Editor::id);
        let roots = self.root_list();
        let lines: Vec<Line> = rows
            .iter()
            .enumerate()
            .skip(start)
            .take(height)
            .filter_map(|(i, row)| {
                let line = match *row {
                    Row::Root(v) => {
                        let root = roots.iter().find(|r| r.id == v)?;
                        let mut spans = vec![
                            Span::styled(
                                if self.collapsed.contains(&v) {
                                    closed
                                } else {
                                    open
                                },
                                theme.dim,
                            ),
                            Span::styled(root.label(), theme.title),
                        ];
                        if root.read_only {
                            spans.push(Span::styled(lock, theme.key_hint));
                        }
                        Line::from(spans)
                    }
                    Row::Node { depth, id } => {
                        let node = tree.get(id)?;
                        let mut spans = vec![Span::raw("  ".repeat(depth))];
                        if let Some((_, input)) = self.rename.as_ref().filter(|(rid, _)| *rid == id)
                        {
                            let text = input.text();
                            spans.push(Span::raw(match node {
                                SiteNode::Folder(_) => closed,
                                SiteNode::Site(_) => dot,
                            }));
                            spans.push(Span::styled(format!("{text} "), theme.selection));
                            return Some(Line::from(spans));
                        }
                        let read_only = match node {
                            SiteNode::Folder(f) => {
                                spans.push(Span::styled(
                                    if f.expanded { open } else { closed },
                                    theme.dim,
                                ));
                                spans.push(Span::styled(f.name.clone(), theme.dir));
                                f.read_only || self.locked_vault(f.vault).is_some()
                            }
                            SiteNode::Site(s) => {
                                let color =
                                    if s.color == courier_ftp_core::model::item::SiteColor::None {
                                        theme.dim
                                    } else {
                                        color_style(s.color)
                                    };
                                spans.push(Span::styled(dot, color));
                                spans.push(Span::raw(s.name.clone()));
                                s.read_only || self.locked_vault(s.vault).is_some()
                            }
                        };
                        if read_only {
                            spans.push(Span::styled(lock, theme.dim));
                        }
                        if dirty_id == Some(id) {
                            spans.push(Span::styled(" *", theme.key_hint));
                        }
                        if self.cut == Some(id) {
                            spans.push(Span::styled(" (cut)", theme.dim));
                        }
                        Line::from(spans)
                    }
                };
                Some(if i == self.cursor {
                    let style = if focused {
                        theme.selection
                    } else {
                        theme.title
                    };
                    line.style(style)
                } else {
                    line
                })
            })
            .collect();
        frame.render_widget(Paragraph::new(lines), list_area);
    }

    fn draw_editor(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let focused = self.focus == Pane::Editor;
        let block = Block::bordered().title(" Site ").border_style(if focused {
            theme.focused_border
        } else {
            theme.border
        });
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if let Some(ed) = &self.editor {
            ed.draw(frame, inner, focused, theme);
            return;
        }
        if let Some(root) = self.root.and_then(|v| self.root_info(Some(v))) {
            let mut text = vec![Line::styled(root.label(), theme.title), Line::raw("")];
            if root.personal {
                text.push(Line::raw("Your own sites: only your devices see them."));
            } else {
                text.push(Line::raw(
                    "Shared with your team (sync panel → Teams), end-to-end encrypted.",
                ));
            }
            text.push(Line::styled(
                if root.read_only {
                    "You can use these sites but not change them."
                } else {
                    "n adds a site here, f a folder; c/m copy or move a site to another vault."
                },
                theme.dim,
            ));
            frame.render_widget(
                Paragraph::new(text).wrap(ratatui::widgets::Wrap { trim: true }),
                inner,
            );
            return;
        }
        let text = match self.selected.and_then(|id| self.node(id)) {
            Some(node @ SiteNode::Folder(f)) => {
                let (folders, sites) = node.count();
                vec![
                    Line::styled(f.name.clone(), theme.title),
                    Line::raw(""),
                    Line::raw(format!(
                        "Folder with {} and {}.",
                        plural(folders - 1, "folder"),
                        plural(sites, "site")
                    )),
                    Line::styled("n adds a site here, f a folder.", theme.dim),
                ]
            }
            _ => vec![Line::styled(
                "Select a site to edit it, or press n to create one.",
                theme.dim,
            )],
        };
        frame.render_widget(Paragraph::new(text), inner);
    }
}

/// "1 site", "3 sites".
fn plural(n: usize, what: &str) -> String {
    if n == 1 {
        format!("1 {what}")
    } else {
        format!("{n} {what}s")
    }
}
