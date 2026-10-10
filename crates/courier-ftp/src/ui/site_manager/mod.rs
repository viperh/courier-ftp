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

use courier_ftp_core::{
    model::{Protocol, item::ItemId},
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

pub(crate) use editor::FieldId;
use editor::{EditorKey, color_style};
pub(crate) use picker::{site_paths, site_picker};

use super::{
    dialog::{
        ButtonRow, Form, FormDialog, LocalPathCompleter, PathInput, Select, TextInput, ask,
        confirm, message, prompt_password, prompt_text,
    },
    modal::{Modal, ModalOutcome},
    theme::Theme,
};
use crate::sites::{ExportFormat, SiteOp, SiteOutcome, SitesReply, Snapshot};

pub(crate) use editor::Editor;

/// Keys of the tree, shown at the bottom.
pub(crate) const TREE_HINTS: &str = "n new · f folder · d dup · r rename · x delete · ^x/^v move · / search · Enter connect · Esc close";
/// Keys of the editor, shown at the bottom.
pub(crate) const EDITOR_HINTS: &str =
    "Tab next field · [ ] or ^PgUp/^PgDn tabs · ^s save · Alt-c connect · Esc back to the tree";

const BUTTONS: [&str; 5] = ["Connect", "Save", "Import…", "Export…", "Close"];

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
    Close,
    NewSite,
    NewFolder,
    Duplicate,
    Delete,
    Paste,
    Import,
    Export,
    Connect(ItemId),
}

type Then = Box<dyn FnOnce(&mut SiteManagerView) + Send>;

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

    /// The visible rows: (depth, id).
    fn rows(&self) -> Vec<(usize, ItemId)> {
        self.tree_ref()
            .map(|t| {
                t.visible_rows()
                    .iter()
                    .map(|r| (r.depth, r.node.id()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn node(&self, id: ItemId) -> Option<&SiteNode> {
        self.tree_ref()?.get(id)
    }

    fn info(&mut self, text: impl Into<String>) {
        self.message = Some((text.into(), false));
    }

    fn error(&mut self, text: impl Into<String>) {
        self.message = Some((text.into(), true));
    }

    fn request(&mut self, op: SiteOp) {
        if !matches!(op, SiteOp::Connect(_)) {
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
        let store_passwords = self.opts.store_passwords;
        if let Some(ed) = self.editor.as_ref() {
            let id = ed.id();
            let stored = self.tree_ref().and_then(|t| t.site(id)).cloned();
            let bookmarks = self.bookmarks_of(id);
            match stored {
                Some(stored) if !ed.is_new() => {
                    if let Some(ed) = self.editor.as_mut() {
                        if ed.is_dirty() {
                            ed.tree_changed(&stored.name, stored.parent);
                            ed.set_bookmarks(bookmarks);
                        } else {
                            let mut fresh = Editor::new(stored, false, store_passwords, bookmarks);
                            fresh.keep_place(ed);
                            *ed = fresh;
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
        if self.selected.is_none() {
            let rows = self.rows();
            let row = self.cursor.min(rows.len().saturating_sub(1));
            self.selected = rows.get(row).map(|r| r.1);
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
        let mut editor = Editor::new(site, true, self.opts.store_passwords, Vec::new());
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
        self.editor = site.map(|s| {
            let bookmarks = self.bookmarks_of(s.id);
            Editor::new(s, false, self.opts.store_passwords, bookmarks)
        });
    }

    fn sync_cursor(&mut self) {
        let rows = self.rows();
        if let Some(id) = self.selected
            && let Some(i) = rows.iter().position(|r| r.1 == id)
        {
            self.cursor = i;
            return;
        }
        self.cursor = self.cursor.min(rows.len().saturating_sub(1));
    }

    fn dirty(&self) -> bool {
        self.editor.as_ref().is_some_and(Editor::is_dirty)
    }

    /// The folder new entries go into: the selected folder, or the selected
    /// site's folder.
    fn context_folder(&self) -> Option<ItemId> {
        let node = self.node(self.selected?)?;
        if node.is_folder() {
            Some(node.id())
        } else {
            node.parent()
        }
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
            Cmd::Import | Cmd::Export | Cmd::Connect(_) | Cmd::NewFolder => true,
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
                if id != self.editor.as_ref().map(Editor::id) {
                    self.selected = id;
                    self.rebuild_editor();
                }
                self.sync_cursor();
            }
            Cmd::Close => self.closed = true,
            Cmd::NewSite => self.new_site(),
            Cmd::NewFolder => self.new_folder(),
            Cmd::Duplicate => match self.selected {
                Some(id) => self.request(SiteOp::Duplicate(id)),
                None => self.error("Nothing selected"),
            },
            Cmd::Delete => self.delete(),
            Cmd::Paste => self.paste(),
            Cmd::Import => self.import(),
            Cmd::Export => self.export(),
            Cmd::Connect(id) => {
                self.request(SiteOp::Connect(id));
                self.closed = true;
            }
        }
    }

    fn new_site(&mut self) {
        let parent = self.context_folder();
        let suggested = self
            .tree_ref()
            .map(|t| t.unique_name(parent, "New site"))
            .unwrap_or_else(|| "New site".to_owned());
        let (modal, rx) = prompt_text("New site", "Name", &suggested);
        self.overlay(modal, rx, move |view, name| {
            if let Some(name) = name {
                let mut site = Site::new(name, Protocol::Sftp, "");
                site.parent = parent;
                view.add_new_site(site);
            }
        });
    }

    fn new_folder(&mut self) {
        let parent = self.context_folder();
        let suggested = self
            .tree_ref()
            .map(|t| t.unique_name(parent, "New folder"))
            .unwrap_or_else(|| "New folder".to_owned());
        let (modal, rx) = prompt_text("New folder", "Name", &suggested);
        self.overlay(modal, rx, move |view, name| {
            if let Some(name) = name {
                view.request(SiteOp::AddFolder { parent, name });
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
            self.selected = self.rows().get(self.cursor).map(|r| r.1);
            self.rebuild_editor();
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
        let parent = self.context_folder();
        self.request(SiteOp::Move { id, parent });
    }

    fn start_rename(&mut self) {
        let Some(id) = self.selected else {
            return;
        };
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

    /// Connect to the selected site, saving first when it has changes.
    fn connect(&mut self) {
        let Some(id) = self.selected else {
            self.error("Select a site to connect to");
            return;
        };
        if self.node(id).is_some_and(SiteNode::is_folder) {
            self.error("Select a site to connect to");
            return;
        }
        if self.dirty() {
            self.save(Some(Cmd::Connect(id)));
        } else {
            self.run(Cmd::Connect(id));
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
                        let mut fresh = Editor::new(
                            stored,
                            false,
                            self.opts.store_passwords,
                            self.bookmarks_of(*id),
                        );
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
                self.selected = rows.get(self.cursor).map(|r| r.1);
                self.rebuild_editor();
                self.info(format!("Deleted {}", plural(*n, "item")));
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
            0 => self.connect(),
            1 => self.save(None),
            2 => self.guarded(Cmd::Import),
            3 => self.guarded(Cmd::Export),
            _ => self.guarded(Cmd::Close),
        }
    }

    fn move_to(&mut self, row: usize) {
        let rows = self.rows();
        if rows.is_empty() {
            return;
        }
        let row = row.min(rows.len() - 1);
        let id = rows[row].1;
        if Some(id) != self.selected {
            self.guarded(Cmd::Select(Some(id)));
        }
    }

    fn set_expanded(&mut self, id: ItemId, expanded: bool) {
        if let Some(s) = self.snapshot.as_mut() {
            s.tree.set_expanded(id, expanded);
        }
        self.sync_cursor();
    }

    fn tree_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let rows = self.rows();
        let current = self
            .selected
            .and_then(|id| self.node(id))
            .map(|n| (n.id(), n.as_folder().map(|f| f.expanded), n.parent()));
        match key.code {
            KeyCode::Char('x') if ctrl => self.cut(),
            KeyCode::Char('v') if ctrl => self.guarded(Cmd::Paste),
            _ if ctrl => {}
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
                    if let Some(i) = rows.iter().position(|r| r.1 == parent) {
                        self.move_to(i);
                    }
                }
                _ => {}
            },
            KeyCode::Char(' ') => {
                if let Some((id, Some(expanded), _)) = current {
                    self.set_expanded(id, !expanded);
                }
            }
            KeyCode::Enter => match current {
                Some((id, Some(expanded), _)) => self.set_expanded(id, !expanded),
                Some(_) => self.connect(),
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
        if tree.is_empty() {
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
        let rows = tree.visible_rows();
        let height = usize::from(list_area.height.max(1));
        let start = self.cursor.saturating_sub(height - 1);
        let (open, closed, dot) = if self.opts.unicode {
            ("▾ ", "▸ ", "● ")
        } else {
            ("v ", "> ", "o ")
        };
        let dirty_id = self
            .editor
            .as_ref()
            .filter(|e| e.is_dirty())
            .map(Editor::id);
        let lines: Vec<Line> = rows
            .iter()
            .enumerate()
            .skip(start)
            .take(height)
            .map(|(i, row)| {
                let id = row.node.id();
                let mut spans = vec![Span::raw("  ".repeat(row.depth))];
                if let Some((rid, input)) = self.rename.as_ref().filter(|(rid, _)| *rid == id) {
                    let _ = rid;
                    let text = input.text();
                    spans.push(Span::raw(match row.node {
                        SiteNode::Folder(_) => closed,
                        SiteNode::Site(_) => dot,
                    }));
                    spans.push(Span::styled(format!("{text} "), theme.selection));
                    return Line::from(spans);
                }
                match row.node {
                    SiteNode::Folder(f) => {
                        spans.push(Span::styled(
                            if f.expanded { open } else { closed },
                            theme.dim,
                        ));
                        spans.push(Span::styled(f.name.clone(), theme.dir));
                    }
                    SiteNode::Site(s) => {
                        let color = if s.color == courier_ftp_core::model::item::SiteColor::None {
                            theme.dim
                        } else {
                            color_style(s.color)
                        };
                        spans.push(Span::styled(dot, color));
                        spans.push(Span::raw(s.name.clone()));
                    }
                }
                if dirty_id == Some(id) {
                    spans.push(Span::styled(" *", theme.key_hint));
                }
                if self.cut == Some(id) {
                    spans.push(Span::styled(" (cut)", theme.dim));
                }
                let line = Line::from(spans);
                if i == self.cursor {
                    let style = if focused {
                        theme.selection
                    } else {
                        theme.title
                    };
                    line.style(style)
                } else {
                    line
                }
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
