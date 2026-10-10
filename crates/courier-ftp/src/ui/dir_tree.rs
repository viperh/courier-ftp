//! The directory tree pane (T54): an optional folder tree beside or above
//! each file list, like FileZilla's upper panes.
//!
//! Children are listed lazily: a node's subdirectories are only asked for
//! when it is expanded and the tree is on screen ([`DirTree::take_requests`],
//! answered through the listing cache with [`Action::TreeListDir`]). Every
//! listing the side's file list receives also fills in the tree, and the
//! tree follows the file list: its current directory's ancestors are
//! expanded and the current directory scrolled into view
//! ([`DirTree::sync_to`]).
//!
//! [`Action::TreeListDir`]: crate::action::Action::TreeListDir

use std::collections::HashMap;

use courier_ftp_core::{backend::Listing, model::RemotePath};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{
    Side,
    panes::{block, spinner_frame},
    theme::Theme,
};
use crate::action::Action;

/// A subdirectory as the tree keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Child {
    name: String,
    hidden: bool,
}

/// What the tree knows about one directory.
#[derive(Debug, Default)]
struct Node {
    expanded: bool,
    /// Sorted subdirectories; `None` until listed.
    children: Option<Vec<Child>>,
    /// A listing was asked for and hasn't arrived yet.
    loading: bool,
    /// The cached listing changed (T46): list it again when shown.
    stale: bool,
    /// Why the last listing failed.
    error: Option<String>,
}

/// One visible row.
#[derive(Debug, Clone)]
struct Row {
    /// Index into `roots`.
    root: usize,
    path: RemotePath,
    depth: usize,
    /// Indent guides drawn before the marker.
    guides: String,
    label: String,
}

/// What the tree asks the screen to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TreeEffect {
    /// Show this directory in the side's file list.
    Navigate(RemotePath),
}

/// One side's directory tree.
pub(crate) struct DirTree {
    side: Side,
    unicode: bool,
    /// Top-level entries: label and directory. `/` for both sides; on
    /// Windows the local side adds Home and Desktop above the drive list.
    roots: Vec<(String, RemotePath)>,
    /// Whether Home and Desktop shortcuts are shown (Windows).
    shortcuts: bool,
    nodes: HashMap<RemotePath, Node>,
    /// The file list's directory.
    current: Option<RemotePath>,
    rows: Vec<Row>,
    cursor: usize,
    scroll: usize,
    /// Rows that fit, from the last draw.
    height: usize,
    show_hidden: bool,
    /// Move the cursor to the current directory once its row exists.
    reveal: bool,
    /// Center the cursor on the next draw (after a reveal), so the current
    /// directory's subdirectories show below it.
    center: bool,
    /// A node just expanded: scroll its children into view once they are
    /// known.
    follow: Option<RemotePath>,
    /// Remote: whether a connection is up.
    active: bool,
}

/// Actions the focused tree handles.
pub(crate) fn is_tree_action(action: &Action) -> bool {
    matches!(
        action,
        Action::CursorDown
            | Action::CursorUp
            | Action::PageDown
            | Action::PageUp
            | Action::HalfPageDown
            | Action::HalfPageUp
            | Action::Top
            | Action::Bottom
            | Action::Open
            | Action::ParentDir
    )
}

impl DirTree {
    pub(crate) fn new(side: Side, unicode: bool, show_hidden: bool) -> Self {
        let shortcuts = side == Side::Local && cfg!(windows);
        Self::with_shortcuts(side, unicode, show_hidden, shortcuts)
    }

    /// A tree with or without the Windows Home/Desktop shortcuts (tests use
    /// it on every OS).
    pub(crate) fn with_shortcuts(
        side: Side,
        unicode: bool,
        show_hidden: bool,
        shortcuts: bool,
    ) -> Self {
        let root_label = if shortcuts { "Computer" } else { "/" };
        let mut tree = Self {
            side,
            unicode,
            roots: vec![(root_label.to_owned(), RemotePath::root())],
            shortcuts,
            nodes: HashMap::new(),
            current: None,
            rows: Vec::new(),
            cursor: 0,
            scroll: 0,
            height: 1,
            show_hidden,
            reveal: false,
            center: false,
            follow: None,
            active: side == Side::Local,
        };
        tree.node(&RemotePath::root()).expanded = true;
        tree.rebuild();
        tree
    }

    fn node(&mut self, dir: &RemotePath) -> &mut Node {
        self.nodes.entry(dir.clone()).or_default()
    }

    /// The home directory is known: on Windows, add the Home and Desktop
    /// shortcuts at the top.
    pub(crate) fn set_home(&mut self, home: &RemotePath) {
        if !self.shortcuts || self.roots.len() > 1 {
            return;
        }
        let mut shortcuts = vec![("Home".to_owned(), home.clone())];
        if let Ok(desktop) = home.join("Desktop") {
            shortcuts.push(("Desktop".to_owned(), desktop));
        }
        self.roots.splice(0..0, shortcuts);
        self.rebuild();
    }

    /// Forget everything (remote: connecting or disconnected).
    pub(crate) fn reset(&mut self) {
        self.nodes.clear();
        self.current = None;
        self.cursor = 0;
        self.scroll = 0;
        self.reveal = false;
        self.active = self.side == Side::Local;
        self.node(&RemotePath::root()).expanded = true;
        self.rebuild();
    }

    /// Remote: a connection is up, listings can be asked for.
    pub(crate) fn set_active(&mut self, active: bool) {
        self.active = active;
    }

    /// Follow the file list's hidden-files toggle.
    pub(crate) fn set_show_hidden(&mut self, show: bool) {
        if self.show_hidden != show {
            self.show_hidden = show;
            self.rebuild();
        }
    }

    /// The directory the file list shows.
    #[cfg(test)]
    pub(crate) fn current(&self) -> Option<&RemotePath> {
        self.current.as_ref()
    }

    /// The directory under the cursor.
    pub(crate) fn cursor_path(&self) -> Option<&RemotePath> {
        self.rows.get(self.cursor).map(|r| &r.path)
    }

    /// The file list moved to `dir`: expand it and its ancestors and scroll
    /// it into view.
    pub(crate) fn sync_to(&mut self, dir: &RemotePath) {
        if self.current.as_ref() == Some(dir) {
            return;
        }
        self.current = Some(dir.clone());
        self.reveal = true;
        for ancestor in ancestors(dir) {
            self.node(&ancestor).expanded = true;
        }
        self.node(dir).expanded = true;
        // Expanded shortcut roots (Windows) that lead to `dir` too.
        let roots: Vec<RemotePath> = self.roots.iter().map(|(_, p)| p.clone()).collect();
        for root in roots.iter().filter(|r| dir.starts_with(r) && *r != dir) {
            self.node(root).expanded = true;
        }
        self.keep_current_path();
        self.rebuild();
    }

    /// A listing of `listing.dir` arrived (for the tree or the file list).
    pub(crate) fn listing(&mut self, listing: &Listing) {
        let mut children: Vec<Child> = listing
            .entries
            .iter()
            .filter(|e| e.is_dir_like())
            .map(|e| Child {
                name: e.name.clone(),
                hidden: e.hidden,
            })
            .collect();
        sort_children(&mut children);
        let node = self.node(&listing.dir);
        node.children = Some(children);
        node.loading = false;
        node.stale = false;
        node.error = None;
        self.keep_current_path();
        self.rebuild();
    }

    /// The path to the current directory always shows, even when a listing
    /// on the way (an older cached one) doesn't have the next step.
    fn keep_current_path(&mut self) {
        let Some(cur) = self.current.clone() else {
            return;
        };
        let mut path = ancestors(&cur);
        path.push(cur);
        for pair in path.windows(2) {
            let (dir, next) = (&pair[0], &pair[1]);
            let Some(name) = next.file_name() else {
                continue;
            };
            if let Some(children) = self.nodes.get_mut(dir).and_then(|n| n.children.as_mut())
                && !children.iter().any(|c| c.name == name)
            {
                children.push(Child {
                    name: name.to_owned(),
                    hidden: name.starts_with('.'),
                });
                sort_children(children);
            }
        }
    }

    /// The listing asked for with [`Action::TreeListDir`] finished.
    pub(crate) fn loaded(&mut self, dir: &RemotePath, result: &Result<Listing, String>) {
        match result {
            Ok(listing) => self.listing(listing),
            Err(e) => {
                tracing::debug!(dir = %dir, error = %e, "tree listing failed");
                let node = self.node(dir);
                node.loading = false;
                node.stale = false;
                if node.children.is_none() {
                    node.children = Some(Vec::new());
                }
                node.error = Some(e.clone());
                self.rebuild();
            }
        }
    }

    /// The cached listing of `dir` changed (create/delete/rename, T46):
    /// list it again when it is shown.
    pub(crate) fn invalidate(&mut self, dir: &RemotePath) {
        if let Some(node) = self.nodes.get_mut(dir)
            && node.children.is_some()
        {
            node.stale = true;
        }
    }

    /// The directories to list now: expanded, on-screen nodes whose children
    /// are unknown or stale. They are marked as loading.
    pub(crate) fn take_requests(&mut self) -> Vec<RemotePath> {
        if !self.active {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut stack: Vec<RemotePath> = self.roots.iter().rev().map(|(_, p)| p.clone()).collect();
        // The path to the current directory is listed in parallel rather
        // than one level per round trip.
        if let Some(cur) = &self.current {
            stack.extend(ancestors(cur).into_iter().rev());
        }
        while let Some(dir) = stack.pop() {
            let Some(node) = self.nodes.get_mut(&dir) else {
                continue;
            };
            if !node.expanded {
                continue;
            }
            if (node.children.is_none() || node.stale) && !node.loading {
                node.loading = true;
                out.push(dir.clone());
            }
            if let Some(children) = &node.children {
                for c in children.iter().rev() {
                    if let Ok(path) = dir.join(&c.name) {
                        stack.push(path);
                    }
                }
            }
        }
        if !out.is_empty() {
            self.rebuild();
        }
        out
    }

    fn visible_child(&self, dir: &RemotePath, child: &Child) -> bool {
        if !child.hidden || self.show_hidden {
            return true;
        }
        // A hidden directory on the way to the current one stays visible.
        self.current
            .as_ref()
            .zip(dir.join(&child.name).ok())
            .is_some_and(|(cur, path)| cur.starts_with(&path))
    }

    /// Recompute the visible rows, keeping the cursor on the same directory.
    fn rebuild(&mut self) {
        let keep = self.rows.get(self.cursor).map(|r| (r.root, r.path.clone()));
        let mut rows = Vec::new();
        for (i, (label, path)) in self.roots.iter().enumerate() {
            rows.push(Row {
                root: i,
                path: path.clone(),
                depth: 0,
                guides: String::new(),
                label: label.clone(),
            });
            self.push_children(&mut rows, i, path, 1, "");
        }
        self.rows = rows;
        let reveal = self.reveal.then(|| self.current.clone()).flatten();
        let found = reveal.as_ref().and_then(|cur| {
            // The deepest root holding it (a Windows shortcut beats the
            // drive list).
            self.rows
                .iter()
                .enumerate()
                .filter(|(_, r)| &r.path == cur)
                .max_by_key(|(_, r)| self.roots[r.root].1.components().count())
                .map(|(i, _)| i)
        });
        if let Some(i) = found {
            self.cursor = i;
            self.reveal = false;
            self.center = true;
        } else if let Some((root, path)) = keep {
            self.cursor = self
                .rows
                .iter()
                .position(|r| r.root == root && r.path == path)
                .unwrap_or(self.cursor);
        }
        self.cursor = self.cursor.min(self.rows.len().saturating_sub(1));
    }

    fn push_children(
        &self,
        rows: &mut Vec<Row>,
        root: usize,
        dir: &RemotePath,
        depth: usize,
        prefix: &str,
    ) {
        let Some(node) = self.nodes.get(dir) else {
            return;
        };
        if !node.expanded {
            return;
        }
        let Some(children) = &node.children else {
            return;
        };
        let shown: Vec<&Child> = children
            .iter()
            .filter(|c| self.visible_child(dir, c))
            .collect();
        let (tee, elbow, bar, blank) = if self.unicode {
            ("├─", "└─", "│ ", "  ")
        } else {
            ("|-", "`-", "| ", "  ")
        };
        for (i, c) in shown.iter().enumerate() {
            let last = i + 1 == shown.len();
            let Ok(path) = dir.join(&c.name) else {
                continue;
            };
            rows.push(Row {
                root,
                path: path.clone(),
                depth,
                guides: format!("{prefix}{}", if last { elbow } else { tee }),
                label: c.name.clone(),
            });
            let next = format!("{prefix}{}", if last { blank } else { bar });
            self.push_children(rows, root, &path, depth + 1, &next);
        }
    }

    fn marker(&self, path: &RemotePath) -> &'static str {
        let node = self.nodes.get(path);
        let (expanded, collapsed) = if self.unicode {
            ("▾", "▸")
        } else {
            ("-", "+")
        };
        match node {
            Some(n) if n.loading && n.children.is_none() => "?",
            Some(n) if n.error.is_some() => "!",
            Some(Node {
                children: Some(c), ..
            }) if c.is_empty() => " ",
            Some(n) if n.expanded => expanded,
            _ => collapsed,
        }
    }

    fn move_cursor(&mut self, delta: isize) {
        let last = self.rows.len().saturating_sub(1);
        self.cursor = self.cursor.saturating_add_signed(delta).min(last);
    }

    /// Apply a navigation action while the tree has focus.
    pub(crate) fn update(&mut self, action: &Action) -> Option<TreeEffect> {
        let page = self.height.max(1) as isize;
        match action {
            Action::CursorDown => self.move_cursor(1),
            Action::CursorUp => self.move_cursor(-1),
            Action::PageDown => self.move_cursor(page),
            Action::PageUp => self.move_cursor(-page),
            Action::HalfPageDown => self.move_cursor(page / 2),
            Action::HalfPageUp => self.move_cursor(-(page / 2)),
            Action::Top => self.cursor = 0,
            Action::Bottom => self.cursor = self.rows.len().saturating_sub(1),
            Action::Open => self.expand_or_enter(),
            Action::ParentDir => self.collapse_or_parent(),
            _ => {}
        }
        None
    }

    /// `l`/`→`: expand the node under the cursor, or step into its first
    /// child when it is already expanded.
    fn expand_or_enter(&mut self) {
        let Some(row) = self.rows.get(self.cursor).cloned() else {
            return;
        };
        let node = self.node(&row.path);
        if node.expanded {
            if self
                .rows
                .get(self.cursor + 1)
                .is_some_and(|next| next.depth > row.depth)
            {
                self.cursor += 1;
            }
        } else {
            node.expanded = true;
            // An error from a previous attempt: try again.
            if node.error.take().is_some() {
                node.children = None;
            }
            self.follow = Some(row.path);
            self.rebuild();
        }
    }

    /// `h`/`←`: collapse the node under the cursor, or go to its parent.
    fn collapse_or_parent(&mut self) {
        let Some(row) = self.rows.get(self.cursor).cloned() else {
            return;
        };
        if let Some(node) = self.nodes.get_mut(&row.path)
            && node.expanded
        {
            node.expanded = false;
            self.rebuild();
            return;
        }
        if let Some(parent) = self.rows[..self.cursor]
            .iter()
            .rposition(|r| r.depth + 1 == row.depth)
        {
            self.cursor = parent;
        }
    }

    /// `Enter` shows the directory under the cursor in the file list.
    /// Returns `None` for keys the tree doesn't take itself.
    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> Option<Option<TreeEffect>> {
        if key.code != KeyCode::Enter || !key.modifiers.is_empty() {
            return None;
        }
        Some(self.cursor_path().cloned().map(TreeEffect::Navigate))
    }

    fn loading(&self) -> bool {
        self.nodes.values().any(|n| n.loading)
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
            Side::Local => " Local tree ",
            Side::Remote => " Remote tree ",
        };
        let mut title = vec![Span::styled(label, theme.title)];
        if self.active && self.loading() {
            title.push(Span::raw(format!("{} ", spinner_frame(tick))));
        }
        let outer = block(Line::from(title), focused, theme);
        let inner = outer.inner(area);
        frame.render_widget(outer, area);
        if inner.height == 0 || inner.width == 0 {
            return;
        }
        if !self.active {
            frame.render_widget(
                Paragraph::new(Line::styled("Not connected.", theme.dim)),
                inner,
            );
            return;
        }
        self.height = usize::from(inner.height);
        if std::mem::take(&mut self.center) {
            self.scroll = self.cursor.saturating_sub(self.height / 2);
        } else if self.cursor < self.scroll {
            self.scroll = self.cursor;
        } else if self.cursor >= self.scroll + self.height {
            self.scroll = self.cursor + 1 - self.height;
        }
        if let Some(path) = self.follow.clone()
            && self.cursor_path() == Some(&path)
        {
            // The last row of the expanded subtree, once it has rows; the
            // cursor stays on screen.
            let depth = self.rows[self.cursor].depth;
            let end = self.rows[self.cursor + 1..]
                .iter()
                .position(|r| r.depth <= depth)
                .map_or(self.rows.len(), |n| self.cursor + 1 + n)
                - 1;
            if end > self.cursor {
                if end >= self.scroll + self.height {
                    self.scroll = (end + 1 - self.height).min(self.cursor);
                }
                self.follow = None;
            }
        } else {
            self.follow = None;
        }
        self.scroll = self.scroll.min(self.rows.len().saturating_sub(self.height));
        let width = usize::from(inner.width);
        let cursor_style = if focused {
            theme.selection
        } else {
            Style::new().add_modifier(Modifier::UNDERLINED)
        };
        let lines: Vec<Line> = self
            .rows
            .iter()
            .enumerate()
            .skip(self.scroll)
            .take(self.height)
            .map(|(i, row)| {
                let is_current = self.current.as_ref() == Some(&row.path);
                let mut name_style = theme.dir;
                if is_current {
                    name_style = name_style.add_modifier(Modifier::REVERSED);
                }
                let marker = self.marker(&row.path);
                let lead = format!("{}{marker} ", row.guides);
                let room = width.saturating_sub(lead.chars().count());
                let label: String = if row.label.chars().count() > room {
                    let mut s: String = row.label.chars().take(room.saturating_sub(1)).collect();
                    s.push('…');
                    s
                } else {
                    row.label.clone()
                };
                let mut spans = vec![
                    Span::styled(row.guides.clone(), theme.dim),
                    Span::raw(format!("{marker} ")),
                    Span::styled(label, name_style),
                ];
                if i == self.cursor {
                    let used: usize = spans.iter().map(|s| s.content.chars().count()).sum();
                    spans.push(Span::raw(" ".repeat(width.saturating_sub(used))));
                    for s in &mut spans {
                        s.style = s.style.patch(cursor_style);
                    }
                }
                Line::from(spans)
            })
            .collect();
        frame.render_widget(Paragraph::new(lines), inner);
    }
}

fn sort_children(children: &mut [Child]) {
    children.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then_with(|| a.name.cmp(&b.name))
    });
}

/// `dir`'s proper ancestors, from the root down.
fn ancestors(dir: &RemotePath) -> Vec<RemotePath> {
    let mut out = Vec::new();
    let mut cur = dir.parent();
    while let Some(p) = cur {
        cur = p.parent();
        out.push(p);
    }
    out.reverse();
    out
}

#[cfg(test)]
mod tests;
