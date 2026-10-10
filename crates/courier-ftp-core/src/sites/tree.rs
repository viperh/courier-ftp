//! [`SiteTree`]: the folder tree of the Site Manager, with the pure (in-memory)
//! tree operations. [`SiteManager`](super::SiteManager) runs them on a copy
//! and writes the result to the vault.
//!
//! Children are always sorted: folders first, then by name (case-insensitive),
//! as in FileZilla. There is no manual order.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::model::item::{ItemId, UnixMillis, VaultId};

use super::{Site, SiteError, validate_name};

/// The suffix [`SiteTree::duplicate`] adds to a copy's name.
pub const COPY_SUFFIX: &str = " (copy)";

/// A Site Manager folder.
#[derive(Debug, Clone, PartialEq)]
pub struct Folder {
    /// The `site-folder` item's id.
    pub id: ItemId,
    /// The vault the item lives in (`None` until saved).
    pub vault: Option<VaultId>,
    /// The folder it is in (`None` = top level).
    pub parent: Option<ItemId>,
    /// Name (no `/`).
    pub name: String,
    /// Sites and folders in it, sorted.
    pub children: Vec<SiteNode>,
    /// Expanded in the tree view. UI state: kept across reloads, not stored.
    pub expanded: bool,
    /// The item comes from a newer courier-ftp.
    pub read_only: bool,
}

impl Folder {
    /// A new, empty, collapsed folder (new id).
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: ItemId::new(),
            vault: None,
            parent: None,
            name: name.into(),
            children: Vec::new(),
            expanded: false,
            read_only: false,
        }
    }
}

/// A node of the tree.
#[derive(Debug, Clone, PartialEq)]
pub enum SiteNode {
    /// A folder and its contents.
    Folder(Folder),
    /// A site.
    Site(Box<Site>),
}

impl SiteNode {
    /// Item id.
    pub fn id(&self) -> ItemId {
        match self {
            Self::Folder(f) => f.id,
            Self::Site(s) => s.id,
        }
    }

    /// Name.
    pub fn name(&self) -> &str {
        match self {
            Self::Folder(f) => &f.name,
            Self::Site(s) => &s.name,
        }
    }

    /// The containing folder.
    pub fn parent(&self) -> Option<ItemId> {
        match self {
            Self::Folder(f) => f.parent,
            Self::Site(s) => s.parent,
        }
    }

    /// The vault (`None` until saved).
    pub fn vault(&self) -> Option<VaultId> {
        match self {
            Self::Folder(f) => f.vault,
            Self::Site(s) => s.vault,
        }
    }

    /// Whether it is a folder.
    pub fn is_folder(&self) -> bool {
        matches!(self, Self::Folder(_))
    }

    /// The site, if it is one.
    pub fn as_site(&self) -> Option<&Site> {
        match self {
            Self::Site(s) => Some(s),
            Self::Folder(_) => None,
        }
    }

    /// The folder, if it is one.
    pub fn as_folder(&self) -> Option<&Folder> {
        match self {
            Self::Folder(f) => Some(f),
            Self::Site(_) => None,
        }
    }

    fn set_parent(&mut self, parent: Option<ItemId>) {
        match self {
            Self::Folder(f) => f.parent = parent,
            Self::Site(s) => s.parent = parent,
        }
    }

    fn set_name(&mut self, name: String) {
        match self {
            Self::Folder(f) => f.name = name,
            Self::Site(s) => s.name = name,
        }
    }

    /// This node and everything below it, parents before children.
    pub fn walk(&self) -> Vec<&SiteNode> {
        let mut out = vec![self];
        if let Self::Folder(f) = self {
            for c in &f.children {
                out.extend(c.walk());
            }
        }
        out
    }

    /// `(folders, sites)` in this node's subtree, itself included (for the
    /// "delete folder with N sites?" confirmation).
    pub fn count(&self) -> (usize, usize) {
        self.walk().iter().fold((0, 0), |(f, s), n| {
            if n.is_folder() {
                (f + 1, s)
            } else {
                (f, s + 1)
            }
        })
    }
}

/// The folder ordering: folders first, then name (case-insensitive), then
/// exact name and id so the order is total.
fn order(a: &SiteNode, b: &SiteNode) -> Ordering {
    b.is_folder()
        .cmp(&a.is_folder())
        .then_with(|| a.name().to_lowercase().cmp(&b.name().to_lowercase()))
        .then_with(|| a.name().cmp(b.name()))
        .then_with(|| a.id().cmp(&b.id()))
}

/// One visible row of the tree view.
#[derive(Debug, Clone, Copy)]
pub struct TreeRow<'a> {
    /// Nesting depth (0 = top level).
    pub depth: usize,
    /// The node.
    pub node: &'a SiteNode,
}

/// The whole Site Manager tree (the top level is a list, not a folder).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SiteTree {
    roots: Vec<SiteNode>,
}

impl SiteTree {
    /// An empty tree.
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuilds the tree from flat items, as loaded from the vault.
    ///
    /// Synced data can be inconsistent, so: a folder or site whose parent is
    /// missing (or is not a folder) goes to the top level, and a folder cycle
    /// (two devices moving folders into each other offline) is broken by
    /// moving its lowest-id folder to the top level. Nothing is lost.
    pub fn from_items(folders: Vec<Folder>, sites: Vec<Site>) -> Self {
        let mut parents: BTreeMap<ItemId, Option<ItemId>> =
            folders.iter().map(|f| (f.id, f.parent)).collect();
        // Missing parents.
        let ids: BTreeSet<ItemId> = parents.keys().copied().collect();
        for p in parents.values_mut() {
            if p.is_some_and(|id| !ids.contains(&id)) {
                *p = None;
            }
        }
        // Cycles.
        for &start in &ids {
            let mut path = vec![start];
            let mut cur = parents.get(&start).copied().flatten();
            while let Some(p) = cur {
                if let Some(pos) = path.iter().position(|&x| x == p) {
                    if let Some(&lowest) = path[pos..].iter().min() {
                        parents.insert(lowest, None);
                    }
                    break;
                }
                path.push(p);
                cur = parents.get(&p).copied().flatten();
            }
        }

        let mut children: BTreeMap<Option<ItemId>, Vec<SiteNode>> = BTreeMap::new();
        for mut f in folders {
            let parent = parents.get(&f.id).copied().flatten();
            f.parent = parent;
            f.children.clear();
            children
                .entry(parent)
                .or_default()
                .push(SiteNode::Folder(f));
        }
        for mut s in sites {
            if s.parent.is_some_and(|p| !ids.contains(&p)) {
                s.parent = None;
            }
            children
                .entry(s.parent)
                .or_default()
                .push(SiteNode::Site(Box::new(s)));
        }

        fn attach(
            nodes: Vec<SiteNode>,
            children: &mut BTreeMap<Option<ItemId>, Vec<SiteNode>>,
        ) -> Vec<SiteNode> {
            let mut nodes: Vec<SiteNode> = nodes
                .into_iter()
                .map(|n| match n {
                    SiteNode::Folder(mut f) => {
                        let kids = children.remove(&Some(f.id)).unwrap_or_default();
                        f.children = attach(kids, children);
                        SiteNode::Folder(f)
                    }
                    site => site,
                })
                .collect();
            nodes.sort_by(order);
            nodes
        }
        let top = children.remove(&None).unwrap_or_default();
        Self {
            roots: attach(top, &mut children),
        }
    }

    /// The top-level nodes.
    pub fn roots(&self) -> &[SiteNode] {
        &self.roots
    }

    /// Whether the tree has no folders and no sites.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// The node `id`.
    pub fn get(&self, id: ItemId) -> Option<&SiteNode> {
        fn find(nodes: &[SiteNode], id: ItemId) -> Option<&SiteNode> {
            for n in nodes {
                if n.id() == id {
                    return Some(n);
                }
                if let SiteNode::Folder(f) = n
                    && let Some(found) = find(&f.children, id)
                {
                    return Some(found);
                }
            }
            None
        }
        find(&self.roots, id)
    }

    fn get_mut(&mut self, id: ItemId) -> Option<&mut SiteNode> {
        fn find(nodes: &mut [SiteNode], id: ItemId) -> Option<&mut SiteNode> {
            for n in nodes {
                if n.id() == id {
                    return Some(n);
                }
                if let SiteNode::Folder(f) = n
                    && let Some(found) = find(&mut f.children, id)
                {
                    return Some(found);
                }
            }
            None
        }
        find(&mut self.roots, id)
    }

    /// The site `id`.
    pub fn site(&self, id: ItemId) -> Option<&Site> {
        self.get(id).and_then(SiteNode::as_site)
    }

    /// The folder `id`.
    pub fn folder(&self, id: ItemId) -> Option<&Folder> {
        self.get(id).and_then(SiteNode::as_folder)
    }

    /// The contents of `parent` (`None` = the top level).
    ///
    /// # Errors
    /// [`SiteError::NotFound`] / [`SiteError::NotAFolder`].
    pub fn children(&self, parent: Option<ItemId>) -> Result<&[SiteNode], SiteError> {
        match parent {
            None => Ok(&self.roots),
            Some(id) => match self.get(id) {
                Some(SiteNode::Folder(f)) => Ok(&f.children),
                Some(SiteNode::Site(_)) => Err(SiteError::NotAFolder(id)),
                None => Err(SiteError::NotFound(id)),
            },
        }
    }

    fn children_mut(&mut self, parent: Option<ItemId>) -> Result<&mut Vec<SiteNode>, SiteError> {
        match parent {
            None => Ok(&mut self.roots),
            Some(id) => match self.get_mut(id) {
                Some(SiteNode::Folder(f)) => Ok(&mut f.children),
                Some(SiteNode::Site(_)) => Err(SiteError::NotAFolder(id)),
                None => Err(SiteError::NotFound(id)),
            },
        }
    }

    /// Every node, depth first (parents before children).
    pub fn walk(&self) -> Vec<&SiteNode> {
        self.roots.iter().flat_map(SiteNode::walk).collect()
    }

    /// Every site, depth first.
    pub fn sites(&self) -> impl Iterator<Item = &Site> {
        self.walk().into_iter().filter_map(SiteNode::as_site)
    }

    /// The rows a tree view shows: everything inside expanded folders.
    pub fn visible_rows(&self) -> Vec<TreeRow<'_>> {
        fn push<'a>(nodes: &'a [SiteNode], depth: usize, out: &mut Vec<TreeRow<'a>>) {
            for node in nodes {
                out.push(TreeRow { depth, node });
                if let SiteNode::Folder(f) = node
                    && f.expanded
                {
                    push(&f.children, depth + 1, out);
                }
            }
        }
        let mut out = Vec::new();
        push(&self.roots, 0, &mut out);
        out
    }

    /// The folders containing `id`, its parent first.
    pub fn ancestors(&self, id: ItemId) -> Vec<ItemId> {
        let mut out = Vec::new();
        let mut cur = self.get(id).and_then(SiteNode::parent);
        while let Some(p) = cur {
            if out.contains(&p) {
                break;
            }
            out.push(p);
            cur = self.get(p).and_then(SiteNode::parent);
        }
        out
    }

    /// The path of `id`, e.g. `"Work/Production/web01"` (used by
    /// `--site`, T70).
    pub fn path_of(&self, id: ItemId) -> Option<String> {
        let node = self.get(id)?;
        let mut parts: Vec<&str> = self
            .ancestors(id)
            .iter()
            .rev()
            .filter_map(|a| self.get(*a).map(SiteNode::name))
            .collect();
        parts.push(node.name());
        Some(parts.join("/"))
    }

    /// The node at `path` (`"Work/Production/web01"`; leading and trailing
    /// `/` and white space around each part are ignored). Names compare
    /// exactly; when synced data put two same-named entries in one folder
    /// the first in tree order wins.
    pub fn find_path(&self, path: &str) -> Option<&SiteNode> {
        let mut parts = path
            .split('/')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .peekable();
        parts.peek()?;
        let mut nodes = &self.roots;
        let mut found: Option<&SiteNode> = None;
        for part in parts {
            if found.is_some_and(|n| !n.is_folder()) {
                return None;
            }
            let node = nodes.iter().find(|n| n.name() == part)?;
            if let SiteNode::Folder(f) = node {
                nodes = &f.children;
            }
            found = Some(node);
        }
        found
    }

    /// The site at `path` (see [`SiteTree::find_path`]).
    pub fn find_site(&self, path: &str) -> Option<&Site> {
        self.find_path(path).and_then(SiteNode::as_site)
    }

    /// `base`, or `base (2)`, `base (3)`, ... — the first name not used in
    /// `parent` (for imports, T32, and copies).
    pub fn unique_name(&self, parent: Option<ItemId>, base: &str) -> String {
        let taken: HashSet<&str> = self
            .children(parent)
            .map(|c| c.iter().map(SiteNode::name).collect())
            .unwrap_or_default();
        if !taken.contains(base) {
            return base.to_owned();
        }
        (2..)
            .map(|n| format!("{base} ({n})"))
            .find(|name| !taken.contains(name.as_str()))
            .unwrap_or_else(|| base.to_owned())
    }

    fn check_free(
        &self,
        parent: Option<ItemId>,
        name: &str,
        except: Option<ItemId>,
    ) -> Result<(), SiteError> {
        if self
            .children(parent)?
            .iter()
            .any(|c| c.name() == name && Some(c.id()) != except)
        {
            return Err(SiteError::NameTaken(name.to_owned()));
        }
        Ok(())
    }

    /// Adds `node` (with its subtree) to `parent`: the name is validated and
    /// must be free there; the node's `parent` is set.
    ///
    /// # Errors
    /// [`SiteError::InvalidName`], [`SiteError::NameTaken`],
    /// [`SiteError::NotFound`] / [`SiteError::NotAFolder`] for `parent`.
    pub fn insert(&mut self, parent: Option<ItemId>, mut node: SiteNode) -> Result<(), SiteError> {
        let name = validate_name(node.name())?;
        self.check_free(parent, &name, None)?;
        node.set_name(name);
        node.set_parent(parent);
        let list = self.children_mut(parent)?;
        list.push(node);
        list.sort_by(order);
        Ok(())
    }

    /// Replaces the node with `node`'s id in place (same parent), e.g. after
    /// it was re-read from the vault. A folder keeps its children.
    ///
    /// # Errors
    /// [`SiteError::NotFound`].
    pub fn replace(&mut self, node: SiteNode) -> Result<(), SiteError> {
        let id = node.id();
        let current = self.get_mut(id).ok_or(SiteError::NotFound(id))?;
        let parent = current.parent();
        let node = match (node, &mut *current) {
            (SiteNode::Folder(mut new), SiteNode::Folder(old)) => {
                new.children = std::mem::take(&mut old.children);
                new.expanded = old.expanded;
                SiteNode::Folder(new)
            }
            (other, _) => other,
        };
        *current = node;
        current.set_parent(parent);
        self.sort_level(parent);
        Ok(())
    }

    /// Removes `id` and its subtree and returns it.
    pub fn remove(&mut self, id: ItemId) -> Option<SiteNode> {
        let parent = self.get(id)?.parent();
        let list = self.children_mut(parent).ok()?;
        let pos = list.iter().position(|n| n.id() == id)?;
        Some(list.remove(pos))
    }

    /// Renames `id`.
    ///
    /// # Errors
    /// [`SiteError::NotFound`], [`SiteError::InvalidName`],
    /// [`SiteError::NameTaken`].
    pub fn rename(&mut self, id: ItemId, name: &str) -> Result<(), SiteError> {
        let name = validate_name(name)?;
        let parent = self.get(id).ok_or(SiteError::NotFound(id))?.parent();
        self.check_free(parent, &name, Some(id))?;
        if let Some(node) = self.get_mut(id) {
            node.set_name(name);
        }
        self.sort_level(parent);
        Ok(())
    }

    /// Moves `id` into `new_parent` (cut and paste).
    ///
    /// # Errors
    /// [`SiteError::NotFound`], [`SiteError::NotAFolder`],
    /// [`SiteError::IntoOwnDescendant`] (a folder into itself or below
    /// itself), [`SiteError::NameTaken`].
    pub fn move_node(&mut self, id: ItemId, new_parent: Option<ItemId>) -> Result<(), SiteError> {
        let node = self.get(id).ok_or(SiteError::NotFound(id))?;
        if node.parent() == new_parent {
            return Ok(());
        }
        if let Some(target) = new_parent {
            if target == id || self.ancestors(target).contains(&id) {
                return Err(SiteError::IntoOwnDescendant);
            }
            self.children(new_parent)?;
        }
        let name = node.name().to_owned();
        self.check_free(new_parent, &name, None)?;
        let mut node = self.remove(id).ok_or(SiteError::NotFound(id))?;
        node.set_parent(new_parent);
        let list = self.children_mut(new_parent)?;
        list.push(node);
        list.sort_by(order);
        Ok(())
    }

    /// Deep-copies `id` next to itself: new ids everywhere, the copy's name
    /// gets [`COPY_SUFFIX`] (numbered if taken), passwords and device-local
    /// paths included, `created_at` = `now`, never connected. Returns the
    /// copy's id.
    ///
    /// # Errors
    /// [`SiteError::NotFound`].
    pub fn duplicate(&mut self, id: ItemId, now: UnixMillis) -> Result<ItemId, SiteError> {
        fn renew(node: &mut SiteNode, parent: Option<ItemId>, now: UnixMillis) {
            match node {
                SiteNode::Folder(f) => {
                    f.id = ItemId::new();
                    f.parent = parent;
                    f.read_only = false;
                    let id = Some(f.id);
                    for c in &mut f.children {
                        renew(c, id, now);
                    }
                }
                SiteNode::Site(s) => {
                    s.id = ItemId::new();
                    s.parent = parent;
                    s.created_at = Some(now);
                    s.last_connected_at = None;
                    s.read_only = false;
                }
            }
        }
        let original = self.get(id).ok_or(SiteError::NotFound(id))?;
        let parent = original.parent();
        let mut copy = original.clone();
        renew(&mut copy, parent, now);
        let base = format!("{}{COPY_SUFFIX}", original.name());
        copy.set_name(self.unique_name(parent, &base));
        let new_id = copy.id();
        let list = self.children_mut(parent)?;
        list.push(copy);
        list.sort_by(order);
        Ok(new_id)
    }

    /// Expands or collapses folder `id` (UI state).
    pub fn set_expanded(&mut self, id: ItemId, expanded: bool) {
        if let Some(SiteNode::Folder(f)) = self.get_mut(id) {
            f.expanded = expanded;
        }
    }

    /// Expands every folder containing `id`, so it is visible.
    pub fn reveal(&mut self, id: ItemId) {
        for a in self.ancestors(id) {
            self.set_expanded(a, true);
        }
    }

    /// The ids of the expanded folders.
    pub fn expanded(&self) -> BTreeSet<ItemId> {
        self.walk()
            .into_iter()
            .filter_map(SiteNode::as_folder)
            .filter(|f| f.expanded)
            .map(|f| f.id)
            .collect()
    }

    /// Sorts every level (folders first, then name). Every operation keeps
    /// the tree sorted; this is for callers that edit nodes themselves.
    pub fn sort(&mut self) {
        fn sort(nodes: &mut [SiteNode]) {
            nodes.sort_by(order);
            for n in nodes {
                if let SiteNode::Folder(f) = n {
                    sort(&mut f.children);
                }
            }
        }
        sort(&mut self.roots);
    }

    fn sort_level(&mut self, parent: Option<ItemId>) {
        if let Ok(list) = self.children_mut(parent) {
            list.sort_by(order);
        }
    }
}
