//! Bookmarks (T33): global bookmarks and site bookmarks, stored as
//! `bookmark` items (synced) with a device-local local-directory override.
//!
//! - A **global** bookmark (`site_id = None`) has a local directory, a remote
//!   directory or both; the remote one applies to whatever is connected.
//! - A **site** bookmark belongs to a [`Site`](super::Site) and needs a remote
//!   directory.
//! - Local paths differ per machine: [`Bookmark::local_dir`] is the synced
//!   value and [`Bookmark::local_dir_override`] this device's (the store's
//!   `device_local` table, like a site's default local directory). The
//!   override wins ([`Bookmark::effective_local_dir`]).
//! - Order is manual: each scope (global, or one site) is sorted by the
//!   item's `position` key, then name; [`Bookmarks::reorder`] renumbers the
//!   scope and writes only the bookmarks whose position changed.

use std::sync::Arc;

use crate::model::item::{self, ItemId, VaultId};
use crate::model::{LocalPath, RemotePath};
use crate::vault::{ItemVault, ItemVaultExt, VaultError};

use super::{SiteError, SiteLocalStore};

/// A bookmark: a local and/or remote directory to jump to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bookmark {
    /// The `bookmark` item's id.
    pub id: ItemId,
    /// The vault the item lives in (`None` until saved: the personal vault).
    pub vault: Option<VaultId>,
    /// The site it belongs to (`None` = global bookmark).
    pub site_id: Option<ItemId>,
    /// Name (unique within its scope).
    pub name: String,
    /// Local directory (synced).
    pub local_dir: Option<LocalPath>,
    /// This device's local directory, overriding [`Bookmark::local_dir`]
    /// (device-local, never synced).
    pub local_dir_override: Option<LocalPath>,
    /// Remote directory.
    pub remote_dir: Option<RemotePath>,
    /// Turn synchronized browsing on when applied (T66).
    pub sync_browsing: bool,
    /// Turn directory comparison on when applied.
    pub comparison: bool,
    /// Sort key within the scope (set by [`Bookmarks::add`] and
    /// [`Bookmarks::reorder`]).
    pub position: i64,
    /// The item comes from a newer courier-ftp: show it, don't edit it.
    pub read_only: bool,
}

/// What applying a bookmark does: navigate the panes and switch modes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookmarkTarget {
    /// Navigate the local pane here.
    pub local_dir: Option<LocalPath>,
    /// Navigate the remote pane here (only when connected).
    pub remote_dir: Option<RemotePath>,
    /// Enable synchronized browsing (T66).
    pub sync_browsing: bool,
    /// Enable directory comparison.
    pub comparison: bool,
}

impl Bookmark {
    /// A new global bookmark (new id) with no directories yet.
    pub fn global(name: impl Into<String>) -> Self {
        Self {
            id: ItemId::new(),
            vault: None,
            site_id: None,
            name: name.into(),
            local_dir: None,
            local_dir_override: None,
            remote_dir: None,
            sync_browsing: false,
            comparison: false,
            position: 0,
            read_only: false,
        }
    }

    /// A new bookmark of site `site_id` for `remote_dir`.
    pub fn for_site(site_id: ItemId, name: impl Into<String>, remote_dir: RemotePath) -> Self {
        Self {
            site_id: Some(site_id),
            remote_dir: Some(remote_dir),
            ..Self::global(name)
        }
    }

    /// Builds the bookmark from its item view and this device's override.
    pub fn from_item(
        id: ItemId,
        vault: Option<VaultId>,
        view: &item::Bookmark,
        local_dir_override: Option<LocalPath>,
    ) -> Self {
        Self {
            id,
            vault,
            site_id: view.site_id,
            name: view.name.clone(),
            local_dir: non_empty(view.local_dir.as_deref()).map(LocalPath::new),
            local_dir_override,
            remote_dir: non_empty(view.remote_dir.as_deref()).map(RemotePath::new),
            sync_browsing: view.sync_browsing,
            comparison: view.comparison,
            position: view.position.unwrap_or(0),
            read_only: view.read_only,
        }
    }

    /// The synced part, as the `bookmark` item view.
    pub fn to_item(&self) -> item::Bookmark {
        item::Bookmark {
            name: self.name.clone(),
            site_id: self.site_id,
            local_dir: self
                .local_dir
                .as_ref()
                .map(|p| p.as_path().to_string_lossy().into_owned()),
            remote_dir: self.remote_dir.as_ref().map(|p| p.as_str().to_owned()),
            sync_browsing: self.sync_browsing,
            comparison: self.comparison,
            position: Some(self.position),
            read_only: self.read_only,
        }
    }

    /// Whether it is a global bookmark.
    pub fn is_global(&self) -> bool {
        self.site_id.is_none()
    }

    /// The local directory on this device: the override, else the synced
    /// one.
    pub fn effective_local_dir(&self) -> Option<&LocalPath> {
        self.local_dir_override.as_ref().or(self.local_dir.as_ref())
    }

    /// What applying it does. Synchronized browsing needs both directories,
    /// so it is off when one is missing.
    pub fn target(&self) -> BookmarkTarget {
        let local_dir = self.effective_local_dir().cloned();
        let remote_dir = self.remote_dir.clone();
        BookmarkTarget {
            sync_browsing: self.sync_browsing && local_dir.is_some() && remote_dir.is_some(),
            comparison: self.comparison,
            local_dir,
            remote_dir,
        }
    }

    /// Checks the bookmark on its own (not name clashes): a name without
    /// control characters, a remote directory for site bookmarks, at least
    /// one directory for global ones, and both for synchronized browsing.
    ///
    /// # Errors
    /// [`SiteError::InvalidBookmark`] saying what is wrong.
    pub fn validate(&self) -> Result<(), SiteError> {
        let bad = |m: &str| Err(SiteError::InvalidBookmark(m.to_owned()));
        let name = self.name.trim();
        if name.is_empty() {
            return bad("the name is empty");
        }
        if name.chars().any(char::is_control) {
            return bad("the name contains control characters");
        }
        let local = self.effective_local_dir().is_some();
        let remote = self.remote_dir.is_some();
        if self.site_id.is_some() && !remote {
            return bad("a site bookmark needs a remote directory");
        }
        if !local && !remote {
            return bad("a bookmark needs a local or a remote directory");
        }
        if self.sync_browsing && !(local && remote) {
            return bad("synchronized browsing needs both a local and a remote directory");
        }
        Ok(())
    }
}

fn non_empty(s: Option<&str>) -> Option<&str> {
    s.filter(|s| !s.trim().is_empty())
}

/// Every bookmark, loaded from the vault, with add / rename / edit / delete /
/// reorder written straight back.
#[derive(Debug)]
pub struct Bookmarks {
    vault: Arc<dyn ItemVault>,
    local: Arc<dyn SiteLocalStore>,
    all: Vec<Bookmark>,
}

impl Bookmarks {
    /// Loads every bookmark (the vault must be unlocked).
    ///
    /// # Errors
    /// [`SiteError::Vault`] (e.g. [`VaultError::Locked`]),
    /// [`SiteError::Local`].
    pub async fn load(
        vault: Arc<dyn ItemVault>,
        local: Arc<dyn SiteLocalStore>,
    ) -> Result<Self, SiteError> {
        let mut me = Self {
            vault,
            local,
            all: Vec::new(),
        };
        me.reload().await?;
        Ok(me)
    }

    /// Re-reads every bookmark (after a sync).
    ///
    /// # Errors
    /// As [`Bookmarks::load`].
    pub async fn reload(&mut self) -> Result<(), SiteError> {
        let locals = self.local.all().await?;
        let mut all: Vec<Bookmark> = self
            .vault
            .list_views::<item::Bookmark>()
            .await?
            .into_iter()
            .map(|(it, view)| {
                let dir = locals.get(&it.id).and_then(|l| l.default_local_dir.clone());
                Bookmark::from_item(it.id, Some(it.vault_id), &view, dir)
            })
            .collect();
        sort(&mut all);
        self.all = all;
        Ok(())
    }

    /// Every bookmark, by scope (global first) then position.
    pub fn all(&self) -> &[Bookmark] {
        &self.all
    }

    /// The bookmark `id`.
    pub fn get(&self, id: ItemId) -> Option<&Bookmark> {
        self.all.iter().find(|b| b.id == id)
    }

    /// The global bookmarks, in order.
    pub fn global(&self) -> Vec<&Bookmark> {
        self.scope(None)
    }

    /// The bookmarks of site `site_id`, in order.
    pub fn for_site(&self, site_id: ItemId) -> Vec<&Bookmark> {
        self.scope(Some(site_id))
    }

    fn scope(&self, site_id: Option<ItemId>) -> Vec<&Bookmark> {
        self.all.iter().filter(|b| b.site_id == site_id).collect()
    }

    /// Adds a bookmark at the end of its scope and returns its id.
    ///
    /// # Errors
    /// [`SiteError::InvalidBookmark`], [`SiteError::NameTaken`],
    /// [`SiteError::Vault`], [`SiteError::Local`].
    pub async fn add(&mut self, mut bookmark: Bookmark) -> Result<ItemId, SiteError> {
        bookmark.validate()?;
        bookmark.name = bookmark.name.trim().to_owned();
        self.check_name(&bookmark)?;
        bookmark.position = self
            .scope(bookmark.site_id)
            .iter()
            .map(|b| b.position)
            .max()
            .map_or(0, |p| p.saturating_add(1));
        bookmark.read_only = false;
        let id = bookmark.id;
        self.write(&bookmark).await?;
        self.reload().await?;
        Ok(id)
    }

    /// Saves a changed bookmark (same id; scope and position are kept).
    ///
    /// # Errors
    /// [`SiteError::NotFound`], [`SiteError::InvalidBookmark`],
    /// [`SiteError::NameTaken`], [`SiteError::Vault`] (e.g.
    /// [`VaultError::ReadOnlyItem`]), [`SiteError::Local`].
    pub async fn edit(&mut self, mut bookmark: Bookmark) -> Result<(), SiteError> {
        let current = self
            .get(bookmark.id)
            .ok_or(SiteError::NotFound(bookmark.id))?;
        if current.read_only {
            return Err(SiteError::Vault(VaultError::ReadOnlyItem(current.id)));
        }
        bookmark.site_id = current.site_id;
        bookmark.vault = current.vault;
        bookmark.position = current.position;
        bookmark.validate()?;
        bookmark.name = bookmark.name.trim().to_owned();
        self.check_name(&bookmark)?;
        self.write(&bookmark).await?;
        self.reload().await
    }

    /// Renames a bookmark.
    ///
    /// # Errors
    /// As [`Bookmarks::edit`].
    pub async fn rename(&mut self, id: ItemId, name: &str) -> Result<(), SiteError> {
        let mut b = self.get(id).ok_or(SiteError::NotFound(id))?.clone();
        b.name = name.to_owned();
        self.edit(b).await
    }

    /// Deletes a bookmark (and its device-local override).
    ///
    /// # Errors
    /// [`SiteError::NotFound`], [`SiteError::Vault`], [`SiteError::Local`].
    pub async fn delete(&mut self, id: ItemId) -> Result<(), SiteError> {
        if self.get(id).is_none() {
            return Err(SiteError::NotFound(id));
        }
        self.vault.delete(id).await?;
        self.local.forget(id).await?;
        self.all.retain(|b| b.id != id);
        Ok(())
    }

    /// Moves bookmark `id` to `index` within its scope (clamped) and
    /// renumbers the scope `0, 1, 2…`, writing only changed positions.
    ///
    /// # Errors
    /// [`SiteError::NotFound`], [`SiteError::Vault`], [`SiteError::Local`].
    pub async fn reorder(&mut self, id: ItemId, index: usize) -> Result<(), SiteError> {
        let moving = self.get(id).ok_or(SiteError::NotFound(id))?.clone();
        let mut scope: Vec<Bookmark> = self
            .scope(moving.site_id)
            .into_iter()
            .filter(|b| b.id != id)
            .cloned()
            .collect();
        scope.insert(index.min(scope.len()), moving);
        let result = async {
            for (pos, mut b) in scope.into_iter().enumerate() {
                let pos = i64::try_from(pos).unwrap_or(i64::MAX);
                if b.position != pos {
                    b.position = pos;
                    self.write(&b).await?;
                }
            }
            Ok::<_, SiteError>(())
        }
        .await;
        let reloaded = self.reload().await;
        result.and(reloaded)
    }

    fn check_name(&self, bookmark: &Bookmark) -> Result<(), SiteError> {
        let lower = bookmark.name.to_lowercase();
        let taken = self
            .scope(bookmark.site_id)
            .iter()
            .any(|b| b.id != bookmark.id && b.name.to_lowercase() == lower);
        if taken {
            return Err(SiteError::NameTaken(bookmark.name.clone()));
        }
        Ok(())
    }

    async fn write(&self, b: &Bookmark) -> Result<(), SiteError> {
        self.vault.put_view(b.id, b.vault, b.to_item()).await?;
        self.local
            .set_paths(b.id, b.local_dir_override.as_ref(), None)
            .await
    }
}

/// Global first, then by site, position, name, id.
fn sort(all: &mut [Bookmark]) {
    all.sort_by(|a, b| {
        a.site_id
            .cmp(&b.site_id)
            .then(a.position.cmp(&b.position))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then(a.id.cmp(&b.id))
    });
}

/// Deletes the bookmarks of the sites `site_ids` (a deleted site or folder)
/// and their device-local rows. Returns how many were deleted.
pub(super) async fn delete_site_bookmarks(
    vault: &dyn ItemVault,
    local: &dyn SiteLocalStore,
    site_ids: &[ItemId],
) -> Result<usize, SiteError> {
    let mut n = 0;
    for (it, view) in vault.list_views::<item::Bookmark>().await? {
        if view.site_id.is_some_and(|s| site_ids.contains(&s)) {
            vault.delete(it.id).await?;
            local.forget(it.id).await?;
            n += 1;
        }
    }
    Ok(n)
}
