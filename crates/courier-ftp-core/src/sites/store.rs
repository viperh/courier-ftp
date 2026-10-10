//! [`SiteManager`]: the site tree kept in sync with the vault, and the
//! [`SiteLocalStore`] seam for device-local site data.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;

use crate::model::LocalPath;
use crate::model::item::{self, ItemId, SshKey, UnixMillis};
use crate::vault::{ItemVault, ItemVaultExt, VaultError, VaultItem};

use super::{
    Folder, HistoryEntry, Site, SiteConnect, SiteError, SiteIssue, SiteLocal, SiteNode, SiteTree,
};

/// Device-local site data (the store's `device_local` table, T82):
/// implemented by `courier_ftp_store::Store`; [`MemSiteLocalStore`] for
/// tests.
#[async_trait]
pub trait SiteLocalStore: Send + Sync + fmt::Debug {
    /// Every row with site data, by item id.
    ///
    /// # Errors
    /// [`SiteError::Local`].
    async fn all(&self) -> Result<HashMap<ItemId, SiteLocal>, SiteError>;

    /// The row of `id` (default when there is none).
    ///
    /// # Errors
    /// [`SiteError::Local`].
    async fn get(&self, id: ItemId) -> Result<SiteLocal, SiteError>;

    /// Sets (or clears) the default local directory and key file path of
    /// `id`. `last_connected_at` is left alone.
    ///
    /// # Errors
    /// [`SiteError::Local`].
    async fn set_paths(
        &self,
        id: ItemId,
        default_local_dir: Option<&LocalPath>,
        key_path: Option<&LocalPath>,
    ) -> Result<(), SiteError>;

    /// Records a successful connect at `at` (last connected time and
    /// frecency, for "recent servers", T33).
    ///
    /// # Errors
    /// [`SiteError::Local`].
    async fn touch_connected(&self, id: ItemId, at: UnixMillis) -> Result<(), SiteError>;

    /// Removes the row of `id` (a deleted site).
    ///
    /// # Errors
    /// [`SiteError::Local`].
    async fn forget(&self, id: ItemId) -> Result<(), SiteError>;
}

/// An in-memory [`SiteLocalStore`] (feature `test-util`).
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Default)]
pub struct MemSiteLocalStore {
    rows: std::sync::Mutex<HashMap<ItemId, SiteLocal>>,
}

#[cfg(any(test, feature = "test-util"))]
impl MemSiteLocalStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn rows(&self) -> std::sync::MutexGuard<'_, HashMap<ItemId, SiteLocal>> {
        self.rows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(any(test, feature = "test-util"))]
#[async_trait]
impl SiteLocalStore for MemSiteLocalStore {
    async fn all(&self) -> Result<HashMap<ItemId, SiteLocal>, SiteError> {
        Ok(self.rows().clone())
    }

    async fn get(&self, id: ItemId) -> Result<SiteLocal, SiteError> {
        Ok(self.rows().get(&id).cloned().unwrap_or_default())
    }

    async fn set_paths(
        &self,
        id: ItemId,
        default_local_dir: Option<&LocalPath>,
        key_path: Option<&LocalPath>,
    ) -> Result<(), SiteError> {
        let mut rows = self.rows();
        let row = rows.entry(id).or_default();
        row.default_local_dir = default_local_dir.cloned();
        row.key_path = key_path.cloned();
        Ok(())
    }

    async fn touch_connected(&self, id: ItemId, at: UnixMillis) -> Result<(), SiteError> {
        self.rows().entry(id).or_default().last_connected_at = Some(at);
        Ok(())
    }

    async fn forget(&self, id: ItemId) -> Result<(), SiteError> {
        self.rows().remove(&id);
        Ok(())
    }
}

/// The Site Manager's data: the [`SiteTree`] loaded from the vault, and
/// every change written straight back (each through `ItemVault::put`, which
/// stores it and queues it for sync).
///
/// Operations run on a copy of the tree and replace it only when all writes
/// succeeded; when a write fails half way the tree is reloaded from the
/// vault, so it always shows what is stored.
#[derive(Debug)]
pub struct SiteManager {
    vault: Arc<dyn ItemVault>,
    local: Arc<dyn SiteLocalStore>,
    tree: SiteTree,
}

impl SiteManager {
    /// Loads the tree (the vault must be unlocked).
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
            tree: SiteTree::new(),
        };
        me.reload().await?;
        Ok(me)
    }

    /// Re-reads every site and folder (after a sync pulled changes, or
    /// after unlocking). Expanded folders stay expanded.
    ///
    /// # Errors
    /// As [`SiteManager::load`].
    pub async fn reload(&mut self) -> Result<(), SiteError> {
        let expanded = self.tree.expanded();
        let locals = self.local.all().await?;
        let folders = self
            .vault
            .list_views::<item::SiteFolder>()
            .await?
            .into_iter()
            .map(|(it, view)| folder_from(&it, &view))
            .collect();
        let sites = self
            .vault
            .list_views::<item::Site>()
            .await?
            .into_iter()
            .map(|(it, view)| {
                let local = locals.get(&it.id).cloned().unwrap_or_default();
                Site::from_item(it.id, Some(it.vault_id), &view, &local)
            })
            .collect();
        let mut tree = SiteTree::from_items(folders, sites);
        for id in expanded {
            tree.set_expanded(id, true);
        }
        self.tree = tree;
        Ok(())
    }

    /// The tree.
    pub fn tree(&self) -> &SiteTree {
        &self.tree
    }

    /// The site `id`.
    pub fn site(&self, id: ItemId) -> Option<&Site> {
        self.tree.site(id)
    }

    /// The site at `path` (`"Work/Production/web01"`, T70 `--site`).
    pub fn find_site(&self, path: &str) -> Option<&Site> {
        self.tree.find_site(path)
    }

    /// Expands or collapses a folder (UI state, not stored).
    pub fn set_expanded(&mut self, id: ItemId, expanded: bool) {
        self.tree.set_expanded(id, expanded);
    }

    /// Expands the folders containing `id`.
    pub fn reveal(&mut self, id: ItemId) {
        self.tree.reveal(id);
    }

    /// Creates folder `name` in `parent` and returns its id.
    ///
    /// # Errors
    /// Name and parent errors as [`SiteTree::insert`], [`SiteError::Vault`].
    pub async fn add_folder(
        &mut self,
        parent: Option<ItemId>,
        name: &str,
    ) -> Result<ItemId, SiteError> {
        let mut folder = Folder::new(name);
        folder.vault = self.vault_of(parent);
        let id = folder.id;
        let mut next = self.tree.clone();
        next.insert(parent, SiteNode::Folder(folder))?;
        self.commit(next, &[id]).await?;
        Ok(id)
    }

    /// Saves a site: a new one (its id not in the tree) is added to
    /// `site.parent` with `created_at` set; an existing one is updated in
    /// place (use [`SiteManager::move_node`] to move it). Errors from
    /// [`Site::validate`] refuse the save; the warnings are returned.
    ///
    /// After the write the site is re-read from the vault, so the tree holds
    /// what is stored: with `vault.store_passwords = false` its passwords
    /// are gone and connecting asks for them.
    ///
    /// # Errors
    /// [`SiteError::Invalid`], [`SiteError::NameTaken`], parent errors,
    /// [`SiteError::Vault`] (e.g. [`VaultError::ReadOnlyItem`]),
    /// [`SiteError::Local`].
    pub async fn save_site(&mut self, mut site: Site) -> Result<Vec<SiteIssue>, SiteError> {
        let issues = site.validate();
        if issues.iter().any(SiteIssue::is_error) {
            return Err(SiteError::Invalid(issues));
        }
        let mut next = self.tree.clone();
        if let Some(current) = next.get(site.id) {
            site.parent = current.parent();
            site.vault = current.vault();
            let name = site.name.clone();
            next.rename(site.id, &name)?;
            site.name = super::validate_name(&name)?;
            next.replace(SiteNode::Site(Box::new(site.clone())))?;
        } else {
            site.vault = self.vault_of(site.parent);
            site.created_at.get_or_insert_with(UnixMillis::now);
            site.read_only = false;
            let parent = site.parent;
            next.insert(parent, SiteNode::Site(Box::new(site.clone())))?;
        }
        self.commit(next, &[site.id]).await?;
        Ok(issues)
    }

    /// Renames a site or folder.
    ///
    /// # Errors
    /// As [`SiteTree::rename`], [`SiteError::Vault`].
    pub async fn rename(&mut self, id: ItemId, name: &str) -> Result<(), SiteError> {
        let mut next = self.tree.clone();
        next.rename(id, name)?;
        self.commit(next, &[id]).await
    }

    /// Moves a site or folder into `new_parent` (`None` = top level).
    ///
    /// # Errors
    /// As [`SiteTree::move_node`]; [`SiteError::CrossVault`] when the target
    /// folder is in another vault.
    pub async fn move_node(
        &mut self,
        id: ItemId,
        new_parent: Option<ItemId>,
    ) -> Result<(), SiteError> {
        let node = self.tree.get(id).ok_or(SiteError::NotFound(id))?;
        if let (Some(target), Some(own)) = (self.vault_of(new_parent), node.vault())
            && target != own
        {
            return Err(SiteError::CrossVault);
        }
        let mut next = self.tree.clone();
        next.move_node(id, new_parent)?;
        self.commit(next, &[id]).await
    }

    /// Deep-copies a site or folder next to itself (see
    /// [`SiteTree::duplicate`]) and returns the copy's id.
    ///
    /// # Errors
    /// [`SiteError::NotFound`], [`SiteError::Vault`], [`SiteError::Local`].
    pub async fn duplicate(&mut self, id: ItemId) -> Result<ItemId, SiteError> {
        let mut next = self.tree.clone();
        let copy = next.duplicate(id, UnixMillis::now())?;
        let ids: Vec<ItemId> = next
            .get(copy)
            .map(|n| n.walk().iter().map(|n| n.id()).collect())
            .unwrap_or_default();
        self.commit(next, &ids).await?;
        Ok(copy)
    }

    /// Deletes a site, or a folder with everything in it (the UI confirms
    /// first, showing [`SiteNode::count`]). Returns how many items were
    /// deleted. Children go before their folder, so a failure half way
    /// leaves no orphans. The deleted sites' bookmarks (T33) and device-local
    /// rows go too, which also removes them from the recent servers.
    ///
    /// # Errors
    /// [`SiteError::NotFound`], [`SiteError::Vault`], [`SiteError::Local`].
    pub async fn delete(&mut self, id: ItemId) -> Result<usize, SiteError> {
        let node = self.tree.get(id).ok_or(SiteError::NotFound(id))?;
        let doomed: Vec<(ItemId, bool)> = node
            .walk()
            .iter()
            .rev()
            .map(|n| (n.id(), n.is_folder()))
            .collect();
        let sites: Vec<ItemId> = doomed
            .iter()
            .filter(|(_, folder)| !folder)
            .map(|&(id, _)| id)
            .collect();
        let result = async {
            if !sites.is_empty() {
                super::bookmarks::delete_site_bookmarks(&*self.vault, &*self.local, &sites).await?;
            }
            for &(item, folder) in &doomed {
                self.vault.delete(item).await?;
                if !folder {
                    self.local.forget(item).await?;
                }
            }
            Ok::<_, SiteError>(())
        }
        .await;
        if let Err(e) = result {
            let _ = self.reload().await;
            return Err(e);
        }
        self.tree.remove(id);
        Ok(doomed.len())
    }

    /// Records a successful connect to site `id` now (device-local).
    ///
    /// # Errors
    /// [`SiteError::NotFound`], [`SiteError::Local`].
    pub async fn record_connected(&mut self, id: ItemId) -> Result<(), SiteError> {
        let mut site = self.tree.site(id).ok_or(SiteError::NotFound(id))?.clone();
        let now = UnixMillis::now();
        self.local.touch_connected(id, now).await?;
        site.last_connected_at = Some(now);
        self.tree.replace(SiteNode::Site(Box::new(site)))
    }

    /// "Convert quickconnect entry to site" (T33): saves
    /// [`HistoryEntry::to_site`] at the top level under a free name (the
    /// host, then "host (2)"…) and returns the new site's id.
    ///
    /// # Errors
    /// As [`SiteManager::save_site`].
    pub async fn add_from_history(&mut self, entry: &HistoryEntry) -> Result<ItemId, SiteError> {
        let mut site = entry.to_site();
        site.name = self.tree.unique_name(None, &site.name);
        let id = site.id;
        self.save_site(site).await?;
        Ok(id)
    }

    /// The vault this manager reads (for [`Bookmarks`](super::Bookmarks)
    /// and [`History`](super::History) over the same vault).
    pub fn vault(&self) -> &Arc<dyn ItemVault> {
        &self.vault
    }

    /// The device-local store this manager uses.
    pub fn local_store(&self) -> &Arc<dyn SiteLocalStore> {
        &self.local
    }

    /// What connecting to site `id` needs (T31 §3): the `ConnectInfo` with
    /// the saved secrets and a vault SSH key read from the vault, plus the
    /// default directories and modes.
    ///
    /// # Errors
    /// [`SiteError::NotFound`], [`SiteError::KeyMissing`],
    /// [`SiteError::Invalid`], [`SiteError::Vault`].
    pub async fn connect(&self, id: ItemId) -> Result<SiteConnect, SiteError> {
        let site = self.tree.site(id).ok_or(SiteError::NotFound(id))?;
        let key = match site.vault_key_id() {
            Some(key_id) => Some(self.ssh_key(key_id).await?),
            None => None,
        };
        site.to_connect(key.as_ref())
    }

    /// The `ssh-key` items a key login can use (id and view), for the key
    /// picker. Private keys are included: drop them soon.
    ///
    /// # Errors
    /// [`SiteError::Vault`].
    pub async fn ssh_keys(&self) -> Result<Vec<(ItemId, SshKey)>, SiteError> {
        Ok(self
            .vault
            .list_views::<SshKey>()
            .await?
            .into_iter()
            .map(|(it, key)| (it.id, key))
            .collect())
    }

    async fn ssh_key(&self, id: ItemId) -> Result<SshKey, SiteError> {
        let item = self.vault.get(id).await?.ok_or(SiteError::KeyMissing(id))?;
        item.view::<SshKey>().map_err(|_| SiteError::KeyMissing(id))
    }

    /// The vault new items in `parent` go to (`None` = the personal vault).
    fn vault_of(&self, parent: Option<ItemId>) -> Option<crate::model::item::VaultId> {
        parent
            .and_then(|p| self.tree.get(p))
            .and_then(SiteNode::vault)
    }

    /// Writes the nodes `ids` of `next` (parents before children), then
    /// re-reads them and makes `next` the tree. On failure the tree is
    /// reloaded from the vault.
    async fn commit(&mut self, mut next: SiteTree, ids: &[ItemId]) -> Result<(), SiteError> {
        let result = async {
            for &id in ids {
                let node = next.get(id).ok_or(SiteError::NotFound(id))?.clone();
                let fresh = self.write(&node).await?;
                next.replace(fresh)?;
            }
            Ok::<_, SiteError>(())
        }
        .await;
        match result {
            Ok(()) => {
                self.tree = next;
                Ok(())
            }
            Err(e) => {
                if let Err(reload) = self.reload().await {
                    tracing::debug!(error = %reload, "reloading sites after a failed write");
                }
                Err(e)
            }
        }
    }

    /// Writes one node and returns it as stored.
    async fn write(&self, node: &SiteNode) -> Result<SiteNode, SiteError> {
        match node {
            SiteNode::Folder(f) => {
                let view = item::SiteFolder {
                    name: f.name.clone(),
                    parent: f.parent,
                    read_only: f.read_only,
                };
                self.vault.put_view(f.id, f.vault, view).await?;
                let stored = self.stored(f.id).await?;
                let view = stored.view::<item::SiteFolder>().map_err(view_error)?;
                Ok(SiteNode::Folder(folder_from(&stored, &view)))
            }
            SiteNode::Site(s) => {
                self.vault.put_view(s.id, s.vault, s.to_item()).await?;
                let local = s.local();
                self.local
                    .set_paths(
                        s.id,
                        local.default_local_dir.as_ref(),
                        local.key_path.as_ref(),
                    )
                    .await?;
                let stored = self.stored(s.id).await?;
                let view = stored.view::<item::Site>().map_err(view_error)?;
                let local = self.local.get(s.id).await?;
                Ok(SiteNode::Site(Box::new(Site::from_item(
                    s.id,
                    Some(stored.vault_id),
                    &view,
                    &local,
                ))))
            }
        }
    }

    async fn stored(&self, id: ItemId) -> Result<VaultItem, SiteError> {
        self.vault.get(id).await?.ok_or(SiteError::NotFound(id))
    }
}

fn view_error(e: item::ViewError) -> SiteError {
    SiteError::Vault(VaultError::Corrupt(e.to_string()))
}

fn folder_from(item: &VaultItem, view: &item::SiteFolder) -> Folder {
    Folder {
        id: item.id,
        vault: Some(item.vault_id),
        parent: view.parent,
        name: view.name.clone(),
        children: Vec::new(),
        expanded: false,
        read_only: item.read_only || view.read_only,
    }
}
