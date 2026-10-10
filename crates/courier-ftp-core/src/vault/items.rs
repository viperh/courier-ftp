//! Item access for the rest of the client: the [`ItemVault`] trait.
//!
//! The engine that owns the keys and the database lives in
//! `courier_ftp_store::vault::VaultEngine` (the store crate depends on this one,
//! not the other way round). Core code that needs vault items — the site model
//! (T31), bookmarks and history (T33), the trust stores (T21, T12) — takes an
//! `Arc<dyn ItemVault>` and stays testable with any implementation.

use std::fmt;

use async_trait::async_trait;

use super::VaultError;
use crate::model::item::{
    DeviceId, HlcClock, ItemBody, ItemId, ItemKind, ItemView, VaultId, ViewError,
};

/// One decrypted, live (not deleted) item.
#[derive(Debug, Clone, PartialEq)]
pub struct VaultItem {
    /// Item id.
    pub id: ItemId,
    /// The vault it belongs to.
    pub vault_id: VaultId,
    /// The decrypted body, migrated to this build's schema when possible.
    /// `Debug` redacts secret fields.
    pub body: ItemBody,
    /// The body comes from a newer courier-ftp: show it, don't edit it.
    pub read_only: bool,
}

impl VaultItem {
    /// The item's kind.
    pub fn kind(&self) -> ItemKind {
        self.body.kind
    }

    /// The typed view of the body.
    ///
    /// # Errors
    /// [`ViewError`] when the body is of another kind or malformed.
    pub fn view<V: ItemView>(&self) -> Result<V, ViewError> {
        V::from_body(&self.body)
    }
}

/// A change to one item's body: gets the current body (or a new empty one),
/// the vault's HLC and this device's id, and stamps what it changes
/// (`ItemBody::set`, `ItemView::apply_to`).
pub type ItemEdit = Box<dyn FnOnce(&mut ItemBody, &mut HlcClock, DeviceId) + Send>;

/// One write for [`ItemVault::put`].
pub struct ItemWrite {
    /// The item to create or update.
    pub id: ItemId,
    /// Its kind. Updating an item of another kind fails with
    /// [`VaultError::WrongKind`].
    pub kind: ItemKind,
    /// The vault for a new item; `None` = the personal vault. Ignored for an
    /// existing item.
    pub vault: Option<VaultId>,
    /// The change.
    pub edit: ItemEdit,
}

impl fmt::Debug for ItemWrite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemWrite")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("vault", &self.vault)
            .finish_non_exhaustive()
    }
}

/// Encrypted item storage (implemented by `courier_ftp_store::vault::VaultEngine`).
///
/// Every method except [`ItemVault::is_unlocked`] fails with
/// [`VaultError::Locked`] while the vault is locked.
#[async_trait]
pub trait ItemVault: Send + Sync + fmt::Debug {
    /// Whether keys are loaded.
    async fn is_unlocked(&self) -> bool;

    /// The live item `id` (`None` when missing or deleted).
    ///
    /// # Errors
    /// [`VaultError::Locked`].
    async fn get(&self, id: ItemId) -> Result<Option<VaultItem>, VaultError>;

    /// Every live item of `kind`, in id order (UUIDv7: creation order).
    ///
    /// # Errors
    /// [`VaultError::Locked`].
    async fn list(&self, kind: ItemKind) -> Result<Vec<VaultItem>, VaultError>;

    /// Creates or updates an item: runs the edit, stamps changed fields with the
    /// HLC, seals and writes the item and marks it dirty for sync, all at once.
    /// Writing a deleted item's id starts a new body. `Ok(false)` when the edit
    /// changed nothing (nothing is written).
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::ReadOnlyItem`],
    /// [`VaultError::WrongKind`], [`VaultError::Busy`], [`VaultError::Storage`].
    async fn put(&self, write: ItemWrite) -> Result<bool, VaultError>;

    /// Deletes an item (a tombstone, so the delete syncs). `Ok(false)` when
    /// there was no live item.
    ///
    /// # Errors
    /// As [`ItemVault::put`].
    async fn delete(&self, id: ItemId) -> Result<bool, VaultError>;
}

/// Typed helpers on top of [`ItemVault`].
#[async_trait]
pub trait ItemVaultExt: ItemVault {
    /// Writes `view` to item `id` (only the fields that differ are stamped).
    ///
    /// # Errors
    /// As [`ItemVault::put`].
    async fn put_view<V>(
        &self,
        id: ItemId,
        vault: Option<VaultId>,
        view: V,
    ) -> Result<bool, VaultError>
    where
        V: ItemView + Send + 'static,
    {
        self.put(ItemWrite {
            id,
            kind: V::KIND,
            vault,
            edit: Box::new(move |body, clock, device| view.apply_to(body, clock, device)),
        })
        .await
    }

    /// Every live item of `V`'s kind as `(item, view)`. Items whose body
    /// doesn't read as `V` are skipped (logged).
    ///
    /// # Errors
    /// As [`ItemVault::list`].
    async fn list_views<V>(&self) -> Result<Vec<(VaultItem, V)>, VaultError>
    where
        V: ItemView + Send + 'static,
    {
        let items = self.list(V::KIND).await?;
        Ok(items
            .into_iter()
            .filter_map(|item| match item.view::<V>() {
                Ok(view) => Some((item, view)),
                Err(e) => {
                    tracing::warn!(item = %item.id.short(), error = %e, "item does not read as its kind");
                    None
                }
            })
            .collect())
    }
}

impl<T: ItemVault + ?Sized> ItemVaultExt for T {}
