//! Item operations of [`VaultEngine`]: the cache-backed `list`, `get`, every write
//! (one IMMEDIATE transaction each), device-local data, approvals and the change
//! poller.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use courier_ftp_store::meta::keys;
use courier_ftp_store::{PutItem, StoreError, WriteTx};
use parking_lot::Mutex;

use super::cache::{self, CachedItem, Content, OpenFailure};
use super::engine::{POLL_INTERVAL, Session, device_local_info, hlc_from_meta};
use super::policy;
use super::{
    BodyEdit, BodyWrite, DeviceLocalInfo, Loaded, LoadedBody, MAX_BATCH, PutOutcome, VaultChange,
    VaultEngine, VaultError, VaultOptions, VaultPermission,
};
use crate::model::LocalPath;
use crate::model::item::{
    FieldWriter, ItemBody, ItemId, ItemKind, ItemView, VaultId, ViewError, check_vault_refs,
    current_schema, is_secret_field, merge,
};

/// Marks a store transaction aborted by a [`VaultError`] (kept in [`Abort`]).
const ABORT: &str = "vault write aborted";

/// Carries the error that rolled a write transaction back.
#[derive(Clone, Default)]
struct Abort(Arc<Mutex<Option<VaultError>>>);

impl Abort {
    fn fail(&self, e: VaultError) -> StoreError {
        *self.0.lock() = Some(e);
        StoreError::Task(ABORT.into())
    }

    fn map(&self, e: StoreError) -> VaultError {
        match self.0.lock().take() {
            Some(v) => v,
            None => e.into(),
        }
    }
}

type ViewFn = Box<dyn FnOnce(&mut ItemBody, &mut FieldWriter<'_>) + Send>;

/// What one write does to an item.
enum Edit {
    /// A typed view (`put`).
    View(ItemKind, ViewFn),
    /// A raw body (`put_many`).
    Body(BodyEdit),
    /// Tombstone (secrets cleared first).
    Delete,
    /// Clear the tombstone.
    Restore,
}

struct WriteReq {
    /// `None`: the item's current vault (delete, restore).
    vault: Option<VaultId>,
    id: ItemId,
    edit: Edit,
    /// A missing (or, for deletes, already deleted) item is skipped instead of failing.
    skip_missing: bool,
}

/// One committed item write, applied to the cache after commit.
struct Written {
    id: ItemId,
    entry: CachedItem,
    deleted: bool,
}

/// Applies `reqs` in one transaction; returns the items that changed.
fn apply_writes(
    w: &WriteTx<'_>,
    s: &Session,
    opts: &VaultOptions,
    reqs: Vec<WriteReq>,
) -> Result<Vec<Written>, VaultError> {
    let r = w.as_read();
    let stored_hlc = hlc_from_meta(r.get_meta(keys::HLC_LAST)?.as_deref());
    let mut clock = s.clock.lock();
    // Keep stamps monotonic across processes sharing the file.
    let _ = clock.observe(stored_hlc, s.device_id);
    let mut out = Vec::new();
    for req in reqs {
        let id = req.id;
        let row = r.get_item(*id.as_bytes())?;
        let row_vault = row.as_ref().map(|r| VaultId::from_bytes(r.vault_id));
        let vault = match (req.vault, row_vault) {
            (Some(v), Some(cur)) if v != cur => {
                return Err(VaultError::CrossVaultReference(
                    "the item belongs to another vault".into(),
                ));
            }
            (Some(v), _) => v,
            (None, Some(cur)) => cur,
            (None, None) if req.skip_missing => continue,
            (None, None) => return Err(VaultError::NotFound(id)),
        };
        if s.permission(vault) == VaultPermission::Read {
            return Err(VaultError::ReadOnlyVault(vault));
        }
        if !s.has_vault(vault) {
            return Err(VaultError::Locked);
        }
        let current = match &row {
            Some(row) => {
                let (body, read_only) = s.open(row)?;
                if read_only {
                    return Err(VaultError::ReadOnlyItem(id));
                }
                Some(body)
            }
            None => None,
        };
        let device = s.device_id;
        let body = match (req.edit, current.clone()) {
            (Edit::View(kind, apply), cur) => {
                let before = match cur {
                    Some(b) if b.kind != kind => {
                        return Err(VaultError::Corrupt(format!(
                            "item {} is a {}, not a {}",
                            id.short(),
                            b.kind,
                            kind
                        )));
                    }
                    Some(b) => b,
                    None => ItemBody::new(kind, current_schema(kind)),
                };
                let mut after = before.clone();
                apply(&mut after, &mut FieldWriter::new(&mut clock, device));
                if policy::drops_new_secrets(kind, opts) {
                    policy::revert_new_secrets(&before, &mut after);
                }
                after
            }
            (Edit::Body(BodyEdit::Replace(b)), _) => b,
            (Edit::Body(BodyEdit::Merge(remote)), Some(cur)) => merge(&cur, &remote).body,
            (Edit::Body(BodyEdit::Merge(remote)), None) => remote,
            (Edit::Delete | Edit::Restore, None) => continue,
            (Edit::Delete, Some(mut b)) => {
                if b.is_deleted() {
                    if req.skip_missing {
                        continue;
                    }
                    b
                } else {
                    let secrets: Vec<String> = b
                        .fields
                        .iter()
                        .filter(|(k, v)| is_secret_field(k) && !v.value.is_null())
                        .map(|(k, _)| k.clone())
                        .collect();
                    for k in secrets {
                        b.unset(&k, &mut clock, device);
                    }
                    b.delete(&mut clock, device);
                    b
                }
            }
            (Edit::Restore, Some(mut b)) => {
                b.restore(&mut clock, device);
                b
            }
        };
        if current.as_ref() == Some(&body) {
            continue;
        }
        check_vault_refs(vault, &body, |t| s.cache.read().vault_of(t))
            .map_err(|e| VaultError::CrossVaultReference(e.to_string()))?;
        let (key_version, envelope) = s.seal(vault, id, &body)?;
        let deleted = body.is_deleted();
        w.put_item(PutItem {
            vault_id: *vault.as_bytes(),
            id: *id.as_bytes(),
            key_version,
            envelope: &envelope,
            deleted,
            mark_dirty: policy::mark_dirty(body.kind, opts),
        })?;
        if deleted {
            w.delete_device_local(*id.as_bytes())?;
            w.delete_local_approvals_of(*id.as_bytes())?;
        }
        let read_only = false;
        out.push(Written {
            id,
            entry: cache::entry_for(
                vault,
                w.now(),
                row.as_ref().map_or(0, |r| r.revision),
                deleted,
                Ok((body, read_only)),
            ),
            deleted,
        });
    }
    w.set_meta(keys::HLC_LAST, &clock.last().as_u64().to_be_bytes())?;
    Ok(out)
}

fn view_error(id: ItemId, e: &ViewError) -> VaultError {
    match e {
        ViewError::WrongKind { .. } => VaultError::NotFound(id),
        other => VaultError::Corrupt(format!("item {}: {other}", id.short())),
    }
}

impl VaultEngine {
    /// Runs `reqs` in one write transaction, then updates the cache and broadcasts.
    async fn write_items(&self, reqs: Vec<WriteReq>) -> Result<Vec<ItemId>, VaultError> {
        if reqs.len() > MAX_BATCH {
            return Err(VaultError::Storage(format!(
                "at most {MAX_BATCH} items per transaction"
            )));
        }
        let op = self.op().await?;
        let s = Arc::clone(&op.s);
        let opts = self.opts();
        let abort = Abort::default();
        let a = abort.clone();
        let written = self
            .store()
            .write(move |w| apply_writes(w, &s, &opts, reqs).map_err(|e| a.fail(e)))
            .await
            .map_err(|e| abort.map(e))?;
        if written.is_empty() {
            return Ok(Vec::new());
        }
        let mut ids = Vec::with_capacity(written.len());
        let mut kinds = BTreeSet::new();
        {
            let mut cache = op.s.cache.write();
            for wr in written {
                if let Some(k) = wr.entry.kind() {
                    kinds.insert(k);
                }
                if wr.deleted {
                    op.s.device_local.write().remove(&wr.id);
                    op.s.approvals.write().retain(|(i, _, _)| *i != wr.id);
                }
                cache.items.insert(wr.id, wr.entry);
                ids.push(wr.id);
            }
        }
        drop(op);
        ids.sort();
        self.inner
            .local_changes
            .send_modify(|n| *n = n.wrapping_add(1));
        self.emit(VaultChange::ItemsChanged {
            ids: ids.clone(),
            kinds,
        });
        Ok(ids)
    }

    /// Every live item of `V`'s kind from the cache (no I/O), sorted by id. Secret
    /// fields read as `Kept` when stored, `Absent` otherwise. Items whose body does not
    /// fit the view are skipped (logged at `debug`).
    ///
    /// # Errors
    /// [`VaultError::Locked`].
    pub fn list<V: ItemView>(&self) -> Result<Vec<Loaded<V>>, VaultError> {
        self.with_session(|s| {
            let cache = s.cache.read();
            Ok(cache
                .items
                .iter()
                .filter_map(|(id, item)| {
                    let body = item.live_body().filter(|b| b.kind == V::KIND)?;
                    match V::from_body(body) {
                        Ok(view) => Some(Loaded {
                            id: *id,
                            vault: item.vault,
                            view,
                            read_only: item.read_only(),
                            secrets_loaded: false,
                            updated_at: item.updated_at,
                        }),
                        Err(e) => {
                            tracing::debug!(item = %id.short(), error = %e, "item skipped by view");
                            None
                        }
                    }
                })
                .collect())
        })
    }

    /// Ids of every live item of `kind` (cache, no I/O), sorted. Read the bodies with
    /// [`VaultEngine::get_body`].
    ///
    /// # Errors
    /// [`VaultError::Locked`].
    pub fn item_ids(&self, kind: ItemKind) -> Result<Vec<ItemId>, VaultError> {
        self.with_session(|s| {
            Ok(s.cache
                .read()
                .items
                .iter()
                .filter(|(_, i)| i.live_body().is_some_and(|b| b.kind == kind))
                .map(|(id, _)| *id)
                .collect())
        })
    }

    /// Reads, decrypts and migrates one item with its secrets. `None` when missing or
    /// deleted.
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::NotFound`] (another kind),
    /// [`VaultError::ReadOnlyItem`] (unknown kind), [`VaultError::Corrupt`].
    pub async fn get<V: ItemView>(&self, id: ItemId) -> Result<Option<Loaded<V>>, VaultError> {
        let Some(lb) = self.get_body(id).await? else {
            return Ok(None);
        };
        if lb.body.is_deleted() {
            return Ok(None);
        }
        let view = V::from_body(&lb.body).map_err(|e| view_error(id, &e))?;
        let updated_at =
            self.with_session(|s| Ok(s.cache.read().items.get(&id).map_or(0, |c| c.updated_at)))?;
        Ok(Some(Loaded {
            id,
            vault: lb.vault,
            view,
            read_only: lb.read_only,
            secrets_loaded: true,
            updated_at,
        }))
    }

    /// The raw decrypted body with stamps and secrets (deleted bodies included).
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::ReadOnlyItem`] (unknown kind),
    /// [`VaultError::Corrupt`].
    pub async fn get_body(&self, id: ItemId) -> Result<Option<LoadedBody>, VaultError> {
        let op = self.op().await?;
        let Some(row) = self.store().get_item(*id.as_bytes()).await? else {
            return Ok(None);
        };
        let (body, read_only) = op.s.open(&row)?;
        Ok(Some(LoadedBody {
            id,
            vault: VaultId::from_bytes(row.vault_id),
            body,
            read_only,
            revision: row.revision,
        }))
    }

    /// Writes `view` into item `id` of `vault` (created if missing). Only changed fields
    /// get new stamps; nothing is written when nothing changed.
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::ReadOnlyVault`],
    /// [`VaultError::ReadOnlyItem`], [`VaultError::CrossVaultReference`],
    /// [`VaultError::ItemTooLarge`], [`VaultError::Busy`], [`VaultError::Storage`].
    pub async fn put<V: ItemView + Send + 'static>(
        &self,
        vault: VaultId,
        id: ItemId,
        view: V,
    ) -> Result<PutOutcome, VaultError> {
        let apply: ViewFn = Box::new(move |b, w| view.apply_to(b, w));
        let ids = self
            .write_items(vec![WriteReq {
                vault: Some(vault),
                id,
                edit: Edit::View(V::KIND, apply),
                skip_missing: false,
            }])
            .await?;
        Ok(PutOutcome {
            changed: !ids.is_empty(),
        })
    }

    /// Applies up to 10 000 raw body writes in one transaction (imports). Returns how
    /// many items changed.
    ///
    /// # Errors
    /// As [`VaultEngine::put`]; any error rolls back every write.
    pub async fn put_many(&self, writes: Vec<BodyWrite>) -> Result<usize, VaultError> {
        let reqs = writes
            .into_iter()
            .map(|w| WriteReq {
                vault: Some(w.vault),
                id: w.id,
                edit: Edit::Body(w.body),
                skip_missing: false,
            })
            .collect();
        Ok(self.write_items(reqs).await?.len())
    }

    /// Tombstones an item (its secrets are cleared first) and deletes its device-local
    /// data and approvals.
    ///
    /// # Errors
    /// [`VaultError::NotFound`], and as [`VaultEngine::put`].
    pub async fn delete(&self, id: ItemId) -> Result<(), VaultError> {
        self.write_items(vec![WriteReq {
            vault: None,
            id,
            edit: Edit::Delete,
            skip_missing: false,
        }])
        .await
        .map(drop)
    }

    /// Tombstones up to 10 000 items in one transaction; missing and already deleted
    /// ones are skipped. Returns how many were deleted.
    ///
    /// # Errors
    /// As [`VaultEngine::put`].
    pub async fn delete_many(&self, ids: Vec<ItemId>) -> Result<usize, VaultError> {
        let reqs = ids
            .into_iter()
            .map(|id| WriteReq {
                vault: None,
                id,
                edit: Edit::Delete,
                skip_missing: true,
            })
            .collect();
        Ok(self.write_items(reqs).await?.len())
    }

    /// Clears a tombstone (undo).
    ///
    /// # Errors
    /// [`VaultError::NotFound`], and as [`VaultEngine::put`].
    pub async fn restore(&self, id: ItemId) -> Result<(), VaultError> {
        self.write_items(vec![WriteReq {
            vault: None,
            id,
            edit: Edit::Restore,
            skip_missing: false,
        }])
        .await
        .map(drop)
    }

    /// Writes `view` as `id` and tombstones `replaces` in one transaction (trust
    /// stores).
    pub(crate) async fn put_replacing<V: ItemView + Send + 'static>(
        &self,
        vault: VaultId,
        id: ItemId,
        view: V,
        replaces: Vec<ItemId>,
    ) -> Result<(), VaultError> {
        let apply: ViewFn = Box::new(move |b, w| view.apply_to(b, w));
        let mut reqs = vec![WriteReq {
            vault: Some(vault),
            id,
            edit: Edit::View(V::KIND, apply),
            skip_missing: false,
        }];
        reqs.extend(replaces.into_iter().filter(|r| *r != id).map(|r| WriteReq {
            vault: None,
            id: r,
            edit: Edit::Delete,
            skip_missing: true,
        }));
        self.write_items(reqs).await.map(drop)
    }

    /// Tombstones `id` if it exists (trust stores).
    pub(crate) async fn delete_if_present(&self, id: ItemId) -> Result<(), VaultError> {
        self.delete_many(vec![id]).await.map(drop)
    }

    /// Whether `(id, field, value_sha256)` is approved on this device (cached).
    pub fn is_approved(&self, id: ItemId, field: &str, value_sha256: &[u8; 32]) -> bool {
        self.with_session(|s| {
            Ok(s.approvals
                .read()
                .contains(&(id, field.to_owned(), *value_sha256)))
        })
        .unwrap_or(false)
    }

    /// Approves a synced local-acting value on this device (never synced).
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::Storage`].
    pub async fn approve(
        &self,
        id: ItemId,
        field: &str,
        value_sha256: [u8; 32],
    ) -> Result<(), VaultError> {
        let op = self.op().await?;
        self.store()
            .put_local_approval(*id.as_bytes(), field, value_sha256)
            .await?;
        let mut approvals = op.s.approvals.write();
        approvals.retain(|(i, f, _)| !(*i == id && f == field));
        approvals.insert((id, field.to_owned(), value_sha256));
        Ok(())
    }

    /// Device-local data of an item (cached).
    pub fn device_local(&self, id: ItemId) -> Option<DeviceLocalInfo> {
        self.with_session(|s| Ok(s.device_local.read().get(&id).cloned()))
            .ok()
            .flatten()
    }

    async fn refresh_device_local(&self, id: ItemId) -> Result<(), VaultError> {
        let op = self.op().await?;
        let row = self.store().get_device_local(*id.as_bytes()).await?;
        let mut map = op.s.device_local.write();
        match row {
            Some(l) => {
                map.insert(id, device_local_info(&l));
            }
            None => {
                map.remove(&id);
            }
        }
        Ok(())
    }

    /// Records a successful connect (frecency, last connected).
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::Storage`].
    pub async fn touch_connected(&self, id: ItemId) -> Result<(), VaultError> {
        {
            let _op = self.op().await?;
            let now = self.store().now();
            self.store().touch_connected(*id.as_bytes(), now).await?;
        }
        self.refresh_device_local(id).await
    }

    /// Sets (or clears) this device's local directory override.
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::Storage`].
    pub async fn set_local_dir_override(
        &self,
        id: ItemId,
        dir: Option<LocalPath>,
    ) -> Result<(), VaultError> {
        {
            let _op = self.op().await?;
            let dir = dir.map(|d| d.as_path().to_string_lossy().into_owned());
            self.store()
                .set_local_dir_override(*id.as_bytes(), dir)
                .await?;
        }
        self.refresh_device_local(id).await
    }

    /// Sets (or resets) the Site Manager expansion of a folder on this device.
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::Storage`].
    pub async fn set_tree_expanded(
        &self,
        id: ItemId,
        expanded: Option<bool>,
    ) -> Result<(), VaultError> {
        {
            let _op = self.op().await?;
            self.store()
                .set_tree_expanded(*id.as_bytes(), expanded)
                .await?;
        }
        self.refresh_device_local(id).await
    }

    /// Re-reads `ids` from the store into the cache (rows written by another process
    /// or by sync) and broadcasts `ItemsChanged`.
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::Storage`].
    pub async fn reload_items(&self, ids: Vec<ItemId>) -> Result<(), VaultError> {
        if ids.is_empty() {
            return Ok(());
        }
        let op = self.op().await?;
        let wanted: Vec<[u8; 16]> = ids.iter().map(|i| *i.as_bytes()).collect();
        let rows = self
            .store()
            .read(move |r| {
                wanted
                    .into_iter()
                    .map(|id| Ok((id, r.get_item(id)?)))
                    .collect::<courier_ftp_store::Result<Vec<_>>>()
            })
            .await?;
        let mut kinds = BTreeSet::new();
        let mut changed = Vec::new();
        {
            let mut cache = op.s.cache.write();
            for (raw, row) in rows {
                let id = ItemId::from_bytes(raw);
                match row {
                    Some(row) => {
                        let decoded = op.s.decode_row(&row);
                        if let Err(OpenFailure::Unreadable(_)) = &decoded {
                            tracing::warn!(item = %id.short(), "item does not decrypt");
                        }
                        let entry = cache::entry_for_row(&row, decoded);
                        if let Some(k) = entry.kind() {
                            kinds.insert(k);
                        }
                        cache.items.insert(id, entry);
                    }
                    None => {
                        if let Some(old) = cache.items.remove(&id)
                            && let Content::Body { body, .. } = &old.content
                        {
                            kinds.insert(body.kind);
                        }
                    }
                }
                changed.push(id);
            }
        }
        drop(op);
        changed.sort();
        tracing::debug!(items = changed.len(), "vault items reloaded");
        self.emit(VaultChange::ItemsChanged {
            ids: changed,
            kinds,
        });
        Ok(())
    }

    /// One poll: when `PRAGMA data_version` moved, diff the row markers against the
    /// cache and reload what changed.
    async fn poll_once(&self) -> Result<(), VaultError> {
        let (changed, removed) = {
            let op = self.op().await?;
            let version = self.store().data_version().await?;
            if op.s.data_version.swap(version, Ordering::SeqCst) == version {
                return Ok(());
            }
            let markers = self.store().item_markers().await?;
            op.s.cache.read().diff(&markers)
        };
        let mut all = changed;
        all.extend(removed);
        self.reload_items(all).await
    }

    /// Starts the change poller (every 2 s while unlocked).
    pub(crate) fn start_poller(&self) {
        let weak = self.weak();
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(POLL_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await;
            loop {
                interval.tick().await;
                let Some(inner) = weak.upgrade() else { break };
                let engine = VaultEngine::from_inner(inner);
                match engine.poll_once().await {
                    Ok(()) => {}
                    Err(VaultError::Locked) => break,
                    Err(e) => tracing::debug!(error = %e, "vault change poll failed"),
                }
            }
        });
        if let Some(old) = self.inner.poller.lock().replace(handle) {
            old.abort();
        }
    }
}
