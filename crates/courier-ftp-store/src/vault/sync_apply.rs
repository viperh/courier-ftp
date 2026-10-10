//! Applying pulled items and building pushes (T88), under the engine's state
//! lock so local edits and remote changes never interleave.
//!
//! Per incoming item, inside **one** write transaction per page:
//! 1. decrypt it and observe its stamps in the device HLC (clock skew is
//!    reported, the stored stamp is kept);
//! 2. local copy clean or absent → store the server's envelope as received;
//! 3. local copy dirty → `merge(local, remote)` (T81), re-seal, keep it dirty
//!    and rebase its outbox row onto the incoming revision (if the local copy
//!    adds nothing, it simply becomes clean);
//! 4. revoke the device-local approval of every local-acting field whose
//!    value changed (T91 §8);
//! 5. advance the vault cursor (pages), keep it (push conflicts), or set it
//!    to the head after purging clean items the server no longer has and
//!    re-queueing dirty ones as new (full resync after `410 gone`).
//!
//! The decrypted index is updated after the commit.

use std::collections::HashSet;

use courier_ftp_core::model::item::{
    ClockSkew, ItemBody, ItemId, ItemKind, VaultId, merge, migrate,
};
use courier_ftp_core::vault::local_acting::changed_local_acting;
use courier_ftp_core::vault::{VaultError, scrub};
use courier_ftp_crypto::Key32;
use courier_ftp_crypto::envelope::{open_item, seal_item};
use courier_ftp_crypto::keys::os_rng;
use zeroize::Zeroizing;

use super::{Cached, VaultEngine, storage};
use crate::{RemoteItem, StoreError};

/// One item from the server (a pulled page, or a push conflict's current
/// copy).
#[derive(Debug, Clone)]
pub struct Incoming {
    /// Item id.
    pub id: ItemId,
    /// Server revision.
    pub revision: i64,
    /// Vault key version of the envelope.
    pub key_version: u32,
    /// The envelope as received.
    pub envelope: Vec<u8>,
    /// Tombstone flag.
    pub deleted: bool,
}

/// How [`VaultEngine::apply_incoming`] treats the vault cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyMode {
    /// A pulled page: the cursor moves to `cursor` in the same transaction.
    Page {
        /// The new cursor.
        cursor: i64,
    },
    /// Push conflicts merged with the server's copies: the cursor stays.
    Conflict,
    /// A full resync from revision 0 (`410 gone`): every server item is in
    /// the page; clean local items missing from it are purged, dirty ones
    /// re-queued as new (`base_revision = 0`); the cursor moves to `head`.
    Resync {
        /// The server's head revision.
        head: i64,
    },
}

/// What [`VaultEngine::apply_incoming`] did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ApplyReport {
    /// Items written (replaced, merged, re-queued) or purged locally.
    pub applied: Vec<ItemId>,
    /// Dirty local items merged with the server's copy (still queued).
    pub merged: Vec<ItemId>,
    /// Server items that did not decrypt (skipped).
    pub undecryptable: Vec<ItemId>,
    /// Labels of locally deleted items an incoming edit restored (toast).
    pub resurrected: Vec<String>,
    /// The first clock skew seen.
    pub skew: Option<ClockSkew>,
    /// Local-acting fields whose value a remote change set or changed: the
    /// approval on this device was revoked, the connect path asks again.
    pub approvals: Vec<(ItemId, &'static str)>,
    /// Resync: dirty local items the server didn't have, re-queued as new.
    pub requeued: usize,
    /// Resync: clean local items the server didn't have, removed.
    pub purged: usize,
}

/// One queued change ready to push.
#[derive(Debug, Clone)]
pub struct Outgoing {
    /// Item id.
    pub id: ItemId,
    /// The outbox row's `queued_at` (for `mark_pushed`).
    pub queued_at: i64,
    /// The server revision the change is based on.
    pub base_revision: i64,
    /// Vault key version of the envelope.
    pub key_version: u32,
    /// The stored envelope.
    pub envelope: Vec<u8>,
    /// Tombstone flag.
    pub deleted: bool,
    /// A display label (the item's name, else its short id).
    pub label: String,
}

/// What [`VaultEngine::outgoing`] found.
#[derive(Debug, Default, Clone)]
pub struct OutgoingBatch {
    /// Changes to push, oldest first.
    pub changes: Vec<Outgoing>,
    /// Queued items the policy keeps on this device (dropped from the
    /// outbox; the item stays dirty, so enabling the policy later pushes it).
    pub excluded: usize,
    /// Queued items that don't decrypt (not pushed).
    pub undecryptable: Vec<ItemId>,
}

/// A display label: the item's `name`, else its short id.
pub fn label_of(body: Option<&ItemBody>, id: ItemId) -> String {
    body.and_then(|b| b.get("name"))
        .and_then(|v| v.as_text())
        .filter(|s| !s.is_empty())
        .map_or_else(|| id.short(), ToOwned::to_owned)
}

fn open_body(key: &Key32, kv: u32, vault: VaultId, id: ItemId, env: &[u8]) -> Option<ItemBody> {
    let lookup = |v: u32| (v == kv).then_some(key);
    let plain = open_item(lookup, vault.as_bytes(), id.as_bytes(), env).ok()?;
    ItemBody::from_cbor(&plain).ok()
}

fn seal_body(
    key: &Key32,
    kv: u32,
    vault: VaultId,
    id: ItemId,
    body: &ItemBody,
) -> Result<Vec<u8>, StoreError> {
    let cbor = Zeroizing::new(
        body.to_cbor()
            .map_err(|e| StoreError::Corrupt(format!("item body: {e}")))?,
    );
    seal_item(
        key,
        vault.as_bytes(),
        id.as_bytes(),
        kv,
        &cbor,
        &mut os_rng(),
    )
    .map_err(|e| StoreError::Corrupt(format!("sealing item: {e}")))
}

impl VaultEngine {
    /// Applies items received from the server for `vault` (see the module
    /// docs) and updates the decrypted index.
    ///
    /// # Errors
    /// [`VaultError::Locked`] (also for a vault whose key is not loaded),
    /// [`VaultError::Storage`] (the transaction rolled back: nothing applied,
    /// cursor unchanged).
    pub async fn apply_incoming(
        &self,
        vault: VaultId,
        items: Vec<Incoming>,
        mode: ApplyMode,
    ) -> Result<ApplyReport, VaultError> {
        let mut state = self.inner.state.write().await;
        let u = state.as_mut().ok_or(VaultError::Locked)?;
        let entry = u.vaults.get(&vault).ok_or(VaultError::Locked)?;
        let kv = entry.key_version;
        let key = Key32::clone(&entry.key.key);
        let mut report = ApplyReport::default();
        let server_ids: HashSet<ItemId> = items.iter().map(|i| i.id).collect();
        let mut decoded = Vec::with_capacity(items.len());
        for it in items {
            match open_body(&key, kv, vault, it.id, &it.envelope) {
                Some(body) => {
                    for s in body.fields.values() {
                        if let Err(e) = u.clock.observe_stamp(s) {
                            report.skew.get_or_insert(e);
                        }
                    }
                    if let Some(d) = &body.deleted
                        && let Err(e) = u.clock.observe_stamp(d)
                    {
                        report.skew.get_or_insert(e);
                    }
                    decoded.push((it, body));
                }
                None => {
                    tracing::warn!(item = %it.id.short(), vault = %vault.short(), "remote item does not decrypt; skipped");
                    report.undecryptable.push(it.id);
                }
            }
        }
        let hlc = u.clock.last();
        struct TxOut {
            finals: Vec<(ItemId, ItemBody)>,
            purged: Vec<ItemId>,
            merged: Vec<ItemId>,
            resurrected: Vec<String>,
            approvals: Vec<(ItemId, &'static str)>,
            requeued: usize,
        }
        let out = self
            .inner
            .store
            .write(move |w| {
                let mut page = Vec::with_capacity(decoded.len());
                let mut out = TxOut {
                    finals: Vec::new(),
                    purged: Vec::new(),
                    merged: Vec::new(),
                    resurrected: Vec::new(),
                    approvals: Vec::new(),
                    requeued: 0,
                };
                for (it, remote) in decoded {
                    let local = w.as_read().get_item(it.id)?;
                    let local_body = local
                        .as_ref()
                        .filter(|l| l.vault_id == vault)
                        .and_then(|l| open_body(&key, kv, vault, it.id, &l.envelope));
                    let as_received = RemoteItem {
                        id: it.id,
                        revision: it.revision,
                        key_version: it.key_version,
                        envelope: it.envelope,
                        deleted: it.deleted,
                        local_pending: false,
                    };
                    let dirty = local
                        .as_ref()
                        .is_some_and(|l| l.dirty && l.vault_id == vault);
                    let (item, body) = match (&local_body, dirty) {
                        // The local copy adds something: merge, re-seal, keep queued.
                        (Some(lb), true) if merge(&remote, lb).changed() => {
                            let m = merge(lb, &remote);
                            if m.resurrected {
                                out.resurrected.push(label_of(Some(&m.body), it.id));
                            }
                            let envelope = seal_body(&key, kv, vault, it.id, &m.body)?;
                            out.merged.push(it.id);
                            let item = RemoteItem {
                                id: it.id,
                                revision: it.revision,
                                key_version: kv,
                                envelope,
                                deleted: m.body.is_deleted(),
                                local_pending: true,
                            };
                            let mut remote = remote;
                            scrub(&mut remote);
                            (item, m.body)
                        }
                        _ => (as_received, remote),
                    };
                    for field in changed_local_acting(local_body.as_ref(), &body) {
                        w.delete_local_approval(it.id, field)?;
                        out.approvals.push((it.id, field));
                    }
                    if let Some(mut lb) = local_body {
                        scrub(&mut lb);
                    }
                    page.push(item);
                    out.finals.push((it.id, body));
                }
                match mode {
                    ApplyMode::Page { cursor } => w.apply_remote(vault, &page, cursor)?,
                    ApplyMode::Conflict => w.apply_remote_items(vault, &page)?,
                    ApplyMode::Resync { head } => {
                        for local in w.as_read().list_items(vault)? {
                            if server_ids.contains(&local.id) {
                                continue;
                            }
                            if local.dirty {
                                // The server purged it (or never had it):
                                // push again as a new item.
                                page.push(RemoteItem {
                                    id: local.id,
                                    revision: 0,
                                    key_version: local.key_version,
                                    envelope: local.envelope,
                                    deleted: local.deleted,
                                    local_pending: true,
                                });
                                out.requeued += 1;
                            } else {
                                w.purge_item(local.id)?;
                                w.delete_local_approvals_of(local.id)?;
                                out.purged.push(local.id);
                            }
                        }
                        w.apply_remote(vault, &page, head)?;
                    }
                }
                w.set_hlc_last(hlc)?;
                Ok(out)
            })
            .await
            .map_err(storage)?;
        for (id, body) in out.finals {
            let outcome = migrate(body);
            self.inner.store.set_read_only(id, outcome.read_only);
            if outcome.body.is_deleted() {
                u.items.remove(&id);
                let mut b = outcome.body;
                scrub(&mut b);
            } else {
                u.items.insert(
                    id,
                    Cached {
                        vault_id: vault,
                        body: outcome.body,
                        read_only: outcome.read_only,
                    },
                );
            }
            report.applied.push(id);
        }
        report.purged = out.purged.len();
        for id in out.purged {
            u.items.remove(&id);
            report.applied.push(id);
        }
        report.merged = out.merged;
        report.resurrected = out.resurrected;
        report.approvals = out.approvals;
        report.requeued = out.requeued;
        Ok(report)
    }

    /// The queued changes of `vault` ready to push, oldest first, skipping
    /// `skip` (items held back by the engine) and dropping from the outbox
    /// the kinds `allow` keeps on this device.
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::Storage`].
    pub async fn outgoing(
        &self,
        vault: VaultId,
        skip: HashSet<ItemId>,
        allow: impl Fn(ItemKind) -> bool + Send + 'static,
    ) -> Result<OutgoingBatch, VaultError> {
        let (kv, key) = {
            let state = self.inner.state.read().await;
            let u = state.as_ref().ok_or(VaultError::Locked)?;
            let entry = u.vaults.get(&vault).ok_or(VaultError::Locked)?;
            (entry.key_version, Key32::clone(&entry.key.key))
        };
        self.inner
            .store
            .write(move |w| {
                let mut batch = OutgoingBatch::default();
                for row in w.as_read().list_outbox(vault)? {
                    let id = row.item_id;
                    if skip.contains(&id) {
                        continue;
                    }
                    let Some(item) = w.as_read().get_item(id)? else {
                        w.dequeue(id)?;
                        continue;
                    };
                    if item.vault_id != vault {
                        continue;
                    }
                    let Some(mut body) = open_body(&key, kv, vault, id, &item.envelope) else {
                        tracing::warn!(item = %id.short(), "queued item does not decrypt; not pushed");
                        batch.undecryptable.push(id);
                        continue;
                    };
                    let label = label_of(Some(&body), id);
                    let kind = body.kind;
                    scrub(&mut body);
                    if !allow(kind) {
                        w.dequeue(id)?;
                        batch.excluded += 1;
                        continue;
                    }
                    batch.changes.push(Outgoing {
                        id,
                        queued_at: row.queued_at,
                        base_revision: row.base_revision,
                        key_version: item.key_version,
                        envelope: item.envelope,
                        deleted: item.deleted,
                        label,
                    });
                }
                Ok(batch)
            })
            .await
            .map_err(storage)
    }
}
