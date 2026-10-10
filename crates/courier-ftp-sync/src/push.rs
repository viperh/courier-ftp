//! Push: batches from the outbox (≤ 500 items, ≤ 8 MiB of envelopes) posted
//! to `POST /v1/vaults/{id}/changes`. Results:
//! * `ok` → store the revision, clear dirty, delete the outbox row (unless
//!   the item was edited again meanwhile: then it stays queued, rebased). The
//!   cursor is **not** moved: the next pull applies our own revisions
//!   idempotently, so revisions of other devices in between are never
//!   skipped;
//! * `conflict` with `current` → merge (T81), re-seal, rebase onto
//!   `current.revision`, retry (at most [`MAX_CONFLICT_ROUNDS`] rounds, then
//!   the item is held back with an error);
//! * `conflict` without `current` (the server purged the tombstone) → rebase
//!   on 0 and retry as a new item;
//! * `forbidden` / `too_large` → the item is held back with an error shown
//!   in the UI; the local change is kept.
//!
//! Transport errors bump `outbox.attempts`; the engine retries with backoff.
//! Nothing is lost on a failure: the outbox row is only deleted after the
//! server accepted the change.

use std::collections::{HashMap, HashSet};

use courier_ftp_core::model::item::{ItemId, VaultId};
use courier_ftp_proto::ErrorCode;
use courier_ftp_proto::limits::{MAX_ENVELOPE, MAX_PUSH_BYTES, MAX_PUSH_ITEMS};
use courier_ftp_proto::sync::{PushChange, PushRequest, PushStatus};
use courier_ftp_store::StoreError;
use courier_ftp_store::vault::{ApplyMode, Outgoing};

use crate::engine::{BlockReason, Ctx, MAX_CONFLICT_ROUNDS};
use crate::error::SyncError;
use crate::pull::{incoming, wire_rev};
use crate::status::ToastLevel;

/// Splits changes into batches within the protocol limits.
pub(crate) fn batches(changes: Vec<Outgoing>) -> Vec<Vec<Outgoing>> {
    let mut out: Vec<Vec<Outgoing>> = Vec::new();
    let mut cur: Vec<Outgoing> = Vec::new();
    let mut bytes = 0usize;
    for p in changes {
        let len = p.envelope.len();
        if !cur.is_empty() && (cur.len() >= MAX_PUSH_ITEMS || bytes + len > MAX_PUSH_BYTES) {
            out.push(std::mem::take(&mut cur));
            bytes = 0;
        }
        bytes += len;
        cur.push(p);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn wire_change(p: &Outgoing) -> PushChange {
    PushChange {
        id: p.id.uuid(),
        base_revision: u64::try_from(p.base_revision).unwrap_or(0),
        key_version: p.key_version,
        envelope: p.envelope.clone(),
        deleted: p.deleted,
    }
}

fn ignore_not_found(r: Result<(), StoreError>) -> Result<(), StoreError> {
    match r {
        Err(StoreError::NotFound) => Ok(()),
        other => other,
    }
}

impl Ctx {
    fn too_large(&mut self, id: ItemId, label: &str, why: &str) {
        self.block(id, BlockReason::TooLarge(why.to_owned()));
        self.toast(
            ToastLevel::Error,
            format!("‘{label}’ was not uploaded: {why}. It is kept on this device."),
        );
    }

    fn read_only(&mut self, vault: VaultId, ids: &[ItemId]) {
        for id in ids {
            self.block(*id, BlockReason::ReadOnly);
        }
        self.toast(
            ToastLevel::Error,
            format!(
                "You have read-only access to vault {}. Your local change was not uploaded.",
                vault.short()
            ),
        );
    }

    /// Pushes `vault`'s outbox; `true` when something was accepted.
    pub(crate) async fn push_vault(&mut self, vault: VaultId) -> Result<bool, SyncError> {
        let mut accepted = false;
        for _round in 0..MAX_CONFLICT_ROUNDS {
            let skip: HashSet<ItemId> = self.blocked.keys().copied().collect();
            let policy = self.config.policy;
            let batch = self
                .vault
                .outgoing(vault, skip, move |k| policy.allows(k))
                .await?;
            if batch.excluded > 0 {
                tracing::debug!(vault = %vault.short(), n = batch.excluded, "device-local items not pushed");
            }
            for id in batch.undecryptable {
                self.block(id, BlockReason::Undecryptable);
            }
            let mut changes = Vec::with_capacity(batch.changes.len());
            for p in batch.changes {
                if p.envelope.len() > MAX_ENVELOPE {
                    self.too_large(p.id, &p.label, "it is larger than 1 MiB");
                } else {
                    changes.push(p);
                }
            }
            if changes.is_empty() {
                break;
            }
            let mut retry = false;
            for chunk in batches(changes) {
                let req = std::sync::Arc::new(PushRequest {
                    changes: chunk.iter().map(wire_change).collect(),
                });
                let res = self
                    .call(|api, t| {
                        let req = std::sync::Arc::clone(&req);
                        async move { api.push(&t, vault.uuid(), &req).await }
                    })
                    .await;
                match res {
                    Ok(resp) => {
                        let (ok, again) = self.apply_results(vault, chunk, resp.results).await?;
                        accepted |= ok;
                        retry |= again;
                    }
                    Err(e) if e.code() == Some(ErrorCode::Rotating) => {
                        tracing::info!(vault = %vault.short(), "vault key rotation in progress; pushes paused");
                        return Ok(accepted);
                    }
                    Err(e) if e.code() == Some(ErrorCode::Forbidden) => {
                        let ids: Vec<ItemId> = chunk.iter().map(|p| p.id).collect();
                        self.read_only(vault, &ids);
                    }
                    Err(e) => {
                        if e.is_offline() {
                            let ids: Vec<ItemId> = chunk.iter().map(|p| p.id).collect();
                            let _ = self
                                .vault
                                .store()
                                .write(move |w| {
                                    for id in ids {
                                        match w.bump_attempts(id) {
                                            Ok(_) | Err(StoreError::NotFound) => {}
                                            Err(e) => return Err(e),
                                        }
                                    }
                                    Ok(())
                                })
                                .await;
                        }
                        return Err(e);
                    }
                }
            }
            if !retry {
                break;
            }
        }
        Ok(accepted)
    }

    /// Applies one batch's results. Returns (anything accepted, any conflict
    /// to retry).
    async fn apply_results(
        &mut self,
        vault: VaultId,
        chunk: Vec<Outgoing>,
        results: Vec<courier_ftp_proto::sync::PushResult>,
    ) -> Result<(bool, bool), SyncError> {
        let by_id: HashMap<uuid::Uuid, courier_ftp_proto::sync::PushResult> =
            results.into_iter().map(|r| (r.id, r)).collect();
        let mut ok = Vec::new();
        let mut current = Vec::new();
        let mut rebase_new = Vec::new();
        let mut retry = false;
        for p in chunk {
            let Some(r) = by_id.get(&p.id.uuid()) else {
                tracing::warn!(item = %p.id.short(), "no push result for an item; retried later");
                continue;
            };
            match r.status {
                PushStatus::Ok => {
                    if let Some(rev) = r.revision {
                        ok.push((p.id, wire_rev(rev), p.queued_at));
                    }
                }
                PushStatus::Conflict => {
                    let n = self.conflicts.entry(p.id).or_insert(0);
                    *n += 1;
                    if *n >= MAX_CONFLICT_ROUNDS {
                        self.block(p.id, BlockReason::Conflict);
                        self.toast(
                            ToastLevel::Error,
                            format!(
                                "‘{}’ could not be synced: it kept conflicting. It is kept on this device.",
                                p.label
                            ),
                        );
                    } else {
                        retry = true;
                    }
                    match &r.current {
                        Some(cur) => current.push(incoming(cur.clone())),
                        // Purged tombstone: push again as a new item.
                        None => rebase_new.push(p.id),
                    }
                }
                PushStatus::Forbidden => self.read_only(vault, &[p.id]),
                PushStatus::TooLarge => {
                    let why = r.message.clone().unwrap_or_else(|| "too large".into());
                    self.too_large(p.id, &p.label, &why);
                }
            }
        }
        let accepted = !ok.is_empty();
        if accepted || !rebase_new.is_empty() {
            let ok2 = ok.clone();
            self.vault
                .store()
                .write(move |w| {
                    for (id, rev, queued_at) in ok2 {
                        ignore_not_found(w.mark_pushed(id, rev, queued_at))?;
                    }
                    for id in rebase_new {
                        ignore_not_found(w.rebase(id, 0))?;
                    }
                    Ok(())
                })
                .await?;
        }
        for (id, _, _) in ok {
            self.clear_item(id);
        }
        if !current.is_empty() {
            let report = self
                .vault
                .apply_incoming(vault, current, ApplyMode::Conflict)
                .await?;
            self.after_apply(vault, report);
        }
        Ok((accepted, retry))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(len: usize) -> Outgoing {
        Outgoing {
            id: ItemId::new(),
            queued_at: 0,
            base_revision: 0,
            key_version: 1,
            envelope: vec![0; len],
            deleted: false,
            label: String::new(),
        }
    }

    #[test]
    fn batches_respect_count_and_bytes() {
        let b = batches((0..1200).map(|_| p(10)).collect());
        assert_eq!(
            b.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![500, 500, 200]
        );
        let mib = 1024 * 1024;
        let b = batches((0..20).map(|_| p(mib)).collect());
        assert!(b.iter().all(|x| x.len() <= 8));
        assert_eq!(b.iter().map(Vec::len).sum::<usize>(), 20);
        assert!(batches(Vec::new()).is_empty());
    }

    #[test]
    fn policy_keeps_history_local_unless_enabled() {
        use courier_ftp_core::model::item::ItemKind;

        use crate::engine::SyncPolicy;
        let off = SyncPolicy::default();
        assert!(off.allows(ItemKind::Site));
        assert!(!off.allows(ItemKind::HistoryEntry));
        assert!(SyncPolicy { history: true }.allows(ItemKind::HistoryEntry));
    }
}
