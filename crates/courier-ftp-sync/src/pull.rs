//! Pull: `GET changes?since=<cursor>&limit=500`, each page applied in **one**
//! SQLite transaction together with the cursor update
//! (`VaultEngine::apply_incoming`, which decrypts, observes HLC stamps,
//! replaces clean items and merges dirty ones). Loops while `more`.
//!
//! Resync on `410 gone` (the cursor is below the server's tombstone GC
//! floor): everything is pulled from 0 and applied at once; clean local items
//! the server no longer has are deleted, dirty ones are re-queued as new
//! items (`base_revision = 0`).

use courier_ftp_core::model::item::{ItemId, VaultId};
use courier_ftp_proto::ErrorCode;
use courier_ftp_proto::sync::RemoteItem as WireItem;
use courier_ftp_store::vault::{ApplyMode, Incoming};

use crate::engine::Ctx;
use crate::error::SyncError;

pub(crate) fn wire_rev(rev: u64) -> i64 {
    i64::try_from(rev).unwrap_or(i64::MAX)
}

pub(crate) fn incoming(item: WireItem) -> Incoming {
    Incoming {
        id: ItemId::from_uuid(item.id),
        revision: wire_rev(item.revision),
        key_version: item.key_version,
        envelope: item.envelope,
        deleted: item.deleted,
    }
}

impl Ctx {
    /// Pulls `vault` until the server has no more pages.
    pub(crate) async fn pull_vault(&mut self, vault: VaultId) -> Result<(), SyncError> {
        loop {
            let Some(row) = self.vault.store().vaults().get(vault).await? else {
                return Ok(());
            };
            let since = u64::try_from(row.sync_cursor).unwrap_or(0);
            let limit = self.config.page_limit;
            let res = self
                .call(move |api, t| async move { api.pull(&t, vault.uuid(), since, limit).await })
                .await;
            let page = match res {
                Err(e) if e.code() == Some(ErrorCode::Gone) => {
                    return self.full_resync(vault).await;
                }
                Err(e) if e.code() == Some(ErrorCode::NotFound) => {
                    if self.unknown_vaults.insert(vault) {
                        tracing::warn!(vault = %vault.short(), "vault is not on the server (or no longer a member)");
                    }
                    return Ok(());
                }
                other => other?,
            };
            let more = page.more && !page.items.is_empty();
            let cursor = page.next_cursor(since);
            if page.items.is_empty() && cursor == since {
                return Ok(());
            }
            let items = page.items.into_iter().map(incoming).collect();
            let report = self
                .vault
                .apply_incoming(
                    vault,
                    items,
                    ApplyMode::Page {
                        cursor: wire_rev(cursor),
                    },
                )
                .await?;
            self.after_apply(vault, report);
            if !more {
                return Ok(());
            }
        }
    }

    /// Full resync after `410 gone` (see the module docs).
    pub(crate) async fn full_resync(&mut self, vault: VaultId) -> Result<(), SyncError> {
        tracing::info!(vault = %vault.short(), "cursor below the server's GC floor: full resync");
        let mut all = Vec::new();
        let mut since = 0u64;
        let head = loop {
            let limit = self.config.page_limit;
            let page = self
                .call(move |api, t| async move { api.pull(&t, vault.uuid(), since, limit).await })
                .await?;
            let next = page.next_cursor(since);
            let more = page.more && !page.items.is_empty() && next > since;
            let head = page.head_revision;
            all.extend(page.items.into_iter().map(incoming));
            if !more {
                break head;
            }
            since = next;
        };
        let report = self
            .vault
            .apply_incoming(
                vault,
                all,
                ApplyMode::Resync {
                    head: wire_rev(head),
                },
            )
            .await?;
        self.after_apply(vault, report);
        Ok(())
    }
}
