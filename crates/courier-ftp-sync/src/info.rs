//! What this device knows about its sync setup without contacting the
//! server or unlocking: the sync panel (T90) shows it.

use courier_ftp_core::model::item::VaultId;
use courier_ftp_store::meta::keys;
use courier_ftp_store::{Store, VaultKind};

use crate::account::load_account;
use crate::error::SyncError;

/// One vault's local sync state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultInfo {
    /// The vault.
    pub vault: VaultId,
    /// Personal or team.
    pub kind: VaultKind,
    /// Highest server revision applied locally.
    pub cursor: i64,
    /// Queued local changes.
    pub pending: u64,
}

/// The local sync state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalSyncInfo {
    /// `sync_state.server_url`; `None` in local-only mode.
    pub server_url: Option<String>,
    /// Tokens are stored (the device is signed in).
    pub signed_in: bool,
    /// `meta.account.email`.
    pub email: Option<String>,
    /// UNIX ms of the last cycle that finished without an error.
    pub last_sync_ms: Option<i64>,
    /// Every local vault.
    pub vaults: Vec<VaultInfo>,
}

impl LocalSyncInfo {
    /// All pending changes.
    #[must_use]
    pub fn pending_total(&self) -> u64 {
        self.vaults.iter().map(|v| v.pending).sum()
    }
}

/// Reads the local sync state (no network, no keys needed).
///
/// # Errors
/// [`SyncError::Store`].
pub async fn local_info(store: &Store) -> Result<LocalSyncInfo, SyncError> {
    let state = store.sync_state().get().await?;
    let server_url = state.as_ref().and_then(|s| s.server_url.clone());
    let signed_in = state.as_ref().is_some_and(|s| s.tokens_enc.is_some());
    let email = load_account(store).await.ok().flatten().map(|a| a.email);
    let last_sync_ms = store
        .meta()
        .get(keys::SYNC_LAST_OK)
        .await?
        .and_then(|v| String::from_utf8(v).ok())
        .and_then(|v| v.trim().parse().ok());
    let pending = store.outbox().pending_by_vault().await?;
    let vaults = store
        .vaults()
        .list()
        .await?
        .into_iter()
        .map(|v| VaultInfo {
            vault: v.id,
            kind: v.kind,
            cursor: v.sync_cursor,
            pending: pending
                .iter()
                .find(|(id, _)| *id == v.id)
                .map_or(0, |(_, n)| *n),
        })
        .collect();
    Ok(LocalSyncInfo {
        server_url,
        signed_in,
        email,
        last_sync_ms,
        vaults,
    })
}
