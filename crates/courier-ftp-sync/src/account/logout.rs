//! Logout / disable sync, keeping the local data (`--keep-local`).
//!
//! * The tokens are revoked server-side (`POST /v1/auth/logout`) by
//!   [`SyncSession::logout`](crate::SyncSession::logout); offline, the local
//!   part still runs and the report says so.
//! * Team vaults are removed from the device (they belong to the org).
//! * The personal vault and the master password stay as they are. Its items
//!   are reset to "never synced" (`revision = 0`, dirty, `base_revision = 0`,
//!   cursor 0), so a later registration or login uploads them again.
//! * `sync_state`, `meta.account` and the sealed account keys are removed.

use courier_ftp_store::VaultKind;
use courier_ftp_store::vault::VaultEngine;

use super::AccountError;
use super::local;

/// What a logout did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogoutReport {
    /// The server revoked the tokens. `false`: it was unreachable or the
    /// tokens were already invalid.
    pub revoked: bool,
    /// Why the revocation did not happen.
    pub revoke_error: Option<String>,
    /// Team vaults removed from this device.
    pub shared_removed: usize,
    /// Personal items kept (queued for a later upload).
    pub kept_items: u64,
}

/// The local part of a logout (see the module docs): also what runs when
/// this device was revoked or the account deleted. The vault must be
/// unlocked; the engine's state is reloaded.
///
/// # Errors
/// [`AccountError::Local`].
pub async fn logout_local(vault: &VaultEngine) -> Result<LogoutReport, AccountError> {
    let (shared_removed, kept_items) = vault
        .commit(|w| {
            let mut removed = 0;
            let mut kept = 0;
            for row in w.as_read().list_vaults()? {
                match row.kind {
                    VaultKind::Shared => {
                        w.delete_vault(row.id)?;
                        removed += 1;
                    }
                    VaultKind::Personal => kept += w.reset_sync(row.id)?,
                }
            }
            w.clear_sync_state()?;
            local::clear_account(w)?;
            Ok((removed, kept))
        })
        .await?;
    tracing::info!(shared_removed, "logged out; local data kept");
    Ok(LogoutReport {
        revoked: false,
        revoke_error: None,
        shared_removed,
        kept_items,
    })
}
