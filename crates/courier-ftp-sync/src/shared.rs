//! The sync engine's side of team vaults (T89): after each vault list
//! refresh ([`Ctx::reconcile_vaults`]):
//!
//! * **adopt** team vaults shared with the account: fetch the membership
//!   list, pin the granter on first sight, verify the grant
//!   ([`crate::trust::open_verified_grant`]: signature against the **pinned**
//!   granter key, granter has `manage`), then install the key
//!   (`VaultEngine::install_vault_key`) and pull. A refused grant is reported
//!   once (toast) and the key is never used;
//! * **rotated keys**: a vault whose server key version is ahead of the
//!   local one (and no rotation is running) gets the new key from the
//!   account's new grant, verified the same way; local items still under the
//!   old key are re-sealed and the rotated items re-pulled;
//! * **permissions**: a vault with only `read` is marked read-only in the
//!   vault engine (its items show a lock and can't be edited);
//! * **revoked**: a team vault the server no longer lists for the account
//!   (access revoked, org left or removed) is removed from this device;
//! * **abandoned rotations** of vaults the account manages are reported once
//!   ([`crate::SyncEvent::RotationAbandoned`]).

use std::collections::HashMap;
use std::sync::Arc;

use courier_ftp_core::model::item::{OrgId, VaultId};
use courier_ftp_crypto::Key32;
use courier_ftp_crypto::account::AccountKeys;
use courier_ftp_proto::sync::{Permission, VaultKind as ProtoVaultKind, VaultView};
use courier_ftp_store::VaultKind;
use courier_ftp_store::vault::{KeyInstall, VaultEngine};
use uuid::Uuid;

use crate::account::{load_account_keys, seal_vault_name};
use crate::engine::Ctx;
use crate::error::SyncError;
use crate::status::{SyncEvent, ToastLevel};
use crate::teams::{local_vault_name, name_key, open_vault_name, save_vault_name};
use crate::trust::{TokenDirectory, Trust, VaultMembership, open_verified_grant};

/// Installs rotated key `nkv` of `vault` on this device: the locally kept
/// vault name is re-sealed under the new key, then the vault engine
/// re-seals the local items (`VaultEngine::install_vault_key`).
///
/// # Errors
/// [`SyncError::Crypto`] / [`SyncError::Store`].
pub(crate) async fn install_rotated(
    engine: &VaultEngine,
    vault: VaultId,
    nkv: u32,
    old: &Key32,
    new: &Key32,
) -> Result<KeyInstall, SyncError> {
    if let Some(name) = local_vault_name(engine.store(), vault, old).await
        && let Ok(enc) = seal_vault_name(new, vault, nkv, &name)
    {
        save_vault_name(engine.store(), vault, enc).await;
    }
    let row = engine.store().vaults().get(vault).await?;
    let (kind, org) = row.map_or((VaultKind::Shared, None), |r| (r.kind, r.org_id));
    Ok(engine.install_vault_key(vault, kind, org, nkv, new).await?)
}

impl Ctx {
    /// This account and its keys, loaded once per engine (`None` when the
    /// device holds no account keys: team vaults are then not adopted).
    pub(crate) async fn account_keys(&mut self) -> Option<(Uuid, Arc<AccountKeys>)> {
        if self.account.is_none() {
            match load_account_keys(&self.vault).await {
                Ok(Some((acct, keys))) => self.account = Some((acct.user_id, Arc::new(keys))),
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "account keys not available; team vaults wait")
                }
            }
        }
        self.account.clone()
    }

    /// Opens this account's grant for key `version` of `view` after the
    /// trust checks. `Err` carries the reason (for the toast).
    async fn open_team_grant(&mut self, view: &VaultView, version: u32) -> Result<Key32, String> {
        let Some((me, keys)) = self.account_keys().await else {
            return Err("this device holds no account keys".into());
        };
        let id = view.id;
        let membership = match self
            .call(|api, t| async move { api.vault_members(&t, id).await })
            .await
        {
            Ok(m) => VaultMembership::from_view(&m),
            Err(e) => return Err(format!("no member list: {e}")),
        };
        let trust = Trust::new(self.vault.store().clone(), me);
        if let Err(e) = trust
            .pin_granters(
                &TokenDirectory(Arc::clone(&self.tokens)),
                std::slice::from_ref(view),
            )
            .await
        {
            tracing::warn!(vault = %id, error = %e, "could not pin the granter");
        }
        let pins = trust
            .pins()
            .await
            .map_err(|e| e.to_string())?
            .with_self(me, keys.public());
        open_verified_grant(&pins, me, &keys, view, version, Some(&membership)).map_err(|e| {
            tracing::warn!(vault = %id, version, error = %e, "vault key grant rejected");
            e.to_string()
        })
    }

    fn refuse(&mut self, vault: VaultId, reason: String) {
        if self.rejected_grants.insert(vault, reason.clone()).is_none() {
            self.toast(
                ToastLevel::Error,
                format!(
                    "A vault was shared with you, but its key could not be verified and is \
                     not used: {reason}"
                ),
            );
        }
    }

    /// See the module docs. `views` is a fresh `GET /v1/vaults`.
    pub(crate) async fn reconcile_vaults(&mut self, views: &[VaultView]) -> Result<(), SyncError> {
        let local: HashMap<VaultId, courier_ftp_store::VaultRow> = self
            .vault
            .store()
            .vaults()
            .list()
            .await?
            .into_iter()
            .map(|r| (r.id, r))
            .collect();
        for view in views {
            let vault = VaultId::from_uuid(view.id);
            self.note_abandoned(view);
            if view.kind != ProtoVaultKind::Shared {
                continue;
            }
            let row = local.get(&vault);
            let rotating = view.rotation.is_some();
            let has_grant = view
                .grants
                .iter()
                .any(|g| g.key_version == view.key_version);
            match row {
                None if !rotating && has_grant => {
                    let vk = match self.open_team_grant(view, view.key_version).await {
                        Ok(k) => k,
                        Err(reason) => {
                            self.refuse(vault, reason);
                            continue;
                        }
                    };
                    self.vault
                        .install_vault_key(
                            vault,
                            VaultKind::Shared,
                            view.org_id.map(OrgId::from_uuid),
                            view.key_version,
                            &vk,
                        )
                        .await?;
                    save_vault_name(self.vault.store(), vault, view.name_enc.clone()).await;
                    let name = open_vault_name(&vk, vault, &view.name_enc).ok();
                    self.rejected_grants.remove(&vault);
                    self.unknown_vaults.remove(&vault);
                    tracing::info!(vault = %vault.short(), permission = view.permission.as_str(), "team vault adopted");
                    self.toast(
                        ToastLevel::Info,
                        match &name {
                            Some(n) => format!("You now have access to the team vault “{n}”"),
                            None => "You now have access to a team vault".to_owned(),
                        },
                    );
                    self.emit(SyncEvent::VaultAdded { vault, name });
                }
                Some(r) if r.key_version < view.key_version && !rotating && has_grant => {
                    let vk2 = match self.open_team_grant(view, view.key_version).await {
                        Ok(k) => k,
                        Err(reason) => {
                            self.refuse(vault, reason);
                            continue;
                        }
                    };
                    match self.vault.vault_key(vault).await {
                        Ok((_, old)) => {
                            install_rotated(&self.vault, vault, view.key_version, &old, &vk2)
                                .await?;
                        }
                        // The old key never loaded: just install the new one.
                        Err(_) => {
                            self.vault
                                .install_vault_key(
                                    vault,
                                    VaultKind::Shared,
                                    r.org_id,
                                    view.key_version,
                                    &vk2,
                                )
                                .await?;
                            save_vault_name(self.vault.store(), vault, view.name_enc.clone()).await;
                        }
                    }
                    self.rejected_grants.remove(&vault);
                    tracing::info!(vault = %vault.short(), key_version = view.key_version, "rotated vault key installed");
                }
                _ => {}
            }
            if self.vault.loaded_vaults().await.contains(&vault) {
                let read_only = view.permission == Permission::Read;
                if self.vault.set_vault_read_only(vault, read_only).await? {
                    tracing::info!(vault = %vault.short(), read_only, "vault permission changed");
                    self.emit(SyncEvent::VaultAccess { vault });
                }
            }
        }
        // Team vaults the server no longer lists for this account.
        for (vault, row) in &local {
            if row.kind != VaultKind::Shared || views.iter().any(|v| v.id == vault.uuid()) {
                continue;
            }
            let name = match self.vault.vault_key(*vault).await {
                Ok((_, vk)) => local_vault_name(self.vault.store(), *vault, &vk).await,
                Err(_) => None,
            };
            if self.vault.remove_vault(*vault).await? {
                if let Err(e) = self.vault.store().meta().delete(&name_key(*vault)).await {
                    tracing::debug!(error = %e, "vault name not removed");
                }
                self.unknown_vaults.remove(vault);
                self.toast(
                    ToastLevel::Warn,
                    match name {
                        Some(n) => format!("Your access to the team vault “{n}” ended; it was removed from this device"),
                        None => format!("Your access to team vault {} ended; it was removed from this device", vault.short()),
                    },
                );
                self.emit(SyncEvent::VaultRemoved { vault: *vault });
            }
        }
        Ok(())
    }

    /// Reports an abandoned rotation of a vault this account manages, once
    /// per engine.
    fn note_abandoned(&mut self, view: &VaultView) {
        let vault = VaultId::from_uuid(view.id);
        let abandoned = view.rotation.as_ref().is_some_and(|r| r.abandoned);
        if !abandoned {
            self.abandoned_reported.remove(&vault);
            return;
        }
        if view.permission == Permission::Manage && self.abandoned_reported.insert(vault) {
            tracing::warn!(vault = %vault.short(), "a key rotation was abandoned; pushes stay paused until it is restarted");
            self.emit(SyncEvent::RotationAbandoned { vault });
        }
    }
}
