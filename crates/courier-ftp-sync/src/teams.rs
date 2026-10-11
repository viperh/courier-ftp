//! Teams on the client (T89): orgs, members, invites, the audit log, trust
//! (pins and safety numbers), team vaults and key rotation. This is the API
//! the Settings → Teams screens (T90) use.
//!
//! Get a [`Teams`] from a signed-in session with [`crate::SyncSession::teams`]
//! (needs the unlocked vault: the account keys are sealed under the LMK).
//!
//! | Screen / action | Call |
//! |---|---|
//! | Orgs list, create | [`Teams::list_orgs`], [`Teams::create_org`] |
//! | Members with roles and trust state | [`Teams::org_members`] ([`MemberEntry`]) |
//! | Change role, remove (rotates their vaults) | [`Teams::set_role`], [`Teams::remove_member`] |
//! | Leave an org (its vaults leave this device) | [`Teams::leave_org`] |
//! | Invite by email or link, accept a pasted link | [`Teams::invite`], [`Teams::accept_invite`] |
//! | Audit log (admins) | [`Teams::audit`] |
//! | Safety number, mark verified | [`Teams::safety_number`], [`Teams::mark_verified`] |
//! | Key-change warning dialog: accept | [`Teams::accept_new_key`] |
//! | Team vaults with names, "needs key" | [`Teams::org_vaults`] ([`OrgVaultEntry`]) |
//! | Create a team vault | [`Teams::create_vault`] |
//! | Vault members, grant, revoke (+ rotation) | [`Teams::vault_members`], [`Teams::grant`], [`Teams::revoke_and_rotate`] |
//! | Rotate / resume a rotation | [`Teams::rotate`] ([`crate::rotation`]) |
//! | Vault names for the Site Manager roots | [`Teams::vault_names`] |
//! | Copy / move a site between vaults | [`Teams::copy_site_to_vault`], [`Teams::move_site_to_vault`] |
//! | Read-only vault (lock icon, fields disabled) | `VaultEngine::is_vault_read_only`; edits fail with `VaultError::ReadOnlyVault` |
//! | My own login for a team site (credential override) | `courier_ftp_core::sites::SiteManager::{credential_override, set_credential_override}` (applied by `SiteManager::connect`) |
//! | Live changes (vault added / removed, rotation abandoned) | [`crate::SyncEvent`]`::{VaultAdded, VaultRemoved, VaultAccess, RotationAbandoned}` |
//!
//! * **Create**: a fresh vault key (VK), the name sealed under it, the
//!   creator's `manage` self-grant; the VK is installed locally (wrapped under
//!   the LMK). The server never sees the VK.
//! * **Grant**: the member's public keys are fetched and pinned on first
//!   sight, **refused** while a key change is pending; the VK is HPKE-wrapped
//!   to the member and the wrap signed with our Ed25519 key.
//! * **Receive**: the sync engine adopts vaults shared with the account only
//!   after verifying the grant against the pinned granter key and the
//!   membership list ([`crate::trust::verify_grant`]); see `crate::shared`.
//!
//! Vault names are sealed under the VK (`name_enc`). This device keeps the
//! sealed name in `meta` (`vault_name_enc/<id>`, re-sealed under the new key
//! after a rotation) so it never sits in plaintext at rest. A member who
//! joins after a rotation can't open the server's `name_enc` (sealed under
//! the first key) and sees the vault by id until renamed (no rename endpoint
//! yet).
//!
//! Adapted from sverb's `sverb-sync/src/account/{teams,vaults}.rs` (D13).

use std::collections::BTreeMap;
use std::sync::Arc;

use courier_ftp_core::model::item::{ItemId, OrgId, Site, VaultId};
use courier_ftp_core::vault::{ItemVault, ItemVaultExt, VaultError};
use courier_ftp_crypto::Key32;
use courier_ftp_crypto::account::AccountKeys;
use courier_ftp_crypto::envelope::open_item;
use courier_ftp_crypto::grant::{grant_vault_key, self_grant};
use courier_ftp_crypto::keys::{os_rng, random_key32};
use courier_ftp_proto::auth::GrantUpload;
use courier_ftp_proto::orgs::{
    AuditPage, CreateInviteRequest, InviteAccepted, InviteCreated, MemberView, OrgView, Role,
};
use courier_ftp_proto::sync::Permission;
use courier_ftp_proto::vaults::{CreateVaultRequest, GrantRequest, OrgVaultView, VaultMembersView};
use courier_ftp_store::{PinState, PinnedKey, Store, VaultKind};
use uuid::Uuid;

use crate::account::{AccountError, load_account_keys, seal_vault_name};
use crate::error::SyncError;
use crate::rotation::{RotationError, RotationOptions, RotationProgress, RotationReport};
use crate::session::SyncSession;
use crate::trust::{TokenDirectory, Trust, TrustError};

/// `meta` key prefix of a team vault's sealed name (`vault_name_enc/<uuid>`).
pub const META_VAULT_NAME_PREFIX: &str = "vault_name_enc/";

/// Longest vault name.
pub const MAX_VAULT_NAME: usize = 100;

/// Why a team operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TeamError {
    /// A member's (or granter's) key is not trusted: a pending key change
    /// (compare safety numbers and accept it first) or no pin.
    #[error(transparent)]
    Trust(#[from] TrustError),
    /// A server or local error.
    #[error(transparent)]
    Account(#[from] AccountError),
    /// This device holds no key for the vault.
    #[error("this device has no key for vault {}", .0.short())]
    NoKey(VaultId),
    /// Bad input (empty name, not an invite link, …).
    #[error("{0}")]
    Invalid(String),
}

impl From<SyncError> for TeamError {
    fn from(e: SyncError) -> Self {
        Self::Account(e.into())
    }
}

impl From<courier_ftp_store::StoreError> for TeamError {
    fn from(e: courier_ftp_store::StoreError) -> Self {
        Self::Account(e.into())
    }
}

impl From<courier_ftp_crypto::CryptoError> for TeamError {
    fn from(e: courier_ftp_crypto::CryptoError) -> Self {
        Self::Account(e.into())
    }
}

impl From<VaultError> for TeamError {
    fn from(e: VaultError) -> Self {
        Self::Account(e.into())
    }
}

type Res<T> = Result<T, TeamError>;

/// The invite token in a pasted link (`https://server/invite/<token>`) or
/// the bare token.
#[must_use]
pub fn invite_token(link: &str) -> Option<&str> {
    let t = link.trim().trim_end_matches('/');
    let t = t.rsplit_once("/invite/").map_or(t, |(_, tok)| tok);
    let t = t.split(['?', '#']).next().unwrap_or("");
    (!t.is_empty()
        && t.len() <= 128
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    .then_some(t)
}

/// An org member with this device's trust state of their key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberEntry {
    /// The server's row.
    pub member: MemberView,
    /// The pin, when this device has seen their keys (`None`: not fetched
    /// yet; [`Teams::member_keys`] fetches and pins them).
    pub pin: Option<PinnedKey>,
    /// This account.
    pub is_me: bool,
}

impl MemberEntry {
    /// The trust state (`None`: not pinned yet).
    #[must_use]
    pub fn state(&self) -> Option<PinState> {
        self.pin.as_ref().map(PinnedKey::state)
    }
}

/// An org vault as listed for the vault management page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgVaultEntry {
    /// The server's row.
    pub view: OrgVaultView,
    /// The name, when this device holds the key.
    pub name: Option<String>,
}

impl OrgVaultEntry {
    /// "needs key": an org admin without a grant yet.
    #[must_use]
    pub fn needs_key(&self) -> bool {
        !self.view.has_key
    }
}

/// What [`Teams::remove_member`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveReport {
    /// The vaults whose key was rotated, with the outcome. A failed rotation
    /// stays open on the server (pushes paused) until resumed with
    /// [`Teams::rotate`] or abandoned after 15 minutes.
    pub rotations: Vec<(VaultId, Result<RotationReport, RotationError>)>,
}

/// What [`Teams::reconcile_admins`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// `(vault, user)` granted `manage`.
    pub granted: Vec<(VaultId, Uuid)>,
    /// `(vault, user, reason)` not granted (untrusted key, server error).
    pub skipped: Vec<(VaultId, Uuid, String)>,
}

/// Opens a sealed vault name with the vault key.
///
/// # Errors
/// [`AccountError::Crypto`] when it does not open or is not UTF-8.
pub fn open_vault_name(
    vk: &Key32,
    vault: VaultId,
    name_enc: &[u8],
) -> Result<String, AccountError> {
    let plain = open_item(|_| Some(vk), vault.as_bytes(), vault.as_bytes(), name_enc)?;
    String::from_utf8(plain.to_vec())
        .map_err(|_| AccountError::Crypto("vault name is not UTF-8".into()))
}

pub(crate) fn name_key(vault: VaultId) -> String {
    format!("{META_VAULT_NAME_PREFIX}{}", vault.uuid())
}

/// Keeps a vault's sealed name on this device.
pub(crate) async fn save_vault_name(store: &Store, vault: VaultId, name_enc: Vec<u8>) {
    if let Err(e) = store.meta().set(&name_key(vault), name_enc).await {
        tracing::warn!(vault = %vault.short(), error = %e, "vault name not saved");
    }
}

/// The local name of `vault` opened with `vk`, if stored and it opens.
pub(crate) async fn local_vault_name(store: &Store, vault: VaultId, vk: &Key32) -> Option<String> {
    let enc = store.meta().get(&name_key(vault)).await.ok()??;
    open_vault_name(vk, vault, &enc).ok()
}

/// The names of the local team vaults this device can open (sealed names in
/// `meta`, opened with the loaded keys). The personal vault is not listed
/// (the UI calls it "Personal").
///
/// # Errors
/// [`AccountError::Local`].
pub async fn vault_names(
    vault: &courier_ftp_store::vault::VaultEngine,
) -> Result<BTreeMap<VaultId, String>, AccountError> {
    let mut out = BTreeMap::new();
    for row in vault.store().vaults().list().await? {
        if row.kind != VaultKind::Shared {
            continue;
        }
        if let Ok((_, vk)) = vault.vault_key(row.id).await
            && let Some(name) = local_vault_name(vault.store(), row.id, &vk).await
        {
            out.insert(row.id, name);
        }
    }
    Ok(out)
}

/// Team management for the account signed in on this unlocked device.
/// Cheap to clone.
#[derive(Clone)]
pub struct Teams {
    pub(crate) session: SyncSession,
    pub(crate) keys: Arc<AccountKeys>,
    pub(crate) trust: Trust,
    email: String,
}

impl std::fmt::Debug for Teams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Teams")
            .field("me", &self.trust.me())
            .finish_non_exhaustive()
    }
}

impl SyncSession {
    /// Team management for this session's account. Pins this account's own
    /// keys (safety numbers need them).
    ///
    /// # Errors
    /// [`AccountError::NotSignedIn`] (no account keys on this device),
    /// [`AccountError::Local`] (vault locked).
    pub async fn teams(&self) -> Result<Teams, AccountError> {
        let (acct, keys) = load_account_keys(self.vault())
            .await?
            .ok_or(AccountError::NotSignedIn)?;
        let trust = Trust::new(self.vault().store().clone(), acct.user_id);
        trust
            .pin_self(&keys.public(), Some(acct.email.clone()))
            .await
            .map_err(|e| AccountError::Local(e.to_string()))?;
        Ok(Teams {
            session: self.clone(),
            keys: Arc::new(keys),
            trust,
            email: acct.email,
        })
    }
}

impl Teams {
    /// This account.
    #[must_use]
    pub fn me(&self) -> Uuid {
        self.trust.me()
    }

    /// This account's email.
    #[must_use]
    pub fn email(&self) -> &str {
        &self.email
    }

    /// The trust store of this account on this device.
    #[must_use]
    pub const fn trust(&self) -> &Trust {
        &self.trust
    }

    /// The session.
    #[must_use]
    pub const fn session(&self) -> &SyncSession {
        &self.session
    }

    pub(crate) fn store(&self) -> &Store {
        self.session.vault().store()
    }

    pub(crate) fn directory(&self) -> TokenDirectory {
        TokenDirectory(Arc::clone(self.session.tokens()))
    }

    pub(crate) async fn call<T, F, Fut>(&self, f: F) -> Res<T>
    where
        F: Fn(crate::http::ApiClient, secrecy::SecretString) -> Fut,
        Fut: Future<Output = Result<T, SyncError>>,
    {
        Ok(self.session.tokens().call(f).await?)
    }

    /// The current local key of `vault` and its version.
    ///
    /// # Errors
    /// [`TeamError::NoKey`].
    pub(crate) async fn local_key(&self, vault: VaultId) -> Res<(u32, Key32)> {
        self.session
            .vault()
            .vault_key(vault)
            .await
            .map_err(|_| TeamError::NoKey(vault))
    }

    // ------------------------------------------------------------------ orgs

    /// The orgs this account belongs to.
    ///
    /// # Errors
    /// [`TeamError::Account`].
    pub async fn list_orgs(&self) -> Res<Vec<OrgView>> {
        self.call(|api, t| async move { api.list_orgs(&t).await })
            .await
    }

    /// Creates an org (this account becomes its owner).
    ///
    /// # Errors
    /// [`TeamError::Account`] (`400` for a bad name).
    pub async fn create_org(&self, name: &str) -> Res<OrgView> {
        let name = name.trim().to_owned();
        let org = self
            .call(|api, t| {
                let name = name.clone();
                async move { api.create_org(&t, &name).await }
            })
            .await?;
        tracing::info!(org = %org.id, "org created");
        Ok(org)
    }

    /// The members of `org` with this device's trust state of their keys.
    ///
    /// # Errors
    /// [`TeamError::Account`] (`404` when not a member).
    pub async fn org_members(&self, org: Uuid) -> Res<Vec<MemberEntry>> {
        let members = self
            .call(|api, t| async move { api.org_members(&t, org).await })
            .await?;
        let pins = self.trust.members().await?;
        let me = self.me();
        Ok(members
            .into_iter()
            .map(|m| MemberEntry {
                pin: pins.iter().find(|p| p.user_id.uuid() == m.user_id).cloned(),
                is_me: m.user_id == me,
                member: m,
            })
            .collect())
    }

    /// Fetches `user`'s public keys and pins them on first sight (a
    /// different key than the pin is parked as a pending change). Returns
    /// the pin.
    ///
    /// # Errors
    /// [`TeamError::Trust`] (fetch failed, malformed keys).
    pub async fn member_keys(&self, user: Uuid) -> Res<PinnedKey> {
        self.trust.fetch(&self.directory(), user).await?;
        Ok(self
            .trust
            .pin(user)
            .await?
            .ok_or(TrustError::NotPinned(user))?)
    }

    /// The safety number between this account and `user` (60 digits in 12
    /// groups of 5). While a key change is pending it is the **new** key's.
    ///
    /// # Errors
    /// [`TeamError::Trust`] (not pinned yet: call [`Self::member_keys`]).
    pub async fn safety_number(&self, user: Uuid) -> Res<String> {
        Ok(self.trust.safety_number(user).await?)
    }

    /// Marks `user` verified after comparing safety numbers out of band.
    ///
    /// # Errors
    /// [`TeamError::Trust`] (`KeyChanged`: accept the new key instead).
    pub async fn mark_verified(&self, user: Uuid) -> Res<()> {
        Ok(self.trust.mark_verified(user).await?)
    }

    /// "Accept new key" in the key-change warning dialog: the pending key
    /// becomes the pin (`verified` when the user compared the new safety
    /// number). Grants to and from `user` work again. Returns whether a
    /// change was pending.
    ///
    /// # Errors
    /// [`TeamError::Trust`] (store).
    pub async fn accept_new_key(&self, user: Uuid, verified: bool) -> Res<bool> {
        let changed = self.trust.accept_new_key(user, verified).await?;
        if changed {
            tracing::warn!(%user, verified, "new public key accepted for a team member");
        }
        Ok(changed)
    }

    /// Changes a member's role.
    ///
    /// # Errors
    /// [`TeamError::Account`] (`403`, `400` last owner).
    pub async fn set_role(&self, org: Uuid, user: Uuid, role: Role) -> Res<()> {
        self.call(|api, t| async move { api.set_member_role(&t, org, user, role).await })
            .await
    }

    /// Removes `user` from `org` (their grants on the org's vaults are
    /// revoked), then rotates the key of every vault they held a grant on
    /// that this account manages, so they can't read new changes.
    /// Removing **this** account is [`Self::leave_org`].
    ///
    /// # Errors
    /// The removal's errors; rotation failures are in the report.
    pub async fn remove_member(
        &self,
        org: Uuid,
        user: Uuid,
        progress: &(dyn Fn(RotationProgress) + Send + Sync),
    ) -> Res<RemoveReport> {
        if user == self.me() {
            self.leave_org(org).await?;
            return Ok(RemoveReport {
                rotations: Vec::new(),
            });
        }
        // Before the removal: it deletes their grants.
        let vaults = self.vaults_to_rotate_for(org, user).await?;
        self.call(|api, t| async move { api.remove_org_member(&t, org, user).await })
            .await?;
        tracing::info!(%org, %user, vaults = vaults.len(), "org member removed; rotating their vaults");
        let mut rotations = Vec::with_capacity(vaults.len());
        for vault in vaults {
            let r = self
                .rotate_with(vault, RotationOptions::default(), progress)
                .await;
            rotations.push((vault, r));
        }
        Ok(RemoveReport { rotations })
    }

    /// Leaves `org`: the server removes the membership and grants, and the
    /// org's team vaults are removed from this device (they belong to the
    /// org; the personal vault stays). Returns the vaults removed locally.
    ///
    /// # Errors
    /// [`TeamError::Account`] (`400` for the last owner).
    pub async fn leave_org(&self, org: Uuid) -> Res<Vec<VaultId>> {
        let me = self.me();
        self.call(|api, t| async move { api.remove_org_member(&t, org, me).await })
            .await?;
        let vault = self.session.vault();
        let mut removed = Vec::new();
        for row in vault.store().vaults().list().await? {
            if row.kind == VaultKind::Shared
                && row.org_id.map(|o| o.uuid()) == Some(org)
                && vault.remove_vault(row.id).await?
            {
                removed.push(row.id);
            }
        }
        tracing::info!(%org, vaults = removed.len(), "left org");
        Ok(removed)
    }

    /// Invites `email` (or anyone with the link when `None`) to `org` as
    /// `role`. The answer carries the link to copy unless it was mailed.
    ///
    /// # Errors
    /// [`TeamError::Account`] (`403`).
    pub async fn invite(&self, org: Uuid, email: Option<&str>, role: Role) -> Res<InviteCreated> {
        let req = CreateInviteRequest {
            email: email.map(|e| e.trim().to_owned()).filter(|e| !e.is_empty()),
            role,
        };
        let req = &req;
        self.call(|api, t| async move { api.create_invite(&t, org, req).await })
            .await
    }

    /// Accepts a pasted invite link (or bare token). The org's vaults shared
    /// with the account arrive through sync once a `manage` member grants
    /// them.
    ///
    /// # Errors
    /// [`TeamError::Invalid`] for text that is not an invite; the server's
    /// `404` (unknown, used, expired) or `403` (bound to another email).
    pub async fn accept_invite(&self, link: &str) -> Res<InviteAccepted> {
        let token = invite_token(link)
            .ok_or_else(|| TeamError::Invalid("that is not an invite link".into()))?
            .to_owned();
        let token = &token;
        let accepted = self
            .call(|api, t| async move { api.accept_invite(&t, token).await })
            .await?;
        tracing::info!(org = %accepted.org_id, "org invite accepted");
        Ok(accepted)
    }

    /// A page of `org`'s audit log (admins), newest first.
    ///
    /// # Errors
    /// [`TeamError::Account`] (`403`).
    pub async fn audit(&self, org: Uuid, before: Option<i64>, limit: u32) -> Res<AuditPage> {
        self.call(|api, t| async move { api.org_audit(&t, org, before, limit).await })
            .await
    }

    // ---------------------------------------------------------------- vaults

    /// Creates a team vault of `org` named `name` (org admin+). Returns its
    /// id; the vault is ready locally (key under the LMK, name in `meta`) and
    /// syncs like the personal vault. New items go into it with
    /// `ItemWrite::vault = Some(id)`.
    ///
    /// # Errors
    /// [`TeamError::Invalid`] (name), the server's `403` / `404`.
    pub async fn create_vault(&self, org: Uuid, name: &str) -> Res<VaultId> {
        let name = name.trim();
        if name.is_empty()
            || name.chars().count() > MAX_VAULT_NAME
            || name.chars().any(char::is_control)
        {
            return Err(TeamError::Invalid(format!(
                "a vault name has 1 to {MAX_VAULT_NAME} characters"
            )));
        }
        let mut rng = os_rng();
        let vault = VaultId::new();
        let kv = 1;
        let vk = random_key32(&mut rng);
        let me = self.me();
        let name_enc = seal_vault_name(&vk, vault, kv, name)?;
        let grant = self_grant(
            &vk,
            vault.as_bytes(),
            kv,
            me.as_bytes(),
            &self.keys,
            &mut rng,
        )?;
        let req = CreateVaultRequest {
            id: vault.uuid(),
            org_id: org,
            name_enc: name_enc.clone(),
            self_grant: GrantUpload::from_grant(&grant, kv),
        };
        let req = &req;
        self.call(|api, t| async move { api.create_vault(&t, req).await })
            .await?;
        self.session
            .vault()
            .install_vault_key(
                vault,
                VaultKind::Shared,
                Some(OrgId::from_uuid(org)),
                kv,
                &vk,
            )
            .await?;
        save_vault_name(self.store(), vault, name_enc).await;
        tracing::info!(vault = %vault.short(), %org, "team vault created");
        Ok(vault)
    }

    /// The org's members with their permission on `vault` (untrusted).
    ///
    /// # Errors
    /// [`TeamError::Account`] (`404` when invisible).
    pub async fn vault_members(&self, vault: VaultId) -> Res<VaultMembersView> {
        let id = vault.uuid();
        self.call(|api, t| async move { api.vault_members(&t, id).await })
            .await
    }

    /// Grants `user` access to `vault` with `permission` (or changes it):
    /// their keys are fetched and checked against the pins first (pinned on
    /// first sight; **refused** while a key change is pending).
    ///
    /// # Errors
    /// [`TeamError::Trust`] (key changed), [`TeamError::NoKey`], the
    /// server's `403` / `400` / `409 rotating`.
    pub async fn grant(&self, vault: VaultId, user: Uuid, permission: Permission) -> Res<()> {
        let (kv, vk) = self.local_key(vault).await?;
        let keys = match self.trust.keys_for_grant(&self.directory(), user).await {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(vault = %vault.short(), %user, error = %e, "REFUSING to grant: the member's key is not trusted");
                return Err(e.into());
            }
        };
        let g = grant_vault_key(
            &vk,
            vault.as_bytes(),
            kv,
            user.as_bytes(),
            &keys.x25519,
            self.keys.ed25519_signing_key(),
            &mut os_rng(),
        )?;
        let req = GrantRequest {
            permission,
            key_version: kv,
            wrapped_vault_key: g.wrapped,
            signature: g.signature.to_vec(),
        };
        let (id, req) = (vault.uuid(), &req);
        self.call(|api, t| async move { api.grant_vault_member(&t, id, user, req).await })
            .await?;
        tracing::info!(vault = %vault.short(), %user, permission = permission.as_str(), "vault access granted");
        Ok(())
    }

    /// Revokes `user`'s access to `vault` **without** rotating the key (they
    /// could still read new changes with the key they hold): use
    /// [`Self::revoke_and_rotate`]. Revoking this account leaves the vault
    /// (it is removed from this device).
    ///
    /// # Errors
    /// The server's `403` / `404`.
    pub async fn revoke(&self, vault: VaultId, user: Uuid) -> Res<()> {
        let id = vault.uuid();
        self.call(|api, t| async move { api.revoke_vault_member(&t, id, user).await })
            .await?;
        if user == self.me() {
            self.session.vault().remove_vault(vault).await?;
        }
        Ok(())
    }

    /// Revokes `user`'s access to `vault`, then rotates the vault key so
    /// they can't decrypt new changes (they keep what they already
    /// downloaded). Leaving (`user` = this account) does not rotate.
    ///
    /// # Errors
    /// The revoke's errors as [`RotationError::Team`]; then the rotation's
    /// (the revocation stands; resume with [`Self::rotate`]).
    pub async fn revoke_and_rotate(
        &self,
        vault: VaultId,
        user: Uuid,
        progress: &(dyn Fn(RotationProgress) + Send + Sync),
    ) -> Result<Option<RotationReport>, RotationError> {
        self.revoke(vault, user).await?;
        if user == self.me() {
            return Ok(None);
        }
        tracing::info!(vault = %vault.short(), %user, "access revoked; rotating the vault key");
        self.rotate_with(vault, RotationOptions::default(), progress)
            .await
            .map(Some)
    }

    /// Rotates the key of `vault` (or resumes this device's unfinished
    /// rotation, or restarts an abandoned one). See [`crate::rotation`].
    ///
    /// # Errors
    /// [`RotationError`].
    pub async fn rotate(
        &self,
        vault: VaultId,
        progress: &(dyn Fn(RotationProgress) + Send + Sync),
    ) -> Result<RotationReport, RotationError> {
        self.rotate_with(vault, RotationOptions::default(), progress)
            .await
    }

    /// The org's vaults visible to this account, with their names where
    /// this device holds the key ("needs key" otherwise).
    ///
    /// # Errors
    /// [`TeamError::Account`].
    pub async fn org_vaults(&self, org: Uuid) -> Res<Vec<OrgVaultEntry>> {
        let views = self
            .call(|api, t| async move { api.org_vaults(&t, org).await })
            .await?;
        let mut out = Vec::with_capacity(views.len());
        for view in views {
            let vault = VaultId::from_uuid(view.id);
            let name = match self.local_key(vault).await {
                Ok((_, vk)) => match local_vault_name(self.store(), vault, &vk).await {
                    Some(n) => Some(n),
                    None => open_vault_name(&vk, vault, &view.name_enc).ok(),
                },
                Err(_) => None,
            };
            out.push(OrgVaultEntry { view, name });
        }
        Ok(out)
    }

    /// The names of the local team vaults ([`vault_names`]).
    ///
    /// # Errors
    /// [`TeamError::Account`].
    pub async fn vault_names(&self) -> Res<BTreeMap<VaultId, String>> {
        Ok(vault_names(self.session.vault()).await?)
    }

    /// The shared vaults of `org` that `user` holds a grant on and this
    /// account can rotate (it manages them and holds their key). Call it
    /// **before** removing `user` from the org (the removal deletes their
    /// grants).
    ///
    /// # Errors
    /// Listing the org's vaults failed.
    pub async fn vaults_to_rotate_for(&self, org: Uuid, user: Uuid) -> Res<Vec<VaultId>> {
        let mut out = Vec::new();
        for entry in self.org_vaults(org).await? {
            let vault = VaultId::from_uuid(entry.view.id);
            if !entry.view.has_key || entry.view.permission != Permission::Manage {
                continue;
            }
            match self.vault_members(vault).await {
                Ok(m) => {
                    if m.members
                        .iter()
                        .any(|x| x.user_id == user && x.permission.is_some())
                    {
                        out.push(vault);
                    }
                }
                Err(e) => {
                    tracing::warn!(vault = %vault.short(), error = %e, "no member list; not rotated")
                }
            }
        }
        Ok(out)
    }

    /// For every local team vault this account manages, grants `manage` to
    /// org owners and admins that hold no key for the current version (org
    /// admins manage every org vault, but the server can't hand them a key).
    /// Members whose key is not trusted are skipped (reported), never
    /// granted.
    ///
    /// # Errors
    /// Listing the local vaults failed; per-vault errors are in the report.
    pub async fn reconcile_admins(&self) -> Res<ReconcileReport> {
        let mut report = ReconcileReport::default();
        let me = self.me();
        for row in self.store().vaults().list().await? {
            if row.kind != VaultKind::Shared {
                continue;
            }
            let Ok(members) = self.vault_members(row.id).await else {
                continue;
            };
            if row.key_version != members.key_version {
                continue; // a rotation is pending
            }
            let i_manage = members
                .members
                .iter()
                .find(|m| m.user_id == me)
                .and_then(courier_ftp_proto::vaults::VaultMemberView::effective)
                == Some(Permission::Manage);
            if !i_manage {
                continue;
            }
            for m in &members.members {
                if m.user_id == me || m.has_key || m.org_role < Role::Admin {
                    continue;
                }
                match self.grant(row.id, m.user_id, Permission::Manage).await {
                    Ok(()) => report.granted.push((row.id, m.user_id)),
                    Err(e) => report.skipped.push((row.id, m.user_id, e.to_string())),
                }
            }
        }
        Ok(report)
    }

    // ------------------------------------------------------- copy and move

    /// Copies site `id` into vault `target` as a **new** item (new id, no
    /// parent folder; the caller may move it into a folder of `target`).
    /// A site that logs in with a vault SSH key of another vault can't go to
    /// a team vault (a team site must not reference personal items; the
    /// member uses a credential override instead).
    ///
    /// # Errors
    /// [`TeamError::Invalid`] (not a site, cross-vault key),
    /// [`TeamError::Account`] (read-only target, locked).
    pub async fn copy_site_to_vault(&self, id: ItemId, target: VaultId) -> Res<ItemId> {
        let vault = self.session.vault();
        let item = vault
            .get(id)
            .await?
            .ok_or_else(|| TeamError::Invalid(format!("no item {}", id.short())))?;
        let mut site: Site = item
            .view::<Site>()
            .map_err(|_| TeamError::Invalid("only sites can be copied to another vault".into()))?;
        if let Some(key) = site.key_id
            && target != vault.personal_vault().await.unwrap_or(target)
        {
            let key_vault = vault.get(key).await?.map(|k| k.vault_id);
            if key_vault != Some(target) {
                return Err(TeamError::Invalid(
                    "the site logs in with an SSH key from another vault; a team vault site \
                     can't use it (each member sets their own key as a credential override)"
                        .into(),
                ));
            }
        }
        site.parent = None;
        let new_id = ItemId::new();
        vault.put_view(new_id, Some(target), site).await?;
        tracing::debug!(from = %id.short(), to = %new_id.short(), vault = %target.short(), "site copied to another vault");
        Ok(new_id)
    }

    /// Moves site `id` into vault `target`: [`Self::copy_site_to_vault`],
    /// then the original is deleted (a tombstone syncs to its vault).
    ///
    /// # Errors
    /// As [`Self::copy_site_to_vault`]; deleting from a read-only vault.
    pub async fn move_site_to_vault(&self, id: ItemId, target: VaultId) -> Res<ItemId> {
        let new_id = self.copy_site_to_vault(id, target).await?;
        self.session.vault().delete(id).await?;
        Ok(new_id)
    }
}

#[cfg(test)]
mod tests {
    use super::invite_token;

    #[test]
    fn invite_links() {
        let tok = "AbC-12_x";
        assert_eq!(
            invite_token("https://sync.example/invite/AbC-12_x"),
            Some(tok)
        );
        assert_eq!(
            invite_token(" https://sync.example/invite/AbC-12_x/ "),
            Some(tok)
        );
        assert_eq!(invite_token("AbC-12_x"), Some(tok));
        assert_eq!(invite_token("https://sync.example/invite/"), None);
        assert_eq!(invite_token("not a token!"), None);
        assert_eq!(invite_token(""), None);
    }
}
