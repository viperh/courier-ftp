//! Logging in.
//!
//! [`start_login`] runs OPAQUE, opens the account keys and the vault grants,
//! checks whether the account password differs from the local master
//! password, and — when the local personal vault is not the account's —
//! downloads the account's items (in memory) to build the dry-run duplicate
//! preview. Nothing local changes until [`LoginSession::commit`], which does
//! everything in **one** SQLite transaction:
//!
//! * re-wrap the LMK under the account password (new salt) if it differs
//!   (the UI shows [`super::PASSWORD_ADOPT_WARNING`] first);
//! * add the account's vaults (keys wrapped under the LMK) and the
//!   downloaded items;
//! * import the local items under new ids with remapped references
//!   ([`super::merge_local`]), move their device-local rows, and delete the
//!   old local vault;
//! * store `meta.account` and the sealed account keys.
//!
//! A crash before the commit leaves the local vault exactly as it was; the
//! tokens are saved right after it. Pushing the imported items is then
//! ordinary sync.
//!
//! The same entry point covers the other login cases:
//! * a device whose local personal vault **is** the account's (re-login
//!   after a password change elsewhere; after a logout with local data kept;
//!   after a registration that crashed before its local commit): nothing is
//!   imported, the tokens and (if needed) the LMK wrap are renewed;
//! * a new device: the caller first initializes the local vault with the
//!   account password (one password), whose empty personal vault is then
//!   replaced by the account's.

use std::fmt;

use courier_ftp_core::model::item::{DeviceId, ItemBody, ItemId, ItemKind, VaultId};
use courier_ftp_core::vault::{ItemVault, scrub};
use courier_ftp_crypto::Key32;
use courier_ftp_crypto::account::{AccountKeys, derive_akek, open_private_bundle};
use courier_ftp_crypto::envelope::{open_item, seal_item};
use courier_ftp_crypto::grant::verify_and_open_grant;
use courier_ftp_crypto::keys::os_rng;
use courier_ftp_proto::auth::{LoginDevice, LoginPurpose, SessionResponse};
use courier_ftp_proto::limits::MAX_PULL_LIMIT;
use courier_ftp_proto::sync::{VaultKind as ProtoVaultKind, VaultView};
use courier_ftp_store::meta::keys as meta_keys;
use courier_ftp_store::vault::{PasswordWrap, VaultEngine};
use courier_ftp_store::{RemoteItem, VaultKind};
use secrecy::SecretString;
use uuid::Uuid;

use super::local::{self, LocalAccount};
use super::merge_local::{ImportPreview, build_preview, plan_import};
use super::opaque_flow::opaque_login;
use super::{AccountConfig, AccountError, check_email, probe_server};
use crate::http::ApiClient;
use crate::session::SyncSession;
use crate::tokens::{TokenManager, Tokens};

/// What the user typed.
#[derive(Clone)]
pub struct LoginRequest {
    /// Server base URL.
    pub server_url: String,
    /// Account email.
    pub email: String,
    /// Account password (the master password).
    pub password: SecretString,
    /// TOTP code, when the account requires one.
    pub totp: Option<SecretString>,
}

impl fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginRequest")
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

/// A vault of the account with its opened key.
pub(crate) struct AccountVault {
    pub(crate) view: VaultView,
    pub(crate) key: Key32,
}

impl AccountVault {
    pub(crate) fn id(&self) -> VaultId {
        VaultId::from_uuid(self.view.id)
    }

    pub(crate) fn kind(&self) -> VaultKind {
        match self.view.kind {
            ProtoVaultKind::Personal => VaultKind::Personal,
            ProtoVaultKind::Shared => VaultKind::Shared,
        }
    }
}

/// Opens the grants of `views` signed by the account itself (personal vaults;
/// grants by other users need the team trust checks of T89 and are skipped).
/// Returns the personal vault first.
pub(crate) fn open_own_vaults(
    user_id: Uuid,
    account_keys: &AccountKeys,
    views: Vec<VaultView>,
) -> Result<Vec<AccountVault>, AccountError> {
    let me = account_keys.public().ed25519;
    let mut personal = None;
    let mut others = Vec::new();
    for view in views {
        let opened = view
            .grants
            .iter()
            .find(|g| g.key_version == view.key_version && g.wrapped_by == user_id)
            .and_then(|g| g.to_grant().ok())
            .and_then(|grant| {
                verify_and_open_grant(
                    &grant,
                    view.id.as_bytes(),
                    view.key_version,
                    user_id.as_bytes(),
                    account_keys,
                    &me,
                )
                .map_err(|e| {
                    tracing::warn!(vault = %view.id, error = %e, "vault grant refused");
                })
                .ok()
            });
        match (opened, view.kind) {
            (Some(key), ProtoVaultKind::Personal) if personal.is_none() => {
                personal = Some(AccountVault { view, key });
            }
            (Some(key), _) => others.push(AccountVault { view, key }),
            (None, ProtoVaultKind::Personal) => {
                return Err(AccountError::Crypto(
                    "the personal vault's self-grant does not verify".into(),
                ));
            }
            // Team vaults granted by other users: T89.
            (None, ProtoVaultKind::Shared) => {}
        }
    }
    let personal =
        personal.ok_or_else(|| AccountError::Crypto("the account has no personal vault".into()))?;
    Ok(std::iter::once(personal).chain(others).collect())
}

/// The local vault to import.
struct LocalSide {
    vault: VaultId,
    items: Vec<(ItemId, ItemBody)>,
}

/// A login in progress: OPAQUE done, nothing stored yet.
pub struct LoginSession {
    vault: VaultEngine,
    cfg: AccountConfig,
    api: ApiClient,
    email: String,
    password: SecretString,
    user_id: Uuid,
    device_id: Uuid,
    key_version: u32,
    tokens: Option<Tokens>,
    keys: AccountKeys,
    password_differs: bool,
    /// The personal vault first.
    vaults: Vec<AccountVault>,
    /// `None`: the local personal vault is the account's (nothing to import).
    local: Option<LocalSide>,
    remote: Vec<RemoteItem>,
    account_items: Vec<(ItemId, ItemBody)>,
    head: u64,
    preview: ImportPreview,
}

impl fmt::Debug for LoginSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginSession")
            .field("user_id", &self.user_id)
            .field("password_differs", &self.password_differs)
            .field("import", &self.local.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for LoginSession {
    fn drop(&mut self) {
        for (_, b) in &mut self.local.iter_mut().flat_map(|l| l.items.iter_mut()) {
            scrub(b);
        }
        for (_, b) in &mut self.account_items {
            scrub(b);
        }
    }
}

/// The result of [`LoginSession::commit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedIn {
    /// The account.
    pub user_id: Uuid,
    /// This device, as the server knows it.
    pub device_id: Uuid,
    /// The account's personal vault (now the local personal vault).
    pub vault: VaultId,
    /// Local items imported (new ids, or written over an account item).
    pub imported: usize,
    /// Account items downloaded during the login.
    pub downloaded: usize,
    /// Whether the LMK was re-wrapped under the account password.
    pub password_changed: bool,
    /// The local vault that was replaced (deleted), if any.
    pub replaced_vault: Option<VaultId>,
}

/// Starts a login on an unlocked device.
///
/// # Errors
/// [`AccountError::LoginFailed`], [`AccountError::TotpRequired`],
/// [`AccountError::TotpInvalid`], [`AccountError::Unreachable`],
/// [`AccountError::Crypto`] (bundle or grant does not open),
/// [`AccountError::Local`] (vault locked, local items that don't decrypt).
pub async fn start_login(
    vault: &VaultEngine,
    req: &LoginRequest,
    cfg: &AccountConfig,
) -> Result<LoginSession, AccountError> {
    if !vault.is_unlocked().await {
        return Err(AccountError::Local("unlock the vault first".into()));
    }
    let email = check_email(&req.email)?;
    let api = probe_server(&req.server_url, cfg).await?;
    let previous_device = vault
        .store()
        .sync_state()
        .get()
        .await?
        .and_then(|s| s.device_id);
    let device = LoginDevice {
        id: previous_device.map(|d| d.uuid()),
        name: Some(cfg.device.name.clone()),
        platform: Some(cfg.device.platform.clone()),
    };
    let (export_key, session): (_, SessionResponse) = opaque_login(
        &api,
        &email,
        &req.password,
        cfg,
        LoginPurpose::Login,
        device,
        req.totp.as_ref(),
    )
    .await?;
    let SessionResponse {
        user_id,
        device_id,
        tokens,
        account_keys,
        ..
    } = session;
    let tokens = Tokens::from_pair(tokens, vault.store().now());
    let akek = derive_akek(&export_key);
    drop(export_key);
    let keys = open_private_bundle(
        &akek,
        user_id.as_bytes(),
        account_keys.version,
        &account_keys.private_bundle_enc,
    )
    .map_err(|e| AccountError::Crypto(format!("private bundle: {e}")))?;
    let views = api.list_vaults(tokens.access()).await?;
    let vaults = open_own_vaults(user_id, &keys, views)?;
    let password_differs = !vault.is_master_password(&req.password).await?;

    let local_personal = vault
        .personal_vault()
        .await
        .ok_or_else(|| AccountError::Local("the vault is locked".into()))?;
    let local = if local_personal == vaults[0].id() {
        None
    } else {
        Some(LocalSide {
            vault: local_personal,
            items: decrypt_local(vault, local_personal).await?,
        })
    };

    let mut s = LoginSession {
        vault: vault.clone(),
        cfg: cfg.clone(),
        api,
        email,
        password: req.password.clone(),
        user_id,
        device_id,
        key_version: account_keys.version,
        tokens: Some(tokens),
        keys,
        password_differs,
        vaults,
        local,
        remote: Vec::new(),
        account_items: Vec::new(),
        head: 0,
        preview: ImportPreview::default(),
    };
    if s.local.is_some() {
        s.download().await?;
        if let Some(l) = &s.local {
            s.preview = build_preview(&l.items, &s.account_items);
        }
    }
    Ok(s)
}

/// The live items of the local personal vault, decrypted. Refuses when any
/// stored item didn't decrypt at unlock (it would be lost by the import).
async fn decrypt_local(
    vault: &VaultEngine,
    personal: VaultId,
) -> Result<Vec<(ItemId, ItemBody)>, AccountError> {
    let mut out = Vec::new();
    for kind in ItemKind::ALL {
        for item in vault.list(kind).await? {
            if item.vault_id == personal {
                out.push((item.id, item.body.clone()));
            }
        }
    }
    let stored = vault
        .store()
        .items()
        .list(personal)
        .await?
        .into_iter()
        .filter(|r| !r.deleted)
        .count();
    if stored > out.len() {
        return Err(AccountError::Local(format!(
            "{} local item(s) do not decrypt; nothing was imported",
            stored - out.len()
        )));
    }
    Ok(out)
}

impl LoginSession {
    /// Whether the account password differs from the local master password:
    /// show [`super::PASSWORD_ADOPT_WARNING`] before [`Self::commit`].
    #[must_use]
    pub const fn password_differs(&self) -> bool {
        self.password_differs
    }

    /// Whether local items will be imported (the local personal vault is
    /// not the account's).
    #[must_use]
    pub const fn will_import(&self) -> bool {
        self.local.is_some()
    }

    /// The dry-run preview (empty when nothing is imported).
    #[must_use]
    pub const fn preview(&self) -> &ImportPreview {
        &self.preview
    }

    /// The preview, to set the duplicate choices.
    pub fn preview_mut(&mut self) -> &mut ImportPreview {
        &mut self.preview
    }

    /// The account.
    #[must_use]
    pub const fn user_id(&self) -> Uuid {
        self.user_id
    }

    /// The account's personal vault.
    #[must_use]
    pub fn account_vault(&self) -> VaultId {
        self.vaults[0].id()
    }

    /// Downloads every item of the account's personal vault (in memory).
    async fn download(&mut self) -> Result<(), AccountError> {
        let personal = &self.vaults[0];
        let vault = personal.id();
        let key_version = personal.view.key_version;
        let token = self
            .tokens
            .as_ref()
            .map(|t| t.access().clone())
            .ok_or(AccountError::NotSignedIn)?;
        let mut since = 0;
        loop {
            let page = self
                .api
                .pull(&token, vault.uuid(), since, MAX_PULL_LIMIT)
                .await?;
            for it in &page.items {
                let id = ItemId::from_uuid(it.id);
                let lookup = |v: u32| (v == key_version).then_some(&personal.key);
                match open_item(lookup, vault.as_bytes(), id.as_bytes(), &it.envelope)
                    .map_err(|e| e.to_string())
                    .and_then(|pt| ItemBody::from_cbor(&pt).map_err(|e| e.to_string()))
                {
                    Ok(b) => self.account_items.push((id, b)),
                    Err(e) => {
                        tracing::warn!(item = %id.short(), error = %e, "account item does not decrypt");
                    }
                }
                self.remote.push(RemoteItem {
                    id,
                    revision: i64::try_from(it.revision).unwrap_or(i64::MAX),
                    key_version: it.key_version,
                    envelope: it.envelope.clone(),
                    deleted: it.deleted,
                    local_pending: false,
                });
            }
            self.head = page.head_revision;
            let next = page.next_cursor(since);
            if !page.more || page.items.is_empty() || next <= since {
                break;
            }
            since = next;
        }
        Ok(())
    }

    /// Commits the login (see the module docs). Can be retried after a
    /// failure: nothing local changed.
    ///
    /// # Errors
    /// [`AccountError::Local`] / [`AccountError::Crypto`].
    pub async fn commit(mut self) -> Result<(LoggedIn, SyncSession), AccountError> {
        let vault = self.vault.clone();
        let wrap: Option<PasswordWrap> = if self.password_differs {
            Some(vault.password_wrap(&self.password).await?)
        } else {
            None
        };
        let acct = LocalAccount {
            user_id: self.user_id,
            email: self.email.clone(),
            key_version: self.key_version,
        };

        // Vault rows to create or update.
        let mut rows = Vec::new();
        for v in &self.vaults {
            let wrapped = vault.wrap_vault_key(v.id(), &v.key).await?;
            rows.push((v.id(), v.kind(), v.view.key_version, wrapped));
        }

        // The import: plan and seal outside the transaction.
        let account_vault = self.vaults[0].id();
        let account_kv = self.vaults[0].view.key_version;
        let mut sealed = Vec::new();
        let mut moves = Vec::new();
        let mut replaced = None;
        let mut hlc_last = None;
        if let Some(l) = &self.local {
            let (plan, last) = vault
                .with_clock(|clock, device| {
                    let plan =
                        plan_import(&l.items, &self.account_items, &self.preview, clock, device);
                    (plan, clock.last())
                })
                .await?;
            let key = &self.vaults[0].key;
            for mut w in plan.writes {
                let cbor = zeroize::Zeroizing::new(
                    w.body
                        .to_cbor()
                        .map_err(|e| AccountError::Local(format!("item body: {e}")))?,
                );
                scrub(&mut w.body);
                let env = seal_item(
                    key,
                    account_vault.as_bytes(),
                    w.to.as_bytes(),
                    account_kv,
                    &cbor,
                    &mut os_rng(),
                )?;
                sealed.push((w.to, env));
            }
            moves = plan
                .id_map
                .into_iter()
                .filter(|(from, to)| from != to)
                .collect::<Vec<_>>();
            replaced = Some(l.vault);
            hlc_last = Some(last);
        }
        let remote = if self.local.is_some() {
            std::mem::take(&mut self.remote)
        } else {
            Vec::new()
        };
        let downloaded = remote.len();
        let head = i64::try_from(self.head).unwrap_or(i64::MAX);
        let imported = sealed.len();

        vault
            .commit(move |w| {
                if let Some(wrap) = &wrap {
                    wrap.apply(w)?;
                }
                for (id, kind, kv, wrapped) in &rows {
                    match w.as_read().get_vault(*id)? {
                        None => w.create_vault(*id, *kind, None, *kv, wrapped)?,
                        Some(row) if row.key_version != *kv => {
                            w.update_wrapped_key(*id, *kv, wrapped)?;
                        }
                        Some(_) => {}
                    }
                }
                if replaced.is_some() {
                    w.apply_remote(account_vault, &remote, head)?;
                }
                for (id, env) in &sealed {
                    w.put_item(account_vault, *id, account_kv, env, false)?;
                }
                for (from, to) in &moves {
                    w.move_device_local(*from, *to)?;
                }
                if let Some(old) = replaced {
                    w.delete_vault(old)?;
                }
                if let Some(h) = hlc_last {
                    w.set_hlc_last(h)?;
                }
                // The account keys are sealed after the commit (the LMK
                // subkey is the same; only `meta.account` must be atomic).
                local::write_account(w, &acct, None)
            })
            .await?;
        let acct = LocalAccount {
            user_id: self.user_id,
            email: self.email.clone(),
            key_version: self.key_version,
        };
        let keys_enc = local::seal_local_keys(&vault, &acct, &self.keys).await?;
        vault
            .store()
            .meta()
            .set(meta_keys::ACCOUNT_KEYS, keys_enc)
            .await?;
        let tokens = self.tokens.take().ok_or(AccountError::NotSignedIn)?;
        let tm = TokenManager::save_login(
            &vault,
            &self.api,
            DeviceId::from_uuid(self.device_id),
            tokens,
        )
        .await?;
        tracing::info!(
            imported,
            downloaded,
            password_changed = self.password_differs,
            "logged in"
        );
        let session = SyncSession::from_parts(vault, tm, self.cfg.clone());
        Ok((
            LoggedIn {
                user_id: self.user_id,
                device_id: self.device_id,
                vault: account_vault,
                imported,
                downloaded,
                password_changed: self.password_differs,
                replaced_vault: replaced,
            },
            session,
        ))
    }
}
