//! A signed-in device: one [`SyncSession`] per unlocked vault.
//!
//! The session owns the [`TokenManager`] every authenticated call goes
//! through (so there is exactly one refresh in flight for the whole process)
//! and offers the account operations that need a login: devices, password
//! change, TOTP, logout and account deletion. The sync engine (T88) is
//! started from it too.

use std::sync::Arc;

use courier_ftp_crypto::account::{derive_akek, seal_private_bundle};
use courier_ftp_crypto::keys::os_rng;
use courier_ftp_crypto::opaque::client_registration_start;
use courier_ftp_proto::auth::{
    AccountDeleteRequest, DeviceSummary, KeyVersionResponse, LoginDevice, LoginPurpose,
    PasswordChangeRequest, PasswordStartRequest, PasswordStartResponse, ReauthResponse,
    TotpRequest, TotpSetupResponse, TotpStatus,
};
use courier_ftp_store::vault::VaultEngine;
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use crate::account::{
    AccountConfig, AccountError, LocalAccount, LogoutReport, NEEDS_SERVER, load_account,
    load_account_keys, logout_local, opaque_login, require_strong, seal_local_keys, write_account,
};
use crate::error::SyncError;
use crate::tokens::TokenManager;

/// What [`SyncSession::revoke_device`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Revoked {
    /// Another device was revoked.
    Other,
    /// This device was revoked and logged out locally (local data kept).
    ThisDevice(LogoutReport),
}

/// TOTP setup material (show the URI as a QR code and the secret as text;
/// never log them).
pub struct TotpSetup {
    /// `otpauth://totp/...`.
    pub otpauth_uri: SecretString,
    /// The secret in base32.
    pub secret_base32: SecretString,
}

impl std::fmt::Debug for TotpSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpSetup([REDACTED])")
    }
}

struct Inner {
    vault: VaultEngine,
    tokens: Arc<TokenManager>,
    cfg: AccountConfig,
}

/// A device signed in to a sync server. Cheap to clone.
#[derive(Clone)]
pub struct SyncSession {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for SyncSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncSession")
            .field("tokens", &self.inner.tokens)
            .finish_non_exhaustive()
    }
}

impl SyncSession {
    pub(crate) fn from_parts(vault: VaultEngine, tokens: TokenManager, cfg: AccountConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                vault,
                tokens: Arc::new(tokens),
                cfg,
            }),
        }
    }

    /// The session of an unlocked device that is signed in (after unlock),
    /// or `None` when sync is not set up (local-only).
    ///
    /// # Errors
    /// [`AccountError::NeedsLogin`] when a server is configured but no tokens
    /// are stored, [`AccountError::Local`] (vault locked, bad URL),
    /// [`AccountError::Crypto`].
    pub async fn open(
        vault: &VaultEngine,
        cfg: AccountConfig,
    ) -> Result<Option<Self>, AccountError> {
        let Some(state) = vault.store().sync_state().get().await? else {
            return Ok(None);
        };
        let Some(url) = state.server_url else {
            return Ok(None);
        };
        let api = cfg.client(&url)?;
        let tokens = TokenManager::load(vault.clone(), api).await?;
        Ok(Some(Self::from_parts(vault.clone(), tokens, cfg)))
    }

    /// The token manager (shared with the engine and the WebSocket).
    #[must_use]
    pub fn tokens(&self) -> &Arc<TokenManager> {
        &self.inner.tokens
    }

    /// The vault engine.
    #[must_use]
    pub fn vault(&self) -> &VaultEngine {
        &self.inner.vault
    }

    /// The account settings.
    #[must_use]
    pub fn config(&self) -> &AccountConfig {
        &self.inner.cfg
    }

    /// The server base URL.
    #[must_use]
    pub fn server_url(&self) -> &str {
        self.inner.tokens.api().base_url()
    }

    /// `meta.account`.
    ///
    /// # Errors
    /// [`AccountError::Local`].
    pub async fn account(&self) -> Result<Option<LocalAccount>, AccountError> {
        load_account(self.inner.vault.store()).await
    }

    async fn call<T, F, Fut>(&self, f: F) -> Result<T, AccountError>
    where
        F: Fn(crate::http::ApiClient, SecretString) -> Fut,
        Fut: Future<Output = Result<T, SyncError>>,
    {
        Ok(self.inner.tokens.call(f).await?)
    }

    /// The account's devices (revoked ones left out), this device first, then
    /// by creation time.
    ///
    /// # Errors
    /// [`AccountError::NeedsLogin`], [`AccountError::Unreachable`], …
    pub async fn list_devices(&self) -> Result<Vec<DeviceSummary>, AccountError> {
        let mut list = self
            .call(|api, t| async move { api.list_devices(&t).await })
            .await?;
        list.sort_by(|a, b| {
            b.current
                .cmp(&a.current)
                .then(a.created_at.cmp(&b.created_at))
                .then(a.id.cmp(&b.id))
        });
        Ok(list)
    }

    /// Revokes a device. Revoking **this** device is a local logout (sync
    /// state wiped, local data kept).
    ///
    /// # Errors
    /// [`AccountError::NeedsLogin`], [`AccountError::Unreachable`],
    /// [`AccountError::Sync`] (`404` for an unknown device), …
    pub async fn revoke_device(&self, device: Uuid) -> Result<Revoked, AccountError> {
        let list = self.list_devices().await?;
        let current = list.iter().any(|d| d.id == device && d.current);
        self.call(|api, t| async move { api.revoke_device(&t, device).await })
            .await?;
        if !current {
            return Ok(Revoked::Other);
        }
        self.inner.tokens.invalidate().await;
        let mut report = logout_local(&self.inner.vault).await?;
        report.revoked = true;
        Ok(Revoked::ThisDevice(report))
    }

    /// Logs this device out: revokes its tokens on the server (best effort)
    /// and runs [`logout_local`]. The personal vault and the master password
    /// stay.
    ///
    /// # Errors
    /// [`AccountError::Local`].
    pub async fn logout(&self) -> Result<LogoutReport, AccountError> {
        let revoke = self
            .inner
            .tokens
            .call(|api, t| async move {
                api.post_v1_empty::<()>("/auth/logout", None, Some(&t))
                    .await
            })
            .await;
        self.inner.tokens.invalidate().await;
        let mut report = logout_local(&self.inner.vault).await?;
        match revoke {
            Ok(()) => report.revoked = true,
            Err(e) => {
                tracing::warn!(error = %e, "could not revoke the tokens; logged out locally");
                report.revoke_error = Some(e.to_string());
            }
        }
        Ok(report)
    }

    /// A reauth token from an OPAQUE login with `password` (purpose `reauth`).
    async fn reauth(
        &self,
        acct: &LocalAccount,
        password: &SecretString,
        totp: Option<&SecretString>,
    ) -> Result<ReauthResponse, AccountError> {
        let (export_key, reauth): (_, ReauthResponse) = opaque_login(
            self.inner.tokens.api(),
            &acct.email,
            password,
            &self.inner.cfg,
            LoginPurpose::Reauth,
            LoginDevice::default(),
            totp,
        )
        .await?;
        drop(export_key);
        if reauth.user_id != acct.user_id {
            return Err(AccountError::Local(
                "the server answered for a different account".into(),
            ));
        }
        Ok(reauth)
    }

    /// Changes the account and local master password (online only):
    /// 1. OPAQUE reauth with the old password;
    /// 2. a new OPAQUE record and the account bundle re-sealed under the new
    ///    AKEK, uploaded atomically (version = current + 1); the server logs
    ///    out the other devices (`account_changed`);
    /// 3. the LMK re-wrapped under the new password and `meta.account` moved
    ///    to the new version, in one local transaction.
    ///
    /// Returns the new account key version.
    ///
    /// # Errors
    /// [`AccountError::Unreachable`] (with [`NEEDS_SERVER`]) when offline,
    /// [`AccountError::LoginFailed`] for a wrong old password,
    /// [`AccountError::WeakPassword`], [`AccountError::NeedsLogin`],
    /// [`AccountError::NotSignedIn`].
    pub async fn change_password(
        &self,
        old_password: &SecretString,
        new_password: &SecretString,
        totp: Option<&SecretString>,
    ) -> Result<u32, AccountError> {
        require_strong(new_password.expose_secret())?;
        let vault = &self.inner.vault;
        let (acct, keys) = load_account_keys(vault)
            .await?
            .ok_or(AccountError::NotSignedIn)?;
        let api = self.inner.tokens.api().clone();
        let offline = |e: SyncError| match e {
            SyncError::Transport(m) => AccountError::Unreachable(format!("{NEEDS_SERVER} ({m})")),
            other => other.into(),
        };
        api.probe().await.map_err(offline)?;
        let access = self.inner.tokens.access().await.map_err(offline)?;

        // 1. Reauth with the old password.
        let reauth = self.reauth(&acct, old_password, totp).await?;
        let uid = *reauth.user_id.as_bytes();

        // 2. New OPAQUE record + re-sealed bundle, uploaded atomically.
        let mut rng = os_rng();
        let (reg, request) =
            client_registration_start(&mut rng, new_password.expose_secret().as_bytes())?;
        let start: PasswordStartResponse = api
            .post_v1(
                "/account/password/start",
                &PasswordStartRequest {
                    registration_request: request,
                },
                Some(&access),
            )
            .await?;
        let fin = crate::account::finish_record(
            reg,
            new_password,
            start.registration_response,
            &self.inner.cfg,
        )
        .await?;
        let new_version = acct.key_version + 1;
        let bundle = seal_private_bundle(
            &derive_akek(&fin.export_key),
            &uid,
            new_version,
            &keys,
            &mut rng,
        )?;
        // Prepared before the upload so the local step can't fail on Argon2
        // after the server already switched.
        let wrap = vault.password_wrap(new_password).await?;
        let resp: KeyVersionResponse = api
            .post_v1(
                "/account/password",
                &PasswordChangeRequest {
                    reauth_token: reauth.reauth_token.clone(),
                    registration_upload: fin.upload.clone(),
                    private_bundle_enc: bundle,
                    version: new_version,
                },
                Some(&access),
            )
            .await?;

        // 3. Local re-wrap and the new version, in one transaction.
        let acct = LocalAccount {
            key_version: resp.version,
            ..acct
        };
        let keys_enc = seal_local_keys(vault, &acct, &keys).await?;
        vault
            .store()
            .write(move |w| {
                wrap.apply(w)?;
                write_account(w, &acct, Some(&keys_enc))
            })
            .await?;
        tracing::info!(version = resp.version, "account password changed");
        Ok(resp.version)
    }

    /// Starts enabling TOTP: a new pending secret.
    ///
    /// # Errors
    /// [`AccountError::Sync`] (`409` when already enabled), …
    pub async fn totp_start(&self) -> Result<TotpSetup, AccountError> {
        let resp: TotpSetupResponse = self
            .call(|api, t| async move {
                api.post_v1("/account/totp", &TotpRequest::default(), Some(&t))
                    .await
            })
            .await?;
        let TotpSetupResponse {
            otpauth_uri,
            secret_base32,
        } = resp;
        Ok(TotpSetup {
            otpauth_uri: SecretString::from(otpauth_uri),
            secret_base32: SecretString::from(secret_base32),
        })
    }

    /// Confirms the pending TOTP secret with a current code.
    ///
    /// # Errors
    /// [`AccountError::Sync`] (`400` invalid code), …
    pub async fn totp_confirm(&self, code: &SecretString) -> Result<(), AccountError> {
        let code = code.expose_secret().trim().to_owned();
        let status: TotpStatus = self
            .call(|api, t| {
                let req = TotpRequest {
                    code: Some(code.clone()),
                };
                async move { api.post_v1("/account/totp", &req, Some(&t)).await }
            })
            .await?;
        if !status.enabled {
            return Err(AccountError::Local("TOTP was not enabled".into()));
        }
        Ok(())
    }

    /// Disables TOTP (needs a current code).
    ///
    /// # Errors
    /// [`AccountError::Sync`] (`403` invalid code), …
    pub async fn totp_disable(&self, code: &SecretString) -> Result<(), AccountError> {
        let code = code.expose_secret().trim().to_owned();
        self.call(|api, t| {
            let req = TotpRequest {
                code: Some(code.clone()),
            };
            async move { api.delete_v1("/account/totp", Some(&req), &t).await }
        })
        .await
    }

    /// Deletes the account on the server (after an OPAQUE reauth with
    /// `password`), then logs this device out locally. Local data is kept.
    ///
    /// # Errors
    /// [`AccountError::LoginFailed`], [`AccountError::Unreachable`], …
    pub async fn delete_account(
        &self,
        password: &SecretString,
        totp: Option<&SecretString>,
    ) -> Result<LogoutReport, AccountError> {
        let acct = self.account().await?.ok_or(AccountError::NotSignedIn)?;
        let reauth = self.reauth(&acct, password, totp).await?;
        let req = AccountDeleteRequest {
            reauth_token: reauth.reauth_token.clone(),
        };
        let req = &req;
        self.call(|api, t| async move { api.delete_v1("/account", Some(req), &t).await })
            .await?;
        self.inner.tokens.invalidate().await;
        let mut report = logout_local(&self.inner.vault).await?;
        report.revoked = true;
        tracing::info!("account deleted");
        Ok(report)
    }
}
