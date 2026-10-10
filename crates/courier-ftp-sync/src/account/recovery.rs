//! Forgotten password, with the 24-word recovery key.
//!
//! 1. [`request_recovery_code`]: the server mails a one-time code (or the
//!    operator issues it with `courier-ftp-server admin user recovery-code`).
//! 2. [`recover_account`]: email + code + the 24 words + a new password
//!    (zxcvbn ≥ 3) → `recovery/start` returns the recovery bundle, which the
//!    recovery key opens; the account keys are re-sealed under the new AKEK
//!    (version + 1) and the upload is signed with the account Ed25519 key;
//!    `recovery` replaces the OPAQUE record and revokes **every** device.
//! 3. The device signs in again with the new password:
//!    * a **locked** device (the usual case: the password is forgotten):
//!      [`recover_locked_device`] logs in, opens the vault grants with the
//!      account keys and re-keys the local vault through
//!      `VaultEngine::recover_with_vault_keys` (the local items stay
//!      readable: they are sealed under the vault keys, which the grants
//!      hold). The keyring wrap, the device blobs (the saved transfer queue)
//!      and other LMK-wrapped device data are lost.
//!    * an **unlocked** device: an ordinary [`super::start_login`] with the
//!      new password re-wraps the LMK.

use courier_ftp_core::model::item::{DeviceId, VaultId};
use courier_ftp_core::vault::VaultState;
use courier_ftp_crypto::account::{derive_akek, open_private_bundle, seal_private_bundle};
use courier_ftp_crypto::keys::os_rng;
use courier_ftp_crypto::opaque::{client_registration_start, recovery_proof_message};
use courier_ftp_crypto::recovery::{open_recovery_bundle, recovery_key_from_mnemonic};
use courier_ftp_crypto::sign;
use courier_ftp_proto::auth::{
    KeyVersionResponse, LoginDevice, LoginPurpose, RecoveryCodeRequest, RecoveryFinishRequest,
    RecoveryStartRequest, RecoveryStartResponse, SessionResponse,
};
use courier_ftp_store::vault::{RecoveredKey, VaultEngine};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::local::{self, LocalAccount};
use super::login::open_own_vaults;
use super::opaque_flow::{finish_registration_record, opaque_login};
use super::{AccountConfig, AccountError, check_email, probe_server, require_strong};
use crate::error::SyncError;
use crate::session::SyncSession;
use crate::tokens::{TokenManager, Tokens};

/// The result of a recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recovered {
    /// The account.
    pub user_id: Uuid,
    /// The new account key bundle version.
    pub key_version: u32,
}

/// Asks the server to mail a recovery code to `email` (accepted whether or
/// not the account exists).
///
/// # Errors
/// [`AccountError::Unreachable`] and other transport errors.
pub async fn request_recovery_code(
    server_url: &str,
    email: &str,
    cfg: &AccountConfig,
) -> Result<(), AccountError> {
    let email = check_email(email)?;
    let api = probe_server(server_url, cfg).await?;
    api.post_v1_empty(
        "/account/recovery/code",
        Some(&RecoveryCodeRequest { email }),
        None,
    )
    .await?;
    Ok(())
}

fn code_error(e: SyncError) -> AccountError {
    match e {
        SyncError::Api { status: 401, .. } => AccountError::BadRecoveryCode,
        SyncError::Api { status: 403, .. } => {
            AccountError::BadRecoveryPhrase("the server rejected the recovery proof".into())
        }
        other => other.into(),
    }
}

/// Resets the account password with the recovery phrase (step 2 above).
/// Every device of the account is logged out.
///
/// # Errors
/// [`AccountError::BadRecoveryPhrase`] (unparsable phrase, or it does not
/// open the bundle), [`AccountError::BadRecoveryCode`],
/// [`AccountError::WeakPassword`], [`AccountError::Unreachable`].
pub async fn recover_account(
    server_url: &str,
    email: &str,
    code: &SecretString,
    words: &SecretString,
    new_password: &SecretString,
    cfg: &AccountConfig,
) -> Result<Recovered, AccountError> {
    require_strong(new_password.expose_secret())?;
    let email = check_email(email)?;
    let recovery = recovery_key_from_mnemonic(words.expose_secret())
        .map_err(|e| AccountError::BadRecoveryPhrase(e.to_string()))?;
    let api = probe_server(server_url, cfg).await?;
    let code = Zeroizing::new(code.expose_secret().trim().to_owned());
    let mut rng = os_rng();
    let (reg, request) =
        client_registration_start(&mut rng, new_password.expose_secret().as_bytes())?;
    let start: RecoveryStartResponse = api
        .post_v1(
            "/account/recovery/start",
            &RecoveryStartRequest {
                email: email.clone(),
                code: code.to_string(),
                registration_request: request,
            },
            None,
        )
        .await
        .map_err(code_error)?;
    let uid = *start.user_id.as_bytes();
    let account_keys =
        open_recovery_bundle(&recovery, &uid, &start.recovery_bundle_enc).map_err(|_| {
            AccountError::BadRecoveryPhrase(
                "this recovery phrase does not belong to the account".into(),
            )
        })?;
    drop(recovery);
    let fin =
        finish_registration_record(reg, new_password, start.registration_response, cfg).await?;
    let version = start.version + 1;
    let bundle = seal_private_bundle(
        &derive_akek(&fin.export_key),
        &uid,
        version,
        &account_keys,
        &mut rng,
    )?;
    let msg = recovery_proof_message(&uid, version, &fin.upload, &bundle);
    let signature = sign::sign(account_keys.ed25519_signing_key(), &msg);
    let resp: KeyVersionResponse = api
        .post_v1(
            "/account/recovery",
            &RecoveryFinishRequest {
                email,
                code: code.to_string(),
                registration_upload: fin.upload.clone(),
                private_bundle_enc: bundle,
                version,
                signature: signature.to_vec(),
            },
            None,
        )
        .await
        .map_err(code_error)?;
    tracing::info!(version = resp.version, "account recovered");
    Ok(Recovered {
        user_id: start.user_id,
        key_version: resp.version,
    })
}

/// Step 3 for a **locked** device (forgotten password) after
/// [`recover_account`]: logs in with `new_password`, opens the vault grants,
/// re-keys the local vault (`VaultEngine::recover_with_vault_keys`) — which
/// leaves it unlocked — and stores the new tokens and account keys.
///
/// # Errors
/// [`AccountError::Local`] (the vault is not locked: use
/// [`super::start_login`]), [`AccountError::LoginFailed`],
/// [`AccountError::Crypto`], [`AccountError::Local`] for a device whose
/// personal vault is not the account's (`VaultError::NotRecoverable`).
pub async fn recover_device(
    vault: &VaultEngine,
    server_url: &str,
    email: &str,
    new_password: &SecretString,
    totp: Option<&SecretString>,
    cfg: &AccountConfig,
) -> Result<SyncSession, AccountError> {
    let status = vault.status().await?;
    if status.state != VaultState::Locked {
        return Err(AccountError::Local(
            "the vault is not locked; log in with the new password instead".into(),
        ));
    }
    let email = check_email(email)?;
    let api = probe_server(server_url, cfg).await?;
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
        new_password,
        cfg,
        LoginPurpose::Login,
        device,
        totp,
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
    let opened = open_own_vaults(user_id, &keys, views)?;
    let recovered: Vec<RecoveredKey> = opened
        .into_iter()
        .map(|v| RecoveredKey {
            vault: VaultId::from_uuid(v.view.id),
            key_version: v.view.key_version,
            key: v.key,
        })
        .collect();
    let acct = LocalAccount {
        user_id,
        email,
        key_version: account_keys.version,
    };
    let acct2 = acct.clone();
    vault
        .recover_with_vault_keys(new_password, recovered, move |w| {
            local::write_account(w, &acct2, None)
        })
        .await?;
    let keys_enc = local::seal_local_keys(vault, &acct, &keys).await?;
    vault
        .store()
        .meta()
        .set(courier_ftp_store::meta::keys::ACCOUNT_KEYS, keys_enc)
        .await?;
    let tm = TokenManager::save_login(vault, &api, DeviceId::from_uuid(device_id), tokens).await?;
    tracing::info!("device recovered and signed in");
    Ok(SyncSession::from_parts(vault.clone(), tm, cfg.clone()))
}

/// [`recover_account`] then [`recover_device`]: the "forgot password?" path
/// of a locked device with a sync account (`VaultStatus::sync_account`).
///
/// # Errors
/// As both.
pub async fn recover_locked_device(
    vault: &VaultEngine,
    server_url: &str,
    email: &str,
    code: &SecretString,
    words: &SecretString,
    new_password: &SecretString,
    cfg: &AccountConfig,
) -> Result<(Recovered, SyncSession), AccountError> {
    let status = vault.status().await?;
    if status.state != VaultState::Locked {
        return Err(AccountError::Local(
            "the vault is not locked; log in with the new password instead".into(),
        ));
    }
    let recovered = recover_account(server_url, email, code, words, new_password, cfg).await?;
    let session = recover_device(vault, server_url, email, new_password, None, cfg).await?;
    Ok((recovered, session))
}
