//! Local-only → new account.
//!
//! 1. [`prepare_registration`]: probe the server, verify the **current**
//!    master password locally (it is the local master password and strong
//!    enough), generate the account keypairs and the recovery key. Nothing
//!    is sent yet.
//! 2. The UI shows the 24 words once ([`PreparedRegistration::recovery_words`])
//!    and makes the user re-type three random ones
//!    ([`PreparedRegistration::confirm_words`]).
//! 3. [`finish_registration`]: OPAQUE registration with that password, the
//!    sealed private and recovery bundles, the personal vault with a
//!    self-grant (the local personal vault's id and key are reused) and the
//!    device; then `sync_state`, `meta.account`, and every local item queued
//!    with `base_revision = 0`, so the sync engine uploads everything.
//!
//! A crash after the server accepted `register/finish` but before the local
//! commit leaves the account without a signed-in device: logging in
//! ([`super::start_login`]) finds the local vault is the account's personal
//! vault and simply signs in.

use std::fmt;

use courier_ftp_core::model::item::{DeviceId, VaultId};
use courier_ftp_crypto::Key32;
use courier_ftp_crypto::account::{
    AccountKeys, derive_akek, generate_account_keys, seal_private_bundle,
};
use courier_ftp_crypto::envelope::seal_item;
use courier_ftp_crypto::grant::self_grant;
use courier_ftp_crypto::keys::os_rng;
use courier_ftp_crypto::opaque::client_registration_start;
use courier_ftp_crypto::recovery::{
    RecoveryKey, RecoveryMnemonic, recovery_key_generate, seal_recovery_bundle,
};
use courier_ftp_proto::ErrorCode;
use courier_ftp_proto::auth::{
    AccountKeysUpload, GrantUpload, PersonalVaultUpload, RegisterFinishRequest,
    RegisterStartRequest, RegisterStartResponse, SessionResponse,
};
use courier_ftp_store::vault::VaultEngine;
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::confirm::{CONFIRM_WORDS, RecoveryConfirm};
use super::local::{self, LocalAccount};
use super::opaque_flow::finish_registration_record;
use super::{AccountConfig, AccountError, check_email, probe_server, require_strong};
use crate::error::SyncError;
use crate::http::ApiClient;
use crate::session::SyncSession;
use crate::tokens::{TokenManager, Tokens};

/// The account keys' first version.
const FIRST_KEY_VERSION: u32 = 1;

/// The plaintext personal-vault name sealed into `name_enc`.
pub const PERSONAL_VAULT_NAME: &str = "Personal";

/// An invite or first-admin setup token for a server that is not `open`.
#[derive(Clone)]
pub enum RegistrationToken {
    /// An instance or org invite.
    Invite(SecretString),
    /// The one-time setup token printed by `courier-ftp-server` on first start.
    Setup(SecretString),
}

impl fmt::Debug for RegistrationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invite(_) => f.write_str("Invite([REDACTED])"),
            Self::Setup(_) => f.write_str("Setup([REDACTED])"),
        }
    }
}

impl RegistrationToken {
    fn split(token: Option<&Self>) -> (Option<String>, Option<String>) {
        match token {
            Some(Self::Invite(t)) => (Some(t.expose_secret().trim().to_owned()), None),
            Some(Self::Setup(t)) => (None, Some(t.expose_secret().trim().to_owned())),
            None => (None, None),
        }
    }
}

/// Step 1 done: keys and recovery key generated, password verified.
pub struct PreparedRegistration {
    api: ApiClient,
    email: String,
    password: SecretString,
    vault: VaultId,
    vk: Key32,
    vault_key_version: u32,
    keys: AccountKeys,
    recovery: RecoveryKey,
    mnemonic: RecoveryMnemonic,
    confirm: RecoveryConfirm,
}

impl fmt::Debug for PreparedRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedRegistration")
            .field("email", &self.email)
            .field("vault", &self.vault)
            .field("confirmed", &self.confirm.is_confirmed())
            .finish_non_exhaustive()
    }
}

impl PreparedRegistration {
    /// The 24 recovery words, to show **once** (never log them).
    #[must_use]
    pub fn recovery_words(&self) -> Vec<&'static str> {
        self.mnemonic.words().collect()
    }

    /// The recovery phrase as one string (zeroized on drop).
    #[must_use]
    pub fn recovery_phrase(&self) -> Zeroizing<String> {
        self.mnemonic.phrase()
    }

    /// The 1-based numbers of the words to re-type (random, ascending).
    #[must_use]
    pub fn confirm_word_numbers(&self) -> [usize; CONFIRM_WORDS] {
        self.confirm.word_numbers()
    }

    /// Checks the re-typed words (in [`Self::confirm_word_numbers`] order).
    /// [`finish_registration`] refuses until this returned `true`.
    pub fn confirm_words<S: AsRef<str>>(&mut self, answers: &[S; CONFIRM_WORDS]) -> bool {
        self.confirm.submit(answers)
    }

    /// The personal vault that becomes the account's personal vault.
    #[must_use]
    pub const fn vault(&self) -> VaultId {
        self.vault
    }

    /// The server.
    #[must_use]
    pub fn server_url(&self) -> &str {
        self.api.base_url()
    }

    /// The email.
    #[must_use]
    pub fn email(&self) -> &str {
        &self.email
    }
}

/// The result of a registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    /// The new account.
    pub user_id: Uuid,
    /// This device, as the server knows it.
    pub device_id: Uuid,
    /// The personal vault (unchanged id).
    pub vault: VaultId,
    /// Items queued for upload.
    pub queued: u64,
}

/// Step 1: probe `server_url`, verify `password` is the current local master
/// password (and zxcvbn ≥ 3), and generate the account keys and the recovery
/// key. The vault must be unlocked.
///
/// # Errors
/// [`AccountError::Unreachable`] / [`AccountError::IncompatibleServer`],
/// [`AccountError::WrongLocalPassword`], [`AccountError::WeakPassword`],
/// [`AccountError::Local`] (locked, already signed in, invalid email).
pub async fn prepare_registration(
    vault: &VaultEngine,
    server_url: &str,
    email: &str,
    password: &SecretString,
    cfg: &AccountConfig,
) -> Result<PreparedRegistration, AccountError> {
    let email = check_email(email)?;
    if !vault.is_unlocked().await {
        return Err(AccountError::Local("unlock the vault first".into()));
    }
    if vault
        .store()
        .sync_state()
        .get()
        .await?
        .is_some_and(|s| s.tokens_enc.is_some())
    {
        return Err(AccountError::Local(
            "this device is already signed in; log out first".into(),
        ));
    }
    let api = probe_server(server_url, cfg).await?;
    if !vault.is_master_password(password).await? {
        return Err(AccountError::WrongLocalPassword);
    }
    // The password now also protects the server-side bundle.
    require_strong(password.expose_secret())?;
    let personal = vault
        .personal_vault()
        .await
        .ok_or_else(|| AccountError::Local("the vault is locked".into()))?;
    let (vault_key_version, vk) = vault.vault_key(personal).await?;
    let mut rng = os_rng();
    let keys = generate_account_keys(&mut rng);
    let (recovery, mnemonic) = recovery_key_generate(&mut rng);
    let words: Vec<&str> = mnemonic.words().collect();
    let confirm = RecoveryConfirm::with_random_positions(&words);
    Ok(PreparedRegistration {
        api,
        email,
        password: password.clone(),
        vault: personal,
        vk,
        vault_key_version,
        keys,
        recovery,
        mnemonic,
        confirm,
    })
}

fn register_error(e: SyncError) -> AccountError {
    match &e {
        SyncError::Api {
            status: 403,
            message,
            ..
        } => AccountError::InviteRequired(message.clone()),
        SyncError::Api {
            code: Some(ErrorCode::Conflict),
            ..
        } => AccountError::AlreadyRegistered,
        _ => e.into(),
    }
}

/// `name_enc` of a vault: the name sealed like an item envelope with the
/// vault id as item id (so it is bound to this vault).
pub(crate) fn seal_vault_name(
    vk: &Key32,
    vault: VaultId,
    key_version: u32,
    name: &str,
) -> Result<Vec<u8>, AccountError> {
    Ok(seal_item(
        vk,
        vault.as_bytes(),
        vault.as_bytes(),
        key_version,
        name.as_bytes(),
        &mut os_rng(),
    )?)
}

/// Step 3: OPAQUE registration and upload, then the local commit. Only
/// after the recovery words were confirmed. On
/// [`AccountError::InviteRequired`] ask for a token and call again with the
/// same `prepared`.
///
/// # Errors
/// [`AccountError::RecoveryNotConfirmed`], [`AccountError::InviteRequired`],
/// [`AccountError::AlreadyRegistered`], [`AccountError::Unreachable`],
/// [`AccountError::Local`].
pub async fn finish_registration(
    vault: &VaultEngine,
    prepared: &PreparedRegistration,
    token: Option<&RegistrationToken>,
    cfg: &AccountConfig,
) -> Result<(Registered, SyncSession), AccountError> {
    let p = prepared;
    if !p.confirm.is_confirmed() {
        return Err(AccountError::RecoveryNotConfirmed);
    }
    if vault.personal_vault().await != Some(p.vault) {
        return Err(AccountError::Local(
            "the vault changed since the registration started".into(),
        ));
    }
    let mut rng = os_rng();
    let (invite_token, setup_token) = RegistrationToken::split(token);
    let (state, request) =
        client_registration_start(&mut rng, p.password.expose_secret().as_bytes())?;
    let start: RegisterStartResponse = p
        .api
        .post_v1(
            "/auth/register/start",
            &RegisterStartRequest {
                email: p.email.clone(),
                registration_request: request,
                invite_token: invite_token.clone(),
                setup_token: setup_token.clone(),
            },
            None,
        )
        .await
        .map_err(register_error)?;
    let fin =
        finish_registration_record(state, &p.password, start.registration_response, cfg).await?;
    let user_id = start.user_id;
    let uid = *user_id.as_bytes();
    let akek = derive_akek(&fin.export_key);
    let private = seal_private_bundle(&akek, &uid, FIRST_KEY_VERSION, &p.keys, &mut rng)?;
    let rbundle = seal_recovery_bundle(&p.recovery, &uid, &p.keys, &mut rng)?;
    let grant = self_grant(
        &p.vk,
        p.vault.as_bytes(),
        p.vault_key_version,
        &uid,
        &p.keys,
        &mut rng,
    )?;
    let pubk = p.keys.public();
    let req = RegisterFinishRequest {
        email: p.email.clone(),
        user_id,
        registration_upload: fin.upload.clone(),
        account_keys: AccountKeysUpload {
            x25519_pub: pubk.x25519.to_vec(),
            ed25519_pub: pubk.ed25519.to_vec(),
            private_bundle_enc: private,
            recovery_bundle_enc: rbundle,
            version: FIRST_KEY_VERSION,
        },
        personal_vault: PersonalVaultUpload {
            id: p.vault.uuid(),
            name_enc: seal_vault_name(&p.vk, p.vault, p.vault_key_version, PERSONAL_VAULT_NAME)?,
            self_grant: GrantUpload::from_grant(&grant, p.vault_key_version),
        },
        device: cfg.device.clone(),
        invite_token,
        setup_token,
    };
    let session: SessionResponse = p
        .api
        .post_v1("/auth/register/finish", &req, None)
        .await
        .map_err(register_error)?;
    let SessionResponse {
        device_id,
        tokens,
        account_keys,
        ..
    } = session;
    let tokens = Tokens::from_pair(tokens, vault.store().now());

    let acct = LocalAccount {
        user_id,
        email: p.email.clone(),
        key_version: account_keys.version,
    };
    let keys_enc = local::seal_local_keys(vault, &acct, &p.keys).await?;
    let personal = p.vault;
    let queued = vault
        .store()
        .write(move |w| {
            local::write_account(w, &acct, Some(&keys_enc))?;
            w.reset_sync(personal)
        })
        .await?;
    let tm =
        TokenManager::save_login(vault, &p.api, DeviceId::from_uuid(device_id), tokens).await?;
    tracing::info!(queued, "registered; the personal vault will be uploaded");
    let session = SyncSession::from_parts(vault.clone(), tm, cfg.clone());
    Ok((
        Registered {
            user_id,
            device_id,
            vault: personal,
            queued,
        },
        session,
    ))
}
