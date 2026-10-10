//! The device side of an account: `meta.account` and the account keys sealed
//! under a key derived from the LMK.

use courier_ftp_crypto::account::{AccountKeys, open_private_bundle, seal_private_bundle};
use courier_ftp_crypto::keys::os_rng;
use courier_ftp_store::meta::keys;
use courier_ftp_store::vault::VaultEngine;
use courier_ftp_store::{Store, StoreError, WriteTx};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::AccountError;

/// HKDF info of the key sealing the account keys on this device.
const LOCAL_KEYS_INFO: &[u8] = b"courier-ftp/local-account-keys/v1";

/// The account this device is signed in to (`meta.account`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalAccount {
    /// Server user id.
    pub user_id: Uuid,
    /// Account email.
    pub email: String,
    /// The account key bundle version this device last saw (bumped by
    /// password changes and recovery).
    pub key_version: u32,
}

/// `meta.account`, if this device is signed in (or was, before its tokens
/// were revoked). Readable while the vault is locked.
///
/// # Errors
/// [`AccountError::Local`].
pub async fn load_account(store: &Store) -> Result<Option<LocalAccount>, AccountError> {
    let raw = store.meta().get(keys::ACCOUNT).await?;
    raw.map(|b| {
        serde_json::from_slice(&b).map_err(|e| AccountError::Local(format!("meta.account: {e}")))
    })
    .transpose()
}

/// Seals the account keys for `meta.account_keys_enc`.
pub(crate) async fn seal_local_keys(
    vault: &VaultEngine,
    acct: &LocalAccount,
    account_keys: &AccountKeys,
) -> Result<Vec<u8>, AccountError> {
    let kek = vault.lmk_subkey(LOCAL_KEYS_INFO).await?;
    Ok(seal_private_bundle(
        &kek,
        acct.user_id.as_bytes(),
        acct.key_version,
        account_keys,
        &mut os_rng(),
    )?)
}

/// The account and its keys, opened through the unlocked vault (`None` when
/// not signed in).
///
/// # Errors
/// [`AccountError::Local`] / [`AccountError::Crypto`].
pub(crate) async fn load_account_keys(
    vault: &VaultEngine,
) -> Result<Option<(LocalAccount, AccountKeys)>, AccountError> {
    let Some(acct) = load_account(vault.store()).await? else {
        return Ok(None);
    };
    let Some(enc) = vault.store().meta().get(keys::ACCOUNT_KEYS).await? else {
        return Ok(None);
    };
    let kek = vault.lmk_subkey(LOCAL_KEYS_INFO).await?;
    let account_keys = open_private_bundle(&kek, acct.user_id.as_bytes(), acct.key_version, &enc)?;
    Ok(Some((acct, account_keys)))
}

/// Writes `meta.account` and (when given) the sealed keys, inside a
/// transaction.
pub(crate) fn write_account(
    w: &WriteTx<'_>,
    acct: &LocalAccount,
    keys_enc: Option<&[u8]>,
) -> courier_ftp_store::Result<()> {
    let json =
        serde_json::to_vec(acct).map_err(|e| StoreError::Corrupt(format!("meta.account: {e}")))?;
    w.set_meta(keys::ACCOUNT, &json)?;
    match keys_enc {
        Some(k) => w.set_meta(keys::ACCOUNT_KEYS, k),
        None => w.delete_meta(keys::ACCOUNT_KEYS),
    }
}

/// Removes `meta.account`, the sealed keys and the last-sync time, inside a
/// transaction.
pub(crate) fn clear_account(w: &WriteTx<'_>) -> courier_ftp_store::Result<()> {
    w.delete_meta(keys::ACCOUNT)?;
    w.delete_meta(keys::ACCOUNT_KEYS)?;
    w.delete_meta(keys::SYNC_LAST_OK)
}
