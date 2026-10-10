//! The sync client's access to the vault engine (T87, T88).
//!
//! `courier-ftp-sync` never sees the LMK: everything that needs it runs here,
//! inside the engine, and only results leave (sealed blobs, derived subkeys,
//! wrapped vault keys).
//!
//! - **LMK-scoped helpers**: [`VaultEngine::lmk_seal`] / [`VaultEngine::lmk_open`]
//!   (sync tokens), [`VaultEngine::lmk_subkey`] (the key sealing the account
//!   keys on this device), [`VaultEngine::wrap_vault_key`] (a vault key from a
//!   grant, for `vaults.wrapped_key`), [`VaultEngine::password_wrap`] (one
//!   password, two derivations: the LMK re-wrapped under the account password).
//! - **Commits**: [`VaultEngine::commit`] runs one write transaction under the
//!   engine's state lock and reloads the unlocked state from the store, so
//!   new or removed vaults and imported items are what the engine serves next.
//! - **Recovery** of a device whose password is forgotten:
//!   [`VaultEngine::recover_with_vault_keys`] re-keys the device with the vault
//!   keys the recovered account opened from its grants.
//! - **Applying pulled items** (T88): [`VaultEngine::apply_incoming`] decrypts,
//!   merges into dirty local copies, re-seals and stores a page in one
//!   transaction and updates the decrypted index; [`VaultEngine::outgoing`]
//!   builds the push batch.

use courier_ftp_core::model::item::{DeviceId, HlcClock, VaultId};
use courier_ftp_core::vault::{UnlockMethod, VaultError, check_strength, keyring_account};
use courier_ftp_crypto::Key32;
use courier_ftp_crypto::kdf::KdfParams;
use courier_ftp_crypto::keys::{hkdf_key32, os_rng, random_key32};
use courier_ftp_crypto::wrap::{WrapPurpose, unwrap_key, wrap_key};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use super::{UnlockReport, VaultEngine, blocking, storage};
use crate::meta::keys;
use crate::{VaultKind, WriteTx};

/// A new password wrap of the LMK (`meta.kdf` + `meta.lmk_wrapped_pw`),
/// prepared outside a transaction by [`VaultEngine::password_wrap`] (Argon2
/// is slow) and written inside one with [`PasswordWrap::apply`].
#[derive(Clone)]
pub struct PasswordWrap {
    kdf: Vec<u8>,
    lmk_pw: Vec<u8>,
}

impl std::fmt::Debug for PasswordWrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordWrap([REDACTED])")
    }
}

impl PasswordWrap {
    /// Stores the wrap and clears the unlock backoff. The keyring wrap (same
    /// LMK) stays valid and is left alone.
    ///
    /// # Errors
    /// A SQLite error.
    pub fn apply(&self, w: &WriteTx<'_>) -> crate::Result<()> {
        w.set_meta(keys::KDF, &self.kdf)?;
        w.set_meta(keys::LMK_WRAPPED_PW, &self.lmk_pw)?;
        w.delete_meta(keys::UNLOCK_FAILURES)?;
        w.delete_meta(keys::UNLOCK_NEXT_ALLOWED_AT)
    }
}

/// A vault key the recovered account opened from its grant.
pub struct RecoveredKey {
    /// The vault.
    pub vault: VaultId,
    /// The key's version.
    pub key_version: u32,
    /// The key.
    pub key: Key32,
}

impl std::fmt::Debug for RecoveredKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveredKey")
            .field("vault", &self.vault)
            .field("key_version", &self.key_version)
            .finish_non_exhaustive()
    }
}

impl VaultEngine {
    /// Wraps `secret` under the LMK for `purpose` (sync tokens).
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::Corrupt`].
    pub async fn lmk_seal(
        &self,
        purpose: WrapPurpose,
        secret: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        let state = self.inner.state.read().await;
        let u = state.as_ref().ok_or(VaultError::Locked)?;
        wrap_key(&u.lmk.key, &purpose, secret, &mut os_rng())
            .map_err(|e| VaultError::from_crypto(e, purpose.name()))
    }

    /// Opens a blob from [`VaultEngine::lmk_seal`].
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::Corrupt`] (tampered, or sealed
    /// under another LMK).
    pub async fn lmk_open(
        &self,
        purpose: WrapPurpose,
        blob: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let state = self.inner.state.read().await;
        let u = state.as_ref().ok_or(VaultError::Locked)?;
        unwrap_key(&u.lmk.key, &purpose, blob)
            .map_err(|e| VaultError::from_crypto(e, purpose.name()))
    }

    /// `HKDF-SHA256(LMK, info)`: a key for local data bound to this device's
    /// LMK (the account keys at rest, T87). The LMK itself never leaves.
    ///
    /// # Errors
    /// [`VaultError::Locked`].
    pub async fn lmk_subkey(&self, info: &[u8]) -> Result<Key32, VaultError> {
        let state = self.inner.state.read().await;
        let u = state.as_ref().ok_or(VaultError::Locked)?;
        Ok(hkdf_key32(u.lmk.key.expose_secret(), None, info))
    }

    /// Whether `password` is the local master password. Needs an unlocked
    /// vault and does not count toward the unlock backoff: the account flows
    /// use it to verify the current password (registration) and to detect an
    /// account password that differs (login).
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::NotInitialized`],
    /// [`VaultError::Corrupt`].
    pub async fn is_master_password(&self, password: &SecretString) -> Result<bool, VaultError> {
        if !self.is_unlocked().await {
            return Err(VaultError::Locked);
        }
        let m = self.meta().await?;
        let (Some(kdf), Some(wrapped)) = (&m.kdf, &m.lmk_pw) else {
            return Err(VaultError::NotInitialized);
        };
        let params =
            KdfParams::from_cbor(kdf).map_err(|e| VaultError::Corrupt(format!("meta.kdf: {e}")))?;
        let kek = self.derive(password, params).await?;
        let Ok(lmk) = courier_ftp_crypto::wrap::unwrap_key32(&kek, &WrapPurpose::Lmk, wrapped)
        else {
            return Ok(false);
        };
        let state = self.inner.state.read().await;
        Ok(state.as_ref().is_some_and(|u| *u.lmk.key == lmk))
    }

    /// A new wrap of the unlocked LMK under `password` (new salt, the
    /// engine's Argon2 cost), to store with [`PasswordWrap::apply`].
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::Corrupt`].
    pub async fn password_wrap(&self, password: &SecretString) -> Result<PasswordWrap, VaultError> {
        let lmk = {
            let state = self.inner.state.read().await;
            let u = state.as_ref().ok_or(VaultError::Locked)?;
            Key32::clone(&u.lmk.key)
        };
        let mut rng = os_rng();
        let params = KdfParams::generate(self.inner.cost, &mut rng);
        let kek = self.derive(password, params).await?;
        let lmk_pw = wrap_key(&kek, &WrapPurpose::Lmk, lmk.expose_secret(), &mut rng)
            .map_err(|e| VaultError::from_crypto(e, "lmk"))?;
        Ok(PasswordWrap {
            kdf: params.to_cbor(),
            lmk_pw,
        })
    }

    /// The current key of a loaded vault and its version (registration seals
    /// the personal vault's self-grant with it). Zeroized on drop.
    ///
    /// # Errors
    /// [`VaultError::Locked`] (also for a vault whose key is not loaded).
    pub async fn vault_key(&self, vault: VaultId) -> Result<(u32, Key32), VaultError> {
        let state = self.inner.state.read().await;
        let u = state.as_ref().ok_or(VaultError::Locked)?;
        let entry = u.vaults.get(&vault).ok_or(VaultError::Locked)?;
        Ok((entry.key_version, Key32::clone(&entry.key.key)))
    }

    /// `key` wrapped under the LMK for `vaults.wrapped_key` of `vault`.
    ///
    /// # Errors
    /// [`VaultError::Locked`].
    pub async fn wrap_vault_key(&self, vault: VaultId, key: &Key32) -> Result<Vec<u8>, VaultError> {
        self.lmk_seal(
            WrapPurpose::VaultKey(*vault.as_bytes()),
            key.expose_secret(),
        )
        .await
    }

    /// The vaults whose keys are loaded, in id order (empty while locked).
    pub async fn loaded_vaults(&self) -> Vec<VaultId> {
        self.inner
            .state
            .read()
            .await
            .as_ref()
            .map(|u| u.vaults.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Runs `f` with this device's HLC and id (stamping planned writes, e.g.
    /// the login import); the clock's new high-water mark is kept.
    ///
    /// # Errors
    /// [`VaultError::Locked`].
    pub async fn with_clock<T>(
        &self,
        f: impl FnOnce(&mut HlcClock, DeviceId) -> T,
    ) -> Result<T, VaultError> {
        let mut state = self.inner.state.write().await;
        let u = state.as_mut().ok_or(VaultError::Locked)?;
        let device = u.device;
        Ok(f(&mut u.clock, device))
    }

    /// Runs `f` in one write transaction while holding the engine's state
    /// lock, then reloads the unlocked state (vault keys, personal vault,
    /// decrypted items) from the store with the current LMK. Used for account
    /// changes that add, replace or remove vaults (login, logout).
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::Storage`] (the transaction rolled
    /// back; the state is unchanged), or a reload error.
    pub async fn commit<T: Send + 'static>(
        &self,
        f: impl FnOnce(&WriteTx<'_>) -> crate::Result<T> + Send + 'static,
    ) -> Result<T, VaultError> {
        let mut state = self.inner.state.write().await;
        let (lmk, method, min_hlc) = {
            let u = state.as_ref().ok_or(VaultError::Locked)?;
            (Key32::clone(&u.lmk.key), u.method, u.clock.last())
        };
        let out = self.inner.store.write(f).await.map_err(storage)?;
        let (unlocked, report) = self.load_unlocked(self.track(lmk), method, min_hlc).await?;
        *state = Some(unlocked);
        tracing::debug!(
            items = report.items,
            undecryptable = report.undecryptable,
            "vault state reloaded"
        );
        Ok(out)
    }

    /// Recovery of a device whose master password is forgotten, through its
    /// sync account (T87, T30 §9): after the server accepted the recovery,
    /// the account opened its vault grants and hands their keys here.
    ///
    /// Checks `new_password`'s strength, then in **one** transaction: a new
    /// LMK wrapped under `new_password`; every local vault whose key is in
    /// `keys` re-wrapped under it (so local items, sealed under the vault
    /// keys, stay readable); other vaults removed (their keys are gone); the
    /// keyring wrap, the device data key and the device blobs (all under the
    /// old LMK) removed; the stored sync tokens and account keys (under the
    /// old LMK) cleared; then `extra`. Leaves the engine unlocked.
    ///
    /// # Errors
    /// [`VaultError::WeakPassword`] (nothing happens),
    /// [`VaultError::NotRecoverable`] when `keys` lacks the local personal
    /// vault (nothing happens), [`VaultError::NotInitialized`],
    /// [`VaultError::Storage`].
    pub async fn recover_with_vault_keys(
        &self,
        new_password: &SecretString,
        keys: Vec<RecoveredKey>,
        extra: impl FnOnce(&WriteTx<'_>) -> crate::Result<()> + Send + 'static,
    ) -> Result<UnlockReport, VaultError> {
        check_strength(new_password.expose_secret(), &["courier-ftp"])?;
        let m = self.meta().await?;
        if m.kdf.is_none() {
            return Err(VaultError::NotInitialized);
        }
        let rows = self.inner.store.vaults().list().await.map_err(storage)?;
        let personal = rows
            .iter()
            .find(|r| r.kind == VaultKind::Personal)
            .ok_or_else(|| VaultError::Corrupt("there is no personal vault".into()))?;
        if !keys.iter().any(|k| k.vault == personal.id) {
            return Err(VaultError::NotRecoverable(
                "the account does not hold this device's personal vault".into(),
            ));
        }
        let mut rng = os_rng();
        let lmk = random_key32(&mut rng);
        let mut wraps = Vec::new();
        let mut removed = Vec::new();
        for row in &rows {
            match keys.iter().find(|k| k.vault == row.id) {
                Some(k) => {
                    let wrapped = wrap_key(
                        &lmk,
                        &WrapPurpose::VaultKey(*row.id.as_bytes()),
                        k.key.expose_secret(),
                        &mut rng,
                    )
                    .map_err(|e| VaultError::from_crypto(e, "vault key"))?;
                    wraps.push((row.id, k.key_version, wrapped));
                }
                None => removed.push(row.id),
            }
        }
        drop(keys);
        let params = KdfParams::generate(self.inner.cost, &mut rng);
        let kek = self.derive(new_password, params).await?;
        let wrap = PasswordWrap {
            kdf: params.to_cbor(),
            lmk_pw: wrap_key(&kek, &WrapPurpose::Lmk, lmk.expose_secret(), &mut rng)
                .map_err(|e| VaultError::from_crypto(e, "lmk"))?,
        };
        drop(kek);
        let had_keyring = m.lmk_keyring.is_some();
        self.inner
            .store
            .write(move |w| {
                wrap.apply(w)?;
                w.delete_meta(keys::LMK_WRAPPED_KEYRING)?;
                w.delete_meta(keys::DEVICE_KEY_WRAPPED)?;
                w.delete_meta(keys::ACCOUNT_KEYS)?;
                for name in w.as_read().list_device_blobs()? {
                    w.delete_device_blob(&name)?;
                }
                for (id, kv, wrapped) in &wraps {
                    w.update_wrapped_key(*id, *kv, wrapped)?;
                }
                for id in &removed {
                    w.delete_vault(*id)?;
                }
                if let Some(mut st) = w.as_read().get_sync_state()? {
                    st.tokens_enc = None;
                    w.set_sync_state(&st)?;
                }
                extra(w)
            })
            .await
            .map_err(storage)?;
        if had_keyring && let Ok(db_id) = m.db_id() {
            // The keyring entry wrapped the old LMK; it is useless now.
            let keyring = std::sync::Arc::clone(&self.inner.keyring);
            let account = keyring_account(&db_id);
            if let Ok(Err(e)) = blocking(move || keyring.delete(&account)).await {
                tracing::debug!(error = %e, "could not delete the old keyring entry");
            }
        }
        tracing::info!("vault re-keyed after an account recovery");
        self.open_vaults(lmk, UnlockMethod::Password).await
    }
}
