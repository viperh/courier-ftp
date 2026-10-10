//! Encrypted device-local blobs (the transfer queue, T40; open tabs, T61). Sealed with
//! the device key (`meta.device_key_wrapped`), never synced.

use async_trait::async_trait;
use courier_ftp_crypto::device_blob::{open_device_blob, seal_device_blob};
use courier_ftp_crypto::random::os_rng;
use zeroize::Zeroizing;

use super::VaultEngine;
use super::engine::from_crypto;
use crate::Result;

/// Device-local encrypted blob storage (T40's persistence trait; `queue::persist`
/// re-exports it). The vault's `Locked` error surfaces as
/// [`Error::VaultLocked`](crate::Error::VaultLocked).
#[async_trait]
pub trait DeviceBlobStore: Send + Sync {
    /// Stores `plaintext` under `name`, replacing any previous blob.
    ///
    /// # Errors
    /// `VaultLocked`, or a vault/storage error.
    async fn put_blob(&self, name: &str, plaintext: Zeroizing<Vec<u8>>) -> Result<()>;

    /// The blob stored under `name`.
    ///
    /// # Errors
    /// `VaultLocked`, or a vault error (tampered blob, storage).
    async fn get_blob(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;

    /// Deletes the blob (no error when missing).
    ///
    /// # Errors
    /// `VaultLocked`, or a storage error.
    async fn delete_blob(&self, name: &str) -> Result<()>;
}

#[async_trait]
impl DeviceBlobStore for VaultEngine {
    async fn put_blob(&self, name: &str, plaintext: Zeroizing<Vec<u8>>) -> Result<()> {
        let op = self.op().await?;
        let blob = seal_device_blob(op.s.device_key.key(), name, &plaintext, &mut os_rng())
            .map_err(|e| from_crypto(e, "device blob"))?;
        drop(plaintext);
        self.store()
            .put_device_blob(name, blob)
            .await
            .map_err(super::VaultError::from)?;
        tracing::debug!(name, "device blob stored");
        Ok(())
    }

    async fn get_blob(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let op = self.op().await?;
        let Some(blob) = self
            .store()
            .get_device_blob(name)
            .await
            .map_err(super::VaultError::from)?
        else {
            return Ok(None);
        };
        let plain = open_device_blob(op.s.device_key.key(), name, &blob)
            .map_err(|e| from_crypto(e, "device blob"))?;
        Ok(Some(plain))
    }

    async fn delete_blob(&self, name: &str) -> Result<()> {
        let _op = self.op().await?;
        self.store()
            .delete_device_blob(name)
            .await
            .map_err(super::VaultError::from)?;
        Ok(())
    }
}
