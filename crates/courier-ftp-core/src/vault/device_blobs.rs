//! Device-local encrypted blobs: the [`DeviceBlobVault`] seam (T40).
//!
//! Some data never syncs and is not an item: the persisted transfer queue
//! (T40), open tabs. It lives in the store's `device_blobs` table, one sealed
//! blob per name. The engine (`courier_ftp_store::vault::VaultEngine`) seals
//! each blob under a random **device data key** that is wrapped by the LMK
//! (`WrapPurpose::Device`, `meta.device_key_wrapped`) and created on first use:
//!
//! ```text
//! LMK ──wrap(Device)──▶ device key (meta.device_key_wrapped)
//! device key ──HKDF(blob id)──▶ blob key ──▶ v1 envelope (device_blobs.envelope)
//!     aad: vault_id = this device's id, item_id = blob_id(name), key_version 1
//! ```
//!
//! So the blobs are readable only while the vault is unlocked, can't be swapped
//! between names, and the store never sees plaintext. Core code uses the trait
//! and stays testable with [`MemDeviceBlobs`] (feature `test-util`).

use std::fmt;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::VaultError;

/// Domain separation for [`blob_id`].
const BLOB_ID_LABEL: &[u8] = b"courier-ftp-device-blob-v1\0";

/// The 16-byte id a blob name is bound to in its envelope's AAD: the first 16
/// bytes of `SHA-256("courier-ftp-device-blob-v1\0" || name)`.
pub fn blob_id(name: &str) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(BLOB_ID_LABEL)
        .chain_update(name.as_bytes())
        .finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

/// Encrypted, device-local, never-synced blobs (implemented by
/// `courier_ftp_store::vault::VaultEngine`; see the module docs).
///
/// Every method except [`DeviceBlobVault::is_unlocked`] fails with
/// [`VaultError::Locked`] while the vault is locked: nothing is ever written
/// in plaintext.
#[async_trait]
pub trait DeviceBlobVault: Send + Sync + fmt::Debug {
    /// Whether keys are loaded.
    async fn is_unlocked(&self) -> bool;

    /// The decrypted blob `name`, `None` when there is none.
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::Corrupt`] (doesn't decrypt),
    /// [`VaultError::Storage`].
    async fn load_blob(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError>;

    /// Seals `plaintext` and stores it as blob `name`, replacing any previous
    /// one.
    ///
    /// # Errors
    /// [`VaultError::Locked`], [`VaultError::Busy`], [`VaultError::Storage`].
    async fn save_blob(&self, name: &str, plaintext: &[u8]) -> Result<(), VaultError>;

    /// Removes blob `name`. Returns whether it existed. Works while locked
    /// too (deleting needs no key).
    ///
    /// # Errors
    /// [`VaultError::Storage`].
    async fn delete_blob(&self, name: &str) -> Result<bool, VaultError>;
}

#[cfg(any(test, feature = "test-util"))]
pub use self::mem::MemDeviceBlobs;

#[cfg(any(test, feature = "test-util"))]
mod mem {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard, PoisonError};

    use async_trait::async_trait;
    use zeroize::Zeroizing;

    use super::DeviceBlobVault;
    use crate::vault::VaultError;

    /// An unencrypted, in-memory [`DeviceBlobVault`] for tests, with a lock
    /// switch and a write counter.
    #[derive(Debug)]
    pub struct MemDeviceBlobs {
        blobs: Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>,
        unlocked: AtomicBool,
        saves: AtomicUsize,
    }

    impl Default for MemDeviceBlobs {
        fn default() -> Self {
            Self::unlocked()
        }
    }

    impl MemDeviceBlobs {
        /// An empty, unlocked store.
        pub fn unlocked() -> Self {
            Self {
                blobs: Mutex::new(BTreeMap::new()),
                unlocked: AtomicBool::new(true),
                saves: AtomicUsize::new(0),
            }
        }

        /// Locks or unlocks it (the blobs stay).
        pub fn set_unlocked(&self, unlocked: bool) {
            self.unlocked.store(unlocked, Ordering::SeqCst);
        }

        /// How many times [`DeviceBlobVault::save_blob`] succeeded.
        pub fn saves(&self) -> usize {
            self.saves.load(Ordering::SeqCst)
        }

        /// The stored bytes of `name`, regardless of the lock.
        pub fn raw(&self, name: &str) -> Option<Vec<u8>> {
            self.blobs().get(name).map(|b| b.to_vec())
        }

        fn blobs(&self) -> MutexGuard<'_, BTreeMap<String, Zeroizing<Vec<u8>>>> {
            self.blobs.lock().unwrap_or_else(PoisonError::into_inner)
        }

        fn check(&self) -> Result<(), VaultError> {
            if self.unlocked.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(VaultError::Locked)
            }
        }
    }

    #[async_trait]
    impl DeviceBlobVault for MemDeviceBlobs {
        async fn is_unlocked(&self) -> bool {
            self.unlocked.load(Ordering::SeqCst)
        }

        async fn load_blob(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
            self.check()?;
            Ok(self.blobs().get(name).cloned())
        }

        async fn save_blob(&self, name: &str, plaintext: &[u8]) -> Result<(), VaultError> {
            self.check()?;
            self.blobs()
                .insert(name.to_owned(), Zeroizing::new(plaintext.to_vec()));
            self.saves.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn delete_blob(&self, name: &str) -> Result<bool, VaultError> {
            Ok(self.blobs().remove(name).is_some())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_ids_are_stable_and_distinct() {
        assert_eq!(blob_id("transfer_queue"), blob_id("transfer_queue"));
        assert_ne!(blob_id("transfer_queue"), blob_id("tab_state"));
    }
}
