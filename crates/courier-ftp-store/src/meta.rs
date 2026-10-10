//! The `meta` key/value table: device-level settings and wrapped secrets.
//!
//! Values are opaque bytes. Anything secret (the wrapped LMK) is stored already
//! wrapped by the caller.

use courier_ftp_core::model::item::{DeviceId, Hlc};
use rusqlite::{OptionalExtension, params};

use crate::db::{ReadTx, Store, WriteTx};
use crate::error::{Result, StoreError};
use crate::vaults::id16;

/// Well-known `meta` keys.
pub mod keys {
    /// KDF parameters and salt for the password KEK (`KdfParams::to_cbor`).
    pub const KDF: &str = "kdf";
    /// The LMK wrapped under the password KEK.
    pub const LMK_WRAPPED_PW: &str = "lmk_wrapped_pw";
    /// The LMK wrapped under the OS-keyring KEK.
    pub const LMK_WRAPPED_KEYRING: &str = "lmk_wrapped_keyring";
    /// Consecutive failed unlock attempts.
    pub const UNLOCK_FAILURES: &str = "unlock_failures";
    /// Earliest time (UNIX ms) the next unlock attempt is allowed.
    pub const UNLOCK_NEXT_ALLOWED_AT: &str = "unlock_next_allowed_at";
    /// This device's id (16 bytes).
    pub const DEVICE_ID: &str = "device_id";
    /// Last HLC timestamp issued or observed by this device (8 bytes, big-endian).
    pub const HLC_LAST: &str = "hlc_last";
    /// Random id of this database (UUID text), so several data directories use
    /// distinct OS-keyring accounts.
    pub const DB_ID: &str = "db_id";
    /// The device data key (T40) wrapped under the LMK (`WrapPurpose::Device`),
    /// sealing the `device_blobs`. Created on first use; never synced.
    pub const DEVICE_KEY_WRAPPED: &str = "device_key_wrapped";
}

impl ReadTx<'_> {
    /// The value for `key`.
    pub fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .prepare_cached("SELECT value FROM meta WHERE key = ?1")?
            .query_row(params![key], |r| r.get(0))
            .optional()?)
    }

    /// The persisted [`keys::HLC_LAST`], for `HlcClock::with_last`.
    pub fn get_hlc_last(&self) -> Result<Option<Hlc>> {
        self.get_meta(keys::HLC_LAST)?
            .map(|v| {
                <[u8; 8]>::try_from(v.as_slice())
                    .map(|b| Hlc::from_u64(u64::from_be_bytes(b)))
                    .map_err(|_| StoreError::Corrupt("meta.hlc_last is not 8 bytes".into()))
            })
            .transpose()
    }

    /// The persisted [`keys::DEVICE_ID`].
    pub fn get_device_id(&self) -> Result<Option<DeviceId>> {
        self.get_meta(keys::DEVICE_ID)?
            .map(|v| id16(v, "meta.device_id").map(DeviceId::from_bytes))
            .transpose()
    }
}

impl WriteTx<'_> {
    /// Sets `key` to `value`.
    pub fn set_meta(&self, key: &str, value: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Removes `key` (a no-op if absent).
    pub fn delete_meta(&self, key: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM meta WHERE key = ?1", params![key])?;
        Ok(())
    }

    /// Persists `hlc` as [`keys::HLC_LAST`] unless the stored value is newer, so
    /// the value never goes backwards (two processes may write it).
    pub fn set_hlc_last(&self, hlc: Hlc) -> Result<()> {
        if self.as_read().get_hlc_last()?.is_some_and(|cur| cur >= hlc) {
            return Ok(());
        }
        self.set_meta(keys::HLC_LAST, &hlc.as_u64().to_be_bytes())
    }

    /// Persists [`keys::DEVICE_ID`].
    pub fn set_device_id(&self, id: DeviceId) -> Result<()> {
        self.set_meta(keys::DEVICE_ID, id.as_bytes())
    }
}

/// Async access to `meta` ([`Store::meta`]).
#[derive(Debug, Clone, Copy)]
pub struct MetaRepo<'s> {
    store: &'s Store,
}

impl Store {
    /// The `meta` repository.
    pub fn meta(&self) -> MetaRepo<'_> {
        MetaRepo { store: self }
    }
}

impl MetaRepo<'_> {
    /// See [`ReadTx::get_meta`].
    pub async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let key = key.to_owned();
        self.store.read(move |r| r.get_meta(&key)).await
    }

    /// See [`WriteTx::set_meta`].
    pub async fn set(&self, key: &str, value: Vec<u8>) -> Result<()> {
        let key = key.to_owned();
        self.store.write(move |w| w.set_meta(&key, &value)).await
    }

    /// See [`WriteTx::delete_meta`].
    pub async fn delete(&self, key: &str) -> Result<()> {
        let key = key.to_owned();
        self.store.write(move |w| w.delete_meta(&key)).await
    }

    /// See [`ReadTx::get_hlc_last`].
    pub async fn hlc_last(&self) -> Result<Option<Hlc>> {
        self.store.read(|r| r.get_hlc_last()).await
    }

    /// See [`WriteTx::set_hlc_last`].
    pub async fn set_hlc_last(&self, hlc: Hlc) -> Result<()> {
        self.store.write(move |w| w.set_hlc_last(hlc)).await
    }

    /// See [`ReadTx::get_device_id`].
    pub async fn device_id(&self) -> Result<Option<DeviceId>> {
        self.store.read(|r| r.get_device_id()).await
    }

    /// See [`WriteTx::set_device_id`].
    pub async fn set_device_id(&self, id: DeviceId) -> Result<()> {
        self.store.write(move |w| w.set_device_id(id)).await
    }
}
