//! The `meta` key/value table: device-level settings and wrapped secrets.
//!
//! Values are opaque bytes. Anything secret (the wrapped LMK, the device key)
//! is stored already wrapped by the caller (T30).

use rusqlite::{OptionalExtension, params};

use crate::db::{ReadTx, Store, WriteTx};
use crate::error::Result;

/// Well-known `meta` keys (encodings and owners in T82's specification).
pub mod keys {
    /// KDF parameters and salt for the password KEK (CBOR map).
    pub const KDF: &str = "kdf";
    /// The LMK wrapped under the password KEK.
    pub const LMK_WRAPPED_PW: &str = "lmk_wrapped_pw";
    /// The LMK wrapped under the OS-keyring KEK (present iff keyring unlock is on).
    pub const LMK_WRAPPED_KEYRING: &str = "lmk_wrapped_keyring";
    /// The device key (device blobs) wrapped under the LMK.
    pub const DEVICE_KEY_WRAPPED: &str = "device_key_wrapped";
    /// Consecutive failed unlock attempts (u32 BE).
    pub const UNLOCK_FAILURES: &str = "unlock_failures";
    /// Earliest time (Unix ms, i64 BE) the next unlock attempt is allowed.
    pub const UNLOCK_NEXT_ALLOWED_AT: &str = "unlock_next_allowed_at";
    /// This device's id (16 bytes, UUIDv7).
    pub const DEVICE_ID: &str = "device_id";
    /// Random id of this database (UUIDv7 text), so several data directories
    /// use distinct OS-keyring accounts.
    pub const DB_ID: &str = "db_id";
    /// Last HLC timestamp issued by this device (u64 BE).
    pub const HLC_LAST: &str = "hlc_last";
}

impl ReadTx<'_> {
    /// The value for `key`.
    ///
    /// # Errors
    /// A SQLite error.
    pub fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .prepare_cached("SELECT value FROM meta WHERE key = ?1")?
            .query_row(params![key], |r| r.get(0))
            .optional()?)
    }
}

impl WriteTx<'_> {
    /// Sets `key` to `value`.
    ///
    /// # Errors
    /// A SQLite error.
    pub fn set_meta(&self, key: &str, value: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Removes `key` (a no-op if absent).
    ///
    /// # Errors
    /// A SQLite error.
    pub fn delete_meta(&self, key: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM meta WHERE key = ?1", params![key])?;
        Ok(())
    }
}

impl Store {
    /// See [`ReadTx::get_meta`].
    ///
    /// # Errors
    /// As [`ReadTx::get_meta`].
    pub async fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let key = key.to_owned();
        self.read(move |r| r.get_meta(&key)).await
    }

    /// See [`WriteTx::set_meta`].
    ///
    /// # Errors
    /// As [`WriteTx::set_meta`].
    pub async fn set_meta(&self, key: &str, value: Vec<u8>) -> Result<()> {
        let key = key.to_owned();
        self.write(move |w| w.set_meta(&key, &value)).await
    }

    /// See [`WriteTx::delete_meta`].
    ///
    /// # Errors
    /// As [`WriteTx::delete_meta`].
    pub async fn delete_meta(&self, key: &str) -> Result<()> {
        let key = key.to_owned();
        self.write(move |w| w.delete_meta(&key)).await
    }
}
