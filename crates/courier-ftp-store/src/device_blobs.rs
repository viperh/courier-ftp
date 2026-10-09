//! The `device_blobs` table: named, device-key-protected blobs that never
//! leave this device - `transfer-queue` (T40) and `tabs` (T61).
//!
//! Blobs arrive sealed in the T80 `device_blob` format (by T30); the store
//! only checks their shape and size.

use rusqlite::{OptionalExtension, params};

use courier_ftp_crypto::device_blob::{BLOB_V1, MIN_LEN};

use crate::db::{ReadTx, Store, WriteTx};
use crate::error::{Result, StoreError};

/// The largest device blob accepted (256 MiB).
pub const MAX_DEVICE_BLOB_LEN: usize = 256 * 1024 * 1024;

/// Refuses a blob that is not shaped like a sealed device blob.
fn check_device_blob(blob: &[u8]) -> Result<()> {
    if blob.len() > MAX_DEVICE_BLOB_LEN {
        return Err(StoreError::TooLarge);
    }
    if blob.len() < MIN_LEN || blob[0] != BLOB_V1 {
        return Err(StoreError::InvalidEnvelope("not a sealed device blob"));
    }
    Ok(())
}

impl ReadTx<'_> {
    /// The blob stored under `name`.
    ///
    /// # Errors
    /// A SQLite error.
    pub fn get_device_blob(&self, name: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .prepare_cached("SELECT blob FROM device_blobs WHERE name = ?1")?
            .query_row(params![name], |r| r.get(0))
            .optional()?)
    }
}

impl WriteTx<'_> {
    /// Stores (replaces) the blob under `name`.
    ///
    /// # Errors
    /// [`StoreError::TooLarge`], [`StoreError::InvalidEnvelope`] for a value
    /// that is not a sealed blob, or a SQLite error.
    pub fn put_device_blob(&self, name: &str, blob: &[u8]) -> Result<()> {
        check_device_blob(blob)?;
        self.conn.execute(
            "INSERT INTO device_blobs (name, blob, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO UPDATE SET
                blob = excluded.blob,
                updated_at = excluded.updated_at",
            params![name, blob, self.now],
        )?;
        tracing::debug!(name, len = blob.len(), "device blob stored");
        Ok(())
    }

    /// Deletes the blob under `name`. Returns whether it existed.
    ///
    /// # Errors
    /// A SQLite error.
    pub fn delete_device_blob(&self, name: &str) -> Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM device_blobs WHERE name = ?1", params![name])?;
        Ok(n > 0)
    }
}

impl Store {
    /// See [`ReadTx::get_device_blob`].
    ///
    /// # Errors
    /// As [`ReadTx::get_device_blob`].
    pub async fn get_device_blob(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let name = name.to_owned();
        self.read(move |r| r.get_device_blob(&name)).await
    }

    /// See [`WriteTx::put_device_blob`].
    ///
    /// # Errors
    /// As [`WriteTx::put_device_blob`].
    pub async fn put_device_blob(&self, name: &str, blob: Vec<u8>) -> Result<()> {
        // Refuse oversized blobs before handing them to a blocking task.
        check_device_blob(&blob)?;
        let name = name.to_owned();
        self.write(move |w| w.put_device_blob(&name, &blob)).await
    }

    /// See [`WriteTx::delete_device_blob`].
    ///
    /// # Errors
    /// As [`WriteTx::delete_device_blob`].
    pub async fn delete_device_blob(&self, name: &str) -> Result<bool> {
        let name = name.to_owned();
        self.write(move |w| w.delete_device_blob(&name)).await
    }
}
