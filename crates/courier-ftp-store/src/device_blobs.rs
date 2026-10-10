//! The `device_blobs` table: named, encrypted, device-local blobs (the transfer
//! queue, T40; tab state). Never synced: no item, no outbox row.
//!
//! The caller seals each blob before handing it over, in the item-envelope format
//! of `courier_ftp_crypto::envelope` under a device key wrapped by the LMK
//! (`WrapPurpose::Device`). Like items, the store checks the bytes look like an
//! envelope so plaintext cannot reach disk by mistake.

use courier_ftp_crypto::envelope::{FORMAT_V1, MIN_LEN, parse_header};
use rusqlite::{OptionalExtension, params};

use crate::db::{ReadTx, Store, WriteTx};
use crate::error::{Result, StoreError};

/// Well-known blob names.
pub mod names {
    /// The persisted transfer queue (T40).
    pub const TRANSFER_QUEUE: &str = "transfer_queue";
    /// Open tabs and layout.
    pub const TAB_STATE: &str = "tab_state";
}

fn check_blob(envelope: &[u8]) -> Result<()> {
    if envelope.len() < MIN_LEN {
        return Err(StoreError::InvalidEnvelope("too short to be an envelope"));
    }
    if envelope[0] != FORMAT_V1 {
        return Err(StoreError::InvalidEnvelope("not a v1 envelope"));
    }
    parse_header(envelope).map_err(|_| StoreError::InvalidEnvelope("malformed header"))?;
    Ok(())
}

impl ReadTx<'_> {
    /// The sealed blob `name`.
    pub fn get_device_blob(&self, name: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .prepare_cached("SELECT envelope FROM device_blobs WHERE name = ?1")?
            .query_row(params![name], |r| r.get(0))
            .optional()?)
    }

    /// The names of every stored blob, sorted.
    pub fn list_device_blobs(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT name FROM device_blobs ORDER BY name")?;
        let names = stmt
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        Ok(names)
    }
}

impl WriteTx<'_> {
    /// Stores (or replaces) the sealed blob `name`.
    ///
    /// # Errors
    /// [`StoreError::InvalidEnvelope`] for bytes that are not an envelope.
    pub fn put_device_blob(&self, name: &str, envelope: &[u8]) -> Result<()> {
        check_blob(envelope)?;
        self.conn.execute(
            "INSERT INTO device_blobs (name, envelope) VALUES (?1, ?2)
             ON CONFLICT(name) DO UPDATE SET envelope = excluded.envelope",
            params![name, envelope],
        )?;
        Ok(())
    }

    /// Removes the blob `name`. Returns whether it existed.
    pub fn delete_device_blob(&self, name: &str) -> Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM device_blobs WHERE name = ?1", params![name])?;
        Ok(n > 0)
    }
}

/// Async access to `device_blobs` ([`Store::device_blobs`]).
#[derive(Debug, Clone, Copy)]
pub struct DeviceBlobRepo<'s> {
    store: &'s Store,
}

impl Store {
    /// The `device_blobs` repository.
    pub fn device_blobs(&self) -> DeviceBlobRepo<'_> {
        DeviceBlobRepo { store: self }
    }
}

impl DeviceBlobRepo<'_> {
    /// See [`ReadTx::get_device_blob`].
    pub async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let name = name.to_owned();
        self.store.read(move |r| r.get_device_blob(&name)).await
    }

    /// See [`ReadTx::list_device_blobs`].
    pub async fn list(&self) -> Result<Vec<String>> {
        self.store.read(|r| r.list_device_blobs()).await
    }

    /// See [`WriteTx::put_device_blob`].
    pub async fn put(&self, name: &str, envelope: Vec<u8>) -> Result<()> {
        let name = name.to_owned();
        self.store
            .write(move |w| w.put_device_blob(&name, &envelope))
            .await
    }

    /// See [`WriteTx::delete_device_blob`].
    pub async fn delete(&self, name: &str) -> Result<bool> {
        let name = name.to_owned();
        self.store.write(move |w| w.delete_device_blob(&name)).await
    }
}
