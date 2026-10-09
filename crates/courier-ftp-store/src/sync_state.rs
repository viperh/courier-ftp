//! The `sync_state` singleton (row `id = 1`, enforced by a CHECK constraint).
//!
//! `tokens_enc` is stored exactly as given; the caller wraps the tokens under
//! the LMK first (T87).

use rusqlite::{OptionalExtension, params};

use crate::Id16;
use crate::db::{ReadTx, Store, WriteTx};
use crate::error::{Result, id16};
use crate::vaults::check_wrapped;

/// The sync configuration of this device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncState {
    /// Server base URL.
    pub server_url: String,
    /// Server-assigned device id.
    pub device_id: Id16,
    /// Access and refresh tokens, wrapped under the LMK by the caller.
    pub tokens_enc: Vec<u8>,
}

impl ReadTx<'_> {
    /// The singleton row, if set.
    ///
    /// # Errors
    /// [`crate::StoreError::Corrupt`] for an undecodable row, or a SQLite error.
    pub fn get_sync_state(&self) -> Result<Option<SyncState>> {
        let raw = self
            .conn
            .query_row(
                "SELECT server_url, device_id, tokens_enc FROM sync_state WHERE id = 1",
                [],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?;
        raw.map(|(server_url, device_id, tokens_enc)| {
            Ok(SyncState {
                server_url,
                device_id: id16(device_id, "sync_state.device_id")?,
                tokens_enc,
            })
        })
        .transpose()
    }
}

impl WriteTx<'_> {
    /// Replaces the singleton row.
    ///
    /// # Errors
    /// [`crate::StoreError::InvalidEnvelope`] when `tokens_enc` is too short to
    /// be wrapped, or a SQLite error.
    pub fn set_sync_state(&self, state: &SyncState) -> Result<()> {
        check_wrapped(&state.tokens_enc)?;
        self.conn.execute(
            "INSERT INTO sync_state (id, server_url, device_id, tokens_enc) VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET
                server_url = excluded.server_url,
                device_id = excluded.device_id,
                tokens_enc = excluded.tokens_enc",
            params![state.server_url, &state.device_id[..], state.tokens_enc],
        )?;
        Ok(())
    }

    /// Removes the singleton row (sync disabled / logged out).
    ///
    /// # Errors
    /// A SQLite error.
    pub fn clear_sync_state(&self) -> Result<()> {
        self.conn.execute("DELETE FROM sync_state", [])?;
        Ok(())
    }
}

impl Store {
    /// See [`ReadTx::get_sync_state`].
    ///
    /// # Errors
    /// As [`ReadTx::get_sync_state`].
    pub async fn get_sync_state(&self) -> Result<Option<SyncState>> {
        self.read(|r| r.get_sync_state()).await
    }

    /// See [`WriteTx::set_sync_state`].
    ///
    /// # Errors
    /// As [`WriteTx::set_sync_state`].
    pub async fn set_sync_state(&self, state: SyncState) -> Result<()> {
        self.write(move |w| w.set_sync_state(&state)).await
    }

    /// See [`WriteTx::clear_sync_state`].
    ///
    /// # Errors
    /// As [`WriteTx::clear_sync_state`].
    pub async fn clear_sync_state(&self) -> Result<()> {
        self.write(|w| w.clear_sync_state()).await
    }
}
