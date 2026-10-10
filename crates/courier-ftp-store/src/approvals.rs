//! The `local_approvals` table: the device-local allowlist of values the user
//! approved on this machine.
//!
//! One row per `(item_id, field)`, holding the SHA-256 of the exact value the user
//! approved (the caller computes the hash). A changed value no longer matches its
//! row and is asked for again; approving it again upserts the row. The table is
//! never synced: rows are not items, have no envelope and never enter the outbox.

use courier_ftp_core::model::item::ItemId;
use rusqlite::{OptionalExtension, params};

use crate::db::{ReadTx, Store, WriteTx};
use crate::error::{Result, StoreError};
use crate::vaults::id16;

/// One row of `local_approvals`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalApproval {
    /// The item defining the value.
    pub item_id: ItemId,
    /// The (dotted) field name.
    pub field: String,
    /// SHA-256 of the approved value.
    pub value_sha256: [u8; 32],
    /// When it was approved (UNIX ms).
    pub approved_at: i64,
}

type RawApproval = (Vec<u8>, String, Vec<u8>, i64);

fn decode(raw: RawApproval) -> Result<LocalApproval> {
    let (id, field, hash, approved_at) = raw;
    let value_sha256: [u8; 32] = hash
        .try_into()
        .map_err(|_| StoreError::Corrupt("local_approvals.value_sha256 is not 32 bytes".into()))?;
    Ok(LocalApproval {
        item_id: ItemId::from_bytes(id16(id, "local_approvals.item_id")?),
        field,
        value_sha256,
        approved_at,
    })
}

const COLS: &str = "item_id, field, value_sha256, approved_at";

fn raw(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawApproval> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
}

impl ReadTx<'_> {
    /// The approval row of `(item, field)`.
    pub fn get_local_approval(&self, item: ItemId, field: &str) -> Result<Option<LocalApproval>> {
        let found = self
            .conn
            .prepare_cached(&format!(
                "SELECT {COLS} FROM local_approvals WHERE item_id = ?1 AND field = ?2"
            ))?
            .query_row(params![item.as_bytes(), field], raw)
            .optional()?;
        found.map(decode).transpose()
    }

    /// Every approval row, ordered by item and field.
    pub fn list_local_approvals(&self) -> Result<Vec<LocalApproval>> {
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT {COLS} FROM local_approvals ORDER BY item_id, field"
        ))?;
        let raws = stmt
            .query_map([], raw)?
            .collect::<rusqlite::Result<Vec<RawApproval>>>()?;
        raws.into_iter().map(decode).collect()
    }
}

impl WriteTx<'_> {
    /// Approves `value_sha256` for `(item, field)` at the transaction's time
    /// (upsert: a new value replaces the previous approval).
    pub fn put_local_approval(
        &self,
        item: ItemId,
        field: &str,
        value_sha256: &[u8; 32],
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO local_approvals (item_id, field, value_sha256, approved_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(item_id, field) DO UPDATE SET
                value_sha256 = excluded.value_sha256,
                approved_at = excluded.approved_at",
            params![item.as_bytes(), field, &value_sha256[..], self.now],
        )?;
        Ok(())
    }

    /// Revokes the approval of `(item, field)`. Returns whether a row existed.
    pub fn delete_local_approval(&self, item: ItemId, field: &str) -> Result<bool> {
        let n = self.conn.execute(
            "DELETE FROM local_approvals WHERE item_id = ?1 AND field = ?2",
            params![item.as_bytes(), field],
        )?;
        Ok(n > 0)
    }

    /// Revokes every approval of `item` (e.g. after it was purged). Returns the count.
    pub fn delete_local_approvals_of(&self, item: ItemId) -> Result<usize> {
        Ok(self.conn.execute(
            "DELETE FROM local_approvals WHERE item_id = ?1",
            params![item.as_bytes()],
        )?)
    }
}

/// Async access to `local_approvals` ([`Store::approvals`]).
#[derive(Debug, Clone, Copy)]
pub struct ApprovalRepo<'s> {
    store: &'s Store,
}

impl Store {
    /// The `local_approvals` repository.
    pub fn approvals(&self) -> ApprovalRepo<'_> {
        ApprovalRepo { store: self }
    }
}

impl ApprovalRepo<'_> {
    /// See [`WriteTx::put_local_approval`].
    pub async fn put(&self, item: ItemId, field: &str, value_sha256: [u8; 32]) -> Result<()> {
        let field = field.to_owned();
        self.store
            .write(move |w| w.put_local_approval(item, &field, &value_sha256))
            .await
    }

    /// See [`WriteTx::delete_local_approval`].
    pub async fn delete(&self, item: ItemId, field: &str) -> Result<bool> {
        let field = field.to_owned();
        self.store
            .write(move |w| w.delete_local_approval(item, &field))
            .await
    }

    /// See [`ReadTx::get_local_approval`].
    pub async fn get(&self, item: ItemId, field: &str) -> Result<Option<LocalApproval>> {
        let field = field.to_owned();
        self.store
            .read(move |r| r.get_local_approval(item, &field))
            .await
    }

    /// See [`ReadTx::list_local_approvals`].
    pub async fn list(&self) -> Result<Vec<LocalApproval>> {
        self.store.read(|r| r.list_local_approvals()).await
    }
}
