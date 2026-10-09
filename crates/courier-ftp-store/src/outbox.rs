//! The `outbox` table: one row per item with a pending push.
//!
//! Re-queuing an item that is already queued only refreshes `queued_at` and
//! **keeps the original `base_revision`**, so ten local edits produce one push
//! based on the revision the first edit started from. After a pull merges a
//! remote change into a dirty item, [`WriteTx::rebase`] moves the base forward.
//!
//! Rows exist whether or not sync is configured, so enabling sync later pushes
//! everything that is dirty.

use rusqlite::params;

use crate::Id16;
use crate::db::{ReadTx, Store, WriteTx};
use crate::error::{Result, StoreError, count, id16, u32_col};

/// One row of `outbox`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRow {
    /// The queued item.
    pub item_id: Id16,
    /// Its vault.
    pub vault_id: Id16,
    /// Server revision the local edit is based on.
    pub base_revision: i64,
    /// Last (re)queue time, Unix ms.
    pub queued_at: i64,
    /// Failed push attempts (transport errors), for backoff.
    pub attempts: u32,
}

impl ReadTx<'_> {
    /// Queued rows of a vault, oldest first.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an undecodable row, or a SQLite error.
    pub fn list_outbox(&self, vault: Id16) -> Result<Vec<OutboxRow>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT item_id, vault_id, base_revision, queued_at, attempts FROM outbox
             WHERE vault_id = ?1 ORDER BY queued_at, item_id",
        )?;
        let raws = stmt
            .query_map(params![&vault[..]], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        raws.into_iter()
            .map(|(item, vault, base_revision, queued_at, attempts)| {
                Ok(OutboxRow {
                    item_id: id16(item, "outbox.item_id")?,
                    vault_id: id16(vault, "outbox.vault_id")?,
                    base_revision,
                    queued_at,
                    attempts: u32_col(attempts, "outbox.attempts")?,
                })
            })
            .collect()
    }

    /// Total number of queued items across all vaults.
    ///
    /// # Errors
    /// A SQLite error.
    pub fn pending_count(&self) -> Result<u64> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM outbox", [], |r| r.get(0))?;
        count(n)
    }

    /// Queued items per vault (vaults with nothing queued are left out), in
    /// vault id order.
    ///
    /// # Errors
    /// As [`ReadTx::list_outbox`].
    pub fn pending_by_vault(&self) -> Result<Vec<(Id16, u64)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT vault_id, COUNT(*) FROM outbox GROUP BY vault_id ORDER BY vault_id",
        )?;
        let raws = stmt
            .query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        raws.into_iter()
            .map(|(vault, n)| Ok((id16(vault, "outbox.vault_id")?, count(n)?)))
            .collect()
    }
}

impl WriteTx<'_> {
    /// Queues `item` for push. An existing row keeps its `base_revision` and
    /// only gets a fresh `queued_at` (and the item's current vault).
    ///
    /// # Errors
    /// A SQLite error (the item must exist).
    pub fn enqueue(&self, item: Id16, vault: Id16, base_revision: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO outbox (item_id, vault_id, base_revision, queued_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(item_id) DO UPDATE SET
                queued_at = excluded.queued_at,
                vault_id = excluded.vault_id",
            params![&item[..], &vault[..], base_revision, self.now],
        )?;
        self.enqueued.set(true);
        Ok(())
    }

    /// Moves the base revision of a queued item forward (after a pull merge or
    /// a conflict merge).
    ///
    /// # Errors
    /// [`StoreError::NotFound`] if the item is not queued.
    pub fn rebase(&self, item: Id16, new_base: i64) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE outbox SET base_revision = ?2 WHERE item_id = ?1",
            params![&item[..], new_base],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Removes the queued row (a no-op if there is none). Does not touch
    /// `items.dirty`; see [`WriteTx::mark_pushed`].
    ///
    /// # Errors
    /// A SQLite error.
    pub fn dequeue(&self, item: Id16) -> Result<()> {
        self.conn
            .execute("DELETE FROM outbox WHERE item_id = ?1", params![&item[..]])?;
        Ok(())
    }

    /// Increments the failed-attempt counter and returns the new value.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] if the item is not queued.
    pub fn bump_attempts(&self, item: Id16) -> Result<u32> {
        let n = self.conn.execute(
            "UPDATE outbox SET attempts = attempts + 1 WHERE item_id = ?1",
            params![&item[..]],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        let attempts: i64 = self.conn.query_row(
            "SELECT attempts FROM outbox WHERE item_id = ?1",
            params![&item[..]],
            |r| r.get(0),
        )?;
        u32_col(attempts, "outbox.attempts")
    }
}

impl Store {
    /// See [`WriteTx::enqueue`].
    ///
    /// # Errors
    /// As [`WriteTx::enqueue`].
    pub async fn enqueue(&self, item: Id16, vault: Id16, base_revision: i64) -> Result<()> {
        self.write(move |w| w.enqueue(item, vault, base_revision))
            .await
    }

    /// See [`WriteTx::rebase`].
    ///
    /// # Errors
    /// As [`WriteTx::rebase`].
    pub async fn rebase(&self, item: Id16, new_base: i64) -> Result<()> {
        self.write(move |w| w.rebase(item, new_base)).await
    }

    /// See [`WriteTx::dequeue`].
    ///
    /// # Errors
    /// As [`WriteTx::dequeue`].
    pub async fn dequeue(&self, item: Id16) -> Result<()> {
        self.write(move |w| w.dequeue(item)).await
    }

    /// See [`WriteTx::bump_attempts`].
    ///
    /// # Errors
    /// As [`WriteTx::bump_attempts`].
    pub async fn bump_attempts(&self, item: Id16) -> Result<u32> {
        self.write(move |w| w.bump_attempts(item)).await
    }

    /// See [`ReadTx::list_outbox`].
    ///
    /// # Errors
    /// As [`ReadTx::list_outbox`].
    pub async fn list_outbox(&self, vault: Id16) -> Result<Vec<OutboxRow>> {
        self.read(move |r| r.list_outbox(vault)).await
    }

    /// See [`ReadTx::pending_count`].
    ///
    /// # Errors
    /// As [`ReadTx::pending_count`].
    pub async fn pending_count(&self) -> Result<u64> {
        self.read(|r| r.pending_count()).await
    }

    /// See [`ReadTx::pending_by_vault`].
    ///
    /// # Errors
    /// As [`ReadTx::pending_by_vault`].
    pub async fn pending_by_vault(&self) -> Result<Vec<(Id16, u64)>> {
        self.read(|r| r.pending_by_vault()).await
    }
}
