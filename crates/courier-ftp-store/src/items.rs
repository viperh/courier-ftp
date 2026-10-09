//! The `items` table: encrypted item envelopes, server revisions and the dirty
//! flag.
//!
//! **Plaintext guarantee:** the store only ever receives envelopes (bytes sealed
//! by `courier_ftp_crypto::envelope::seal_item`). Every write checks that the
//! bytes look like an envelope ([`check_envelope`]), so a plaintext body handed
//! over by mistake is refused instead of reaching disk. Encryption is T30's job.

use rusqlite::{OptionalExtension, Row, params};

use courier_ftp_crypto::envelope::{FORMAT_V1, MIN_LEN, parse_header};

use crate::Id16;
use crate::db::{ReadTx, Store, WriteTx};
use crate::error::{Result, StoreError, count, id16, u32_col};

/// The largest envelope accepted: a 1 MiB item plus header, tag and padding
/// slack.
pub const MAX_ENVELOPE_LEN: usize = 1_048_576 + 4_096;

/// One row of `items`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRow {
    /// Item id.
    pub id: Id16,
    /// The vault it belongs to.
    pub vault_id: Id16,
    /// Server revision; 0 = never synced.
    pub revision: i64,
    /// Vault key version the envelope is sealed under.
    pub key_version: u32,
    /// The encrypted item body.
    pub envelope: Vec<u8>,
    /// Tombstone flag (mirrors the body's `deleted` stamp, for cheap filtering).
    pub deleted: bool,
    /// Pending push.
    pub dirty: bool,
    /// Last local write, Unix ms.
    pub updated_at: i64,
}

/// What T30 compares with its cache to find rows changed by another process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItemMarker {
    /// Item id.
    pub id: Id16,
    /// Last local write, Unix ms.
    pub updated_at: i64,
    /// Server revision.
    pub revision: i64,
    /// Tombstone flag.
    pub deleted: bool,
}

/// A local write of an item ([`WriteTx::put_item`]).
#[derive(Debug, Clone, Copy)]
pub struct PutItem<'a> {
    /// The vault the item belongs to.
    pub vault_id: Id16,
    /// Item id.
    pub id: Id16,
    /// Vault key version `envelope` is sealed under.
    pub key_version: u32,
    /// The sealed item body.
    pub envelope: &'a [u8],
    /// Tombstone flag.
    pub deleted: bool,
    /// Mark the item dirty and queue it in the outbox (in the same
    /// transaction). `false` only for writes that must never be pushed.
    pub mark_dirty: bool,
}

/// One item of a pulled page, as the sync engine wants it stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteItem {
    /// Item id.
    pub id: Id16,
    /// The server revision of the incoming item.
    pub revision: i64,
    /// Vault key version of `envelope`.
    pub key_version: u32,
    /// The envelope to store: the server's as received, or the locally
    /// re-sealed merge result when `local_pending` is set.
    pub envelope: Vec<u8>,
    /// Tombstone flag.
    pub deleted: bool,
    /// `false`: the item becomes clean and any outbox row is dropped.
    /// `true`: the envelope is a merge of a dirty local copy; the item stays
    /// dirty and its outbox row is rebased onto `revision`.
    pub local_pending: bool,
}

/// Format bytes a newer build may use: `0x02..=0x1F`. They are accepted and
/// stored, not interpreted. Anything else (`0x00`, printable text, JSON, CBOR
/// maps) cannot be an envelope and is refused, so a plaintext body longer than
/// an envelope header does not slip through.
pub const FUTURE_FORMATS: std::ops::RangeInclusive<u8> = 0x02..=0x1F;

/// Checks that `envelope` is shaped like a sealed item and that a v1 header
/// matches `key_version`. Unknown format bytes from newer builds
/// ([`FUTURE_FORMATS`]) are accepted (stored, not interpreted).
///
/// # Errors
/// [`StoreError::InvalidEnvelope`]: shorter than the smallest envelope,
/// larger than [`MAX_ENVELOPE_LEN`], an impossible format byte, or a v1 header
/// whose key version differs.
pub fn check_envelope(envelope: &[u8], key_version: u32) -> Result<()> {
    if envelope.len() < MIN_LEN {
        return Err(StoreError::InvalidEnvelope("too short"));
    }
    if envelope.len() > MAX_ENVELOPE_LEN {
        return Err(StoreError::InvalidEnvelope("too large"));
    }
    if envelope[0] == FORMAT_V1 {
        let header =
            parse_header(envelope).map_err(|_| StoreError::InvalidEnvelope("malformed header"))?;
        if header.key_version != key_version {
            return Err(StoreError::InvalidEnvelope(
                "header key_version does not match the declared key_version",
            ));
        }
    } else if !FUTURE_FORMATS.contains(&envelope[0]) {
        return Err(StoreError::InvalidEnvelope("unknown format byte"));
    }
    Ok(())
}

const ITEM_COLS: &str = "id, vault_id, revision, key_version, envelope, deleted, dirty, updated_at";

type RawItem = (Vec<u8>, Vec<u8>, i64, i64, Vec<u8>, bool, bool, i64);

fn raw_item(row: &Row<'_>) -> rusqlite::Result<RawItem> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

fn decode_item(raw: RawItem) -> Result<ItemRow> {
    let (id, vault_id, revision, key_version, envelope, deleted, dirty, updated_at) = raw;
    Ok(ItemRow {
        id: id16(id, "items.id")?,
        vault_id: id16(vault_id, "items.vault_id")?,
        revision,
        key_version: u32_col(key_version, "items.key_version")?,
        envelope,
        deleted,
        dirty,
        updated_at,
    })
}

impl ReadTx<'_> {
    fn query_items(&self, where_sql: &str, args: impl rusqlite::Params) -> Result<Vec<ItemRow>> {
        let mut stmt = self
            .conn
            .prepare_cached(&format!("SELECT {ITEM_COLS} FROM items {where_sql}"))?;
        let raws = stmt
            .query_map(args, raw_item)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        raws.into_iter().map(decode_item).collect()
    }

    /// One item (tombstones included).
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an undecodable row, or a SQLite error.
    pub fn get_item(&self, id: Id16) -> Result<Option<ItemRow>> {
        let raw = self
            .conn
            .prepare_cached(&format!("SELECT {ITEM_COLS} FROM items WHERE id = ?1"))?
            .query_row(params![&id[..]], raw_item)
            .optional()?;
        raw.map(decode_item).transpose()
    }

    /// All items of a vault (tombstones included), in id order.
    ///
    /// # Errors
    /// As [`ReadTx::get_item`].
    pub fn list_items(&self, vault: Id16) -> Result<Vec<ItemRow>> {
        self.query_items("WHERE vault_id = ?1 ORDER BY id", params![&vault[..]])
    }

    /// Every item of every vault, in id order.
    ///
    /// # Errors
    /// As [`ReadTx::get_item`].
    pub fn list_all_items(&self) -> Result<Vec<ItemRow>> {
        self.query_items("ORDER BY id", [])
    }

    /// Dirty items of a vault (pending push), in id order.
    ///
    /// # Errors
    /// As [`ReadTx::get_item`].
    pub fn list_dirty(&self, vault: Id16) -> Result<Vec<ItemRow>> {
        self.query_items(
            "WHERE dirty = 1 AND vault_id = ?1 ORDER BY id",
            params![&vault[..]],
        )
    }

    /// Number of items (tombstones included).
    ///
    /// # Errors
    /// A SQLite error.
    pub fn item_count(&self) -> Result<u64> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0))?;
        count(n)
    }

    /// `(id, updated_at, revision, deleted)` of every item, in id order: cheap
    /// change detection without reading envelopes.
    ///
    /// # Errors
    /// As [`ReadTx::get_item`].
    pub fn item_markers(&self) -> Result<Vec<ItemMarker>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT id, updated_at, revision, deleted FROM items ORDER BY id")?;
        let raws = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, bool>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        raws.into_iter()
            .map(|(id, updated_at, revision, deleted)| {
                Ok(ItemMarker {
                    id: id16(id, "items.id")?,
                    updated_at,
                    revision,
                    deleted,
                })
            })
            .collect()
    }
}

impl WriteTx<'_> {
    /// Upserts a local write of an item: sets `updated_at = now` and, with
    /// `mark_dirty`, sets `dirty = 1` and queues it in the outbox with the
    /// item's current server revision as base (an existing outbox row keeps its
    /// base, coalescing edits into one push).
    ///
    /// A clean write (`mark_dirty = false`) never clears an existing dirty flag.
    ///
    /// # Errors
    /// [`StoreError::InvalidEnvelope`], or a SQLite error (e.g. unknown vault).
    pub fn put_item(&self, item: PutItem<'_>) -> Result<()> {
        check_envelope(item.envelope, item.key_version)?;
        let id = &item.id[..];
        self.conn.execute(
            "INSERT INTO items (id, vault_id, key_version, envelope, deleted, dirty, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
                vault_id = excluded.vault_id,
                key_version = excluded.key_version,
                envelope = excluded.envelope,
                deleted = excluded.deleted,
                dirty = MAX(items.dirty, excluded.dirty),
                updated_at = excluded.updated_at",
            params![
                id,
                &item.vault_id[..],
                item.key_version,
                item.envelope,
                item.deleted,
                item.mark_dirty,
                self.now
            ],
        )?;
        if item.mark_dirty {
            let revision: i64 = self.conn.query_row(
                "SELECT revision FROM items WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )?;
            self.enqueue(item.id, item.vault_id, revision)?;
        }
        Ok(())
    }

    /// Applies one pulled page and advances the vault cursor to `new_cursor`,
    /// in this transaction. Any error rolls back the whole page and the cursor.
    ///
    /// # Errors
    /// [`StoreError::InvalidEnvelope`], [`StoreError::NotFound`] (unknown
    /// vault), or a SQLite error.
    pub fn apply_remote(&self, vault: Id16, page: &[RemoteItem], new_cursor: i64) -> Result<()> {
        for item in page {
            check_envelope(&item.envelope, item.key_version)?;
            self.conn.execute(
                "INSERT INTO items (id, vault_id, revision, key_version, envelope, deleted, dirty,
                                    updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(id) DO UPDATE SET
                    vault_id = excluded.vault_id,
                    revision = excluded.revision,
                    key_version = excluded.key_version,
                    envelope = excluded.envelope,
                    deleted = excluded.deleted,
                    dirty = excluded.dirty,
                    updated_at = excluded.updated_at",
                params![
                    &item.id[..],
                    &vault[..],
                    item.revision,
                    item.key_version,
                    item.envelope,
                    item.deleted,
                    item.local_pending,
                    self.now
                ],
            )?;
            if item.local_pending {
                // Queue if the row was somehow missing, then move the base.
                self.enqueue(item.id, vault, item.revision)?;
                self.rebase(item.id, item.revision)?;
            } else {
                self.dequeue(item.id)?;
            }
        }
        self.set_sync_cursor(vault, new_cursor)?;
        tracing::debug!(items = page.len(), new_cursor, "remote page applied");
        Ok(())
    }

    /// Records a successful push of `id` at server `revision`.
    ///
    /// If the outbox row is still the one that was pushed (`queued_at` equals
    /// `pushed_queued_at`), the item becomes clean and the row is removed. If
    /// the item was edited again meanwhile, it stays dirty and the row is
    /// rebased onto `revision`.
    ///
    /// # Errors
    /// [`StoreError::NotFound`], or a SQLite error.
    pub fn mark_pushed(&self, id: Id16, revision: i64, pushed_queued_at: i64) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE items SET revision = ?2 WHERE id = ?1",
            params![&id[..], revision],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        let queued: Option<i64> = self
            .conn
            .query_row(
                "SELECT queued_at FROM outbox WHERE item_id = ?1",
                params![&id[..]],
                |r| r.get(0),
            )
            .optional()?;
        match queued {
            Some(q) if q != pushed_queued_at => self.rebase(id, revision),
            _ => {
                self.conn
                    .execute("UPDATE items SET dirty = 0 WHERE id = ?1", params![&id[..]])?;
                self.dequeue(id)
            }
        }
    }

    /// Replaces only the envelope and key version of `id` (the same body
    /// re-sealed under a rotated vault key, T89). Leaves `revision`, `dirty`,
    /// the outbox row and `updated_at` alone.
    ///
    /// # Errors
    /// [`StoreError::InvalidEnvelope`], [`StoreError::NotFound`], or a SQLite
    /// error.
    pub fn reseal_item(&self, id: Id16, key_version: u32, envelope: &[u8]) -> Result<()> {
        check_envelope(envelope, key_version)?;
        let n = self.conn.execute(
            "UPDATE items SET key_version = ?2, envelope = ?3 WHERE id = ?1",
            params![&id[..], key_version, envelope],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Marks every item of `vault` as never synced (full resync after the
    /// server answered `410`, T88): `revision = 0`, dirty, queued with
    /// `base_revision = 0` (existing outbox rows are rebased to 0), and the
    /// vault's cursor back to 0. Returns the number of items.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] (unknown vault), or a SQLite error.
    pub fn reset_sync(&self, vault: Id16) -> Result<u64> {
        let v = &vault[..];
        let n = self.conn.execute(
            "UPDATE items SET revision = 0, dirty = 1 WHERE vault_id = ?1",
            params![v],
        )?;
        let queued = self.conn.execute(
            "INSERT INTO outbox (item_id, vault_id, base_revision, queued_at)
             SELECT id, vault_id, 0, ?2 FROM items WHERE vault_id = ?1
             ON CONFLICT(item_id) DO UPDATE SET
                base_revision = 0,
                queued_at = excluded.queued_at,
                vault_id = excluded.vault_id,
                attempts = 0",
            params![v, self.now],
        )?;
        if queued > 0 {
            self.enqueued.set(true);
        }
        self.set_sync_cursor(vault, 0)?;
        tracing::debug!(items = n, "vault sync reset");
        Ok(n as u64)
    }

    /// Removes an item with its outbox row, its device-local row and its local
    /// approvals from this device. This is not a tombstone; use
    /// [`WriteTx::put_item`] with `deleted` for that.
    ///
    /// # Errors
    /// [`StoreError::NotFound`], or a SQLite error.
    pub fn purge_item(&self, id: Id16) -> Result<()> {
        let b = &id[..];
        self.conn
            .execute("DELETE FROM outbox WHERE item_id = ?1", params![b])?;
        self.conn
            .execute("DELETE FROM device_local WHERE item_id = ?1", params![b])?;
        self.conn
            .execute("DELETE FROM local_approvals WHERE item_id = ?1", params![b])?;
        let n = self
            .conn
            .execute("DELETE FROM items WHERE id = ?1", params![b])?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
}

impl Store {
    /// See [`WriteTx::put_item`].
    ///
    /// # Errors
    /// As [`WriteTx::put_item`].
    pub async fn put_item(&self, item: PutItem<'_>) -> Result<()> {
        let PutItem {
            vault_id,
            id,
            key_version,
            envelope,
            deleted,
            mark_dirty,
        } = item;
        let envelope = envelope.to_vec();
        self.write(move |w| {
            w.put_item(PutItem {
                vault_id,
                id,
                key_version,
                envelope: &envelope,
                deleted,
                mark_dirty,
            })
        })
        .await
    }

    /// See [`ReadTx::get_item`].
    ///
    /// # Errors
    /// As [`ReadTx::get_item`].
    pub async fn get_item(&self, id: Id16) -> Result<Option<ItemRow>> {
        self.read(move |r| r.get_item(id)).await
    }

    /// See [`ReadTx::list_items`].
    ///
    /// # Errors
    /// As [`ReadTx::list_items`].
    pub async fn list_items(&self, vault: Id16) -> Result<Vec<ItemRow>> {
        self.read(move |r| r.list_items(vault)).await
    }

    /// See [`ReadTx::list_all_items`].
    ///
    /// # Errors
    /// As [`ReadTx::list_all_items`].
    pub async fn list_all_items(&self) -> Result<Vec<ItemRow>> {
        self.read(|r| r.list_all_items()).await
    }

    /// See [`ReadTx::list_dirty`].
    ///
    /// # Errors
    /// As [`ReadTx::list_dirty`].
    pub async fn list_dirty(&self, vault: Id16) -> Result<Vec<ItemRow>> {
        self.read(move |r| r.list_dirty(vault)).await
    }

    /// See [`ReadTx::item_count`].
    ///
    /// # Errors
    /// As [`ReadTx::item_count`].
    pub async fn item_count(&self) -> Result<u64> {
        self.read(|r| r.item_count()).await
    }

    /// See [`ReadTx::item_markers`].
    ///
    /// # Errors
    /// As [`ReadTx::item_markers`].
    pub async fn item_markers(&self) -> Result<Vec<ItemMarker>> {
        self.read(|r| r.item_markers()).await
    }

    /// See [`WriteTx::apply_remote`].
    ///
    /// # Errors
    /// As [`WriteTx::apply_remote`].
    pub async fn apply_remote(
        &self,
        vault: Id16,
        page: Vec<RemoteItem>,
        new_cursor: i64,
    ) -> Result<()> {
        self.write(move |w| w.apply_remote(vault, &page, new_cursor))
            .await
    }

    /// See [`WriteTx::mark_pushed`].
    ///
    /// # Errors
    /// As [`WriteTx::mark_pushed`].
    pub async fn mark_pushed(&self, id: Id16, revision: i64, pushed_queued_at: i64) -> Result<()> {
        self.write(move |w| w.mark_pushed(id, revision, pushed_queued_at))
            .await
    }

    /// See [`WriteTx::reseal_item`].
    ///
    /// # Errors
    /// As [`WriteTx::reseal_item`].
    pub async fn reseal_item(&self, id: Id16, key_version: u32, envelope: Vec<u8>) -> Result<()> {
        self.write(move |w| w.reseal_item(id, key_version, &envelope))
            .await
    }

    /// See [`WriteTx::reset_sync`].
    ///
    /// # Errors
    /// As [`WriteTx::reset_sync`].
    pub async fn reset_sync(&self, vault: Id16) -> Result<u64> {
        self.write(move |w| w.reset_sync(vault)).await
    }

    /// See [`WriteTx::purge_item`].
    ///
    /// # Errors
    /// As [`WriteTx::purge_item`].
    pub async fn purge_item(&self, id: Id16) -> Result<()> {
        self.write(move |w| w.purge_item(id)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v1(key_version: u32, len: usize) -> Vec<u8> {
        let mut e = vec![0u8; len];
        e[0] = FORMAT_V1;
        e[1..5].copy_from_slice(&key_version.to_be_bytes());
        e
    }

    #[test]
    fn check_envelope_rules() {
        // Too short (plaintext, an empty value, a header without a tag).
        for bad in [&b""[..], b"hello", &v1(1, MIN_LEN - 1)] {
            assert!(matches!(
                check_envelope(bad, 1),
                Err(StoreError::InvalidEnvelope("too short"))
            ));
        }
        // Key version mismatch.
        assert!(matches!(
            check_envelope(&v1(2, MIN_LEN), 1),
            Err(StoreError::InvalidEnvelope(_))
        ));
        // Too large.
        assert!(matches!(
            check_envelope(&v1(1, MAX_ENVELOPE_LEN + 1), 1),
            Err(StoreError::InvalidEnvelope("too large"))
        ));
        // Valid sizes.
        assert!(check_envelope(&v1(1, MIN_LEN), 1).is_ok());
        assert!(check_envelope(&v1(7, MAX_ENVELOPE_LEN), 7).is_ok());
        // An unknown format byte from a newer build is accepted as-is.
        let mut future = v1(1, MIN_LEN);
        future[0] = 0x02;
        assert!(check_envelope(&future, 99).is_ok());
        future[0] = 0x1F;
        assert!(check_envelope(&future, 99).is_ok());
        // Bytes no envelope starts with: zero, text, JSON, a CBOR map.
        for first in [0x00, b' ', b'{', b'C', 0xA5, 0xFF] {
            future[0] = first;
            assert!(matches!(
                check_envelope(&future, 1),
                Err(StoreError::InvalidEnvelope("unknown format byte"))
            ));
        }
    }
}
