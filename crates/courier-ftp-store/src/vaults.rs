//! The `vaults` table: vault keys wrapped under the LMK and per-vault sync
//! cursors.

use rusqlite::{OptionalExtension, Row, params};

use crate::Id16;
use crate::db::{ReadTx, Store, WriteTx};
use crate::error::{Result, StoreError, id16, u32_col};

/// The shortest value accepted as a wrapped key (a T80 wrapped key is 72
/// bytes; a bare 32-byte key is refused).
pub const MIN_WRAPPED_LEN: usize = 40;

/// Vault kind, stored as an integer (`0` personal, `1` shared).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum VaultKind {
    /// The user's own vault.
    Personal = 0,
    /// A team vault shared through an org (T89).
    Shared = 1,
}

impl VaultKind {
    /// The stored integer.
    pub const fn as_i64(self) -> i64 {
        self as i64
    }

    /// Parses the stored integer.
    pub const fn from_i64(v: i64) -> Option<Self> {
        match v {
            0 => Some(Self::Personal),
            1 => Some(Self::Shared),
            _ => None,
        }
    }
}

/// One row of `vaults`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRow {
    /// Vault id.
    pub id: Id16,
    /// Personal or shared.
    pub kind: VaultKind,
    /// Owning org for shared vaults.
    pub org_id: Option<Id16>,
    /// Version of the vault key `wrapped_key` holds.
    pub key_version: u32,
    /// The vault key, wrapped under the LMK. Never plaintext.
    pub wrapped_key: Vec<u8>,
    /// Highest server revision applied locally.
    pub sync_cursor: i64,
}

/// Refuses a "wrapped" key that is too short to be one.
pub(crate) fn check_wrapped(bytes: &[u8]) -> Result<()> {
    if bytes.len() < MIN_WRAPPED_LEN {
        return Err(StoreError::InvalidEnvelope("too short to be a wrapped key"));
    }
    Ok(())
}

type RawVault = (Vec<u8>, i64, Option<Vec<u8>>, i64, Vec<u8>, i64);

fn raw_vault(row: &Row<'_>) -> rusqlite::Result<RawVault> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

fn decode_vault(raw: RawVault) -> Result<VaultRow> {
    let (id, kind, org, key_version, wrapped_key, sync_cursor) = raw;
    Ok(VaultRow {
        id: id16(id, "vaults.id")?,
        kind: VaultKind::from_i64(kind)
            .ok_or_else(|| StoreError::Corrupt("unknown vaults.kind".into()))?,
        org_id: org.map(|o| id16(o, "vaults.org_id")).transpose()?,
        key_version: u32_col(key_version, "vaults.key_version")?,
        wrapped_key,
        sync_cursor,
    })
}

const VAULT_COLS: &str = "id, kind, org_id, key_version, wrapped_key, sync_cursor";

impl ReadTx<'_> {
    /// All vaults, in id order.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an undecodable row, or a SQLite error.
    pub fn list_vaults(&self) -> Result<Vec<VaultRow>> {
        let mut stmt = self
            .conn
            .prepare_cached(&format!("SELECT {VAULT_COLS} FROM vaults ORDER BY id"))?;
        let raws = stmt
            .query_map([], raw_vault)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        raws.into_iter().map(decode_vault).collect()
    }

    /// One vault.
    ///
    /// # Errors
    /// As [`ReadTx::list_vaults`].
    pub fn get_vault(&self, id: Id16) -> Result<Option<VaultRow>> {
        let raw = self
            .conn
            .prepare_cached(&format!("SELECT {VAULT_COLS} FROM vaults WHERE id = ?1"))?
            .query_row(params![&id[..]], raw_vault)
            .optional()?;
        raw.map(decode_vault).transpose()
    }
}

impl WriteTx<'_> {
    /// Inserts a vault. `wrapped_key` must already be wrapped.
    ///
    /// # Errors
    /// [`StoreError::InvalidEnvelope`] for a too-short wrapped key, or a SQLite
    /// error (e.g. the vault exists).
    pub fn create_vault(
        &self,
        id: Id16,
        kind: VaultKind,
        org_id: Option<Id16>,
        key_version: u32,
        wrapped_key: &[u8],
    ) -> Result<()> {
        check_wrapped(wrapped_key)?;
        self.conn.execute(
            "INSERT INTO vaults (id, kind, org_id, key_version, wrapped_key)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &id[..],
                kind.as_i64(),
                org_id.as_ref().map(|o| &o[..]),
                key_version,
                wrapped_key
            ],
        )?;
        tracing::debug!(kind = ?kind, key_version, "vault created");
        Ok(())
    }

    /// Replaces the wrapped vault key (rewrap or rotation).
    ///
    /// # Errors
    /// [`StoreError::NotFound`], [`StoreError::InvalidEnvelope`], or a SQLite
    /// error.
    pub fn update_wrapped_key(&self, id: Id16, key_version: u32, wrapped_key: &[u8]) -> Result<()> {
        check_wrapped(wrapped_key)?;
        let n = self.conn.execute(
            "UPDATE vaults SET key_version = ?2, wrapped_key = ?3 WHERE id = ?1",
            params![&id[..], key_version, wrapped_key],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Sets the vault's sync cursor.
    ///
    /// # Errors
    /// [`StoreError::NotFound`], or a SQLite error.
    pub fn set_sync_cursor(&self, id: Id16, cursor: i64) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE vaults SET sync_cursor = ?2 WHERE id = ?1",
            params![&id[..], cursor],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Deletes the vault with its items, their outbox rows, their
    /// device-local rows and their local approvals (all inside this
    /// transaction).
    ///
    /// # Errors
    /// [`StoreError::NotFound`], or a SQLite error.
    pub fn delete_vault(&self, id: Id16) -> Result<()> {
        let v = &id[..];
        self.conn.execute(
            "DELETE FROM device_local WHERE item_id IN (SELECT id FROM items WHERE vault_id = ?1)",
            params![v],
        )?;
        self.conn.execute(
            "DELETE FROM local_approvals
             WHERE item_id IN (SELECT id FROM items WHERE vault_id = ?1)",
            params![v],
        )?;
        self.conn
            .execute("DELETE FROM outbox WHERE vault_id = ?1", params![v])?;
        self.conn
            .execute("DELETE FROM items WHERE vault_id = ?1", params![v])?;
        let n = self
            .conn
            .execute("DELETE FROM vaults WHERE id = ?1", params![v])?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
}

impl Store {
    /// See [`WriteTx::create_vault`].
    ///
    /// # Errors
    /// As [`WriteTx::create_vault`].
    pub async fn create_vault(
        &self,
        id: Id16,
        kind: VaultKind,
        org_id: Option<Id16>,
        key_version: u32,
        wrapped_key: Vec<u8>,
    ) -> Result<()> {
        self.write(move |w| w.create_vault(id, kind, org_id, key_version, &wrapped_key))
            .await
    }

    /// See [`ReadTx::list_vaults`].
    ///
    /// # Errors
    /// As [`ReadTx::list_vaults`].
    pub async fn list_vaults(&self) -> Result<Vec<VaultRow>> {
        self.read(|r| r.list_vaults()).await
    }

    /// See [`ReadTx::get_vault`].
    ///
    /// # Errors
    /// As [`ReadTx::get_vault`].
    pub async fn get_vault(&self, id: Id16) -> Result<Option<VaultRow>> {
        self.read(move |r| r.get_vault(id)).await
    }

    /// See [`WriteTx::update_wrapped_key`].
    ///
    /// # Errors
    /// As [`WriteTx::update_wrapped_key`].
    pub async fn update_wrapped_key(
        &self,
        id: Id16,
        key_version: u32,
        wrapped_key: Vec<u8>,
    ) -> Result<()> {
        self.write(move |w| w.update_wrapped_key(id, key_version, &wrapped_key))
            .await
    }

    /// See [`WriteTx::set_sync_cursor`].
    ///
    /// # Errors
    /// As [`WriteTx::set_sync_cursor`].
    pub async fn set_sync_cursor(&self, id: Id16, cursor: i64) -> Result<()> {
        self.write(move |w| w.set_sync_cursor(id, cursor)).await
    }

    /// See [`WriteTx::delete_vault`].
    ///
    /// # Errors
    /// As [`WriteTx::delete_vault`].
    pub async fn delete_vault(&self, id: Id16) -> Result<()> {
        self.write(move |w| w.delete_vault(id)).await
    }
}
