//! The `device_local` table: per-item data that never leaves this device —
//! last connection time, frecency and a site's default local directory
//! override (local paths differ per machine).
//!
//! # Frecency
//!
//! An exponentially decaying connect count with a **14-day half-life** (as in
//! sverb). On each connect at time `t`:
//!
//! ```text
//! frecency = frecency_prev * 0.5^(Δdays / 14) + 1      Δdays = (t - last_connected_at) / 1 day
//! ```
//!
//! (`Δdays` is clamped at 0 if the clock went backwards.) To rank items at time
//! `now`, decay the stored value to `now` with [`DeviceLocal::score_at`]; that
//! makes rankings comparable between items last used at different times.

use std::collections::HashMap;

use async_trait::async_trait;
use courier_ftp_core::model::LocalPath;
use courier_ftp_core::model::item::{ItemId, UnixMillis};
use courier_ftp_core::sites::{SiteError, SiteLocal, SiteLocalStore};
use rusqlite::{OptionalExtension, params};

use crate::db::{ReadTx, Store, WriteTx};
use crate::error::{Result, StoreError};
use crate::vaults::id16;

/// Frecency half-life, in days.
pub const FRECENCY_HALF_LIFE_DAYS: f64 = 14.0;

const DAY_MS: f64 = 86_400_000.0;

/// `value` (last bumped at `then`) decayed to `now`.
pub fn decay(value: f64, then: i64, now: i64) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    let days = (now.saturating_sub(then)).max(0) as f64 / DAY_MS;
    value * 0.5_f64.powf(days / FRECENCY_HALF_LIFE_DAYS)
}

/// The frecency after a connect at `now`, given the previous value and time.
pub fn bump_frecency(prev: Option<(f64, i64)>, now: i64) -> f64 {
    prev.map_or(0.0, |(value, then)| decay(value, then, now)) + 1.0
}

/// One row of `device_local`.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceLocal {
    /// The item.
    pub item_id: ItemId,
    /// Last successful connect, UNIX ms.
    pub last_connected_at: Option<i64>,
    /// Stored frecency (as of `last_connected_at`).
    pub frecency: f64,
    /// The site's default local directory on this device.
    pub local_dir_override: Option<String>,
    /// The site's SSH key file on this device (T31).
    pub key_path_override: Option<String>,
}

impl DeviceLocal {
    /// The frecency decayed to `now`, for ranking.
    pub fn score_at(&self, now: i64) -> f64 {
        match self.last_connected_at {
            Some(then) => decay(self.frecency, then, now),
            None => self.frecency,
        }
    }
}

type RawLocal = (
    Vec<u8>,
    Option<i64>,
    Option<f64>,
    Option<String>,
    Option<String>,
);

fn decode(raw: RawLocal) -> Result<DeviceLocal> {
    let (id, last_connected_at, frecency, local_dir_override, key_path_override) = raw;
    Ok(DeviceLocal {
        item_id: ItemId::from_bytes(id16(id, "device_local.item_id")?),
        last_connected_at,
        frecency: frecency.unwrap_or(0.0),
        local_dir_override,
        key_path_override,
    })
}

fn raw_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawLocal> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
}

const COLS: &str = "item_id, last_connected_at, frecency, local_dir_override, key_path_override";

impl ReadTx<'_> {
    /// The device-local row of an item.
    pub fn get_device_local(&self, item: ItemId) -> Result<Option<DeviceLocal>> {
        let raw = self
            .conn
            .prepare_cached(&format!(
                "SELECT {COLS} FROM device_local WHERE item_id = ?1"
            ))?
            .query_row(params![item.as_bytes()], raw_row)
            .optional()?;
        raw.map(decode).transpose()
    }

    /// All device-local rows.
    pub fn list_device_local(&self) -> Result<Vec<DeviceLocal>> {
        let mut stmt = self
            .conn
            .prepare_cached(&format!("SELECT {COLS} FROM device_local ORDER BY item_id"))?;
        let raws = stmt
            .query_map([], raw_row)?
            .collect::<rusqlite::Result<Vec<RawLocal>>>()?;
        raws.into_iter().map(decode).collect()
    }
}

impl WriteTx<'_> {
    /// Records a connect at `at`: sets `last_connected_at` and bumps the
    /// frecency (see the module docs). Returns the new frecency.
    pub fn touch_connected(&self, item: ItemId, at: i64) -> Result<f64> {
        let prev = self.as_read().get_device_local(item)?;
        let frecency = bump_frecency(
            prev.as_ref()
                .and_then(|p| p.last_connected_at.map(|t| (p.frecency, t))),
            at,
        );
        self.conn.execute(
            "INSERT INTO device_local (item_id, last_connected_at, frecency) VALUES (?1, ?2, ?3)
             ON CONFLICT(item_id) DO UPDATE SET
                last_connected_at = excluded.last_connected_at,
                frecency = excluded.frecency",
            params![item.as_bytes(), at, frecency],
        )?;
        Ok(frecency)
    }

    /// Sets (or clears) the item's local directory override.
    pub fn set_local_dir_override(&self, item: ItemId, dir: Option<&str>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO device_local (item_id, local_dir_override) VALUES (?1, ?2)
             ON CONFLICT(item_id) DO UPDATE SET local_dir_override = excluded.local_dir_override",
            params![item.as_bytes(), dir],
        )?;
        Ok(())
    }

    /// Sets (or clears) the site's local SSH key file path.
    pub fn set_key_path_override(&self, item: ItemId, path: Option<&str>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO device_local (item_id, key_path_override) VALUES (?1, ?2)
             ON CONFLICT(item_id) DO UPDATE SET key_path_override = excluded.key_path_override",
            params![item.as_bytes(), path],
        )?;
        Ok(())
    }

    /// Deletes the device-local row of `item` (a deleted site).
    pub fn delete_device_local(&self, item: ItemId) -> Result<()> {
        self.conn.execute(
            "DELETE FROM device_local WHERE item_id = ?1",
            params![item.as_bytes()],
        )?;
        Ok(())
    }

    /// Moves the device-local row of `from` to `to` (an item re-created under a
    /// new id, e.g. imported into the account vault at login), replacing any row
    /// of `to`. A no-op when `from` has no row.
    pub fn move_device_local(&self, from: ItemId, to: ItemId) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO device_local
                (item_id, last_connected_at, frecency, local_dir_override, key_path_override)
             SELECT ?2, last_connected_at, frecency, local_dir_override, key_path_override
             FROM device_local WHERE item_id = ?1",
            params![from.as_bytes(), to.as_bytes()],
        )?;
        self.conn.execute(
            "DELETE FROM device_local WHERE item_id = ?1",
            params![from.as_bytes()],
        )?;
        Ok(())
    }
}

/// Async access to `device_local` ([`Store::device_local`]).
#[derive(Debug, Clone, Copy)]
pub struct DeviceLocalRepo<'s> {
    store: &'s Store,
}

impl Store {
    /// The `device_local` repository.
    pub fn device_local(&self) -> DeviceLocalRepo<'_> {
        DeviceLocalRepo { store: self }
    }
}

impl DeviceLocalRepo<'_> {
    /// See [`WriteTx::touch_connected`].
    pub async fn touch_connected(&self, item: ItemId, at: i64) -> Result<f64> {
        self.store.write(move |w| w.touch_connected(item, at)).await
    }

    /// See [`ReadTx::get_device_local`].
    pub async fn get(&self, item: ItemId) -> Result<Option<DeviceLocal>> {
        self.store.read(move |r| r.get_device_local(item)).await
    }

    /// See [`ReadTx::list_device_local`].
    pub async fn list(&self) -> Result<Vec<DeviceLocal>> {
        self.store.read(|r| r.list_device_local()).await
    }

    /// See [`WriteTx::set_local_dir_override`].
    pub async fn set_local_dir_override(&self, item: ItemId, dir: Option<String>) -> Result<()> {
        self.store
            .write(move |w| w.set_local_dir_override(item, dir.as_deref()))
            .await
    }

    /// See [`WriteTx::set_key_path_override`].
    pub async fn set_key_path_override(&self, item: ItemId, path: Option<String>) -> Result<()> {
        self.store
            .write(move |w| w.set_key_path_override(item, path.as_deref()))
            .await
    }

    /// See [`WriteTx::delete_device_local`].
    pub async fn delete(&self, item: ItemId) -> Result<()> {
        self.store.write(move |w| w.delete_device_local(item)).await
    }
}

// ------------------------------------------------------------------ sites (T31)

fn site_local(row: &DeviceLocal) -> SiteLocal {
    SiteLocal {
        default_local_dir: row.local_dir_override.as_deref().map(LocalPath::new),
        key_path: row.key_path_override.as_deref().map(LocalPath::new),
        last_connected_at: row.last_connected_at.map(UnixMillis),
    }
}

fn site_err(e: StoreError) -> SiteError {
    SiteError::Local(e.to_string())
}

fn path_text(path: Option<&LocalPath>) -> Option<String> {
    path.map(|p| p.as_path().to_string_lossy().into_owned())
}

/// The Site Manager's device-local data (`courier_ftp_core::sites`).
#[async_trait]
impl SiteLocalStore for Store {
    async fn all(&self) -> std::result::Result<HashMap<ItemId, SiteLocal>, SiteError> {
        let rows = self.device_local().list().await.map_err(site_err)?;
        Ok(rows.iter().map(|r| (r.item_id, site_local(r))).collect())
    }

    async fn get(&self, id: ItemId) -> std::result::Result<SiteLocal, SiteError> {
        let row = self.device_local().get(id).await.map_err(site_err)?;
        Ok(row.as_ref().map(site_local).unwrap_or_default())
    }

    async fn set_paths(
        &self,
        id: ItemId,
        default_local_dir: Option<&LocalPath>,
        key_path: Option<&LocalPath>,
    ) -> std::result::Result<(), SiteError> {
        let dir = path_text(default_local_dir);
        let key = path_text(key_path);
        self.write(move |w| {
            w.set_local_dir_override(id, dir.as_deref())?;
            w.set_key_path_override(id, key.as_deref())
        })
        .await
        .map_err(site_err)
    }

    async fn touch_connected(
        &self,
        id: ItemId,
        at: UnixMillis,
    ) -> std::result::Result<(), SiteError> {
        self.device_local()
            .touch_connected(id, at.0)
            .await
            .map(|_| ())
            .map_err(site_err)
    }

    async fn forget(&self, id: ItemId) -> std::result::Result<(), SiteError> {
        self.device_local().delete(id).await.map_err(site_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400_000;

    // Two connects 14 days apart → 0.5·1 + 1 = 1.5; recent use ranks higher.
    #[test]
    fn t10_frecency_half_life() {
        let first = bump_frecency(None, 0);
        assert!((first - 1.0).abs() < 1e-12);
        let second = bump_frecency(Some((first, 0)), 14 * DAY);
        assert!((second - 1.5).abs() < 1e-12, "{second}");

        // A: used 3 times long ago. B: used once yesterday. At day 100 B ranks higher.
        let mut a = None;
        for t in [0, DAY, 2 * DAY] {
            let f = bump_frecency(a, t);
            a = Some((f, t));
        }
        let b = (bump_frecency(None, 99 * DAY), 99 * DAY);
        let (fa, ta) = a.unwrap_or_default();
        let now = 100 * DAY;
        assert!(decay(b.0, b.1, now) > decay(fa, ta, now));
        // …but at day 3, A's three recent connects beat a single one.
        let c = (bump_frecency(None, 3 * DAY), 3 * DAY);
        assert!(decay(fa, ta, 3 * DAY) > decay(c.0, c.1, 3 * DAY));

        // Clock going backwards does not inflate the score.
        assert!((decay(2.0, 10 * DAY, 5 * DAY) - 2.0).abs() < 1e-12);
    }
}
