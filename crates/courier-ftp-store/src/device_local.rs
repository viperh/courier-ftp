//! The `device_local` table: per-item data that never leaves this device -
//! last connection time, frecency, the local directory override and the
//! site-tree expansion state.
//!
//! Rows are keyed by item id but are never synced, never in an envelope and
//! never touch the outbox. A row may precede its item (no foreign key);
//! [`WriteTx::purge_item`] and [`WriteTx::delete_vault`] delete the rows of
//! the items they remove, and [`ReadTx::list_device_local`] ignores rows whose
//! item does not exist.
//!
//! # Frecency
//!
//! An exponentially decaying connect count with a **14-day half-life** (sverb).
//! On each connect at time `t`:
//!
//! ```text
//! frecency = frecency_prev * 0.5^(Δdays / 14) + 1      Δdays = (t - last_connected_at) / 1 day
//! ```
//!
//! (`Δdays` is clamped at 0 if the clock went backwards.) To rank items at time
//! `now`, decay the stored value to `now` with [`DeviceLocal::score_at`].

use rusqlite::{OptionalExtension, params};

use crate::Id16;
use crate::db::{ReadTx, Store, WriteTx};
use crate::error::{Result, id16};

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
    pub item_id: Id16,
    /// Last successful connect, Unix ms.
    pub last_connected_at: Option<i64>,
    /// Stored frecency (as of `last_connected_at`).
    pub frecency: f64,
    /// Per-site local directory override (this machine's path).
    pub local_dir_override: Option<String>,
    /// Whether the site-tree node is expanded (`None`: default).
    pub tree_expanded: Option<bool>,
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
    Option<bool>,
);

fn raw(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawLocal> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
}

fn decode(raw: RawLocal) -> Result<DeviceLocal> {
    let (id, last_connected_at, frecency, local_dir_override, tree_expanded) = raw;
    Ok(DeviceLocal {
        item_id: id16(id, "device_local.item_id")?,
        last_connected_at,
        frecency: frecency.filter(|f| f.is_finite()).unwrap_or(0.0),
        local_dir_override,
        tree_expanded,
    })
}

const COLS: &str = "item_id, last_connected_at, frecency, local_dir_override, tree_expanded";

impl ReadTx<'_> {
    /// The device-local row of an item (also before the item exists).
    ///
    /// # Errors
    /// [`crate::StoreError::Corrupt`] for an undecodable row, or a SQLite error.
    pub fn get_device_local(&self, item: Id16) -> Result<Option<DeviceLocal>> {
        let raw = self
            .conn
            .prepare_cached(&format!(
                "SELECT {COLS} FROM device_local WHERE item_id = ?1"
            ))?
            .query_row(params![&item[..]], raw)
            .optional()?;
        raw.map(decode).transpose()
    }

    /// The device-local rows of existing items, in item id order.
    ///
    /// # Errors
    /// As [`ReadTx::get_device_local`].
    pub fn list_device_local(&self) -> Result<Vec<DeviceLocal>> {
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT {COLS} FROM device_local
             WHERE item_id IN (SELECT id FROM items) ORDER BY item_id"
        ))?;
        let raws = stmt
            .query_map([], raw)?
            .collect::<rusqlite::Result<Vec<RawLocal>>>()?;
        raws.into_iter().map(decode).collect()
    }
}

impl WriteTx<'_> {
    /// Records a connect at `at`: sets `last_connected_at` and bumps the
    /// frecency (see the module docs). Returns the new frecency.
    ///
    /// # Errors
    /// A SQLite error.
    pub fn touch_connected(&self, item: Id16, at: i64) -> Result<f64> {
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
            params![&item[..], at, frecency],
        )?;
        Ok(frecency)
    }

    /// Sets (or clears) the item's local directory override.
    ///
    /// # Errors
    /// A SQLite error.
    pub fn set_local_dir_override(&self, item: Id16, dir: Option<&str>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO device_local (item_id, local_dir_override) VALUES (?1, ?2)
             ON CONFLICT(item_id) DO UPDATE SET local_dir_override = excluded.local_dir_override",
            params![&item[..], dir],
        )?;
        Ok(())
    }

    /// Sets (or clears) the item's site-tree expansion state.
    ///
    /// # Errors
    /// A SQLite error.
    pub fn set_tree_expanded(&self, item: Id16, expanded: Option<bool>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO device_local (item_id, tree_expanded) VALUES (?1, ?2)
             ON CONFLICT(item_id) DO UPDATE SET tree_expanded = excluded.tree_expanded",
            params![&item[..], expanded],
        )?;
        Ok(())
    }

    /// Moves the device-local row of `from` to `to` (an item re-created under
    /// a new id), replacing any row of `to`. A no-op when `from` has no row.
    ///
    /// # Errors
    /// A SQLite error.
    pub fn move_device_local(&self, from: Id16, to: Id16) -> Result<()> {
        self.conn.execute(
            &format!(
                "INSERT OR REPLACE INTO device_local ({COLS})
                 SELECT ?2, last_connected_at, frecency, local_dir_override, tree_expanded
                 FROM device_local WHERE item_id = ?1"
            ),
            params![&from[..], &to[..]],
        )?;
        if from != to {
            self.delete_device_local(from)?;
        }
        Ok(())
    }

    /// Deletes the device-local row of `item` (a no-op if absent).
    ///
    /// # Errors
    /// A SQLite error.
    pub fn delete_device_local(&self, item: Id16) -> Result<()> {
        self.conn.execute(
            "DELETE FROM device_local WHERE item_id = ?1",
            params![&item[..]],
        )?;
        Ok(())
    }
}

impl Store {
    /// See [`ReadTx::get_device_local`].
    ///
    /// # Errors
    /// As [`ReadTx::get_device_local`].
    pub async fn get_device_local(&self, item: Id16) -> Result<Option<DeviceLocal>> {
        self.read(move |r| r.get_device_local(item)).await
    }

    /// See [`ReadTx::list_device_local`].
    ///
    /// # Errors
    /// As [`ReadTx::list_device_local`].
    pub async fn list_device_local(&self) -> Result<Vec<DeviceLocal>> {
        self.read(|r| r.list_device_local()).await
    }

    /// See [`WriteTx::touch_connected`].
    ///
    /// # Errors
    /// As [`WriteTx::touch_connected`].
    pub async fn touch_connected(&self, item: Id16, at: i64) -> Result<f64> {
        self.write(move |w| w.touch_connected(item, at)).await
    }

    /// See [`WriteTx::set_local_dir_override`].
    ///
    /// # Errors
    /// As [`WriteTx::set_local_dir_override`].
    pub async fn set_local_dir_override(&self, item: Id16, dir: Option<String>) -> Result<()> {
        self.write(move |w| w.set_local_dir_override(item, dir.as_deref()))
            .await
    }

    /// See [`WriteTx::set_tree_expanded`].
    ///
    /// # Errors
    /// As [`WriteTx::set_tree_expanded`].
    pub async fn set_tree_expanded(&self, item: Id16, expanded: Option<bool>) -> Result<()> {
        self.write(move |w| w.set_tree_expanded(item, expanded))
            .await
    }

    /// See [`WriteTx::move_device_local`].
    ///
    /// # Errors
    /// As [`WriteTx::move_device_local`].
    pub async fn move_device_local(&self, from: Id16, to: Id16) -> Result<()> {
        self.write(move |w| w.move_device_local(from, to)).await
    }

    /// See [`WriteTx::delete_device_local`].
    ///
    /// # Errors
    /// As [`WriteTx::delete_device_local`].
    pub async fn delete_device_local(&self, item: Id16) -> Result<()> {
        self.write(move |w| w.delete_device_local(item)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400_000;

    #[test]
    fn decay_halves_after_14_days() {
        assert!((decay(2.0, 0, 14 * DAY) - 1.0).abs() < 1e-12);
        assert!((decay(4.0, DAY, 29 * DAY) - 1.0).abs() < 1e-12);
        // Two connects 14 days apart: 0.5 * 1 + 1.
        let second = bump_frecency(Some((1.0, 0)), 14 * DAY);
        assert!((second - 1.5).abs() < 1e-12, "{second}");
    }

    #[test]
    fn bump_adds_one() {
        assert!((bump_frecency(None, 0) - 1.0).abs() < 1e-12);
        assert!((bump_frecency(Some((3.0, 5)), 5) - 4.0).abs() < 1e-12);
        // Recent use ranks higher than old use.
        let mut a = None;
        for t in [0, DAY, 2 * DAY] {
            a = Some((bump_frecency(a, t), t));
        }
        let (fa, ta) = a.unwrap_or_default();
        let b = (bump_frecency(None, 99 * DAY), 99 * DAY);
        assert!(decay(b.0, b.1, 100 * DAY) > decay(fa, ta, 100 * DAY));
    }

    #[test]
    fn clock_backwards_clamped() {
        assert!((decay(2.0, 10 * DAY, 5 * DAY) - 2.0).abs() < 1e-12);
        assert!((bump_frecency(Some((2.0, 10 * DAY)), 5 * DAY) - 3.0).abs() < 1e-12);
        let row = DeviceLocal {
            item_id: [0; 16],
            last_connected_at: Some(10 * DAY),
            frecency: 2.0,
            local_dir_override: None,
            tree_expanded: None,
        };
        assert!((row.score_at(0) - 2.0).abs() < 1e-12);
    }
}
