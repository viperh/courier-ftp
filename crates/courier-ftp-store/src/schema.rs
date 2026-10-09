//! Versioned schema migrations.
//!
//! The SQL lives in `crates/courier-ftp-store/migrations/` and is embedded with
//! `include_str!`. Migrations are append-only: a released file is never edited.

use rusqlite_migration::{M, Migrations};

/// The migrations this build knows, in order.
pub const MIGRATIONS: &[&str] = &[include_str!("../migrations/0001_init.sql")];

/// The latest schema version (`PRAGMA user_version`) this build knows: the
/// number of migrations.
// The list has a handful of entries; the cast cannot truncate.
#[allow(clippy::cast_possible_wrap)]
pub const SCHEMA_VERSION: i64 = MIGRATIONS.len() as i64;

/// The persistent tables created by the migrations. No table in this list ever
/// holds decrypted data.
pub const TABLES: &[&str] = &[
    "meta",
    "vaults",
    "items",
    "outbox",
    "device_local",
    "device_blobs",
    "sync_state",
    "local_approvals",
    "pinned_keys",
];

/// Builds the migration set, plus `extra` steps (tests only).
pub(crate) fn migrations(extra: &[&'static str]) -> Migrations<'static> {
    Migrations::new(
        MIGRATIONS
            .iter()
            .chain(extra.iter())
            .copied()
            .map(M::up)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn tables_constant_matches_sqlite_master() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        migrations(&[]).to_latest(&mut conn).unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table' \
                 AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .unwrap();
        let found: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        let mut expected: Vec<String> = TABLES.iter().map(|s| (*s).to_owned()).collect();
        expected.sort();
        assert_eq!(found, expected);
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(SCHEMA_VERSION, 1);
    }
}
