//! Versioned schema migrations (`PRAGMA user_version`, `rusqlite_migration`).
//!
//! The SQL lives in `crates/courier-ftp-store/migrations/` (inside the crate so
//! `cargo package` works). Migrations only ever append: never edit a released one.

use rusqlite_migration::{M, Migrations};

/// The migrations this build knows, in order.
pub const MIGRATIONS: &[&str] = &[
    include_str!("../migrations/0001_init.sql"),
    include_str!("../migrations/0002_device_local_key_path.sql"),
];

/// The latest schema version (`PRAGMA user_version`) this build knows.
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
    "pinned_keys",
    "local_approvals",
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
