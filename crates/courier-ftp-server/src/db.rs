//! PostgreSQL pool and the embedded migration runner.
//!
//! Queries are runtime-checked (`sqlx_core::query*`), so building never needs a
//! database. Migrations live in `crates/courier-ftp-server/migrations/` and are
//! embedded with `include_str!`; add new files to [`MIGRATIONS`] in order and never
//! edit a released one.
//!
//! Bookkeeping table: `schema_migrations(version, name, checksum, applied_at)` with
//! the SHA-256 of each file. [`migrate`] holds `pg_advisory_lock(0x434F55524945)`
//! while it applies each missing migration in its own transaction, so replicas
//! starting together migrate once. `serve` without `--migrate` refuses to start
//! while migrations are pending ([`migration_status`]); a recorded version this
//! binary does not know, or a checksum mismatch, always refuses.

use std::collections::BTreeMap;
use std::time::Duration;

use sha2::{Digest, Sha256};
use sqlx_core::connection::Connection as _;
use sqlx_core::executor::Executor as _;
use sqlx_core::query::query;
use sqlx_core::query_as::query_as;
use sqlx_core::query_scalar::query_scalar;
use sqlx_postgres::{PgConnection, PgPool, PgPoolOptions};

/// Embedded migrations: `(version, name, sql)`.
pub const MIGRATIONS: &[(i64, &str, &str)] =
    &[(1, "init", include_str!("../migrations/0001_init.sql"))];

/// Key of the advisory lock held while migrating (`"COURIE"` in ASCII).
pub const ADVISORY_LOCK_KEY: i64 = 0x434F_5552_4945;

/// Pool size.
pub const MAX_CONNECTIONS: u32 = 16;
/// How long a request waits for a pooled connection before `503`.
pub const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

const CREATE_BOOKKEEPING: &str = "CREATE TABLE IF NOT EXISTS schema_migrations (\
     version BIGINT PRIMARY KEY, name TEXT NOT NULL, checksum BYTEA NOT NULL, \
     applied_at TIMESTAMPTZ NOT NULL)";

/// The SHA-256 of a migration's SQL.
#[must_use]
pub fn checksum(sql: &str) -> Vec<u8> {
    Sha256::digest(sql.as_bytes()).to_vec()
}

fn pool_options() -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .acquire_timeout(ACQUIRE_TIMEOUT)
}

/// Connects to PostgreSQL (fails fast when the database is unreachable).
///
/// # Errors
/// Connection or URL errors.
pub async fn connect(url: &str) -> Result<PgPool, sqlx_core::Error> {
    pool_options().connect(url).await
}

/// A pool that connects on first use.
///
/// # Errors
/// Malformed URLs.
pub fn connect_lazy(url: &str) -> Result<PgPool, sqlx_core::Error> {
    pool_options().connect_lazy(url)
}

/// How the database schema compares with [`MIGRATIONS`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationStatus {
    /// Every embedded migration is applied.
    Current,
    /// These versions still have to be applied.
    Pending(Vec<i64>),
    /// The database has a migration this binary does not know.
    SchemaTooNew(i64),
    /// An applied migration's file changed afterwards.
    Modified(i64),
}

/// Migration failures.
#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    /// Database failure.
    #[error("database error: {0}")]
    Db(#[from] sqlx_core::Error),
    /// The database has a migration this binary does not know.
    #[error("database schema is newer than this binary (it has migration {0})")]
    SchemaTooNew(i64),
    /// An applied migration's file changed afterwards.
    #[error("migration {0} was modified after it was applied")]
    Modified(i64),
}

async fn status_on(conn: &mut PgConnection) -> Result<MigrationStatus, sqlx_core::Error> {
    let has_table: bool =
        query_scalar("SELECT to_regclass('public.schema_migrations') IS NOT NULL")
            .fetch_one(&mut *conn)
            .await?;
    let known: BTreeMap<i64, Vec<u8>> = MIGRATIONS
        .iter()
        .map(|&(v, _, sql)| (v, checksum(sql)))
        .collect();
    if !has_table {
        return Ok(MigrationStatus::Pending(known.keys().copied().collect()));
    }
    let applied: Vec<(i64, Vec<u8>)> =
        query_as("SELECT version, checksum FROM schema_migrations ORDER BY version")
            .fetch_all(&mut *conn)
            .await?;
    for (version, sum) in &applied {
        match known.get(version) {
            None => return Ok(MigrationStatus::SchemaTooNew(*version)),
            Some(expected) if expected != sum => return Ok(MigrationStatus::Modified(*version)),
            Some(_) => {}
        }
    }
    let pending: Vec<i64> = known
        .keys()
        .copied()
        .filter(|v| !applied.iter().any(|(a, _)| a == v))
        .collect();
    Ok(if pending.is_empty() {
        MigrationStatus::Current
    } else {
        MigrationStatus::Pending(pending)
    })
}

/// Compares `schema_migrations` with [`MIGRATIONS`] without modifying anything.
///
/// # Errors
/// Database errors.
pub async fn migration_status(pool: &PgPool) -> Result<MigrationStatus, sqlx_core::Error> {
    let mut conn = pool.acquire().await?;
    status_on(&mut conn).await
}

async fn apply_pending(conn: &mut PgConnection) -> Result<Vec<i64>, MigrationError> {
    conn.execute(CREATE_BOOKKEEPING).await?;
    let pending = match status_on(conn).await? {
        MigrationStatus::Current => return Ok(Vec::new()),
        MigrationStatus::Pending(v) => v,
        MigrationStatus::SchemaTooNew(v) => return Err(MigrationError::SchemaTooNew(v)),
        MigrationStatus::Modified(v) => return Err(MigrationError::Modified(v)),
    };
    for &(version, name, sql) in MIGRATIONS.iter().filter(|m| pending.contains(&m.0)) {
        let mut tx = conn.begin().await?;
        // Simple-query protocol: the file may hold several statements.
        tx.execute(sql).await?;
        query(
            "INSERT INTO schema_migrations (version, name, checksum, applied_at) \
             VALUES ($1, $2, $3, now())",
        )
        .bind(version)
        .bind(name)
        .bind(checksum(sql))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        tracing::info!(version, name, "migration applied");
    }
    Ok(pending)
}

/// Applies every pending migration under the advisory lock. Returns the versions
/// applied (empty when the schema was current).
///
/// # Errors
/// [`MigrationError`].
pub async fn migrate(pool: &PgPool) -> Result<Vec<i64>, MigrationError> {
    let mut conn = pool.acquire().await?;
    query("SELECT pg_advisory_lock($1)")
        .bind(ADVISORY_LOCK_KEY)
        .execute(&mut *conn)
        .await?;
    let result = apply_pending(&mut conn).await;
    let unlocked = query("SELECT pg_advisory_unlock($1)")
        .bind(ADVISORY_LOCK_KEY)
        .execute(&mut *conn)
        .await;
    if unlocked.is_err() {
        // Never hand a connection that may still hold the lock back to the pool.
        drop(conn.detach());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_are_ordered_and_embedded() {
        let versions: Vec<i64> = MIGRATIONS.iter().map(|m| m.0).collect();
        let mut sorted = versions.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(versions, sorted);
        assert_eq!(versions.first(), Some(&1));
        let init = MIGRATIONS[0].2;
        for table in [
            "server_secrets",
            "settings",
            "users",
            "account_keys",
            "devices",
            "auth_tokens",
            "login_states",
            "reauth_tokens",
            "recovery_codes",
            "orgs",
            "org_members",
            "invites",
            "vaults",
            "vault_members",
            "items",
            "items_rotation_staging",
            "audit_events",
        ] {
            assert!(
                init.contains(&format!("CREATE TABLE {table} ")),
                "missing {table}"
            );
        }
        assert!(init.contains("CREATE EXTENSION IF NOT EXISTS citext"));
        assert_eq!(checksum("x").len(), 32);
        assert_eq!(ADVISORY_LOCK_KEY, 0x434F55524945);
    }
}
