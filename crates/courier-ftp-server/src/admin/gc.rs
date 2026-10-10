//! `admin gc`: purge expired and finished state, the same work the
//! background job does every `COURIER_GC_INTERVAL_HOURS`:
//! * expired access/refresh tokens, login states, reauth tokens, recovery
//!   codes and unaccepted invites;
//! * tombstones older than `COURIER_TOMBSTONE_HORIZON_DAYS`, raising
//!   `vaults.gc_floor_revision` (pulls below it get `410 gone`).
//!
//! Abandoned key rotations are discarded by T89.

use sqlx_postgres::PgPool;

use super::AdminError;
use crate::auth::AuthStore;
use crate::config::Config;

/// What [`run`] removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GcReport {
    /// Expired access/refresh tokens.
    pub expired_tokens: u64,
    /// Expired login states, reauth tokens and recovery codes.
    pub expired_other: u64,
    /// Expired invites that were never accepted.
    pub expired_invites: u64,
    /// Tombstones purged.
    pub purged_tombstones: u64,
    /// Vaults whose GC floor was raised.
    pub gc_floor_vaults: u64,
}

/// Runs every GC step.
///
/// # Errors
/// Database errors.
pub async fn run(pool: &PgPool, config: &Config) -> Result<GcReport, AdminError> {
    let now = chrono::Utc::now();
    let purged = AuthStore::Postgres(pool.clone()).purge_expired(now).await?;
    let cutoff = crate::sync::gc::cutoff(now, config.limits.tombstone_horizon_days);
    let tombstones = crate::sync::gc::pg_purge_tombstones(pool, cutoff).await?;
    Ok(GcReport {
        expired_tokens: purged.tokens,
        expired_other: purged.other,
        expired_invites: purged.invites,
        purged_tombstones: tombstones.purged_tombstones,
        gc_floor_vaults: tombstones.vaults,
    })
}
