//! Instance invites: `admin invite <email>` and `admin user create <email>`.
//!
//! The server can't create an account itself (OPAQUE registration happens
//! on the client), so both commands create a single-use, email-bound
//! registration invite (`invites` row with `org_id = NULL`) and return its
//! token, which the user enters in courier-ftp together with the server URL
//! when setting up sync. Only the token's SHA-256 is stored.

use chrono::{DateTime, Duration, Utc};
use sqlx_postgres::PgPool;
use uuid::Uuid;

use super::AdminError;
use crate::registration::{generate_token, hash_token, normalize_email};

/// Invite lifetime.
pub const INVITE_TTL_DAYS: i64 = 7;

/// A freshly created invite. `token` is shown once and never stored.
#[derive(Clone)]
pub struct CreatedInvite {
    /// Row id.
    pub id: Uuid,
    /// Normalised email it is bound to.
    pub email: String,
    /// The plaintext token.
    pub token: String,
    /// Expiry.
    pub expires_at: DateTime<Utc>,
}

// The token never reaches `Debug` output.
impl std::fmt::Debug for CreatedInvite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedInvite")
            .field("id", &self.id)
            .field("email", &self.email)
            .field("token", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Creates an email-bound instance invite.
///
/// # Errors
/// [`AdminError::Invalid`] for a bad email; database errors.
pub async fn create(pool: &PgPool, email: &str) -> Result<CreatedInvite, AdminError> {
    let email = normalize_email(email)?;
    let token = generate_token();
    let id = Uuid::now_v7();
    let expires_at = Utc::now() + Duration::days(INVITE_TTL_DAYS);
    sqlx_core::query::query(
        "INSERT INTO invites (id, org_id, email, role, token_hash, created_by, expires_at) \
         VALUES ($1, NULL, $2, NULL, $3, NULL, $4)",
    )
    .bind(id)
    .bind(&email)
    .bind(hash_token(&token).to_vec())
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(CreatedInvite {
        id,
        email,
        token,
        expires_at,
    })
}
