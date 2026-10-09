//! The bearer-token extractor.
//!
//! `Authorization: Bearer <access token>` → SHA-256 lookup; the token must be an
//! unexpired access token of an unrevoked device of an enabled account. A
//! missing or malformed header is `401 "authentication required"`, anything else
//! `401 "invalid or expired token"`. Add [`AuthCtx`] as a handler argument to
//! require authentication.

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use uuid::Uuid;

use super::tokens::hash_presented;
use crate::error::ApiError;
use crate::state::AppState;

/// Message for a missing or malformed `Authorization` header.
pub const AUTH_MISSING_MESSAGE: &str = "authentication required";
/// Message for an unknown, expired or revoked token.
pub const AUTH_INVALID_MESSAGE: &str = "invalid or expired token";

/// The authenticated caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthCtx {
    /// The account.
    pub user_id: Uuid,
    /// The device the access token is bound to.
    pub device_id: Uuid,
    /// Whether the account is the instance admin.
    pub is_instance_admin: bool,
}

/// The bearer token of a request, if the header is well-formed.
#[must_use]
pub fn bearer(parts: &Parts) -> Option<&str> {
    let value = parts.headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.trim().split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim())
        .filter(|t| !t.is_empty())
}

impl FromRequestParts<AppState> for AuthCtx {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        if let Some(ctx) = parts.extensions.get::<Self>() {
            return Ok(*ctx);
        }
        let token =
            bearer(parts).ok_or_else(|| ApiError::AuthRequired(AUTH_MISSING_MESSAGE.into()))?;
        let invalid = || ApiError::AuthRequired(AUTH_INVALID_MESSAGE.into());
        let hash = hash_presented(token).ok_or_else(invalid)?;
        let ctx = state
            .store()
            .authenticate(&hash, state.auth().now())
            .await?
            .ok_or_else(invalid)?;
        parts.extensions.insert(ctx);
        Ok(ctx)
    }
}
