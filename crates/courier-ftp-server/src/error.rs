//! The API error type and its mapping to the uniform JSON envelope (T83).
//!
//! Handlers return `Result<_, ApiError>`. Every variant maps to one
//! [`ErrorCode`] and HTTP status; `RateLimited` also sets `Retry-After`.
//! `Internal` causes are logged (inside the request span, so with its
//! `request_id`) but never sent to the client.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use courier_ftp_proto::{ErrorCode, ErrorEnvelope, ProtoError};

/// Boxed cause of an internal error.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Body message of every 429.
pub const RATE_LIMITED_MESSAGE: &str = "too many attempts";
/// Body message of every 500.
pub const INTERNAL_MESSAGE: &str = "internal error";
/// Body message of every 503.
pub const UNAVAILABLE_MESSAGE: &str = "service unavailable";

/// An API error, rendered as `{"error": {"code", "message", "retry_after_s"?}}`.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// 400 `invalid`.
    #[error("{0}")]
    Invalid(String),
    /// 401 `auth_required`.
    #[error("{0}")]
    AuthRequired(String),
    /// 403 `forbidden`.
    #[error("{0}")]
    Forbidden(String),
    /// 404 `not_found`.
    #[error("{0}")]
    NotFound(String),
    /// 409 `conflict`.
    #[error("{0}")]
    Conflict(String),
    /// 409 `rotating` (T85/T89).
    #[error("{0}")]
    Rotating(String),
    /// 410 `gone` (T85).
    #[error("{0}")]
    Gone(String),
    /// 429 `rate_limited` with `Retry-After`.
    #[error("too many attempts")]
    RateLimited {
        /// Seconds until a retry may succeed (at least 1).
        retry_after_s: u64,
    },
    /// 503 `internal`: the database pool is exhausted or the database is down.
    #[error("service unavailable")]
    Unavailable,
    /// 500 `internal`; the cause is logged, not returned.
    #[error("internal error")]
    Internal(#[source] BoxError),
}

impl ApiError {
    /// Wraps any error as `Internal`.
    pub fn internal(err: impl Into<BoxError>) -> Self {
        Self::Internal(err.into())
    }

    /// An `Internal` error with a fixed description (never shown to clients).
    #[must_use]
    pub fn internal_msg(msg: &'static str) -> Self {
        Self::Internal(std::io::Error::other(msg).into())
    }

    /// The envelope code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Invalid(_) => ErrorCode::Invalid,
            Self::AuthRequired(_) => ErrorCode::AuthRequired,
            Self::Forbidden(_) => ErrorCode::Forbidden,
            Self::NotFound(_) => ErrorCode::NotFound,
            Self::Conflict(_) => ErrorCode::Conflict,
            Self::Rotating(_) => ErrorCode::Rotating,
            Self::Gone(_) => ErrorCode::Gone,
            Self::RateLimited { .. } => ErrorCode::RateLimited,
            Self::Unavailable | Self::Internal(_) => ErrorCode::Internal,
        }
    }

    /// The HTTP status.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::Invalid(_) => StatusCode::BAD_REQUEST,
            Self::AuthRequired(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) | Self::Rotating(_) => StatusCode::CONFLICT,
            Self::Gone(_) => StatusCode::GONE,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Builds an envelope response; `retry_after_s` also sets `Retry-After`.
#[must_use]
pub fn envelope_response(
    status: StatusCode,
    code: ErrorCode,
    message: impl Into<String>,
    retry_after_s: Option<u64>,
) -> Response {
    let mut resp = (
        status,
        Json(ErrorEnvelope::new(code, message, retry_after_s)),
    )
        .into_response();
    if let Some(secs) = retry_after_s {
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from(secs));
    }
    resp
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let code = self.code();
        match self {
            Self::Internal(cause) => {
                tracing::error!(error = %cause, "internal error");
                envelope_response(status, code, INTERNAL_MESSAGE, None)
            }
            Self::Unavailable => {
                tracing::error!("service unavailable (database)");
                envelope_response(status, code, UNAVAILABLE_MESSAGE, None)
            }
            Self::RateLimited { retry_after_s } => envelope_response(
                status,
                code,
                RATE_LIMITED_MESSAGE,
                Some(retry_after_s.max(1)),
            ),
            other => envelope_response(status, code, other.to_string(), None),
        }
    }
}

impl From<sqlx_core::Error> for ApiError {
    fn from(err: sqlx_core::Error) -> Self {
        match err {
            sqlx_core::Error::PoolTimedOut => Self::Unavailable,
            other => Self::internal(other),
        }
    }
}

impl From<ProtoError> for ApiError {
    fn from(err: ProtoError) -> Self {
        Self::Invalid(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_match_codes() {
        let all = [
            ApiError::Invalid(String::new()),
            ApiError::AuthRequired(String::new()),
            ApiError::Forbidden(String::new()),
            ApiError::NotFound(String::new()),
            ApiError::Conflict(String::new()),
            ApiError::Rotating(String::new()),
            ApiError::Gone(String::new()),
            ApiError::RateLimited { retry_after_s: 1 },
            ApiError::internal_msg("x"),
        ];
        for e in all {
            assert_eq!(e.status().as_u16(), e.code().default_status(), "{e:?}");
        }
        assert_eq!(ApiError::Unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(matches!(
            ApiError::from(sqlx_core::Error::PoolTimedOut),
            ApiError::Unavailable
        ));
    }
}
