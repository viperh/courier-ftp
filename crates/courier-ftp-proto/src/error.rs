//! The uniform API error body.
//!
//! Every non-2xx response from `courier-ftp-server` has the body
//! `{"error": {"code": "...", "message": "...", "retry_after_s": 5}}`
//! (`retry_after_s` only for `rate_limited`). `429` responses also carry a
//! `Retry-After` header with the same number of seconds.

use serde::{Deserialize, Serialize};

/// Machine-readable error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// 409: optimistic-concurrency or uniqueness conflict.
    Conflict,
    /// 403: authenticated but not allowed.
    Forbidden,
    /// 404: no such resource (or not visible to the caller).
    NotFound,
    /// 429: rate limited; see `retry_after_s`.
    RateLimited,
    /// 400 (and 413/405/...): malformed or unacceptable request, including an
    /// unsupported protocol version or a request over a limit.
    Invalid,
    /// 410: the pull cursor is below the vault's GC floor; resync from 0.
    Gone,
    /// 409: the vault is in the middle of a key rotation.
    Rotating,
    /// 401: missing, expired or revoked credentials.
    AuthRequired,
    /// 5xx: unexpected server failure; clients treat it as transient.
    Internal,
}

impl ErrorCode {
    /// Every code, in declaration order (for table-driven tests).
    pub const ALL: [Self; 9] = [
        Self::Conflict,
        Self::Forbidden,
        Self::NotFound,
        Self::RateLimited,
        Self::Invalid,
        Self::Gone,
        Self::Rotating,
        Self::AuthRequired,
        Self::Internal,
    ];

    /// The wire spelling, e.g. `"rate_limited"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Conflict => "conflict",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::RateLimited => "rate_limited",
            Self::Invalid => "invalid",
            Self::Gone => "gone",
            Self::Rotating => "rotating",
            Self::AuthRequired => "auth_required",
            Self::Internal => "internal",
        }
    }

    /// The HTTP status the server uses for this code by default.
    #[must_use]
    pub const fn default_status(self) -> u16 {
        match self {
            Self::Conflict | Self::Rotating => 409,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::RateLimited => 429,
            Self::Invalid => 400,
            Self::Gone => 410,
            Self::AuthRequired => 401,
            Self::Internal => 500,
        }
    }

    /// Whether a client may retry the same request later unchanged
    /// (`rate_limited`, `rotating`, `internal`).
    #[must_use]
    pub const fn is_transient(self) -> bool {
        matches!(self, Self::RateLimited | Self::Rotating | Self::Internal)
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The inner `error` object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Machine-readable code.
    pub code: ErrorCode,
    /// Human-readable message (never contains secrets).
    pub message: String,
    /// Seconds until a retry may succeed (`rate_limited` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_s: Option<u64>,
}

/// The top-level error document: `{"error": {...}}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    /// The error.
    pub error: ErrorBody,
}

impl ErrorEnvelope {
    /// Builds an envelope.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>, retry_after_s: Option<u64>) -> Self {
        Self {
            error: ErrorBody {
                code,
                message: message.into(),
                retry_after_s,
            },
        }
    }

    /// The HTTP status to answer with ([`ErrorCode::default_status`]).
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.error.code.default_status()
    }
}

impl std::fmt::Display for ErrorEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.error.code, self.error.message)?;
        if let Some(s) = self.error.retry_after_s {
            write!(f, " (retry after {s} s)")?;
        }
        Ok(())
    }
}

impl std::error::Error for ErrorEnvelope {}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn codes_serialize_as_wire_strings() {
        for code in ErrorCode::ALL {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{}\"", code.as_str()));
            let back: ErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, code);
        }
    }

    #[test]
    fn envelope_shape() {
        let env = ErrorEnvelope::new(ErrorCode::RateLimited, "slow down", Some(12));
        assert_eq!(
            serde_json::to_string(&env).unwrap(),
            r#"{"error":{"code":"rate_limited","message":"slow down","retry_after_s":12}}"#
        );
        assert_eq!(env.status(), 429);
        assert_eq!(
            env.to_string(),
            "rate_limited: slow down (retry after 12 s)"
        );
        let env = ErrorEnvelope::new(ErrorCode::NotFound, "nope", None);
        assert_eq!(
            serde_json::to_string(&env).unwrap(),
            r#"{"error":{"code":"not_found","message":"nope"}}"#
        );
    }

    #[test]
    fn unknown_code_is_rejected() {
        assert!(serde_json::from_str::<ErrorCode>(r#""teapot""#).is_err());
    }
}
