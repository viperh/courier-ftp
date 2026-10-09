//! The uniform API error envelope and this crate's own error type.
//!
//! Every non-2xx response from `courier-ftp-server` has the body
//! `{"error": {"code": "...", "message": "...", "retry_after_s"?: n}}`.
//! `429` responses also carry a `Retry-After` header with the same number of seconds.

use serde::{Deserialize, Serialize};

/// Message of the generic login failure: identical for an unknown email, a wrong
/// password and a disabled account (401 from `login/finish`).
pub const LOGIN_FAILED_MESSAGE: &str = "invalid email or password";
/// Message prefix of the 401 when the account has TOTP enabled and no code was sent.
pub const TOTP_REQUIRED_HINT: &str = "totp_required";
/// Message prefix of the 401 for a wrong or replayed TOTP code.
pub const TOTP_INVALID_HINT: &str = "totp_invalid";
/// Message prefix of the 400 for a push or grant with an old vault key version.
pub const KEY_VERSION_STALE_HINT: &str = "key_version_stale";
/// `PushResult.message` with `too_large`: the account or org quota is used up.
pub const QUOTA_EXCEEDED_MESSAGE: &str = "quota exceeded";
/// `PushResult.message` with `too_large`: one envelope is over
/// [`crate::limits::MAX_ENVELOPE_BYTES`].
pub const ENVELOPE_TOO_LARGE_MESSAGE: &str = "envelope exceeds 1 MiB";
/// `PushResult.message` with `too_large`: the team vault size cap is reached.
pub const VAULT_CAP_MESSAGE: &str = "team vault size cap reached";

/// Machine-readable error code; wire spelling in `snake_case`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// 409: optimistic-concurrency or uniqueness conflict.
    Conflict,
    /// 403: authenticated but not allowed.
    Forbidden,
    /// 404: no such resource, or not visible to the caller.
    NotFound,
    /// 429: rate limited; see `retry_after_s` and the `Retry-After` header.
    RateLimited,
    /// 400 (also 405, 413, 415, 422 bodies): malformed or unacceptable request.
    Invalid,
    /// 410: pull cursor below the GC floor.
    Gone,
    /// 409: vault key rotation in progress.
    Rotating,
    /// 401: missing, expired or revoked credentials.
    AuthRequired,
    /// 500/503: unexpected server failure; clients treat it as transient.
    Internal,
}

impl ErrorCode {
    /// Every code, in declaration order.
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
    /// Human-readable, English; never contains secrets, emails or hostnames.
    pub message: String,
    /// Seconds until a retry may succeed (only with `rate_limited`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_s: Option<u64>,
}

/// `{"error": {...}}`: the body of every non-2xx response.
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
}

/// Errors of this crate's own helpers (version negotiation, validation).
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    /// A field fails a shape check.
    #[error("invalid {field}: {reason}")]
    Invalid {
        /// The offending field (wire name).
        field: &'static str,
        /// Why it is rejected (never contains the value of a secret).
        reason: String,
    },
    /// The `Courier-Proto` header names a version outside `[N-1, N]`.
    #[error(
        "unsupported protocol version {0} (server supports {min}..{max})",
        min = crate::version::MIN_SUPPORTED_PROTO_VERSION,
        max = crate::version::PROTO_VERSION
    )]
    UnsupportedVersion(u32),
    /// The `Courier-Proto` header is not 1–5 ASCII digits.
    #[error("malformed Courier-Proto header")]
    MalformedVersion,
}

impl ProtoError {
    /// Shorthand for [`ProtoError::Invalid`].
    pub(crate) fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        Self::Invalid {
            field,
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn codes_serialize_as_spec_strings() {
        for code in ErrorCode::ALL {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{}\"", code.as_str()));
            let back: ErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, code);
            assert_eq!(code.to_string(), code.as_str());
        }
        let table = [
            (ErrorCode::Conflict, "conflict", 409),
            (ErrorCode::Forbidden, "forbidden", 403),
            (ErrorCode::NotFound, "not_found", 404),
            (ErrorCode::RateLimited, "rate_limited", 429),
            (ErrorCode::Invalid, "invalid", 400),
            (ErrorCode::Gone, "gone", 410),
            (ErrorCode::Rotating, "rotating", 409),
            (ErrorCode::AuthRequired, "auth_required", 401),
            (ErrorCode::Internal, "internal", 500),
        ];
        assert_eq!(table.len(), ErrorCode::ALL.len());
        for (code, s, status) in table {
            assert_eq!(code.as_str(), s);
            assert_eq!(code.default_status(), status);
        }
    }

    #[test]
    fn retry_after_omitted_when_none() {
        let env = ErrorEnvelope::new(ErrorCode::RateLimited, "too many login attempts", Some(12));
        assert_eq!(
            serde_json::to_string(&env).unwrap(),
            r#"{"error":{"code":"rate_limited","message":"too many login attempts","retry_after_s":12}}"#
        );
        let env = ErrorEnvelope::new(ErrorCode::NotFound, "not found", None);
        assert_eq!(
            serde_json::to_string(&env).unwrap(),
            r#"{"error":{"code":"not_found","message":"not found"}}"#
        );
        let back: ErrorEnvelope =
            serde_json::from_str(r#"{"error":{"code":"gone","message":"x","extra":1}}"#).unwrap();
        assert_eq!(back, ErrorEnvelope::new(ErrorCode::Gone, "x", None));
    }

    #[test]
    fn proto_error_texts() {
        assert_eq!(
            ProtoError::UnsupportedVersion(7).to_string(),
            "unsupported protocol version 7 (server supports 0..1)"
        );
        assert_eq!(
            ProtoError::MalformedVersion.to_string(),
            "malformed Courier-Proto header"
        );
        assert_eq!(
            ProtoError::invalid("email", "too long").to_string(),
            "invalid email: too long"
        );
    }
}
