//! Protocol versioning and shared HTTP header names.
//!
//! The HTTP API lives under [`API_PREFIX`]; the sync protocol is versioned separately
//! through the `Courier-Proto` request/response header. The server accepts the
//! current version `N` and the previous one `N-1`; a request without the header
//! speaks the current version.
//!
//! Adding an optional request field or any response field is compatible (no bump).
//! Removing or renaming a field, changing a type or changing semantics bumps
//! [`PROTO_VERSION`]; the server then keeps the `N-1` handlers for one release.

use crate::error::ProtoError;

/// Header carrying the sync protocol version (sent as `Courier-Proto: 1`, echoed
/// by the server). HTTP header names are case-insensitive.
pub const PROTO_HEADER: &str = "courier-proto";

/// Current protocol version (`N`).
pub const PROTO_VERSION: u32 = 1;

/// Oldest protocol version the server still accepts (`N-1`).
pub const MIN_SUPPORTED_PROTO_VERSION: u32 = PROTO_VERSION.saturating_sub(1);

/// Request-id header, accepted from clients (1–128 chars of `[A-Za-z0-9-]`) and
/// echoed in every response.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Path prefix of the versioned HTTP API.
pub const API_PREFIX: &str = "/v1";

/// Prefix of the client's `User-Agent` (`courier-ftp/<semver>`).
pub const USER_AGENT_PREFIX: &str = "courier-ftp/";

/// Maximum number of digits of a `Courier-Proto` header value.
const MAX_VERSION_DIGITS: usize = 5;

/// Whether a client speaking `version` can be served.
// The lower bound is 0 while `PROTO_VERSION` is 1; the check matters for later versions.
#[allow(clippy::absurd_extreme_comparisons)]
#[must_use]
pub const fn is_supported(version: u32) -> bool {
    version >= MIN_SUPPORTED_PROTO_VERSION && version <= PROTO_VERSION
}

/// Parses a `Courier-Proto` header value: ASCII decimal, 1–5 digits, no sign or
/// space. `None` (header absent) means the current version.
///
/// # Errors
/// [`ProtoError::MalformedVersion`] for an empty, non-digit or too long value,
/// [`ProtoError::UnsupportedVersion`] for a version outside `[N-1, N]`.
pub fn negotiate(header: Option<&[u8]>) -> Result<u32, ProtoError> {
    let Some(raw) = header else {
        return Ok(PROTO_VERSION);
    };
    if raw.is_empty() || raw.len() > MAX_VERSION_DIGITS || !raw.iter().all(u8::is_ascii_digit) {
        return Err(ProtoError::MalformedVersion);
    }
    // At most 5 digits: always fits.
    let version = raw
        .iter()
        .fold(0u32, |acc, d| acc * 10 + u32::from(d - b'0'));
    if is_supported(version) {
        Ok(version)
    } else {
        Err(ProtoError::UnsupportedVersion(version))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_n_and_n_minus_one_only() {
        assert!(is_supported(PROTO_VERSION));
        assert!(is_supported(PROTO_VERSION - 1));
        assert!(!is_supported(PROTO_VERSION + 1));
        assert!(!is_supported(u32::MAX));
    }

    #[test]
    fn negotiate_table() {
        #[derive(Debug, PartialEq)]
        enum Want {
            Ok(u32),
            Malformed,
            Unsupported(u32),
        }
        let table: [(Option<&[u8]>, Want); 12] = [
            (None, Want::Ok(1)),
            (Some(b"1"), Want::Ok(1)),
            (Some(b"0"), Want::Ok(0)),
            (Some(b"01"), Want::Ok(1)),
            (Some(b"2"), Want::Unsupported(2)),
            (Some(b"99999"), Want::Unsupported(99_999)),
            (Some(b"-1"), Want::Malformed),
            (Some(b"01x"), Want::Malformed),
            (Some(b""), Want::Malformed),
            (Some(b"123456"), Want::Malformed),
            (Some(b" 1"), Want::Malformed),
            (Some(b"+1"), Want::Malformed),
        ];
        for (input, want) in table {
            let got = match negotiate(input) {
                Ok(v) => Want::Ok(v),
                Err(ProtoError::MalformedVersion) => Want::Malformed,
                Err(ProtoError::UnsupportedVersion(v)) => Want::Unsupported(v),
                Err(e) => panic!("unexpected error {e}"),
            };
            assert_eq!(got, want, "input {input:?}");
        }
    }
}
