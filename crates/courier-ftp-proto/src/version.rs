//! Protocol versioning and shared HTTP header names.
//!
//! The HTTP API lives under [`API_PREFIX`] (`/v1`); the sync protocol inside it
//! is versioned separately with the [`PROTO_HEADER`] request header
//! (`Courier-Proto: 1`). The server accepts the current version `N` and the
//! previous one `N-1` ([`negotiate`]) and sends its own version back in the
//! same header, which the client checks with [`check_server`]. A request
//! without the header is treated as speaking the current version.
//!
//! Bump [`PROTO_VERSION`] for any change an older peer would misread (a
//! renamed or removed field, a new required field, changed semantics). Adding
//! an optional request field or a response field is not a bump: every DTO
//! ignores unknown fields.

use thiserror::Error;

/// Header carrying the protocol version, sent by clients and echoed by the
/// server (HTTP header names are case-insensitive; this is the canonical
/// lower-case form of `Courier-Proto`).
pub const PROTO_HEADER: &str = "courier-proto";

/// Current protocol version (`N`).
pub const PROTO_VERSION: u32 = 1;

/// Oldest protocol version the server still accepts (`N-1`, never below 1).
pub const MIN_SUPPORTED_PROTO_VERSION: u32 = if PROTO_VERSION > 1 {
    PROTO_VERSION - 1
} else {
    1
};

/// Request-id header, accepted from clients (or generated) and echoed in
/// every response.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Path prefix of the versioned HTTP API.
pub const API_PREFIX: &str = "/v1";

/// Whether a peer speaking `version` can be served.
#[must_use]
pub const fn is_supported(version: u32) -> bool {
    version >= MIN_SUPPORTED_PROTO_VERSION && version <= PROTO_VERSION
}

/// Why a protocol version was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VersionError {
    /// The header is not a decimal number.
    #[error("malformed {PROTO_HEADER} header: {0:?} (expected a number such as {PROTO_VERSION})")]
    Malformed(String),
    /// The peer is newer than this build.
    #[error(
        "protocol version {got} is newer than the supported {MIN_SUPPORTED_PROTO_VERSION}..={PROTO_VERSION}; update courier-ftp"
    )]
    TooNew {
        /// The version the peer speaks.
        got: u32,
    },
    /// The peer is older than this build still accepts.
    #[error(
        "protocol version {got} is older than the supported {MIN_SUPPORTED_PROTO_VERSION}..={PROTO_VERSION}; update the older side"
    )]
    TooOld {
        /// The version the peer speaks.
        got: u32,
    },
}

impl From<VersionError> for crate::ErrorEnvelope {
    fn from(e: VersionError) -> Self {
        Self::new(crate::ErrorCode::Invalid, e.to_string(), None)
    }
}

/// Parses a version number and checks that it is supported.
///
/// # Errors
/// [`VersionError`] for a malformed or unsupported version.
pub fn parse(value: &str) -> Result<u32, VersionError> {
    let trimmed = value.trim();
    let got: u32 = if !trimmed.is_empty() && trimmed.bytes().all(|b| b.is_ascii_digit()) {
        trimmed
            .parse()
            .map_err(|_| VersionError::Malformed(value.into()))?
    } else {
        return Err(VersionError::Malformed(value.chars().take(32).collect()));
    };
    if got > PROTO_VERSION {
        Err(VersionError::TooNew { got })
    } else if got < MIN_SUPPORTED_PROTO_VERSION {
        Err(VersionError::TooOld { got })
    } else {
        Ok(got)
    }
}

/// Server side: the version a request speaks, from its [`PROTO_HEADER`]
/// value (`None` when absent, which means [`PROTO_VERSION`]).
///
/// # Errors
/// [`VersionError`]; answer `400 invalid` with it (`ErrorEnvelope::from`).
pub fn negotiate(header: Option<&str>) -> Result<u32, VersionError> {
    header.map_or(Ok(PROTO_VERSION), parse)
}

/// Client side: checks the [`PROTO_HEADER`] the server answered with. A
/// missing header is accepted (proxies may strip it).
///
/// # Errors
/// [`VersionError`] when the server speaks a version this client can't.
pub fn check_server(header: Option<&str>) -> Result<u32, VersionError> {
    negotiate(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_n_and_n_minus_one_only() {
        assert!(is_supported(PROTO_VERSION));
        assert!(is_supported(MIN_SUPPORTED_PROTO_VERSION));
        assert!(!is_supported(PROTO_VERSION + 1));
        assert!(!is_supported(0));
    }

    #[test]
    fn negotiation() {
        assert_eq!(negotiate(None), Ok(PROTO_VERSION));
        assert_eq!(negotiate(Some("1")), Ok(1));
        assert_eq!(negotiate(Some(" 1 ")), Ok(1));
        assert_eq!(negotiate(Some("2")), Err(VersionError::TooNew { got: 2 }));
        assert_eq!(negotiate(Some("0")), Err(VersionError::TooOld { got: 0 }));
        assert!(matches!(
            negotiate(Some("v1")),
            Err(VersionError::Malformed(_))
        ));
        assert!(matches!(
            negotiate(Some("")),
            Err(VersionError::Malformed(_))
        ));
        assert!(matches!(
            negotiate(Some("-1")),
            Err(VersionError::Malformed(_))
        ));
        assert!(matches!(
            negotiate(Some("99999999999")),
            Err(VersionError::Malformed(_))
        ));
        assert_eq!(check_server(Some("1")), Ok(1));
    }

    #[test]
    fn errors_are_clear() {
        let e = negotiate(Some("7")).unwrap_err();
        assert_eq!(
            e.to_string(),
            "protocol version 7 is newer than the supported 1..=1; update courier-ftp"
        );
        let env = crate::ErrorEnvelope::from(e);
        assert_eq!(env.error.code, crate::ErrorCode::Invalid);
    }
}
