//! User public keys (T89).
//!
//! | Endpoint | Request | Response |
//! |---|---|---|
//! | `GET /v1/users/{id}/public-keys` | – | [`UserPublicKeys`] |
//!
//! The server serves whatever keys it has. Clients never trust them blindly:
//! they are pinned on first sight and compared on every later fetch (TOFU),
//! and a changed key is a loud warning, not an update.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A user's account public keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPublicKeys {
    /// The user.
    pub user_id: Uuid,
    /// The account email. Untrusted: for display and lookups only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// X25519 public key (32 B), for HPKE-wrapping vault keys.
    #[serde(with = "crate::b64")]
    pub x25519_pub: Vec<u8>,
    /// Ed25519 public key (32 B), for verifying grant signatures.
    #[serde(with = "crate::b64")]
    pub ed25519_pub: Vec<u8>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn email_is_optional() {
        let k: UserPublicKeys = serde_json::from_str(
            r#"{"user_id":"00000000-0000-0000-0000-000000000000","x25519_pub":"","ed25519_pub":""}"#,
        )
        .unwrap();
        assert_eq!(k.email, None);
    }
}
