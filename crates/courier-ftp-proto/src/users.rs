//! User public keys (`GET /v1/users/{id}/public-keys`, T89), pinned by clients.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A user's public keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPublicKeys {
    /// The user.
    pub user_id: Uuid,
    /// Email, for display only (untrusted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// X25519 public key.
    #[serde(with = "crate::b64")]
    pub x25519_pub: Vec<u8>,
    /// Ed25519 public key.
    #[serde(with = "crate::b64")]
    pub ed25519_pub: Vec<u8>,
}
