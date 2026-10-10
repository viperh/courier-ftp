//! Vault key rotation (`POST /v1/vaults/{id}/rotate`, T86 server, T89 client).
//!
//! One endpoint, three actions (the `action` tag of [`RotateRequest`]):
//!
//! | Action | Request | Effect |
//! |---|---|---|
//! | `begin` | `new_key_version` (= current + 1) | marks the vault as rotating; pushes now get `409 rotating` |
//! | `upload` | up to [`MAX_ROTATION_CHUNK`] `{id, envelope}` | stages re-encrypted items (idempotent) |
//! | `commit` | one `{user, wrapped, signature}` per remaining member | one transaction: full coverage check, fresh revisions, new grants, old grants removed, `key_version` bumped |
//!
//! Every action answers [`RotateResponse`]. Errors ([`crate::ErrorEnvelope`]):
//! * `404 not_found`: unknown vault, not visible, or a personal vault;
//! * `403 forbidden`: the caller has no `manage` on the vault;
//! * `409 rotating`: `begin` while another rotation is active and not
//!   abandoned; `upload` / `commit` by someone other than the rotating user;
//! * `400 invalid`: `new_key_version` is not current + 1, no rotation is
//!   running, an oversized chunk or envelope, staging that does not cover
//!   every item (the message names the missing count; nothing is applied), or
//!   wrapped keys that miss a member, name a non-member, or are malformed.
//!
//! **Abandonment:** a rotation started more than [`ROTATION_ABANDON_SECS`] ago
//! is abandoned. `GET /v1/vaults` then reports
//! [`crate::sync::RotationView::abandoned`]; the next `begin` by any `manage`
//! client discards its staging. The same user calling `begin` again for the
//! same key version **resumes** the rotation (staging kept).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::limits::LimitError;
pub use crate::limits::MAX_ROTATION_CHUNK;

/// A rotation older than this (seconds since it began) is abandoned
/// (15 minutes).
pub const ROTATION_ABANDON_SECS: i64 = 15 * 60;

/// One re-encrypted item (same id, AAD key version = the new one).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotatedItem {
    /// Item id (unchanged).
    pub id: Uuid,
    /// The item sealed under the new vault key.
    #[serde(with = "crate::b64")]
    pub envelope: Vec<u8>,
}

/// The new vault key wrapped for one remaining member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationGrant {
    /// The member.
    pub user: Uuid,
    /// The new vault key HPKE-wrapped to the member's pinned X25519 key.
    #[serde(with = "crate::b64")]
    pub wrapped: Vec<u8>,
    /// The committer's Ed25519 signature over the canonical grant.
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
}

/// Body of `POST /v1/vaults/{id}/rotate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum RotateRequest {
    /// Start (or resume) a rotation to `new_key_version`.
    Begin {
        /// Must be the vault's key version + 1.
        new_key_version: u32,
    },
    /// Stage re-encrypted items.
    Upload {
        /// At most [`MAX_ROTATION_CHUNK`].
        items: Vec<RotatedItem>,
    },
    /// Swap the staged items in and install the new grants.
    Commit {
        /// One per remaining member, the committer included.
        wrapped_keys: Vec<RotationGrant>,
    },
}

impl RotateRequest {
    /// Checks the chunk size of an `upload` (other actions always pass).
    ///
    /// # Errors
    /// [`LimitError::RotationChunk`].
    pub fn check_limits(&self) -> Result<(), LimitError> {
        match self {
            Self::Upload { items } if items.len() > MAX_ROTATION_CHUNK => {
                Err(LimitError::RotationChunk { got: items.len() })
            }
            _ => Ok(()),
        }
    }
}

/// Response of every rotate action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateResponse {
    /// The vault's key version (after `commit`: the new one).
    pub key_version: u32,
    /// The key version being rotated to (`commit`: equals `key_version`).
    pub new_key_version: u32,
    /// The vault's head revision (after `commit`: the new head).
    pub head_revision: u64,
    /// Items currently staged (0 after `commit`).
    pub staged: u64,
    /// `begin`: an existing rotation of the caller was resumed.
    #[serde(default)]
    pub resumed: bool,
    /// `begin`: an abandoned rotation was discarded first.
    #[serde(default)]
    pub replaced_abandoned: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn response_flags_default_to_false() {
        let r: RotateResponse = serde_json::from_str(
            r#"{"key_version":1,"new_key_version":2,"head_revision":5,"staged":0}"#,
        )
        .unwrap();
        assert!(!r.resumed && !r.replaced_abandoned);
    }

    #[test]
    fn chunk_limit() {
        let item = RotatedItem {
            id: Uuid::nil(),
            envelope: vec![],
        };
        let ok = RotateRequest::Upload {
            items: vec![item.clone(); MAX_ROTATION_CHUNK],
        };
        assert_eq!(ok.check_limits(), Ok(()));
        let big = RotateRequest::Upload {
            items: vec![item; MAX_ROTATION_CHUNK + 1],
        };
        assert!(big.check_limits().is_err());
        assert_eq!(
            RotateRequest::Begin { new_key_version: 2 }.check_limits(),
            Ok(())
        );
    }

    #[test]
    fn unknown_action_is_rejected() {
        assert!(serde_json::from_str::<RotateRequest>(r#"{"action":"abort"}"#).is_err());
    }
}
