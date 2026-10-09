//! Vault key rotation (`POST /v1/vaults/{id}/rotate`, T89).
//!
//! A rotation is three calls tagged by `"action"`: `begin` (announce the new key
//! version; pushes get `409 rotating`), any number of `upload` chunks (items
//! re-sealed under the new key, ≤ [`crate::limits::MAX_ROTATION_CHUNK`] items and
//! ≤ [`crate::limits::MAX_BATCH_BYTES`] per chunk), then `commit` (the new wraps for
//! every remaining member). Each call answers with a [`RotateResponse`].

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::sync::Permission;

/// One item re-sealed under the new vault key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotatedItem {
    /// Item id.
    pub id: Uuid,
    /// The re-sealed envelope.
    #[serde(with = "crate::b64")]
    pub envelope: Vec<u8>,
}

/// The new vault key wrapped to one member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationGrant {
    /// The member.
    pub user: Uuid,
    /// The new vault key wrapped to the member (T80 grant wire format).
    #[serde(with = "crate::b64")]
    pub wrapped: Vec<u8>,
    /// The rotator's Ed25519 signature.
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
    /// The member's permission, carried over.
    pub permission: Permission,
}

/// `POST /v1/vaults/{id}/rotate`, tagged by `"action"`. See
/// [`RotateRequest::validate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum RotateRequest {
    /// Start (or resume) a rotation to `new_key_version`.
    Begin {
        /// The current key version + 1.
        new_key_version: u32,
    },
    /// Stage re-sealed items.
    Upload {
        /// The items of this chunk.
        items: Vec<RotatedItem>,
    },
    /// Swap in the staged items and the new wraps.
    Commit {
        /// One wrap per remaining member.
        wrapped_keys: Vec<RotationGrant>,
    },
}

/// Answer to every [`RotateRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateResponse {
    /// The vault's key version (the new one after `commit`).
    pub key_version: u32,
    /// The version being introduced.
    pub new_key_version: u32,
    /// The vault's head revision.
    pub head_revision: u64,
    /// Items staged so far.
    pub staged: u64,
    /// `begin` resumed the caller's own rotation.
    #[serde(default)]
    pub resumed: bool,
    /// `begin` replaced an abandoned rotation of someone else.
    #[serde(default)]
    pub replaced_abandoned: bool,
}
