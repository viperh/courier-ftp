//! Vault list, pull and push (T85).
//!
//! Revisions are per-vault, gap-free and start at 1; `0` means "nothing yet" (a pull
//! cursor of 0, or the base revision of an item the client believes is new).
//!
//! | Endpoint | Request | Response |
//! |---|---|---|
//! | `GET /v1/vaults` | – | `[`[`VaultView`]`]` |
//! | `GET /v1/vaults/{id}/changes?since=&limit=` | [`PullQuery`] | [`PullResponse`] |
//! | `POST /v1/vaults/{id}/changes` | [`PushRequest`] | [`PushResponse`] |
//!
//! Pull ordering: `items` are sorted by `revision` ascending, all `> since`. When
//! `more == false` the client may set its cursor to `head_revision`, otherwise to the
//! last item's revision.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Personal or team vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultKind {
    /// The account's own vault (one per account).
    Personal,
    /// An org vault shared with members.
    Team,
}

impl VaultKind {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Team => "team",
        }
    }

    /// Parses the wire spelling.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "personal" => Some(Self::Personal),
            "team" => Some(Self::Team),
            _ => None,
        }
    }
}

/// A member's permission on a vault. Ordered: `Read < Write < Manage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Pull only.
    Read,
    /// Pull and push.
    Write,
    /// Write, plus grants, revocations and key rotation.
    Manage,
}

impl Permission {
    /// Whether this permission may push changes.
    #[must_use]
    pub const fn can_write(self) -> bool {
        matches!(self, Self::Write | Self::Manage)
    }

    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Manage => "manage",
        }
    }

    /// Parses the wire spelling.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "manage" => Some(Self::Manage),
            _ => None,
        }
    }
}

/// One of the caller's wraps of a vault key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultGrant {
    /// Vault key version this wrap holds.
    pub key_version: u32,
    /// The wrapped vault key (T80 grant wire format).
    #[serde(with = "crate::b64")]
    pub wrapped_vault_key: Vec<u8>,
    /// The user who wrapped (and signed) it.
    pub wrapped_by: Uuid,
    /// Ed25519 signature of `wrapped_by`.
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
}

/// A key rotation in progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationView {
    /// The key version being introduced.
    pub new_key_version: u32,
    /// Who started it.
    pub by: Uuid,
    /// When it started.
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    /// `started_at` is older than [`crate::limits::ROTATION_ABANDON_SECS`].
    #[serde(default)]
    pub abandoned: bool,
}

/// One entry of `GET /v1/vaults`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultView {
    /// Vault id.
    pub id: Uuid,
    /// Personal or team.
    pub kind: VaultKind,
    /// The owning org (team vaults only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<Uuid>,
    /// Vault name sealed under the vault key.
    #[serde(with = "crate::b64")]
    pub name_enc: Vec<u8>,
    /// Current vault key version.
    pub key_version: u32,
    /// Highest revision in the vault.
    pub head_revision: u64,
    /// The caller's effective permission.
    pub permission: Permission,
    /// The caller's wraps, ascending `key_version`.
    pub grants: Vec<VaultGrant>,
    /// A rotation in progress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation: Option<RotationView>,
}

/// Query of `GET /v1/vaults/{id}/changes`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullQuery {
    /// Return items with `revision > since` (0 = from the start).
    #[serde(default)]
    pub since: u64,
    /// Page size; capped at, and defaults to, [`crate::limits::MAX_PULL_LIMIT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// An item as stored on the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteItem {
    /// Item id.
    pub id: Uuid,
    /// Revision of the last change.
    pub revision: u64,
    /// Vault key version the envelope is sealed under.
    pub key_version: u32,
    /// The sealed item (opaque bytes, T80 envelope).
    #[serde(with = "crate::b64")]
    pub envelope: Vec<u8>,
    /// Tombstone.
    #[serde(default)]
    pub deleted: bool,
}

/// Response of a pull.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullResponse {
    /// Changes, `revision` ascending, all `> since`.
    pub items: Vec<RemoteItem>,
    /// The vault's head revision.
    pub head_revision: u64,
    /// More pages follow.
    pub more: bool,
}

/// One change in a push.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushChange {
    /// Item id.
    pub id: Uuid,
    /// The revision this change is based on (0 = new item).
    pub base_revision: u64,
    /// Vault key version the envelope is sealed under (must be the current one).
    pub key_version: u32,
    /// The sealed item.
    #[serde(with = "crate::b64")]
    pub envelope: Vec<u8>,
    /// Tombstone.
    #[serde(default)]
    pub deleted: bool,
}

/// `POST /v1/vaults/{id}/changes`. See [`PushRequest::validate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRequest {
    /// The changes.
    pub changes: Vec<PushChange>,
}

/// Outcome of one change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushStatus {
    /// Stored at `revision`.
    Ok,
    /// `base_revision` is stale; `current` holds the server's item.
    Conflict,
    /// The caller may not write this item.
    Forbidden,
    /// Envelope, quota or vault cap exceeded; see `message`.
    TooLarge,
}

/// Result of one change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushResult {
    /// Item id.
    pub id: Uuid,
    /// Outcome.
    pub status: PushStatus,
    /// The new revision ([`PushStatus::Ok`] only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<u64>,
    /// The server's item ([`PushStatus::Conflict`] only; `None` = absent on the server).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<RemoteItem>,
    /// [`PushStatus::TooLarge`]: one of the `*_MESSAGE` constants of [`crate::error`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Response of a push: same order and length as the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushResponse {
    /// One result per change.
    pub results: Vec<PushResult>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn permission_order_and_can_write() {
        assert!(Permission::Read < Permission::Write);
        assert!(Permission::Write < Permission::Manage);
        assert!(!Permission::Read.can_write());
        assert!(Permission::Write.can_write());
        assert!(Permission::Manage.can_write());
        for p in [Permission::Read, Permission::Write, Permission::Manage] {
            assert_eq!(Permission::parse(p.as_str()), Some(p));
            assert_eq!(
                serde_json::to_string(&p).unwrap(),
                format!("\"{}\"", p.as_str())
            );
        }
        for k in [VaultKind::Personal, VaultKind::Team] {
            assert_eq!(VaultKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(Permission::parse("Read"), None);
        assert_eq!(VaultKind::parse(""), None);
    }

    #[test]
    fn unknown_fields_ignored() {
        let v: VaultView = serde_json::from_value(serde_json::json!({
            "id": Uuid::nil(),
            "kind": "team",
            "org_id": Uuid::nil(),
            "name_enc": "AQ",
            "key_version": 1,
            "head_revision": 0,
            "permission": "write",
            "grants": [],
            "foo": {"bar": 1},
        }))
        .unwrap();
        assert_eq!(v.kind, VaultKind::Team);
        assert!(v.rotation.is_none());
    }

    #[test]
    fn deleted_and_since_default() {
        let item: RemoteItem = serde_json::from_value(serde_json::json!({
            "id": Uuid::nil(), "revision": 1, "key_version": 1, "envelope": "AQ"
        }))
        .unwrap();
        assert!(!item.deleted);
        let q: PullQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q, PullQuery::default());
    }
}
