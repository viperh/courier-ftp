//! Vault list, pull and push DTOs (T85 server, T88 client).
//!
//! Binary fields (envelopes, wrapped keys, signatures, encrypted names) are
//! base64url without padding ([`crate::b64`]). Revisions are per vault,
//! gap-free and start at 1; `0` means "nothing yet" (a pull cursor of 0, or
//! the base revision of an item the client believes is new). Envelopes are
//! `courier_ftp_crypto::envelope` sealed `ItemBody`s, bound by AAD to the vault
//! id, item id and key version.
//!
//! | Endpoint | Request | Response |
//! |---|---|---|
//! | `GET /v1/vaults` | – | `[`[`VaultView`]`]` |
//! | `GET /v1/vaults/{id}/changes?since=&limit=` | [`PullQuery`] | [`PullResponse`] |
//! | `POST /v1/vaults/{id}/changes` | [`PushRequest`] | [`PushResponse`] |
//!
//! Errors ([`crate::ErrorEnvelope`]):
//! * `404 not_found`: unknown vault **or** not a member (existence is not
//!   revealed);
//! * `410 gone` (pull): `since` is non-zero and below the vault's GC floor;
//!   the client resyncs from `since=0`;
//! * `403 forbidden` (push): the caller only has `read` permission;
//! * `409 rotating` (push): a key rotation is in progress;
//! * `400 invalid` (push): [`PushRequest::check_limits`] fails, or a change's
//!   `key_version` is not the vault's current one (the client has a stale
//!   vault key and must refresh `GET /v1/vaults` first).
//!
//! Per-item outcomes are in [`PushResult`]; see [`PushStatus`].

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::limits::{LimitError, MAX_ENVELOPE, MAX_PULL_LIMIT, MAX_PUSH_BYTES, MAX_PUSH_ITEMS};

/// [`PushResult::message`] of a change rejected because it would exceed the
/// storage quota (status [`PushStatus::TooLarge`]).
pub const QUOTA_EXCEEDED_MESSAGE: &str = "quota exceeded";

/// [`PushResult::message`] of a change whose envelope exceeds
/// [`MAX_ENVELOPE`] (status [`PushStatus::TooLarge`]).
pub const ENVELOPE_TOO_LARGE_MESSAGE: &str = "envelope exceeds 1 MiB";

// ------------------------------------------------------------------ vaults

/// The kind of a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultKind {
    /// The user's own vault (created at registration).
    Personal,
    /// An org vault (T89).
    Shared,
}

impl VaultKind {
    /// The wire / database spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Shared => "shared",
        }
    }

    /// Parses the wire / database spelling.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "personal" => Some(Self::Personal),
            "shared" => Some(Self::Shared),
            _ => None,
        }
    }
}

/// A member's permission on a vault. Ordered: `Read < Write < Manage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Pull only; pushes are rejected with `403 forbidden`.
    Read,
    /// Pull and push.
    Write,
    /// Pull, push, grant, revoke and rotate.
    Manage,
}

impl Permission {
    /// The wire / database spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Manage => "manage",
        }
    }

    /// Parses the wire / database spelling.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "manage" => Some(Self::Manage),
            _ => None,
        }
    }

    /// Whether this permission may push.
    #[must_use]
    pub const fn can_write(self) -> bool {
        matches!(self, Self::Write | Self::Manage)
    }
}

/// One wrapped vault key of the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultGrant {
    /// Key version this wrap is for.
    pub key_version: u32,
    /// The vault key HPKE-wrapped to the caller's X25519 key.
    #[serde(with = "crate::b64")]
    pub wrapped_vault_key: Vec<u8>,
    /// The granting user (verify `signature` with their pinned Ed25519 key).
    pub wrapped_by: Uuid,
    /// Ed25519 signature by the granter.
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
}

impl VaultGrant {
    /// As a `courier_ftp_crypto::grant::Grant` for `verify_and_open_grant`.
    ///
    /// # Errors
    /// The signature is not 64 bytes.
    pub fn to_grant(&self) -> Result<courier_ftp_crypto::grant::Grant, LimitError> {
        crate::auth::grant_from_parts(&self.wrapped_vault_key, &self.signature)
    }
}

/// A key rotation in progress (see [`crate::rotation`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationView {
    /// The key version the rotation will commit.
    pub new_key_version: u32,
    /// The user running the rotation.
    pub by: Uuid,
    /// When it began.
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    /// Older than [`crate::rotation::ROTATION_ABANDON_SECS`]: the next
    /// `manage` client should restart it.
    #[serde(default)]
    pub abandoned: bool,
}

/// An element of `GET /v1/vaults`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultView {
    /// Vault id.
    pub id: Uuid,
    /// Personal or shared.
    pub kind: VaultKind,
    /// The owning org (shared vaults).
    #[serde(default)]
    pub org_id: Option<Uuid>,
    /// Vault name encrypted under the vault key.
    #[serde(with = "crate::b64")]
    pub name_enc: Vec<u8>,
    /// Current key version: pushes must use it.
    pub key_version: u32,
    /// Highest assigned revision.
    pub head_revision: u64,
    /// The caller's permission.
    pub permission: Permission,
    /// The caller's wrapped keys, every key version still present
    /// (several during a rotation), ascending.
    pub grants: Vec<VaultGrant>,
    /// Present while a key rotation is in progress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation: Option<RotationView>,
}

// -------------------------------------------------------------------- pull

/// Query of `GET /v1/vaults/{id}/changes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PullQuery {
    /// The client's cursor: return revisions strictly greater (default 0).
    #[serde(default)]
    pub since: u64,
    /// Page size, 1..=[`MAX_PULL_LIMIT`] (default and cap
    /// [`MAX_PULL_LIMIT`]; larger values are clamped, 0 is rejected).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

impl PullQuery {
    /// The page size the server uses.
    ///
    /// # Errors
    /// [`LimitError::ZeroPullLimit`].
    pub fn effective_limit(&self) -> Result<u32, LimitError> {
        match self.limit {
            None => Ok(MAX_PULL_LIMIT),
            Some(0) => Err(LimitError::ZeroPullLimit),
            Some(n) => Ok(n.min(MAX_PULL_LIMIT)),
        }
    }
}

/// An item as stored on the server (pull page entry, and
/// [`PushResult::current`] on conflict).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteItem {
    /// Item id (`courier_ftp_core::model::item::ItemId`).
    pub id: Uuid,
    /// The revision assigned when this version was pushed.
    pub revision: u64,
    /// Key version the envelope is sealed under.
    pub key_version: u32,
    /// The sealed item.
    #[serde(with = "crate::b64")]
    pub envelope: Vec<u8>,
    /// Tombstone (the envelope still carries the delete stamp for merging).
    #[serde(default)]
    pub deleted: bool,
}

/// Response of `GET /v1/vaults/{id}/changes`.
///
/// `items` is ordered by `revision` ascending, all `> since`. When `more` is
/// `false` the page reached the end of a consistent snapshot and the client
/// sets its cursor to `head_revision`; otherwise it sets the cursor to the
/// last item's revision and pulls again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullResponse {
    /// The page.
    pub items: Vec<RemoteItem>,
    /// The vault's head revision in the same snapshot.
    pub head_revision: u64,
    /// More items after this page.
    pub more: bool,
}

impl PullResponse {
    /// The cursor to store after applying this page.
    #[must_use]
    pub fn next_cursor(&self, since: u64) -> u64 {
        if self.more {
            self.items.last().map_or(since, |i| i.revision)
        } else {
            self.head_revision.max(since)
        }
    }
}

// -------------------------------------------------------------------- push

/// One change of a push.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushChange {
    /// Item id (client-generated).
    pub id: Uuid,
    /// The server revision this change is based on (0 for a new item).
    pub base_revision: u64,
    /// Must equal the vault's current key version.
    pub key_version: u32,
    /// The sealed item.
    #[serde(with = "crate::b64")]
    pub envelope: Vec<u8>,
    /// Tombstone.
    #[serde(default)]
    pub deleted: bool,
}

impl PushChange {
    /// Whether the envelope exceeds [`MAX_ENVELOPE`] (the server answers
    /// [`PushStatus::TooLarge`] for it).
    #[must_use]
    pub fn is_too_large(&self) -> bool {
        self.envelope.len() > MAX_ENVELOPE
    }
}

/// Body of `POST /v1/vaults/{id}/changes`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PushRequest {
    /// The batch, applied in one transaction, revisions assigned in order.
    pub changes: Vec<PushChange>,
}

impl PushRequest {
    /// Checks the whole-request limits: at most [`MAX_PUSH_ITEMS`] changes,
    /// at most [`MAX_PUSH_BYTES`] of envelopes, no item twice. Single
    /// envelopes over [`MAX_ENVELOPE`] are not an error here; they get a
    /// per-item [`PushStatus::TooLarge`].
    ///
    /// # Errors
    /// The first limit violated.
    pub fn check_limits(&self) -> Result<(), LimitError> {
        if self.changes.len() > MAX_PUSH_ITEMS {
            return Err(LimitError::TooManyItems {
                got: self.changes.len(),
            });
        }
        let bytes: usize = self.changes.iter().map(|c| c.envelope.len()).sum();
        if bytes > MAX_PUSH_BYTES {
            return Err(LimitError::TooManyBytes { got: bytes });
        }
        let mut seen = HashSet::with_capacity(self.changes.len());
        for c in &self.changes {
            if !seen.insert(c.id) {
                return Err(LimitError::DuplicateItem(c.id));
            }
        }
        Ok(())
    }

    /// Splits changes into requests that each pass [`Self::check_limits`]
    /// (client side). Order is kept; a change whose id is already in the
    /// current batch starts a new one.
    #[must_use]
    pub fn batches(changes: Vec<PushChange>) -> Vec<Self> {
        let mut out = Vec::new();
        let mut cur = Self::default();
        let mut bytes = 0usize;
        let mut ids = HashSet::new();
        for c in changes {
            let len = c.envelope.len();
            let full = cur.changes.len() >= MAX_PUSH_ITEMS
                || bytes + len > MAX_PUSH_BYTES
                || ids.contains(&c.id);
            if full && !cur.changes.is_empty() {
                out.push(std::mem::take(&mut cur));
                bytes = 0;
                ids.clear();
            }
            bytes += len;
            ids.insert(c.id);
            cur.changes.push(c);
        }
        if !cur.changes.is_empty() {
            out.push(cur);
        }
        out
    }
}

/// Per-change outcome of a push.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushStatus {
    /// Accepted; [`PushResult::revision`] is the new revision.
    Ok,
    /// `base_revision` is stale; [`PushResult::current`] is the server's
    /// version (absent when the item does not exist on the server, e.g. its
    /// tombstone was purged: push it again with `base_revision = 0`).
    Conflict,
    /// Reserved for per-item ACLs (a `read` member gets a whole-request 403).
    Forbidden,
    /// The envelope exceeds [`MAX_ENVELOPE`], or accepting it would exceed
    /// the storage quota ([`PushResult::message`] says which).
    TooLarge,
}

/// One element of [`PushResponse::results`], in request order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushResult {
    /// Item id.
    pub id: Uuid,
    /// Outcome.
    pub status: PushStatus,
    /// New revision (`ok` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<u64>,
    /// The server's current item (`conflict` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<RemoteItem>,
    /// Human-readable detail (`too_large`: [`QUOTA_EXCEEDED_MESSAGE`] or
    /// [`ENVELOPE_TOO_LARGE_MESSAGE`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl PushResult {
    /// An accepted change.
    #[must_use]
    pub const fn ok(id: Uuid, revision: u64) -> Self {
        Self {
            id,
            status: PushStatus::Ok,
            revision: Some(revision),
            current: None,
            message: None,
        }
    }

    /// A stale change, with the server's current version if it has one.
    #[must_use]
    pub const fn conflict(id: Uuid, current: Option<RemoteItem>) -> Self {
        Self {
            id,
            status: PushStatus::Conflict,
            revision: None,
            current,
            message: None,
        }
    }

    /// A change refused for size or quota.
    #[must_use]
    pub fn too_large(id: Uuid, message: &str) -> Self {
        Self {
            id,
            status: PushStatus::TooLarge,
            revision: None,
            current: None,
            message: Some(message.into()),
        }
    }
}

/// Response of `POST /v1/vaults/{id}/changes`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PushResponse {
    /// One result per change, in request order.
    pub results: Vec<PushResult>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn change(id: u128, len: usize) -> PushChange {
        PushChange {
            id: Uuid::from_u128(id),
            base_revision: 0,
            key_version: 1,
            envelope: vec![0; len],
            deleted: false,
        }
    }

    #[test]
    fn deleted_defaults_to_false() {
        let c: PushChange = serde_json::from_str(&format!(
            r#"{{"id":"{}","base_revision":3,"key_version":2,"envelope":"AQ"}}"#,
            Uuid::nil()
        ))
        .unwrap();
        assert!(!c.deleted);
        assert_eq!(c.envelope, vec![1]);
    }

    #[test]
    fn permissions_and_kinds() {
        assert!(Permission::Read < Permission::Write && Permission::Write < Permission::Manage);
        assert!(!Permission::Read.can_write() && Permission::Write.can_write());
        for p in [Permission::Read, Permission::Write, Permission::Manage] {
            assert_eq!(Permission::parse(p.as_str()), Some(p));
        }
        for k in [VaultKind::Personal, VaultKind::Shared] {
            assert_eq!(VaultKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(Permission::parse("root"), None);
    }

    #[test]
    fn pull_query_limits() {
        let q: PullQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q, PullQuery::default());
        assert_eq!(q.effective_limit(), Ok(MAX_PULL_LIMIT));
        let q = PullQuery {
            since: 0,
            limit: Some(10_000),
        };
        assert_eq!(q.effective_limit(), Ok(MAX_PULL_LIMIT));
        let q = PullQuery {
            since: 0,
            limit: Some(0),
        };
        assert_eq!(q.effective_limit(), Err(LimitError::ZeroPullLimit));
    }

    #[test]
    fn pull_cursor() {
        let item = |revision| RemoteItem {
            id: Uuid::nil(),
            revision,
            key_version: 1,
            envelope: vec![],
            deleted: false,
        };
        let page = PullResponse {
            items: vec![item(3), item(5)],
            head_revision: 9,
            more: true,
        };
        assert_eq!(page.next_cursor(2), 5);
        let last = PullResponse {
            more: false,
            ..page
        };
        assert_eq!(last.next_cursor(2), 9);
    }

    #[test]
    fn push_limits() {
        let ok = PushRequest {
            changes: vec![change(1, 10), change(2, MAX_ENVELOPE + 1)],
        };
        assert_eq!(ok.check_limits(), Ok(()));
        assert!(ok.changes[1].is_too_large());

        let many = PushRequest {
            changes: (0..=MAX_PUSH_ITEMS as u128).map(|i| change(i, 0)).collect(),
        };
        assert_eq!(
            many.check_limits(),
            Err(LimitError::TooManyItems {
                got: MAX_PUSH_ITEMS + 1
            })
        );

        let big = PushRequest {
            changes: (0..9).map(|i| change(i, MAX_ENVELOPE)).collect(),
        };
        assert_eq!(
            big.check_limits(),
            Err(LimitError::TooManyBytes {
                got: 9 * MAX_ENVELOPE
            })
        );

        let dup = PushRequest {
            changes: vec![change(1, 0), change(1, 0)],
        };
        assert_eq!(
            dup.check_limits(),
            Err(LimitError::DuplicateItem(Uuid::from_u128(1)))
        );
    }

    #[test]
    fn batching_respects_every_limit() {
        let mut changes: Vec<_> = (0..1200).map(|i| change(i, 16)).collect();
        changes.extend((2000..2010).map(|i| change(i, MAX_ENVELOPE)));
        changes.push(change(5, 1));
        let total = changes.len();
        let batches = PushRequest::batches(changes);
        assert!(batches.iter().all(|b| b.check_limits().is_ok()));
        assert_eq!(
            batches.iter().map(|b| b.changes.len()).sum::<usize>(),
            total
        );
        assert!(PushRequest::batches(vec![]).is_empty());
    }
}
