//! Shared vaults: create, members, grants (T86 server, T89 client).
//!
//! | Endpoint | Request | Response |
//! |---|---|---|
//! | `POST /v1/vaults` | [`CreateVaultRequest`] | [`crate::sync::VaultView`] |
//! | `GET /v1/vaults/{id}/members` | – | [`VaultMembersView`] |
//! | `PUT /v1/vaults/{id}/members/{user}` | [`GrantRequest`] | 204 |
//! | `DELETE /v1/vaults/{id}/members/{user}` | – | 204 |
//! | `GET /v1/orgs/{id}/vaults` | – | `[`[`OrgVaultView`]`]` |
//!
//! The server never holds a vault key: a shared vault is created with the
//! creator's **self-grant** (`manage`), and every other member is granted by a
//! `manage` member's client, which HPKE-wraps the key to the member's pinned
//! X25519 key and signs the wrap (`courier_ftp_crypto::grant`). Org owners and
//! admins implicitly have `manage` on every org vault: they may grant and
//! revoke, and a vault they hold no key for is listed by
//! `GET /v1/orgs/{id}/vaults` with `has_key = false` ("needs key") until a
//! `manage` member's client grants it. Revoking a member is followed by a key
//! rotation ([`crate::rotation`]).
//!
//! Errors ([`crate::ErrorEnvelope`]): `404 not_found` for a vault or org the
//! caller can't see, `403 forbidden` when the caller may not create, grant or
//! revoke, `400 invalid` for a grant to a non-member, a stale key version or a
//! `name_enc` over [`crate::limits::MAX_NAME_ENC_BYTES`], `409 conflict` for a
//! vault id that exists.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::GrantUpload;
use crate::orgs::Role;
use crate::sync::Permission;

/// `POST /v1/vaults`: create a shared vault (org admin or owner).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateVaultRequest {
    /// Client-generated UUIDv7.
    pub id: Uuid,
    /// The owning org.
    pub org_id: Uuid,
    /// The vault name sealed under the vault key.
    #[serde(with = "crate::b64")]
    pub name_enc: Vec<u8>,
    /// The creator's self-grant (permission `manage`).
    pub self_grant: GrantUpload,
}

/// `PUT /v1/vaults/{id}/members/{user}`: grant (or change) access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRequest {
    /// The member's permission.
    pub permission: Permission,
    /// The vault key version wrapped (the vault's current one).
    pub key_version: u32,
    /// The vault key HPKE-wrapped to the member's X25519 key.
    #[serde(with = "crate::b64")]
    pub wrapped_vault_key: Vec<u8>,
    /// The granter's Ed25519 signature over the canonical grant.
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
}

/// One org member as seen from a shared vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMemberView {
    /// The user.
    pub user_id: Uuid,
    /// Their email.
    #[serde(default)]
    pub email: Option<String>,
    /// Their org role.
    pub org_role: Role,
    /// Their explicit vault permission (`None`: no grant).
    #[serde(default)]
    pub permission: Option<Permission>,
    /// They hold a grant for the vault's **current** key version.
    pub has_key: bool,
    /// Who granted their newest grant.
    #[serde(default)]
    pub granted_by: Option<Uuid>,
}

impl VaultMemberView {
    /// The permission in effect: the explicit one, or `manage` for org owners
    /// and admins.
    #[must_use]
    pub fn effective(&self) -> Option<Permission> {
        if self.org_role >= Role::Admin {
            Some(Permission::Manage)
        } else {
            self.permission
        }
    }
}

/// `GET /v1/vaults/{id}/members`: every member of the owning org with their
/// vault permission. **Untrusted** on the client: it can only narrow trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMembersView {
    /// The vault.
    pub vault_id: Uuid,
    /// The owning org.
    pub org_id: Uuid,
    /// The vault's current key version.
    pub key_version: u32,
    /// The user whose self-grant created the vault (TOFU-trusted granter).
    #[serde(default)]
    pub created_by: Option<Uuid>,
    /// The org's members, by email.
    pub members: Vec<VaultMemberView>,
}

/// An element of `GET /v1/orgs/{id}/vaults`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgVaultView {
    /// The vault.
    pub id: Uuid,
    /// The vault name sealed under the vault key.
    #[serde(with = "crate::b64")]
    pub name_enc: Vec<u8>,
    /// Current key version.
    pub key_version: u32,
    /// The caller's effective permission (`manage` for org owners and admins).
    pub permission: Permission,
    /// The caller holds a grant for the current key version (`false`: "needs key").
    pub has_key: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admins_manage_implicitly() {
        let mut m = VaultMemberView {
            user_id: Uuid::nil(),
            email: None,
            org_role: Role::Member,
            permission: Some(Permission::Read),
            has_key: true,
            granted_by: None,
        };
        assert_eq!(m.effective(), Some(Permission::Read));
        m.org_role = Role::Admin;
        assert_eq!(m.effective(), Some(Permission::Manage));
        m.org_role = Role::Member;
        m.permission = None;
        assert_eq!(m.effective(), None);
    }
}
