//! Team vault creation, members and grants (T89).
//!
//! | Endpoint | Request | Response |
//! |---|---|---|
//! | `POST /v1/vaults` | [`CreateVaultRequest`] | 201 [`crate::sync::VaultView`] |
//! | `GET /v1/vaults/{id}/members` | – | [`VaultMembersView`] |
//! | `PUT /v1/vaults/{id}/members/{user}` | [`GrantRequest`] | 204 |
//! | `DELETE /v1/vaults/{id}/members/{user}` | – | 204 |
//! | `GET /v1/orgs/{id}/vaults` | – | `[`[`OrgVaultView`]`]` |

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::GrantUpload;
use crate::orgs::Role;
use crate::sync::Permission;

/// `POST /v1/vaults`: a new team vault; the creator gets `manage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateVaultRequest {
    /// Client-generated vault id.
    pub id: Uuid,
    /// The owning org.
    pub org_id: Uuid,
    /// Vault name sealed under the vault key.
    #[serde(with = "crate::b64")]
    pub name_enc: Vec<u8>,
    /// The creator's self-grant.
    pub self_grant: GrantUpload,
}

/// `PUT /v1/vaults/{id}/members/{user}`: grant (or change) a member's access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRequest {
    /// The permission.
    pub permission: Permission,
    /// The vault key version wrapped (must be the current one).
    pub key_version: u32,
    /// The vault key wrapped to the member (T80 grant wire format).
    #[serde(with = "crate::b64")]
    pub wrapped_vault_key: Vec<u8>,
    /// The granter's Ed25519 signature.
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
}

/// One org member as seen from a vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMemberView {
    /// The member.
    pub user_id: Uuid,
    /// Their email (display only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Their org role.
    pub org_role: Role,
    /// Explicit grant; `None` = no grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission: Option<Permission>,
    /// Holds a grant for the current key version.
    #[serde(default)]
    pub has_key: bool,
    /// Who granted it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_by: Option<Uuid>,
}

impl VaultMemberView {
    /// The permission in effect: `Manage` for org owners and admins, otherwise the
    /// explicit one.
    #[must_use]
    pub fn effective(&self) -> Option<Permission> {
        if self.org_role >= Role::Admin {
            Some(Permission::Manage)
        } else {
            self.permission
        }
    }
}

/// `GET /v1/vaults/{id}/members` (untrusted on the client).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMembersView {
    /// The vault.
    pub vault_id: Uuid,
    /// Its org.
    pub org_id: Uuid,
    /// Current vault key version.
    pub key_version: u32,
    /// The creator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<Uuid>,
    /// Every org member.
    pub members: Vec<VaultMemberView>,
}

/// One entry of `GET /v1/orgs/{id}/vaults`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgVaultView {
    /// Vault id.
    pub id: Uuid,
    /// Vault name sealed under the vault key.
    #[serde(with = "crate::b64")]
    pub name_enc: Vec<u8>,
    /// Current vault key version.
    pub key_version: u32,
    /// The caller's effective permission.
    pub permission: Permission,
    /// The caller holds a grant for the current key version.
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
            permission: None,
            has_key: false,
            granted_by: None,
        };
        assert_eq!(m.effective(), None);
        m.permission = Some(Permission::Read);
        assert_eq!(m.effective(), Some(Permission::Read));
        m.org_role = Role::Admin;
        assert_eq!(m.effective(), Some(Permission::Manage));
        m.org_role = Role::Owner;
        m.permission = None;
        assert_eq!(m.effective(), Some(Permission::Manage));
    }
}
