//! Orgs, members, invites and the audit log (T89).
//!
//! | Endpoint | Request | Response |
//! |---|---|---|
//! | `POST /v1/orgs` | [`CreateOrgRequest`] | 201 [`OrgView`] |
//! | `GET /v1/orgs` | – | `[`[`OrgView`]`]` |
//! | `GET /v1/orgs/{id}/members` | – | `[`[`MemberView`]`]` |
//! | `PATCH /v1/orgs/{id}/members/{user}` | [`UpdateMemberRequest`] | 204 |
//! | `DELETE /v1/orgs/{id}/members/{user}` | – | 204 |
//! | `POST /v1/orgs/{id}/invites` | [`CreateInviteRequest`] | 201 [`InviteCreated`] |
//! | `POST /v1/invites/{token}/accept` | – | [`InviteAccepted`] |
//! | `GET /v1/orgs/{id}/audit?before=&limit=` | [`AuditQuery`] | [`AuditPage`] |

use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::redact_opt;

/// An org member's role. Ordered by power: `Member < Admin < Owner`. Wire: lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Sees the vaults granted to them.
    Member,
    /// Manages members, invites and every vault.
    Admin,
    /// Admin, plus owner changes and org deletion.
    Owner,
}

impl Role {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Admin => "admin",
            Self::Owner => "owner",
        }
    }

    /// Parses the wire spelling.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "member" => Some(Self::Member),
            "admin" => Some(Self::Admin),
            "owner" => Some(Self::Owner),
            _ => None,
        }
    }
}

/// `POST /v1/orgs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateOrgRequest {
    /// Display name (1–100 chars, see [`crate::validate::validate_org_name`]).
    pub name: String,
}

/// An org as seen by a member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgView {
    /// Org id.
    pub id: Uuid,
    /// Display name.
    pub name: String,
    /// The caller's role.
    pub role: Role,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// One org member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberView {
    /// The member.
    pub user_id: Uuid,
    /// Their email.
    pub email: String,
    /// Their role.
    pub role: Role,
}

/// `PATCH /v1/orgs/{id}/members/{user}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateMemberRequest {
    /// The new role.
    pub role: Role,
}

/// `POST /v1/orgs/{id}/invites`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateInviteRequest {
    /// Invitee email: the invite is mailed (when SMTP is configured) and bound to it.
    /// `None` makes an open link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Role on acceptance.
    pub role: Role,
}

/// A created invite.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteCreated {
    /// Invite id.
    pub id: Uuid,
    /// The org.
    pub org_id: Uuid,
    /// Invitee email, if bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Role on acceptance.
    pub role: Role,
    /// Expiry ([`crate::limits::INVITE_TTL_SECS`] after creation).
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// `<public_url>/invite/<token>`. Secret (contains the token).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    /// Whether the invite was mailed.
    pub emailed: bool,
}

impl fmt::Debug for InviteCreated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InviteCreated")
            .field("id", &self.id)
            .field("org_id", &self.org_id)
            .field("email", &self.email)
            .field("role", &self.role)
            .field("expires_at", &self.expires_at)
            .field("link", &redact_opt(self.link.as_ref()))
            .field("emailed", &self.emailed)
            .finish()
    }
}

/// Response of `POST /v1/invites/{token}/accept`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteAccepted {
    /// The org joined.
    pub org_id: Uuid,
    /// The role received.
    pub role: Role,
}

/// Query of `GET /v1/orgs/{id}/audit`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditQuery {
    /// Return events with `id < before` (newest first); `None` = from the newest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<i64>,
    /// Page size; capped at [`crate::limits::MAX_AUDIT_PAGE`], default
    /// [`crate::limits::DEFAULT_AUDIT_PAGE`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// One audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEventView {
    /// Event id (monotonic).
    pub id: i64,
    /// One of [`audit_kind`].
    pub kind: String,
    /// Who did it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<Uuid>,
    /// Whom or what it concerned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<Uuid>,
    /// When.
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    /// Object with ids, roles and counts only (never secrets or names).
    pub meta: serde_json::Value,
}

/// A page of audit events, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditPage {
    /// The events.
    pub events: Vec<AuditEventView>,
    /// `before` of the next page; `None` = last page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_before: Option<i64>,
}

/// Audit event kinds ([`AuditEventView::kind`]).
pub mod audit_kind {
    /// An org was created.
    pub const ORG_CREATED: &str = "org.created";
    /// An account was deleted (`org_id` NULL).
    pub const ACCOUNT_DELETED: &str = "account.deleted";
    /// A rotated-out refresh token was presented again (`org_id` NULL).
    pub const REFRESH_TOKEN_REUSE: &str = "auth.refresh_token_reuse";
    /// A member joined.
    pub const MEMBER_ADDED: &str = "member.added";
    /// A member was removed.
    pub const MEMBER_REMOVED: &str = "member.removed";
    /// A member's role changed.
    pub const MEMBER_ROLE_CHANGED: &str = "member.role_changed";
    /// An invite was created.
    pub const INVITE_SENT: &str = "invite.sent";
    /// An invite was accepted.
    pub const INVITE_ACCEPTED: &str = "invite.accepted";
    /// A team vault was created.
    pub const VAULT_CREATED: &str = "vault.created";
    /// A member was granted access to a vault.
    pub const VAULT_GRANTED: &str = "vault.member_granted";
    /// A member's vault access was revoked.
    pub const VAULT_REVOKED: &str = "vault.member_revoked";
    /// A vault key was rotated.
    pub const VAULT_ROTATED: &str = "vault.rotated";
    /// Items were pushed; meta: `{"vault_id", "item_ids": [..≤500]}`.
    pub const ITEMS_PUSHED: &str = "vault.items_pushed";
    /// A device was added.
    pub const DEVICE_ADDED: &str = "device.added";
    /// A device was revoked.
    pub const DEVICE_REVOKED: &str = "device.revoked";
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn roles() {
        assert!(Role::Member < Role::Admin && Role::Admin < Role::Owner);
        for r in [Role::Member, Role::Admin, Role::Owner] {
            assert_eq!(Role::parse(r.as_str()), Some(r));
            assert_eq!(
                serde_json::to_string(&r).unwrap(),
                format!("\"{}\"", r.as_str())
            );
        }
    }

    #[test]
    fn invite_request_email_is_optional() {
        let r: CreateInviteRequest = serde_json::from_str(r#"{"role":"admin"}"#).unwrap();
        assert_eq!(r.email, None);
        assert_eq!(serde_json::to_string(&r).unwrap(), r#"{"role":"admin"}"#);
    }
}
