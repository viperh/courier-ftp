//! Orgs, members, invites and the audit log (T86 server, T89 client).
//!
//! | Endpoint | Request | Response |
//! |---|---|---|
//! | `POST /v1/orgs` | [`CreateOrgRequest`] | [`OrgView`] |
//! | `GET /v1/orgs` | – | `[`[`OrgView`]`]` |
//! | `GET /v1/orgs/{id}/members` | – | `[`[`MemberView`]`]` |
//! | `PATCH /v1/orgs/{id}/members/{user}` | [`UpdateMemberRequest`] | 204 |
//! | `DELETE /v1/orgs/{id}/members/{user}` | – | 204 |
//! | `POST /v1/orgs/{id}/invites` | [`CreateInviteRequest`] | [`InviteCreated`] |
//! | `POST /v1/invites/{token}/accept` | – | [`InviteAccepted`] |
//! | `GET /v1/orgs/{id}/audit?before=&limit=` | [`AuditQuery`] | [`AuditPage`] |
//!
//! Errors ([`crate::ErrorEnvelope`]): `404 not_found` for an org the caller is
//! not a member of (existence is not revealed), `403 forbidden` for a role
//! that may not do this, `400 invalid` for removing or demoting the last
//! owner.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::limits::MAX_AUDIT_PAGE;

/// Default audit page size.
pub const DEFAULT_AUDIT_PAGE: u32 = 50;

/// Invite lifetime, in seconds (7 days).
pub const INVITE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// A member's role in an org. Ordered by power.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Uses the org vaults it is granted.
    Member,
    /// Invites, changes member/admin, removes members, reads the audit log;
    /// implicitly `manage` on every org vault.
    Admin,
    /// Everything; only owners create or demote owners. Always at least one.
    Owner,
}

impl Role {
    /// The wire / database spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Admin => "admin",
            Self::Owner => "owner",
        }
    }

    /// The inverse of [`Role::as_str`].
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

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `POST /v1/orgs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateOrgRequest {
    /// Display name (1 to [`crate::limits::MAX_ORG_NAME_CHARS`] characters).
    pub name: String,
}

/// An org the caller belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgView {
    /// Org id.
    pub id: Uuid,
    /// Name.
    pub name: String,
    /// The caller's role.
    pub role: Role,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// A member of an org.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberView {
    /// The user.
    pub user_id: Uuid,
    /// Their account email.
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

/// `POST /v1/orgs/{id}/invites`. Without `email` the invite is a single-use
/// link anyone can accept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateInviteRequest {
    /// Bind the invite to this email (it must be accepted by that account).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// The role it grants.
    pub role: Role,
}

/// The created invite. The server stores only a hash of the token.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteCreated {
    /// Invite id.
    pub id: Uuid,
    /// Its org.
    pub org_id: Uuid,
    /// Bound email, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Granted role.
    pub role: Role,
    /// Expiry ([`INVITE_TTL_SECS`] after creation).
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// The link `<public url>/invite/<token>`, unless it was mailed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    /// It was sent by mail (SMTP configured and an email given).
    pub emailed: bool,
}

impl std::fmt::Debug for InviteCreated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InviteCreated")
            .field("id", &self.id)
            .field("org_id", &self.org_id)
            .field("role", &self.role)
            .field("expires_at", &self.expires_at)
            .field("link", &self.link.as_ref().map(|_| "[REDACTED]"))
            .field("emailed", &self.emailed)
            .finish_non_exhaustive()
    }
}

/// Response of `POST /v1/invites/{token}/accept`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteAccepted {
    /// The org joined.
    pub org_id: Uuid,
    /// The role held now (an existing higher role is kept).
    pub role: Role,
}

/// Query of `GET /v1/orgs/{id}/audit`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditQuery {
    /// Only events with an id below this (the previous page's `next_before`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<i64>,
    /// Page size (default [`DEFAULT_AUDIT_PAGE`], at most [`MAX_AUDIT_PAGE`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

impl AuditQuery {
    /// The page size the server uses (0 counts as 1, larger values clamp).
    #[must_use]
    pub fn effective_limit(&self) -> u32 {
        self.limit
            .unwrap_or(DEFAULT_AUDIT_PAGE)
            .clamp(1, MAX_AUDIT_PAGE)
    }
}

/// One audit event (metadata only: never item contents or names).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEventView {
    /// Monotonic id.
    pub id: i64,
    /// What happened (`member.added`, `invite.sent`, `vault.rotated`, ...).
    pub kind: String,
    /// Who did it.
    pub actor: Option<Uuid>,
    /// What it was done to (a user, invite, vault, item or device id).
    pub target: Option<Uuid>,
    /// When.
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    /// Kind-specific details (roles, counts).
    pub meta: serde_json::Value,
}

/// A page of the audit log, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditPage {
    /// Events.
    pub events: Vec<AuditEventView>,
    /// Pass as `before` for the next (older) page; `None` at the end.
    pub next_before: Option<i64>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn roles() {
        assert!(Role::Owner > Role::Admin && Role::Admin > Role::Member);
        for r in [Role::Member, Role::Admin, Role::Owner] {
            assert_eq!(Role::parse(r.as_str()), Some(r));
            assert_eq!(serde_json::to_string(&r).unwrap(), format!("\"{r}\""));
        }
        assert_eq!(Role::parse("root"), None);
    }

    #[test]
    fn invite_request_email_is_optional() {
        let r: CreateInviteRequest = serde_json::from_str(r#"{"role":"admin"}"#).unwrap();
        assert_eq!(r.email, None);
        assert_eq!(r.role, Role::Admin);
    }

    #[test]
    fn audit_limit() {
        assert_eq!(AuditQuery::default().effective_limit(), DEFAULT_AUDIT_PAGE);
        let q = |n| AuditQuery {
            before: None,
            limit: Some(n),
        };
        assert_eq!(q(0).effective_limit(), 1);
        assert_eq!(q(5000).effective_limit(), MAX_AUDIT_PAGE);
    }
}
