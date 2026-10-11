//! The team endpoints of [`ApiClient`] (T89): orgs, members, invites, the
//! audit log, user public keys, shared vaults and key rotation. DTOs in
//! [`courier_ftp_proto::orgs`], [`courier_ftp_proto::users`],
//! [`courier_ftp_proto::vaults`] and [`courier_ftp_proto::rotation`].
//!
//! Adapted from sverb's `sverb-sync/src/http/{shared_vaults,rotation}.rs`
//! and the org calls of `sverb-sync/src/http.rs`.

use courier_ftp_proto::orgs::{
    AuditPage, CreateInviteRequest, CreateOrgRequest, InviteAccepted, InviteCreated, MemberView,
    OrgView, Role, UpdateMemberRequest,
};
use courier_ftp_proto::rotation::{RotateRequest, RotateResponse};
use courier_ftp_proto::sync::VaultView;
use courier_ftp_proto::users::UserPublicKeys;
use courier_ftp_proto::vaults::{CreateVaultRequest, GrantRequest, OrgVaultView, VaultMembersView};
use secrecy::SecretString;
use uuid::Uuid;

use super::ApiClient;
use crate::error::SyncError;

impl ApiClient {
    /// `GET /v1{path}` with a JSON response.
    async fn get_v1<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        token: &SecretString,
    ) -> Result<T, SyncError> {
        let rb = Self::authed(self.http.get(self.url(path)), token);
        self.send(rb).await
    }

    /// `POST /v1/orgs`: creates an org; the caller becomes its owner.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`400` bad name) / [`SyncError::Transport`].
    pub async fn create_org(&self, token: &SecretString, name: &str) -> Result<OrgView, SyncError> {
        let req = CreateOrgRequest {
            name: name.to_owned(),
        };
        self.post_v1("/orgs", &req, Some(token)).await
    }

    /// `GET /v1/orgs`: the caller's orgs with their role.
    ///
    /// # Errors
    /// [`SyncError::Api`] / [`SyncError::Transport`].
    pub async fn list_orgs(&self, token: &SecretString) -> Result<Vec<OrgView>, SyncError> {
        self.get_v1("/orgs", token).await
    }

    /// `GET /v1/orgs/{id}/members`.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`404` not a member) / [`SyncError::Transport`].
    pub async fn org_members(
        &self,
        token: &SecretString,
        org: Uuid,
    ) -> Result<Vec<MemberView>, SyncError> {
        self.get_v1(&format!("/orgs/{org}/members"), token).await
    }

    /// `PATCH /v1/orgs/{id}/members/{user}`: changes a member's role.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`403`, `400` last owner, `404`) /
    /// [`SyncError::Transport`].
    pub async fn set_member_role(
        &self,
        token: &SecretString,
        org: Uuid,
        user: Uuid,
        role: Role,
    ) -> Result<(), SyncError> {
        let url = self.url(&format!("/orgs/{org}/members/{user}"));
        let rb = Self::authed(
            self.http.patch(url).json(&UpdateMemberRequest { role }),
            token,
        );
        self.fetch(rb).await.map(drop)
    }

    /// `DELETE /v1/orgs/{id}/members/{user}`: removes a member (or leaves,
    /// for the caller's own id). Their vault grants in the org are revoked.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`403`, `400` last owner, `404`) /
    /// [`SyncError::Transport`].
    pub async fn remove_org_member(
        &self,
        token: &SecretString,
        org: Uuid,
        user: Uuid,
    ) -> Result<(), SyncError> {
        self.delete_v1::<()>(&format!("/orgs/{org}/members/{user}"), None, token)
            .await
    }

    /// `POST /v1/orgs/{id}/invites`.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`403`, `404`) / [`SyncError::Transport`].
    pub async fn create_invite(
        &self,
        token: &SecretString,
        org: Uuid,
        req: &CreateInviteRequest,
    ) -> Result<InviteCreated, SyncError> {
        self.post_v1(&format!("/orgs/{org}/invites"), req, Some(token))
            .await
    }

    /// `POST /v1/invites/{token}/accept`.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`404` unknown, used or expired, `403` bound to
    /// another email) / [`SyncError::Transport`].
    pub async fn accept_invite(
        &self,
        token: &SecretString,
        invite: &str,
    ) -> Result<InviteAccepted, SyncError> {
        self.post_v1(
            &format!("/invites/{invite}/accept"),
            &serde_json::json!({}),
            Some(token),
        )
        .await
    }

    /// `GET /v1/orgs/{id}/audit?before=&limit=` (org admins).
    ///
    /// # Errors
    /// [`SyncError::Api`] (`403`, `404`) / [`SyncError::Transport`].
    pub async fn org_audit(
        &self,
        token: &SecretString,
        org: Uuid,
        before: Option<i64>,
        limit: u32,
    ) -> Result<AuditPage, SyncError> {
        let mut path = format!("/orgs/{org}/audit?limit={limit}");
        if let Some(b) = before {
            path.push_str(&format!("&before={b}"));
        }
        self.get_v1(&path, token).await
    }

    /// `GET /v1/users/{id}/public-keys` (users sharing an org with the
    /// caller). **Untrusted**: pin them (`crate::trust`).
    ///
    /// # Errors
    /// [`SyncError::Api`] (`404`) / [`SyncError::Transport`].
    pub async fn user_public_keys(
        &self,
        token: &SecretString,
        user: Uuid,
    ) -> Result<UserPublicKeys, SyncError> {
        self.get_v1(&format!("/users/{user}/public-keys"), token)
            .await
    }

    /// `POST /v1/vaults`: creates a shared vault (org admin+).
    ///
    /// # Errors
    /// [`SyncError::Api`] (`403`, `404`, `409`) / [`SyncError::Transport`].
    pub async fn create_vault(
        &self,
        token: &SecretString,
        req: &CreateVaultRequest,
    ) -> Result<VaultView, SyncError> {
        self.post_v1("/vaults", req, Some(token)).await
    }

    /// `GET /v1/vaults/{id}/members`. **Untrusted**: it only narrows trust.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`404`) / [`SyncError::Transport`].
    pub async fn vault_members(
        &self,
        token: &SecretString,
        vault: Uuid,
    ) -> Result<VaultMembersView, SyncError> {
        self.get_v1(&format!("/vaults/{vault}/members"), token)
            .await
    }

    /// `PUT /v1/vaults/{id}/members/{user}`: grants or changes access.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`403`, `400`, `409 rotating`) /
    /// [`SyncError::Transport`].
    pub async fn grant_vault_member(
        &self,
        token: &SecretString,
        vault: Uuid,
        user: Uuid,
        req: &GrantRequest,
    ) -> Result<(), SyncError> {
        let url = self.url(&format!("/vaults/{vault}/members/{user}"));
        let rb = Self::authed(self.http.put(url).json(req), token);
        self.fetch(rb).await.map(drop)
    }

    /// `DELETE /v1/vaults/{id}/members/{user}` (also leaving: `user` = self).
    ///
    /// # Errors
    /// [`SyncError::Api`] (`403`, `404`) / [`SyncError::Transport`].
    pub async fn revoke_vault_member(
        &self,
        token: &SecretString,
        vault: Uuid,
        user: Uuid,
    ) -> Result<(), SyncError> {
        self.delete_v1::<()>(&format!("/vaults/{vault}/members/{user}"), None, token)
            .await
    }

    /// `GET /v1/orgs/{id}/vaults`: the org's vaults visible to the caller.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`404`) / [`SyncError::Transport`].
    pub async fn org_vaults(
        &self,
        token: &SecretString,
        org: Uuid,
    ) -> Result<Vec<OrgVaultView>, SyncError> {
        self.get_v1(&format!("/orgs/{org}/vaults"), token).await
    }

    /// `POST /v1/vaults/{id}/rotate`: one rotate action.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`400`, `403`, `404`, `409 rotating`) /
    /// [`SyncError::Transport`].
    pub async fn rotate(
        &self,
        token: &SecretString,
        vault: Uuid,
        req: &RotateRequest,
    ) -> Result<RotateResponse, SyncError> {
        self.post_v1(&format!("/vaults/{vault}/rotate"), req, Some(token))
            .await
    }
}
