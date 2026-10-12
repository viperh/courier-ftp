//! Golden JSON for every DTO: each value is serialised, compared with its
//! `insta` snapshot (the documented wire form) and parsed back.
//!
//! A changed snapshot is a wire-format change: either it is compatible (an
//! added optional field) or [`courier_ftp_proto::version::PROTO_VERSION`]
//! must be bumped.

#![allow(clippy::unwrap_used)]

use std::fmt::Debug;

use courier_ftp_proto::auth::*;
use courier_ftp_proto::orgs::*;
use courier_ftp_proto::rotation::*;
use courier_ftp_proto::sync::*;
use courier_ftp_proto::users::*;
use courier_ftp_proto::vaults::*;
use courier_ftp_proto::ws::*;
use courier_ftp_proto::{ErrorCode, ErrorEnvelope};
use pretty_assertions::assert_eq;
use serde::Serialize;
use serde::de::DeserializeOwned;
use time::OffsetDateTime;
use time::macros::datetime;
use uuid::Uuid;

/// Serialises `v`, checks the snapshot `name`, and checks it parses back.
fn golden<T: Serialize + DeserializeOwned + PartialEq + Debug>(name: &str, v: &T) {
    let json = serde_json::to_string_pretty(v).unwrap();
    insta::assert_snapshot!(name, json);
    let back: T = serde_json::from_str(&json).unwrap();
    assert_eq!(&back, v, "{name}: pretty round trip");
    let compact = serde_json::to_string(v).unwrap();
    let back: T = serde_json::from_str(&compact).unwrap();
    assert_eq!(&back, v, "{name}: compact round trip");
}

fn id(n: u128) -> Uuid {
    Uuid::from_u128(0x0190_0000_0000_7000_8000_0000_0000_0000 | n)
}

const T0: OffsetDateTime = datetime!(2026-10-10 12:00:00 UTC);
const T1: OffsetDateTime = datetime!(2026-10-10 12:34:56.5 UTC);

fn grant_upload() -> GrantUpload {
    GrantUpload {
        wrapped_vault_key: vec![0x11; 8],
        signature: vec![0x22; 64],
        key_version: 1,
    }
}

fn remote_item(rev: u64, deleted: bool) -> RemoteItem {
    RemoteItem {
        id: id(0x10 + rev as u128),
        revision: rev,
        key_version: 1,
        envelope: vec![0xfb, 0xff, rev as u8],
        deleted,
    }
}

// ----------------------------------------------------------------- errors

#[test]
fn error_envelope() {
    golden(
        "error_rate_limited",
        &ErrorEnvelope::new(ErrorCode::RateLimited, "too many login attempts", Some(5)),
    );
    golden(
        "error_conflict",
        &ErrorEnvelope::new(ErrorCode::Conflict, "vault exists", None),
    );
    let all: Vec<ErrorCode> = ErrorCode::ALL.to_vec();
    golden("error_codes", &all);
}

// ------------------------------------------------------------------- auth

#[test]
fn registration() {
    golden(
        "register_start_request",
        &RegisterStartRequest {
            email: "ada@example.test".into(),
            registration_request: vec![1, 2, 3, 4],
            invite_token: Some("inv-token".into()),
            setup_token: None,
        },
    );
    golden(
        "register_start_response",
        &RegisterStartResponse {
            registration_response: vec![5, 6, 7],
            user_id: id(1),
        },
    );
    golden(
        "register_finish_request",
        &RegisterFinishRequest {
            email: "ada@example.test".into(),
            user_id: id(1),
            registration_upload: vec![8, 9],
            account_keys: AccountKeysUpload {
                x25519_pub: vec![0xaa; 32],
                ed25519_pub: vec![0xbb; 32],
                private_bundle_enc: vec![0xcc; 12],
                recovery_bundle_enc: vec![0xdd; 12],
                version: 1,
            },
            personal_vault: PersonalVaultUpload {
                id: id(2),
                name_enc: vec![0xee; 6],
                self_grant: grant_upload(),
            },
            device: DeviceInfo {
                name: "laptop".into(),
                platform: "linux".into(),
            },
            invite_token: None,
            setup_token: Some("setup-token".into()),
        },
    );
}

#[test]
fn login() {
    golden(
        "login_start_request",
        &LoginStartRequest {
            email: "ada@example.test".into(),
            credential_request: vec![1; 5],
        },
    );
    golden(
        "login_start_response",
        &LoginStartResponse {
            credential_response: vec![2; 5],
            login_state_id: id(3),
        },
    );
    golden(
        "login_finish_request",
        &LoginFinishRequest {
            login_state_id: id(3),
            credential_finalization: vec![3; 5],
            totp: Some("123456".into()),
            device: LoginDevice {
                id: None,
                name: Some("desktop".into()),
                platform: Some("windows".into()),
            },
            purpose: LoginPurpose::Login,
        },
    );
    golden(
        "login_finish_request_reauth",
        &LoginFinishRequest {
            login_state_id: id(3),
            credential_finalization: vec![3; 5],
            totp: None,
            device: LoginDevice {
                id: Some(id(4)),
                name: None,
                platform: None,
            },
            purpose: LoginPurpose::Reauth,
        },
    );
    let tokens = TokenPair {
        access_token: "access".into(),
        refresh_token: "refresh".into(),
        access_expires_in_s: ACCESS_TOKEN_TTL_SECS,
        refresh_expires_in_s: REFRESH_TOKEN_TTL_SECS,
    };
    golden("token_pair", &tokens);
    golden(
        "session_response",
        &SessionResponse {
            user_id: id(1),
            device_id: id(4),
            tokens,
            account_keys: AccountKeysView {
                x25519_pub: vec![0xaa; 32],
                ed25519_pub: vec![0xbb; 32],
                private_bundle_enc: vec![0xcc; 12],
                version: 2,
            },
            is_instance_admin: true,
        },
    );
    golden(
        "reauth_response",
        &ReauthResponse {
            user_id: id(1),
            reauth_token: "reauth".into(),
            reauth_expires_in_s: REAUTH_TOKEN_TTL_SECS,
        },
    );
    golden(
        "refresh_request",
        &RefreshRequest {
            refresh_token: "refresh".into(),
        },
    );
}

#[test]
fn devices() {
    golden(
        "device_summaries",
        &vec![
            DeviceSummary {
                id: id(4),
                name: "laptop".into(),
                platform: "linux".into(),
                created_at: T0,
                last_seen_at: Some(T1),
                current: true,
            },
            DeviceSummary {
                id: id(5),
                name: "phone".into(),
                platform: "macos".into(),
                created_at: T0,
                last_seen_at: None,
                current: false,
            },
        ],
    );
}

#[test]
fn account() {
    golden("totp_request_start", &TotpRequest { code: None });
    golden(
        "totp_request_confirm",
        &TotpRequest {
            code: Some("123456".into()),
        },
    );
    golden(
        "totp_setup_response",
        &TotpSetupResponse {
            otpauth_uri: "otpauth://totp/courier-ftp:ada@example.test?secret=JBSWY3DPEHPK3PXP"
                .into(),
            secret_base32: "JBSWY3DPEHPK3PXP".into(),
        },
    );
    golden("totp_status", &TotpStatus { enabled: true });
    golden(
        "password_start_request",
        &PasswordStartRequest {
            registration_request: vec![1, 2],
        },
    );
    golden(
        "password_start_response",
        &PasswordStartResponse {
            registration_response: vec![3, 4],
        },
    );
    golden(
        "password_change_request",
        &PasswordChangeRequest {
            reauth_token: "reauth".into(),
            registration_upload: vec![5, 6],
            private_bundle_enc: vec![7, 8],
            version: 3,
        },
    );
    golden("key_version_response", &KeyVersionResponse { version: 3 });
    golden(
        "recovery_code_request",
        &RecoveryCodeRequest {
            email: "ada@example.test".into(),
        },
    );
    golden(
        "recovery_start_request",
        &RecoveryStartRequest {
            email: "ada@example.test".into(),
            code: "ABCD-EFGH".into(),
            registration_request: vec![1],
        },
    );
    golden(
        "recovery_start_response",
        &RecoveryStartResponse {
            user_id: id(1),
            recovery_bundle_enc: vec![2; 4],
            registration_response: vec![3; 4],
            version: 2,
        },
    );
    golden(
        "recovery_finish_request",
        &RecoveryFinishRequest {
            email: "ada@example.test".into(),
            code: "ABCD-EFGH".into(),
            registration_upload: vec![4; 4],
            private_bundle_enc: vec![5; 4],
            version: 3,
            signature: vec![6; 64],
        },
    );
    golden(
        "account_delete_request",
        &AccountDeleteRequest {
            reauth_token: "reauth".into(),
        },
    );
}

// ------------------------------------------------------------------- sync

#[test]
fn vault_list() {
    golden(
        "vault_views",
        &vec![
            VaultView {
                id: id(2),
                kind: VaultKind::Personal,
                org_id: None,
                name_enc: vec![0xee; 6],
                key_version: 1,
                head_revision: 42,
                permission: Permission::Manage,
                grants: vec![VaultGrant {
                    key_version: 1,
                    wrapped_vault_key: vec![0x11; 8],
                    wrapped_by: id(1),
                    signature: vec![0x22; 64],
                }],
                rotation: None,
            },
            VaultView {
                id: id(6),
                kind: VaultKind::Shared,
                org_id: Some(id(7)),
                name_enc: vec![0xef; 6],
                key_version: 2,
                head_revision: 7,
                permission: Permission::Read,
                grants: vec![
                    VaultGrant {
                        key_version: 2,
                        wrapped_vault_key: vec![0x33; 8],
                        wrapped_by: id(8),
                        signature: vec![0x44; 64],
                    },
                    VaultGrant {
                        key_version: 3,
                        wrapped_vault_key: vec![0x55; 8],
                        wrapped_by: id(8),
                        signature: vec![0x66; 64],
                    },
                ],
                rotation: Some(RotationView {
                    new_key_version: 3,
                    by: id(8),
                    started_at: T1,
                    abandoned: false,
                }),
            },
        ],
    );
}

#[test]
fn pull() {
    golden(
        "pull_query",
        &PullQuery {
            since: 40,
            limit: Some(100),
        },
    );
    golden("pull_query_default", &PullQuery::default());
    golden(
        "pull_response",
        &PullResponse {
            items: vec![remote_item(41, false), remote_item(42, true)],
            head_revision: 42,
            more: false,
        },
    );
}

#[test]
fn push() {
    golden(
        "push_request",
        &PushRequest {
            changes: vec![
                PushChange {
                    id: id(0x20),
                    base_revision: 0,
                    key_version: 1,
                    envelope: vec![1, 2, 3],
                    deleted: false,
                },
                PushChange {
                    id: id(0x21),
                    base_revision: 41,
                    key_version: 1,
                    envelope: vec![4, 5, 6],
                    deleted: true,
                },
            ],
        },
    );
    golden(
        "push_response",
        &PushResponse {
            results: vec![
                PushResult::ok(id(0x20), 43),
                PushResult::conflict(id(0x21), Some(remote_item(42, false))),
                PushResult::conflict(id(0x22), None),
                PushResult::too_large(id(0x23), ENVELOPE_TOO_LARGE_MESSAGE),
                PushResult::too_large(id(0x24), QUOTA_EXCEEDED_MESSAGE),
                PushResult {
                    id: id(0x25),
                    status: PushStatus::Forbidden,
                    revision: None,
                    current: None,
                    message: None,
                },
            ],
        },
    );
}

// --------------------------------------------------------- team vaults

#[test]
fn users() {
    golden(
        "user_public_keys",
        &UserPublicKeys {
            user_id: id(8),
            email: Some("bob@example.test".into()),
            x25519_pub: vec![0xaa; 32],
            ed25519_pub: vec![0xbb; 32],
        },
    );
}

#[test]
fn orgs() {
    golden(
        "create_org_request",
        &CreateOrgRequest {
            name: "Acme Ops".into(),
        },
    );
    golden(
        "org_views",
        &vec![OrgView {
            id: id(7),
            name: "Acme Ops".into(),
            role: Role::Owner,
            created_at: T0,
        }],
    );
    golden(
        "member_views",
        &vec![
            MemberView {
                user_id: id(1),
                email: "ada@example.test".into(),
                role: Role::Owner,
            },
            MemberView {
                user_id: id(8),
                email: "bob@example.test".into(),
                role: Role::Member,
            },
        ],
    );
    golden(
        "update_member_request",
        &UpdateMemberRequest { role: Role::Admin },
    );
    golden(
        "create_invite_request",
        &CreateInviteRequest {
            email: Some("carol@example.test".into()),
            role: Role::Member,
        },
    );
    golden(
        "invite_created",
        &InviteCreated {
            id: id(9),
            org_id: id(7),
            email: None,
            role: Role::Member,
            expires_at: T0,
            link: Some("https://sync.example.test/invite/tok".into()),
            emailed: false,
        },
    );
    golden(
        "invite_accepted",
        &InviteAccepted {
            org_id: id(7),
            role: Role::Member,
        },
    );
    golden(
        "audit_query",
        &AuditQuery {
            before: Some(100),
            limit: Some(50),
        },
    );
    golden(
        "audit_page",
        &AuditPage {
            events: vec![
                AuditEventView {
                    id: 99,
                    kind: "member.added".into(),
                    actor: Some(id(1)),
                    target: Some(id(8)),
                    at: T1,
                    meta: serde_json::json!({"role": "member"}),
                },
                AuditEventView {
                    id: 98,
                    kind: "vault.rotated".into(),
                    actor: Some(id(1)),
                    target: Some(id(6)),
                    at: T0,
                    meta: serde_json::json!({"key_version": 3, "items": 12}),
                },
            ],
            next_before: Some(98),
        },
    );
}

#[test]
fn vaults() {
    golden(
        "create_vault_request",
        &CreateVaultRequest {
            id: id(6),
            org_id: id(7),
            name_enc: vec![0xef; 6],
            self_grant: grant_upload(),
        },
    );
    golden(
        "grant_request",
        &GrantRequest {
            permission: Permission::Write,
            key_version: 2,
            wrapped_vault_key: vec![0x33; 8],
            signature: vec![0x44; 64],
        },
    );
    golden(
        "vault_members_view",
        &VaultMembersView {
            vault_id: id(6),
            org_id: id(7),
            key_version: 2,
            created_by: Some(id(1)),
            members: vec![
                VaultMemberView {
                    user_id: id(1),
                    email: Some("ada@example.test".into()),
                    org_role: Role::Owner,
                    permission: Some(Permission::Manage),
                    has_key: true,
                    granted_by: Some(id(1)),
                },
                VaultMemberView {
                    user_id: id(8),
                    email: None,
                    org_role: Role::Member,
                    permission: None,
                    has_key: false,
                    granted_by: None,
                },
            ],
        },
    );
    golden(
        "org_vault_views",
        &vec![OrgVaultView {
            id: id(6),
            name_enc: vec![0xef; 6],
            key_version: 2,
            permission: Permission::Manage,
            has_key: false,
        }],
    );
}

#[test]
fn rotation() {
    golden("rotate_begin", &RotateRequest::Begin { new_key_version: 3 });
    golden(
        "rotate_upload",
        &RotateRequest::Upload {
            items: vec![RotatedItem {
                id: id(0x20),
                envelope: vec![0xfb, 0xff],
            }],
        },
    );
    golden(
        "rotate_commit",
        &RotateRequest::Commit {
            wrapped_keys: vec![RotationGrant {
                user: id(1),
                wrapped: vec![0x55; 8],
                signature: vec![0x66; 64],
            }],
        },
    );
    golden(
        "rotate_response",
        &RotateResponse {
            key_version: 2,
            new_key_version: 3,
            head_revision: 7,
            staged: 12,
            resumed: true,
            replaced_abandoned: false,
        },
    );
}

// --------------------------------------------------------------------- ws

#[test]
fn websocket() {
    golden(
        "ws_client",
        &vec![
            ClientMsg::Auth {
                token: "access".into(),
            },
            ClientMsg::Ping,
            ClientMsg::Pong,
        ],
    );
    golden(
        "ws_server",
        &vec![
            ServerMsg::VaultChanged {
                vault_id: id(2),
                head_revision: 43,
            },
            ServerMsg::VaultAccess {
                vault_id: id(6),
                change: AccessChange::Granted,
            },
            ServerMsg::VaultAccess {
                vault_id: id(6),
                change: AccessChange::Revoked,
            },
            ServerMsg::VaultAccess {
                vault_id: id(6),
                change: AccessChange::Rotated,
            },
            ServerMsg::AccountChanged { key_version: 3 },
            ServerMsg::Ping,
            ServerMsg::Pong,
        ],
    );
}

// ------------------------------------------------------------- tolerance

/// Receivers ignore unknown fields, so adding a response field is not a
/// protocol bump.
#[test]
fn unknown_fields_are_ignored() {
    let item: RemoteItem = serde_json::from_value(serde_json::json!({
        "id": id(1), "revision": 1, "key_version": 1, "envelope": "AQ",
        "future_field": {"x": 1}
    }))
    .unwrap();
    assert_eq!(item.envelope, vec![1]);
}

/// Binary fields reject padded and standard-alphabet base64.
#[test]
fn strict_base64() {
    for bad in ["AQ==", "+/8", "-_8="] {
        let r = serde_json::from_value::<RemoteItem>(serde_json::json!({
            "id": id(1), "revision": 1, "key_version": 1, "envelope": bad
        }));
        assert!(r.is_err(), "{bad}");
    }
}
