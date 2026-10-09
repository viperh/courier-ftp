//! JSON snapshot of every DTO (T83 AC1): fixed ids (`Uuid::from_u128`), fixed
//! timestamps and short byte arrays. A changed snapshot is a wire-format change and
//! needs a protocol-version review (`version.rs`).
#![allow(clippy::unwrap_used)]

use courier_ftp_proto::auth::*;
use courier_ftp_proto::error::{ErrorCode, ErrorEnvelope, QUOTA_EXCEEDED_MESSAGE};
use courier_ftp_proto::orgs::*;
use courier_ftp_proto::rotation::*;
use courier_ftp_proto::sync::*;
use courier_ftp_proto::users::UserPublicKeys;
use courier_ftp_proto::vaults::*;
use courier_ftp_proto::ws::{AccessChange, ClientMsg, ServerMsg};
use serde::Serialize;
use serde::de::DeserializeOwned;
use time::OffsetDateTime;
use time::macros::datetime;
use uuid::Uuid;

const T0: OffsetDateTime = datetime!(2026-01-02 03:04:05 UTC);

fn id(n: u128) -> Uuid {
    Uuid::from_u128(0x0192_f0c4_7a10_7c3e_9a55_0f6b_2c1d_3e00 + n)
}

/// Pretty JSON of `value`, after checking that it decodes back to itself.
fn json<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(value: &T) -> String {
    let s = serde_json::to_string_pretty(value).unwrap();
    let back: T = serde_json::from_str(&s).unwrap();
    assert_eq!(&back, value);
    s
}

fn grant_upload() -> GrantUpload {
    GrantUpload {
        wrapped_vault_key: vec![1, 2, 3],
        signature: vec![4, 5, 6],
        key_version: 1,
    }
}

fn tokens() -> TokenPair {
    TokenPair {
        access_token: "a".repeat(43),
        refresh_token: "r".repeat(43),
        access_expires_in_s: 900,
        refresh_expires_in_s: 2_592_000,
    }
}

fn remote_item() -> RemoteItem {
    RemoteItem {
        id: id(1),
        revision: 7,
        key_version: 1,
        envelope: vec![1],
        deleted: true,
    }
}

#[test]
fn every_dto_json() {
    // ---- error
    insta::assert_snapshot!(
        "error_envelope",
        json(&ErrorEnvelope::new(
            ErrorCode::RateLimited,
            "too many login attempts",
            Some(12)
        ))
    );
    insta::assert_snapshot!(
        "error_envelope_no_retry",
        json(&ErrorEnvelope::new(ErrorCode::NotFound, "not found", None))
    );

    // ---- auth
    insta::assert_snapshot!(
        "register_start_request",
        json(&RegisterStartRequest {
            email: "alice@example.com".into(),
            registration_request: vec![0xfb, 0xff],
            invite_token: Some("invite".into()),
            setup_token: None,
        })
    );
    insta::assert_snapshot!(
        "register_start_response",
        json(&RegisterStartResponse {
            registration_response: vec![1, 2],
            user_id: id(1),
        })
    );
    insta::assert_snapshot!(
        "register_finish_request",
        json(&RegisterFinishRequest {
            email: "alice@example.com".into(),
            user_id: id(1),
            registration_upload: vec![1, 2, 3],
            account_keys: AccountKeysUpload {
                x25519_pub: vec![1; 4],
                ed25519_pub: vec![2; 4],
                private_bundle_enc: vec![3; 4],
                recovery_bundle_enc: vec![4; 4],
                version: 1,
            },
            personal_vault: PersonalVaultUpload {
                id: id(2),
                name_enc: vec![5, 6],
                self_grant: grant_upload(),
            },
            device: DeviceInfo {
                name: "laptop".into(),
                platform: "linux".into(),
            },
            invite_token: None,
            setup_token: Some("setup".into()),
        })
    );
    insta::assert_snapshot!(
        "login_start_request",
        json(&LoginStartRequest {
            email: "alice@example.com".into(),
            credential_request: vec![1, 2, 3],
        })
    );
    insta::assert_snapshot!(
        "login_start_response",
        json(&LoginStartResponse {
            credential_response: vec![1, 2, 3],
            login_state_id: id(3),
        })
    );
    insta::assert_snapshot!(
        "login_finish_request",
        json(&LoginFinishRequest {
            login_state_id: id(3),
            credential_finalization: vec![9],
            totp: Some("123456".into()),
            device: LoginDevice {
                id: Some(id(4)),
                name: None,
                platform: Some("macos".into()),
            },
            purpose: LoginPurpose::Reauth,
        })
    );
    insta::assert_snapshot!("token_pair", json(&tokens()));
    insta::assert_snapshot!(
        "session_response",
        json(&SessionResponse {
            user_id: id(1),
            device_id: id(4),
            tokens: tokens(),
            account_keys: AccountKeysView {
                x25519_pub: vec![1; 4],
                ed25519_pub: vec![2; 4],
                private_bundle_enc: vec![3; 4],
                version: 2,
            },
            is_instance_admin: true,
        })
    );
    insta::assert_snapshot!(
        "reauth_response",
        json(&ReauthResponse {
            user_id: id(1),
            reauth_token: "t".repeat(43),
            reauth_expires_in_s: 300,
        })
    );
    insta::assert_snapshot!(
        "refresh_request",
        json(&RefreshRequest {
            refresh_token: "r".repeat(43),
        })
    );
    insta::assert_snapshot!(
        "device_views",
        json(&vec![
            DeviceView {
                id: id(4),
                name: Some("laptop".into()),
                platform: Some("linux".into()),
                created_at: Some(T0),
                last_seen_at: Some(T0),
                current: true,
                revoked_at: None,
            },
            DeviceView {
                id: id(5),
                name: None,
                platform: None,
                created_at: None,
                last_seen_at: None,
                current: false,
                revoked_at: Some(T0),
            },
        ])
    );
    insta::assert_snapshot!(
        "totp_request",
        json(&TotpRequest {
            code: Some("123456".into()),
        })
    );
    insta::assert_snapshot!("totp_request_empty", json(&TotpRequest::default()));
    insta::assert_snapshot!(
        "totp_setup_response",
        json(&TotpSetupResponse {
            otpauth_uri: "otpauth://totp/courier-ftp:alice?secret=JBSWY3DP".into(),
            secret_base32: "JBSWY3DP".into(),
        })
    );
    insta::assert_snapshot!("totp_status", json(&TotpStatus { enabled: true }));
    insta::assert_snapshot!(
        "password_start_request",
        json(&PasswordStartRequest {
            registration_request: vec![1],
        })
    );
    insta::assert_snapshot!(
        "password_start_response",
        json(&PasswordStartResponse {
            registration_response: vec![2],
        })
    );
    insta::assert_snapshot!(
        "password_change_request",
        json(&PasswordChangeRequest {
            reauth_token: "t".repeat(43),
            registration_upload: vec![1, 2],
            private_bundle_enc: vec![3, 4],
            version: 3,
        })
    );
    insta::assert_snapshot!(
        "key_version_response",
        json(&KeyVersionResponse { version: 3 })
    );
    insta::assert_snapshot!(
        "recovery_code_request",
        json(&RecoveryCodeRequest {
            email: "alice@example.com".into(),
        })
    );
    insta::assert_snapshot!(
        "recovery_start_request",
        json(&RecoveryStartRequest {
            email: "alice@example.com".into(),
            code: "ABCD-EFGH-JKMN-PQRS".into(),
            registration_request: vec![1],
        })
    );
    insta::assert_snapshot!(
        "recovery_start_response",
        json(&RecoveryStartResponse {
            user_id: id(1),
            recovery_bundle_enc: vec![4; 4],
            registration_response: vec![2],
            version: 2,
        })
    );
    insta::assert_snapshot!(
        "recovery_finish_request",
        json(&RecoveryFinishRequest {
            email: "alice@example.com".into(),
            code: "ABCD-EFGH-JKMN-PQRS".into(),
            registration_upload: vec![1],
            private_bundle_enc: vec![2],
            version: 3,
            signature: vec![3; 4],
        })
    );
    insta::assert_snapshot!(
        "account_delete_request",
        json(&AccountDeleteRequest {
            reauth_token: "t".repeat(43),
        })
    );

    // ---- sync
    insta::assert_snapshot!(
        "vault_views",
        json(&vec![
            VaultView {
                id: id(2),
                kind: VaultKind::Personal,
                org_id: None,
                name_enc: vec![5, 6],
                key_version: 1,
                head_revision: 42,
                permission: Permission::Manage,
                grants: vec![VaultGrant {
                    key_version: 1,
                    wrapped_vault_key: vec![1, 2, 3],
                    wrapped_by: id(1),
                    signature: vec![4, 5, 6],
                }],
                rotation: None,
            },
            VaultView {
                id: id(6),
                kind: VaultKind::Team,
                org_id: Some(id(7)),
                name_enc: vec![7],
                key_version: 2,
                head_revision: 0,
                permission: Permission::Read,
                grants: vec![],
                rotation: Some(RotationView {
                    new_key_version: 3,
                    by: id(8),
                    started_at: T0,
                    abandoned: false,
                }),
            },
        ])
    );
    insta::assert_snapshot!(
        "pull_query",
        json(&PullQuery {
            since: 41,
            limit: Some(100),
        })
    );
    insta::assert_snapshot!(
        "pull_response",
        json(&PullResponse {
            items: vec![remote_item()],
            head_revision: 7,
            more: false,
        })
    );
    insta::assert_snapshot!(
        "push_request",
        json(&PushRequest {
            changes: vec![PushChange {
                id: id(1),
                base_revision: 0,
                key_version: 1,
                envelope: vec![1, 0, 0, 0, 1],
                deleted: false,
            }],
        })
    );
    insta::assert_snapshot!(
        "push_response",
        json(&PushResponse {
            results: vec![
                PushResult {
                    id: id(1),
                    status: PushStatus::Conflict,
                    revision: None,
                    current: Some(remote_item()),
                    message: None,
                },
                PushResult {
                    id: id(2),
                    status: PushStatus::TooLarge,
                    revision: None,
                    current: None,
                    message: Some(QUOTA_EXCEEDED_MESSAGE.into()),
                },
                PushResult {
                    id: id(3),
                    status: PushStatus::Ok,
                    revision: Some(8),
                    current: None,
                    message: None,
                },
                PushResult {
                    id: id(4),
                    status: PushStatus::Forbidden,
                    revision: None,
                    current: None,
                    message: None,
                },
            ],
        })
    );

    // ---- users
    insta::assert_snapshot!(
        "user_public_keys",
        json(&UserPublicKeys {
            user_id: id(1),
            email: Some("alice@example.com".into()),
            x25519_pub: vec![1; 4],
            ed25519_pub: vec![2; 4],
        })
    );

    // ---- orgs
    insta::assert_snapshot!(
        "create_org_request",
        json(&CreateOrgRequest {
            name: "Acme".into(),
        })
    );
    insta::assert_snapshot!(
        "org_views",
        json(&vec![OrgView {
            id: id(7),
            name: "Acme".into(),
            role: Role::Owner,
            created_at: T0,
        }])
    );
    insta::assert_snapshot!(
        "member_views",
        json(&vec![MemberView {
            user_id: id(8),
            email: "bob@example.com".into(),
            role: Role::Member,
        }])
    );
    insta::assert_snapshot!(
        "update_member_request",
        json(&UpdateMemberRequest { role: Role::Admin })
    );
    insta::assert_snapshot!(
        "create_invite_request",
        json(&CreateInviteRequest {
            email: Some("bob@example.com".into()),
            role: Role::Member,
        })
    );
    insta::assert_snapshot!(
        "invite_created",
        json(&InviteCreated {
            id: id(9),
            org_id: id(7),
            email: Some("bob@example.com".into()),
            role: Role::Member,
            expires_at: T0,
            link: Some("https://sync.example/invite/tok".into()),
            emailed: true,
        })
    );
    insta::assert_snapshot!(
        "invite_accepted",
        json(&InviteAccepted {
            org_id: id(7),
            role: Role::Member,
        })
    );
    insta::assert_snapshot!(
        "audit_query",
        json(&AuditQuery {
            before: Some(100),
            limit: Some(50),
        })
    );
    insta::assert_snapshot!(
        "audit_page",
        json(&AuditPage {
            events: vec![AuditEventView {
                id: 99,
                kind: audit_kind::ITEMS_PUSHED.into(),
                actor: Some(id(1)),
                target: None,
                at: T0,
                meta: serde_json::json!({"vault_id": id(6), "item_ids": [id(1)]}),
            }],
            next_before: Some(99),
        })
    );

    // ---- vaults
    insta::assert_snapshot!(
        "create_vault_request",
        json(&CreateVaultRequest {
            id: id(6),
            org_id: id(7),
            name_enc: vec![7],
            self_grant: grant_upload(),
        })
    );
    insta::assert_snapshot!(
        "grant_request",
        json(&GrantRequest {
            permission: Permission::Write,
            key_version: 2,
            wrapped_vault_key: vec![1, 2, 3],
            signature: vec![4, 5, 6],
        })
    );
    insta::assert_snapshot!(
        "vault_members_view",
        json(&VaultMembersView {
            vault_id: id(6),
            org_id: id(7),
            key_version: 2,
            created_by: Some(id(1)),
            members: vec![
                VaultMemberView {
                    user_id: id(1),
                    email: Some("alice@example.com".into()),
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
        })
    );
    insta::assert_snapshot!(
        "org_vault_views",
        json(&vec![OrgVaultView {
            id: id(6),
            name_enc: vec![7],
            key_version: 2,
            permission: Permission::Write,
            has_key: true,
        }])
    );

    // ---- rotation
    insta::assert_snapshot!(
        "rotate_begin",
        json(&RotateRequest::Begin { new_key_version: 3 })
    );
    insta::assert_snapshot!(
        "rotate_upload",
        json(&RotateRequest::Upload {
            items: vec![RotatedItem {
                id: id(1),
                envelope: vec![1, 2],
            }],
        })
    );
    insta::assert_snapshot!(
        "rotate_commit",
        json(&RotateRequest::Commit {
            wrapped_keys: vec![RotationGrant {
                user: id(8),
                wrapped: vec![1, 2, 3],
                signature: vec![4, 5, 6],
                permission: Permission::Read,
            }],
        })
    );
    insta::assert_snapshot!(
        "rotate_response",
        json(&RotateResponse {
            key_version: 2,
            new_key_version: 3,
            head_revision: 42,
            staged: 10,
            resumed: true,
            replaced_abandoned: false,
        })
    );

    // ---- ws
    insta::assert_snapshot!(
        "ws_client_auth",
        json(&ClientMsg::Auth {
            token: "a".repeat(43),
        })
    );
    insta::assert_snapshot!("ws_client_ping", json(&ClientMsg::Ping));
    insta::assert_snapshot!("ws_client_pong", json(&ClientMsg::Pong));
    insta::assert_snapshot!(
        "ws_server_msgs",
        json(&vec![
            ServerMsg::VaultChanged {
                vault_id: id(6),
                head_revision: 42,
            },
            ServerMsg::VaultAccess {
                vault_id: id(6),
                change: AccessChange::Revoked,
            },
            ServerMsg::AccountChanged { key_version: 3 },
            ServerMsg::Ping,
            ServerMsg::Pong,
        ])
    );
}

/// The compact forms quoted in the task's *Data formats* section.
#[test]
fn spec_examples_compact() {
    let err = ErrorEnvelope::new(ErrorCode::RateLimited, "too many login attempts", Some(12));
    assert_eq!(
        serde_json::to_string(&err).unwrap(),
        r#"{"error":{"code":"rate_limited","message":"too many login attempts","retry_after_s":12}}"#
    );
    let begin = RotateRequest::Begin { new_key_version: 3 };
    assert_eq!(
        serde_json::to_string(&begin).unwrap(),
        r#"{"action":"begin","new_key_version":3}"#
    );
    let conflict = PushResult {
        id: id(1),
        status: PushStatus::Conflict,
        revision: None,
        current: Some(RemoteItem {
            envelope: vec![1],
            ..remote_item()
        }),
        message: None,
    };
    let v = serde_json::to_value(&conflict).unwrap();
    assert_eq!(v["current"]["envelope"], "AQ");
    assert!(v.get("revision").is_none() && v.get("message").is_none());
}

/// Every response type ignores unknown fields (AC6).
#[test]
fn responses_ignore_unknown_fields() {
    fn extra<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(value: &T) {
        let mut v = serde_json::to_value(value).unwrap();
        match &mut v {
            serde_json::Value::Object(m) => {
                m.insert("zz_future_field".into(), serde_json::json!({"x": [1]}));
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    if let serde_json::Value::Object(m) = item {
                        m.insert("zz_future_field".into(), serde_json::json!(1));
                    }
                }
            }
            _ => panic!("not an object"),
        }
        let back: T = serde_json::from_value(v).unwrap();
        assert_eq!(&back, value);
    }
    extra(&ErrorEnvelope::new(ErrorCode::Gone, "gone", None));
    extra(&RegisterStartResponse {
        registration_response: vec![1],
        user_id: id(1),
    });
    extra(&LoginStartResponse {
        credential_response: vec![1],
        login_state_id: id(1),
    });
    extra(&SessionResponse {
        user_id: id(1),
        device_id: id(2),
        tokens: tokens(),
        account_keys: AccountKeysView {
            x25519_pub: vec![1],
            ed25519_pub: vec![2],
            private_bundle_enc: vec![3],
            version: 1,
        },
        is_instance_admin: false,
    });
    extra(&ReauthResponse {
        user_id: id(1),
        reauth_token: "t".into(),
        reauth_expires_in_s: 300,
    });
    extra(&tokens());
    extra(&vec![DeviceView {
        id: id(1),
        name: None,
        platform: None,
        created_at: Some(T0),
        last_seen_at: None,
        current: true,
        revoked_at: None,
    }]);
    extra(&TotpSetupResponse {
        otpauth_uri: "u".into(),
        secret_base32: "s".into(),
    });
    extra(&TotpStatus { enabled: false });
    extra(&PasswordStartResponse {
        registration_response: vec![1],
    });
    extra(&KeyVersionResponse { version: 1 });
    extra(&RecoveryStartResponse {
        user_id: id(1),
        recovery_bundle_enc: vec![1],
        registration_response: vec![2],
        version: 1,
    });
    extra(&PullResponse {
        items: vec![remote_item()],
        head_revision: 7,
        more: true,
    });
    extra(&PushResponse { results: vec![] });
    extra(&UserPublicKeys {
        user_id: id(1),
        email: None,
        x25519_pub: vec![1],
        ed25519_pub: vec![2],
    });
    extra(&vec![OrgView {
        id: id(7),
        name: "Acme".into(),
        role: Role::Admin,
        created_at: T0,
    }]);
    extra(&vec![MemberView {
        user_id: id(1),
        email: "a@b.c".into(),
        role: Role::Member,
    }]);
    extra(&InviteCreated {
        id: id(9),
        org_id: id(7),
        email: None,
        role: Role::Member,
        expires_at: T0,
        link: None,
        emailed: false,
    });
    extra(&InviteAccepted {
        org_id: id(7),
        role: Role::Member,
    });
    extra(&AuditPage {
        events: vec![],
        next_before: None,
    });
    extra(&VaultMembersView {
        vault_id: id(6),
        org_id: id(7),
        key_version: 1,
        created_by: None,
        members: vec![],
    });
    extra(&vec![OrgVaultView {
        id: id(6),
        name_enc: vec![1],
        key_version: 1,
        permission: Permission::Read,
        has_key: false,
    }]);
    extra(&RotateResponse {
        key_version: 1,
        new_key_version: 2,
        head_revision: 0,
        staged: 0,
        resumed: false,
        replaced_abandoned: false,
    });
    extra(&ServerMsg::VaultChanged {
        vault_id: id(6),
        head_revision: 1,
    });
}
