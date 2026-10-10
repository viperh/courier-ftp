//! Property tests (T83): every DTO survives a JSON round trip, and the fuzz body
//! `fuzz_decode_all` never panics (the `sync_dto_decode` fuzz target runs the same
//! body under libFuzzer).
#![allow(clippy::unwrap_used)]

use courier_ftp_proto::auth::*;
use courier_ftp_proto::error::{ErrorBody, ErrorCode, ErrorEnvelope};
use courier_ftp_proto::fuzz_decode_all;
use courier_ftp_proto::orgs::*;
use courier_ftp_proto::rotation::*;
use courier_ftp_proto::sync::*;
use courier_ftp_proto::users::UserPublicKeys;
use courier_ftp_proto::vaults::*;
use courier_ftp_proto::ws::{AccessChange, ClientMsg, ServerMsg};
use proptest::option::of;
use proptest::prelude::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use time::OffsetDateTime;
use uuid::Uuid;

fn uuid() -> impl Strategy<Value = Uuid> {
    any::<u128>().prop_map(Uuid::from_u128)
}

fn bytes() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..24)
}

fn text() -> impl Strategy<Value = String> {
    ".{0,12}"
}

fn ts() -> impl Strategy<Value = OffsetDateTime> {
    // Years 1970..=2096, with nanoseconds.
    (0i64..4_000_000_000, 0u32..1_000_000_000).prop_map(|(secs, nanos)| {
        OffsetDateTime::from_unix_timestamp(secs)
            .unwrap()
            .replace_nanosecond(nanos)
            .unwrap()
    })
}

fn code() -> impl Strategy<Value = ErrorCode> {
    proptest::sample::select(ErrorCode::ALL.to_vec())
}

fn permission() -> impl Strategy<Value = Permission> {
    prop_oneof![
        Just(Permission::Read),
        Just(Permission::Write),
        Just(Permission::Manage)
    ]
}

fn role() -> impl Strategy<Value = Role> {
    prop_oneof![Just(Role::Member), Just(Role::Admin), Just(Role::Owner)]
}

fn json_value() -> impl Strategy<Value = serde_json::Value> {
    (any::<i64>(), text(), of(uuid()), any::<bool>()).prop_map(|(n, s, id, b)| {
        serde_json::json!({"count": n, "role": s, "vault_id": id, "flag": b, "ids": [n]})
    })
}

prop_compose! {
    fn error_envelope()(code in code(), message in text(), retry in of(any::<u64>())) -> ErrorEnvelope {
        ErrorEnvelope { error: ErrorBody { code, message, retry_after_s: retry } }
    }
}

prop_compose! {
    fn grant_upload()(w in bytes(), s in bytes(), v in any::<u32>()) -> GrantUpload {
        GrantUpload { wrapped_vault_key: w, signature: s, key_version: v }
    }
}

prop_compose! {
    fn register_start()(email in text(), r in bytes(), i in of(text()), s in of(text())) -> RegisterStartRequest {
        RegisterStartRequest { email, registration_request: r, invite_token: i, setup_token: s }
    }
}

prop_compose! {
    fn register_finish()(
        email in text(), user_id in uuid(), up in bytes(),
        keys in (bytes(), bytes(), bytes(), bytes(), any::<u32>()),
        vault in (uuid(), bytes(), grant_upload()),
        device in (text(), text()),
        tokens in (of(text()), of(text())),
    ) -> RegisterFinishRequest {
        RegisterFinishRequest {
            email,
            user_id,
            registration_upload: up,
            account_keys: AccountKeysUpload {
                x25519_pub: keys.0, ed25519_pub: keys.1, private_bundle_enc: keys.2,
                recovery_bundle_enc: keys.3, version: keys.4,
            },
            personal_vault: PersonalVaultUpload { id: vault.0, name_enc: vault.1, self_grant: vault.2 },
            device: DeviceInfo { name: device.0, platform: device.1 },
            invite_token: tokens.0,
            setup_token: tokens.1,
        }
    }
}

prop_compose! {
    fn login_finish()(
        id in uuid(), f in bytes(), totp in of(text()),
        dev in (of(uuid()), of(text()), of(text())), reauth in any::<bool>(),
    ) -> LoginFinishRequest {
        LoginFinishRequest {
            login_state_id: id,
            credential_finalization: f,
            totp,
            device: LoginDevice { id: dev.0, name: dev.1, platform: dev.2 },
            purpose: if reauth { LoginPurpose::Reauth } else { LoginPurpose::Login },
        }
    }
}

prop_compose! {
    fn token_pair()(a in text(), r in text(), ae in any::<u64>(), re in any::<u64>()) -> TokenPair {
        TokenPair { access_token: a, refresh_token: r, access_expires_in_s: ae, refresh_expires_in_s: re }
    }
}

prop_compose! {
    fn session()(
        u in uuid(), d in uuid(), t in token_pair(),
        k in (bytes(), bytes(), bytes(), any::<u32>()), admin in any::<bool>(),
    ) -> SessionResponse {
        SessionResponse {
            user_id: u, device_id: d, tokens: t,
            account_keys: AccountKeysView { x25519_pub: k.0, ed25519_pub: k.1, private_bundle_enc: k.2, version: k.3 },
            is_instance_admin: admin,
        }
    }
}

prop_compose! {
    fn device_view()(
        id in uuid(), name in of(text()), platform in of(text()),
        c in of(ts()), l in of(ts()), current in any::<bool>(), r in of(ts()),
    ) -> DeviceView {
        DeviceView { id, name, platform, created_at: c, last_seen_at: l, current, revoked_at: r }
    }
}

prop_compose! {
    fn recovery_finish()(
        email in text(), code in text(), up in bytes(), b in bytes(), v in any::<u32>(), s in bytes(),
    ) -> RecoveryFinishRequest {
        RecoveryFinishRequest {
            email, code, registration_upload: up, private_bundle_enc: b, version: v, signature: s,
        }
    }
}

prop_compose! {
    fn remote_item()(id in uuid(), rev in any::<u64>(), kv in any::<u32>(), env in bytes(), del in any::<bool>()) -> RemoteItem {
        RemoteItem { id, revision: rev, key_version: kv, envelope: env, deleted: del }
    }
}

prop_compose! {
    fn vault_view()(
        id in uuid(), team in any::<bool>(), org in of(uuid()), name in bytes(),
        kv in any::<u32>(), head in any::<u64>(), p in permission(),
        grants in proptest::collection::vec((any::<u32>(), bytes(), uuid(), bytes()), 0..3),
        rot in of((any::<u32>(), uuid(), ts(), any::<bool>())),
    ) -> VaultView {
        VaultView {
            id,
            kind: if team { VaultKind::Team } else { VaultKind::Personal },
            org_id: org,
            name_enc: name,
            key_version: kv,
            head_revision: head,
            permission: p,
            grants: grants.into_iter().map(|g| VaultGrant {
                key_version: g.0, wrapped_vault_key: g.1, wrapped_by: g.2, signature: g.3,
            }).collect(),
            rotation: rot.map(|r| RotationView { new_key_version: r.0, by: r.1, started_at: r.2, abandoned: r.3 }),
        }
    }
}

prop_compose! {
    fn push_request()(changes in proptest::collection::vec(
        (uuid(), any::<u64>(), any::<u32>(), bytes(), any::<bool>()), 0..4,
    )) -> PushRequest {
        PushRequest {
            changes: changes.into_iter().map(|c| PushChange {
                id: c.0, base_revision: c.1, key_version: c.2, envelope: c.3, deleted: c.4,
            }).collect(),
        }
    }
}

fn push_status() -> impl Strategy<Value = PushStatus> {
    prop_oneof![
        Just(PushStatus::Ok),
        Just(PushStatus::Conflict),
        Just(PushStatus::Forbidden),
        Just(PushStatus::TooLarge)
    ]
}

prop_compose! {
    fn push_response()(results in proptest::collection::vec(
        (uuid(), push_status(), of(any::<u64>()), of(remote_item()), of(text())), 0..4,
    )) -> PushResponse {
        PushResponse {
            results: results.into_iter().map(|r| PushResult {
                id: r.0, status: r.1, revision: r.2, current: r.3, message: r.4,
            }).collect(),
        }
    }
}

prop_compose! {
    fn invite_created()(
        id in uuid(), org in uuid(), email in of(text()), role in role(), exp in ts(),
        link in of(text()), emailed in any::<bool>(),
    ) -> InviteCreated {
        InviteCreated { id, org_id: org, email, role, expires_at: exp, link, emailed }
    }
}

prop_compose! {
    fn audit_page()(
        events in proptest::collection::vec(
            (any::<i64>(), text(), of(uuid()), of(uuid()), ts(), json_value()), 0..3,
        ),
        next in of(any::<i64>()),
    ) -> AuditPage {
        AuditPage {
            events: events.into_iter().map(|e| AuditEventView {
                id: e.0, kind: e.1, actor: e.2, target: e.3, at: e.4, meta: e.5,
            }).collect(),
            next_before: next,
        }
    }
}

prop_compose! {
    fn vault_members()(
        v in uuid(), o in uuid(), kv in any::<u32>(), by in of(uuid()),
        members in proptest::collection::vec(
            (uuid(), of(text()), role(), of(permission()), any::<bool>(), of(uuid())), 0..3,
        ),
    ) -> VaultMembersView {
        VaultMembersView {
            vault_id: v, org_id: o, key_version: kv, created_by: by,
            members: members.into_iter().map(|m| VaultMemberView {
                user_id: m.0, email: m.1, org_role: m.2, permission: m.3, has_key: m.4, granted_by: m.5,
            }).collect(),
        }
    }
}

fn rotate_request() -> impl Strategy<Value = RotateRequest> {
    prop_oneof![
        any::<u32>().prop_map(|v| RotateRequest::Begin { new_key_version: v }),
        proptest::collection::vec((uuid(), bytes()), 0..3).prop_map(|items| {
            RotateRequest::Upload {
                items: items
                    .into_iter()
                    .map(|(id, envelope)| RotatedItem { id, envelope })
                    .collect(),
            }
        }),
        proptest::collection::vec((uuid(), bytes(), bytes(), permission()), 0..3).prop_map(|g| {
            RotateRequest::Commit {
                wrapped_keys: g
                    .into_iter()
                    .map(|g| RotationGrant {
                        user: g.0,
                        wrapped: g.1,
                        signature: g.2,
                        permission: g.3,
                    })
                    .collect(),
            }
        }),
    ]
}

fn server_msg() -> impl Strategy<Value = ServerMsg> {
    let change = prop_oneof![
        Just(AccessChange::Granted),
        Just(AccessChange::Revoked),
        Just(AccessChange::Rotated)
    ];
    prop_oneof![
        (uuid(), any::<u64>()).prop_map(|(vault_id, head_revision)| ServerMsg::VaultChanged {
            vault_id,
            head_revision
        }),
        (uuid(), change).prop_map(|(vault_id, change)| ServerMsg::VaultAccess { vault_id, change }),
        any::<u32>().prop_map(|key_version| ServerMsg::AccountChanged { key_version }),
        Just(ServerMsg::Ping),
        Just(ServerMsg::Pong),
        Just(ServerMsg::Unknown),
    ]
}

fn client_msg() -> impl Strategy<Value = ClientMsg> {
    prop_oneof![
        text().prop_map(|token| ClientMsg::Auth { token }),
        Just(ClientMsg::Ping),
        Just(ClientMsg::Pong),
    ]
}

fn rt<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(value: &T) {
    let s = serde_json::to_string(value).unwrap();
    let back: T = serde_json::from_str(&s).unwrap();
    assert_eq!(&back, value, "json: {s}");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn dto_roundtrip(
        a in (error_envelope(), register_start(), register_finish(), login_finish(), token_pair(), session()),
        b in (
            (bytes(), uuid()).prop_map(|(r, u)| RegisterStartResponse { registration_response: r, user_id: u }),
            (text(), bytes()).prop_map(|(e, c)| LoginStartRequest { email: e, credential_request: c }),
            (bytes(), uuid()).prop_map(|(c, l)| LoginStartResponse { credential_response: c, login_state_id: l }),
            (uuid(), text(), any::<u64>()).prop_map(|(u, t, e)| ReauthResponse { user_id: u, reauth_token: t, reauth_expires_in_s: e }),
            text().prop_map(|t| RefreshRequest { refresh_token: t }),
            proptest::collection::vec(device_view(), 0..3),
        ),
        c in (
            of(text()).prop_map(|code| TotpRequest { code }),
            (text(), text()).prop_map(|(u, s)| TotpSetupResponse { otpauth_uri: u, secret_base32: s }),
            any::<bool>().prop_map(|enabled| TotpStatus { enabled }),
            bytes().prop_map(|r| PasswordStartRequest { registration_request: r }),
            bytes().prop_map(|r| PasswordStartResponse { registration_response: r }),
            (text(), bytes(), bytes(), any::<u32>()).prop_map(|(t, u, b, v)| PasswordChangeRequest {
                reauth_token: t, registration_upload: u, private_bundle_enc: b, version: v,
            }),
            any::<u32>().prop_map(|version| KeyVersionResponse { version }),
            text().prop_map(|email| RecoveryCodeRequest { email }),
            (text(), text(), bytes()).prop_map(|(e, c, r)| RecoveryStartRequest { email: e, code: c, registration_request: r }),
            (uuid(), bytes(), bytes(), any::<u32>()).prop_map(|(u, b, r, v)| RecoveryStartResponse {
                user_id: u, recovery_bundle_enc: b, registration_response: r, version: v,
            }),
            recovery_finish(),
            text().prop_map(|t| AccountDeleteRequest { reauth_token: t }),
        ),
        d in (
            proptest::collection::vec(vault_view(), 0..3),
            (any::<u64>(), of(any::<u32>())).prop_map(|(since, limit)| PullQuery { since, limit }),
            (proptest::collection::vec(remote_item(), 0..3), any::<u64>(), any::<bool>())
                .prop_map(|(items, head_revision, more)| PullResponse { items, head_revision, more }),
            push_request(),
            push_response(),
            (uuid(), of(text()), bytes(), bytes()).prop_map(|(u, e, x, ed)| UserPublicKeys {
                user_id: u, email: e, x25519_pub: x, ed25519_pub: ed,
            }),
        ),
        e in (
            text().prop_map(|name| CreateOrgRequest { name }),
            (uuid(), text(), role(), ts()).prop_map(|(id, name, role, created_at)| OrgView { id, name, role, created_at }),
            (uuid(), text(), role()).prop_map(|(user_id, email, role)| MemberView { user_id, email, role }),
            role().prop_map(|role| UpdateMemberRequest { role }),
            (of(text()), role()).prop_map(|(email, role)| CreateInviteRequest { email, role }),
            invite_created(),
            (uuid(), role()).prop_map(|(org_id, role)| InviteAccepted { org_id, role }),
            (of(any::<i64>()), of(any::<u32>())).prop_map(|(before, limit)| AuditQuery { before, limit }),
            audit_page(),
        ),
        f in (
            (uuid(), uuid(), bytes(), grant_upload()).prop_map(|(id, org_id, name_enc, self_grant)| CreateVaultRequest {
                id, org_id, name_enc, self_grant,
            }),
            (permission(), any::<u32>(), bytes(), bytes()).prop_map(|(permission, key_version, w, s)| GrantRequest {
                permission, key_version, wrapped_vault_key: w, signature: s,
            }),
            vault_members(),
            (uuid(), bytes(), any::<u32>(), permission(), any::<bool>()).prop_map(|(id, n, kv, p, h)| OrgVaultView {
                id, name_enc: n, key_version: kv, permission: p, has_key: h,
            }),
            rotate_request(),
            (any::<u32>(), any::<u32>(), any::<u64>(), any::<u64>(), any::<bool>(), any::<bool>()).prop_map(
                |(k, n, h, s, r, a)| RotateResponse {
                    key_version: k, new_key_version: n, head_revision: h, staged: s, resumed: r, replaced_abandoned: a,
                },
            ),
            server_msg(),
            client_msg(),
        ),
    ) {
        rt(&a.0); rt(&a.1); rt(&a.2); rt(&a.3); rt(&a.4); rt(&a.5);
        rt(&b.0); rt(&b.1); rt(&b.2); rt(&b.3); rt(&b.4); rt(&b.5);
        rt(&c.0); rt(&c.1); rt(&c.2); rt(&c.3); rt(&c.4); rt(&c.5);
        rt(&c.6); rt(&c.7); rt(&c.8); rt(&c.9); rt(&c.10); rt(&c.11);
        rt(&d.0); rt(&d.1); rt(&d.2); rt(&d.3); rt(&d.4); rt(&d.5);
        rt(&e.0); rt(&e.1); rt(&e.2); rt(&e.3); rt(&e.4); rt(&e.5);
        rt(&e.6); rt(&e.7); rt(&e.8);
        rt(&f.0); rt(&f.1); rt(&f.2); rt(&f.3); rt(&f.4); rt(&f.5);
        rt(&f.6); rt(&f.7);
        // The fuzz body accepts every valid encoding too.
        fuzz_decode_all(serde_json::to_string(&d.3).unwrap().as_bytes());
        fuzz_decode_all(serde_json::to_string(&f.4).unwrap().as_bytes());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// AC8: arbitrary bytes never panic the decoders or the validators.
    #[test]
    fn fuzz_body_never_panics(data in prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..256),
        // JSON-shaped noise reaches deeper into the decoders.
        r#"[{}\[\]":, a-z0-9_\-]{0,96}"#.prop_map(String::into_bytes),
    ]) {
        fuzz_decode_all(&data);
    }
}

/// The seed corpus of `sync_dto_decode` (`fuzz/seed-corpus.sh`) decodes as at
/// least one type, and runs through the fuzz body.
#[test]
fn fixtures_decode() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dto");
    let mut n = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let data = std::fs::read(entry.unwrap().path()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert!(v.is_object());
        fuzz_decode_all(&data);
        n += 1;
    }
    assert!(n >= 5);
}
