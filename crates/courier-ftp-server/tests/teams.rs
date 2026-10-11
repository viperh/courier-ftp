//! Orgs, invites, team vaults, grants and key rotation (T89) end to end over
//! HTTP against an in-process server, with the real client crypto for
//! grants and envelopes.
//!
//! Every scenario runs on the in-memory store (`*_mem`) and on PostgreSQL
//! (`*_pg`, `COURIER_SERVER_PG_TEST=1` + `DATABASE_URL`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

mod common;

use chrono::TimeDelta;
use common::client::{Account, login, open_and_register, register, try_register};
use common::sync::{pull_raw, push_raw, vaults};
use common::{Server, assert_error};
use courier_ftp_crypto::envelope::seal_item;
use courier_ftp_crypto::grant::{grant_vault_key, self_grant};
use courier_ftp_crypto::keys::{Key32, os_rng, random_key32};
use courier_ftp_proto::b64;
use courier_ftp_proto::orgs::{AuditPage, InviteCreated, MemberView, OrgView, Role};
use courier_ftp_proto::sync::{Permission, VaultKind};
use courier_ftp_proto::vaults::VaultMembersView;
use courier_ftp_server::mail::{Mailer, ORG_INVITE_SUBJECT};
use courier_ftp_server::registration::RegistrationMode;
use reqwest::StatusCode;
use serde_json::{Value, json};
use uuid::Uuid;

macro_rules! both {
    ($scenario:ident, $mem:ident, $pg:ident) => {
        #[tokio::test]
        async fn $mem() {
            let h = Server::mem().await;
            $scenario(&h).await;
        }

        #[tokio::test]
        async fn $pg() {
            let h = $crate::db_or_skip!(Server::pg());
            $scenario(&h).await;
            h.cleanup().await;
        }
    };
}

async fn create_org(h: &Server, a: &Account, name: &str) -> OrgView {
    let (st, v) = h
        .post("/v1/orgs", json!({ "name": name }), Some(a.access()))
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    serde_json::from_value(v).unwrap()
}

async fn invite(
    h: &Server,
    a: &Account,
    org: Uuid,
    email: Option<&str>,
    role: &str,
) -> InviteCreated {
    let (st, v) = h
        .post(
            &format!("/v1/orgs/{org}/invites"),
            json!({ "email": email, "role": role }),
            Some(a.access()),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    serde_json::from_value(v).unwrap()
}

fn token_of(link: &str) -> &str {
    link.rsplit_once("/invite/").unwrap().1
}

async fn accept(h: &Server, a: &Account, token: &str) -> (StatusCode, Value) {
    h.post(
        &format!("/v1/invites/{token}/accept"),
        json!({}),
        Some(a.access()),
    )
    .await
}

/// Owner `alice` with org "Acme" and `bob` as a member.
async fn team(h: &Server) -> (Account, Account, Uuid) {
    let alice = open_and_register(h, "alice@example.com").await;
    let bob = register(h, "bob@example.com", "correct horse battery staple").await;
    let org = create_org(h, &alice, "Acme").await;
    let inv = invite(h, &alice, org.id, None, "member").await;
    let (st, v) = accept(h, &bob, token_of(inv.link.as_deref().unwrap())).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    (alice, bob, org.id)
}

/// A team vault created by `a` in `org`; returns its id and key.
async fn create_vault(h: &Server, a: &Account, org: Uuid) -> (Uuid, Key32) {
    let mut rng = os_rng();
    let id = Uuid::now_v7();
    let vk = random_key32(&mut rng);
    let g = self_grant(
        &vk,
        id.as_bytes(),
        1,
        a.user_id.as_bytes(),
        &a.keys,
        &mut rng,
    )
    .unwrap();
    let (st, v) = h
        .post(
            "/v1/vaults",
            json!({
                "id": id,
                "org_id": org,
                "name_enc": b64::encode(b"sealed-name"),
                "self_grant": {
                    "wrapped_vault_key": b64::encode(&g.wrapped),
                    "signature": b64::encode(&g.signature),
                    "key_version": 1,
                },
            }),
            Some(a.access()),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    (id, vk)
}

/// `granter` grants `member` `permission` on `vault` with key `vk` (version `kv`).
async fn grant(
    h: &Server,
    granter: &Account,
    vault: Uuid,
    member: &Account,
    vk: &Key32,
    kv: u32,
    permission: &str,
) -> (StatusCode, Value) {
    let g = grant_vault_key(
        vk,
        vault.as_bytes(),
        kv,
        member.user_id.as_bytes(),
        &member.keys.public().x25519,
        granter.keys.ed25519_signing_key(),
        &mut os_rng(),
    )
    .unwrap();
    h.call(
        "PUT",
        &format!("/v1/vaults/{vault}/members/{}", member.user_id),
        Some(json!({
            "permission": permission,
            "key_version": kv,
            "wrapped_vault_key": b64::encode(&g.wrapped),
            "signature": b64::encode(&g.signature),
        })),
        Some(granter.access()),
    )
    .await
}

fn sealed(vk: &Key32, vault: Uuid, item: Uuid, kv: u32) -> Vec<u8> {
    seal_item(
        vk,
        vault.as_bytes(),
        item.as_bytes(),
        kv,
        b"{}",
        &mut os_rng(),
    )
    .unwrap()
}

fn change(vk: &Key32, vault: Uuid, item: Uuid, base: u64, kv: u32) -> Value {
    json!({
        "id": item,
        "base_revision": base,
        "key_version": kv,
        "envelope": b64::encode(&sealed(vk, vault, item, kv)),
        "deleted": false,
    })
}

async fn rotate(h: &Server, a: &Account, vault: Uuid, body: Value) -> (StatusCode, Value) {
    rotate_as(h, a.access(), vault, body).await
}

async fn rotate_as(h: &Server, token: &str, vault: Uuid, body: Value) -> (StatusCode, Value) {
    h.post(&format!("/v1/vaults/{vault}/rotate"), body, Some(token))
        .await
}

fn rotation_grant(granter: &Account, member: &Account, vault: Uuid, vk: &Key32, kv: u32) -> Value {
    let g = grant_vault_key(
        vk,
        vault.as_bytes(),
        kv,
        member.user_id.as_bytes(),
        &member.keys.public().x25519,
        granter.keys.ed25519_signing_key(),
        &mut os_rng(),
    )
    .unwrap();
    json!({
        "user": member.user_id,
        "wrapped": b64::encode(&g.wrapped),
        "signature": b64::encode(&g.signature),
    })
}

/// Orgs, members, roles, invites by mail and by link, the audit log and
/// public keys.
async fn t01_orgs_and_invites(h: &Server) {
    let recorded = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    h.state.set_mailer(Mailer::Recording(recorded.clone()));
    let alice = open_and_register(h, "alice@example.com").await;
    let bob = register(h, "bob@example.com", "correct horse battery staple").await;
    let carol = register(h, "carol@example.com", "correct horse battery staple").await;

    let (st, v) = h
        .post("/v1/orgs", json!({ "name": "  " }), Some(alice.access()))
        .await;
    assert_error(st, &v, StatusCode::BAD_REQUEST, "invalid");
    let org = create_org(h, &alice, "Acme").await;
    assert_eq!(org.role, Role::Owner);

    // Mailed invite: no link in the answer, the link is in the mail.
    let inv = invite(h, &alice, org.id, Some("Bob@Example.com"), "member").await;
    assert!(inv.emailed);
    assert!(inv.link.is_none());
    let mail = recorded.lock().unwrap().pop().unwrap();
    assert!(mail.to.eq_ignore_ascii_case("bob@example.com"));
    assert_eq!(mail.subject, ORG_INVITE_SUBJECT);
    assert!(mail.body.contains("\"Acme\""));
    let link = mail
        .body
        .lines()
        .find(|l| l.contains("/invite/"))
        .unwrap()
        .trim()
        .to_owned();
    // Bound to bob: carol can't use it.
    let (st, _) = accept(h, &carol, token_of(&link)).await;
    assert!(
        st == StatusCode::FORBIDDEN || st == StatusCode::NOT_FOUND,
        "{st}"
    );
    let (st, v) = accept(h, &bob, token_of(&link)).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["role"], "member");
    // Single use.
    let (st, _) = accept(h, &bob, token_of(&link)).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = accept(h, &bob, "not-a-token").await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    // Members see the member list; strangers get 404.
    let (st, v) = h
        .get(&format!("/v1/orgs/{}/members", org.id), Some(bob.access()))
        .await;
    assert_eq!(st, StatusCode::OK);
    let members: Vec<MemberView> = serde_json::from_value(v).unwrap();
    assert_eq!(members.len(), 2);
    let (st, _) = h
        .get(
            &format!("/v1/orgs/{}/members", org.id),
            Some(carol.access()),
        )
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, v) = h.get("/v1/orgs", Some(bob.access())).await;
    assert_eq!(st, StatusCode::OK);
    let orgs: Vec<OrgView> = serde_json::from_value(v).unwrap();
    assert_eq!(orgs.len(), 1);
    assert_eq!(orgs[0].role, Role::Member);

    // Members can't invite or read the audit log.
    let (st, v) = h
        .post(
            &format!("/v1/orgs/{}/invites", org.id),
            json!({ "role": "member" }),
            Some(bob.access()),
        )
        .await;
    assert_error(st, &v, StatusCode::FORBIDDEN, "forbidden");
    let (st, _) = h
        .get(&format!("/v1/orgs/{}/audit", org.id), Some(bob.access()))
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Public keys: co-members only.
    let (st, v) = h
        .get(
            &format!("/v1/users/{}/public-keys", bob.user_id),
            Some(alice.access()),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        b64::decode(v["x25519_pub"].as_str().unwrap()).unwrap(),
        bob.keys.public().x25519.to_vec()
    );
    let (st, _) = h
        .get(
            &format!("/v1/users/{}/public-keys", bob.user_id),
            Some(carol.access()),
        )
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    // Roles: admin promotion, the last owner can't leave or be demoted.
    let (st, _) = h
        .call(
            "PATCH",
            &format!("/v1/orgs/{}/members/{}", org.id, bob.user_id),
            Some(json!({ "role": "admin" })),
            Some(alice.access()),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, _) = h
        .call(
            "PATCH",
            &format!("/v1/orgs/{}/members/{}", org.id, alice.user_id),
            Some(json!({ "role": "member" })),
            Some(bob.access()),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "admins can't demote owners");
    let (st, v) = h
        .call(
            "DELETE",
            &format!("/v1/orgs/{}/members/{}", org.id, alice.user_id),
            None,
            Some(alice.access()),
        )
        .await;
    assert_error(st, &v, StatusCode::BAD_REQUEST, "invalid");

    // The admin reads the audit log: ids and kinds, no secrets.
    let (st, v) = h
        .get(
            &format!("/v1/orgs/{}/audit?limit=2", org.id),
            Some(bob.access()),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let page: AuditPage = serde_json::from_value(v).unwrap();
    assert_eq!(page.events.len(), 2);
    assert!(page.next_before.is_some());
    let (_, v) = h
        .get(
            &format!("/v1/orgs/{}/audit?limit=100", org.id),
            Some(bob.access()),
        )
        .await;
    let page: AuditPage = serde_json::from_value(v.clone()).unwrap();
    let kinds: Vec<&str> = page.events.iter().map(|e| e.kind.as_str()).collect();
    for k in [
        "org.created",
        "invite.sent",
        "invite.accepted",
        "member.role_changed",
    ] {
        assert!(kinds.contains(&k), "{k} missing in {kinds:?}");
    }
    assert!(!v.to_string().contains(token_of(&link)));

    // Removing bob.
    let (st, _) = h
        .call(
            "DELETE",
            &format!("/v1/orgs/{}/members/{}", org.id, bob.user_id),
            None,
            Some(alice.access()),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (_, v) = h.get("/v1/orgs", Some(bob.access())).await;
    assert_eq!(v, json!([]));
}

/// An org invite admits a registration on an invite-only server and makes
/// the new account a member.
async fn t02_invite_at_registration(h: &Server) {
    let alice = open_and_register(h, "alice@example.com").await;
    let org = create_org(h, &alice, "Acme").await;
    let inv = invite(h, &alice, org.id, Some("dave@example.com"), "admin").await;
    let token = token_of(inv.link.as_deref().unwrap()).to_owned();
    h.set_mode(RegistrationMode::InviteOnly).await;
    // Bound to dave.
    let err = try_register(
        h,
        "eve@example.com",
        "correct horse battery staple",
        json!({ "invite_token": token }),
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, StatusCode::FORBIDDEN);
    let dave = try_register(
        h,
        "dave@example.com",
        "correct horse battery staple",
        json!({ "invite_token": token }),
        None,
    )
    .await
    .unwrap();
    let (st, v) = h.get("/v1/orgs", Some(dave.access())).await;
    assert_eq!(st, StatusCode::OK);
    let orgs: Vec<OrgView> = serde_json::from_value(v).unwrap();
    assert_eq!(orgs.len(), 1);
    assert_eq!((orgs[0].id, orgs[0].role), (org.id, Role::Admin));
    // Used up.
    let (st, _) = accept(h, &dave, &token).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

/// Team vault creation, grants, permissions and revocation.
async fn t03_shared_vaults(h: &Server) {
    let (alice, bob, org) = team(h).await;
    let stranger = register(h, "mallory@example.com", "correct horse battery staple").await;

    // Members can't create team vaults; admins can.
    let (st, _) = h
        .post(
            "/v1/vaults",
            json!({
                "id": Uuid::now_v7(), "org_id": org, "name_enc": b64::encode(b"x"),
                "self_grant": { "wrapped_vault_key": b64::encode(b"w"), "signature": b64::encode(&[0u8; 64]), "key_version": 1 },
            }),
            Some(bob.access()),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (vault, vk) = create_vault(h, &alice, org).await;
    let list = vaults(h, alice.access()).await;
    let v = list.iter().find(|v| v.id == vault).unwrap();
    assert_eq!(v.kind, VaultKind::Shared);
    assert_eq!(v.permission, Permission::Manage);
    assert_eq!(v.org_id, Some(org));

    // Bob doesn't see it until granted.
    assert!(vaults(h, bob.access()).await.iter().all(|v| v.id != vault));
    let (st, _) = pull_raw(h, bob.access(), vault, 0, None).await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let item = Uuid::now_v7();
    let (st, v) = push_raw(
        h,
        alice.access(),
        vault,
        vec![change(&vk, vault, item, 0, 1)],
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");

    // Read grant: bob pulls, can't push, can't grant.
    let (st, v) = grant(h, &alice, vault, &bob, &vk, 1, "read").await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{v}");
    let list = vaults(h, bob.access()).await;
    let v = list.iter().find(|v| v.id == vault).unwrap();
    assert_eq!(v.permission, Permission::Read);
    assert!(v.grants.iter().any(|g| g.wrapped_by == alice.user_id));
    let (st, _) = pull_raw(h, bob.access(), vault, 0, None).await;
    assert_eq!(st, StatusCode::OK);
    let (st, v) = push_raw(h, bob.access(), vault, vec![change(&vk, vault, item, 1, 1)]).await;
    assert_error(st, &v, StatusCode::FORBIDDEN, "forbidden");
    let (st, _) = grant(h, &bob, vault, &bob, &vk, 1, "manage").await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    // Strangers can't be granted (not in the org).
    let (st, _) = grant(h, &alice, vault, &stranger, &vk, 1, "read").await;
    assert!(
        st == StatusCode::BAD_REQUEST || st == StatusCode::NOT_FOUND,
        "{st}"
    );

    // Member list with permissions and key state.
    let (st, v) = h
        .get(&format!("/v1/vaults/{vault}/members"), Some(alice.access()))
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let members: VaultMembersView = serde_json::from_value(v).unwrap();
    assert_eq!(members.key_version, 1);
    assert_eq!(members.created_by, Some(alice.user_id));
    let b = members
        .members
        .iter()
        .find(|m| m.user_id == bob.user_id)
        .unwrap();
    assert_eq!(b.permission, Some(Permission::Read));
    assert!(b.has_key);
    assert_eq!(b.granted_by, Some(alice.user_id));

    // Write: bob pushes.
    let (st, _) = grant(h, &alice, vault, &bob, &vk, 1, "write").await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, v) = push_raw(h, bob.access(), vault, vec![change(&vk, vault, item, 1, 1)]).await;
    assert_eq!(st, StatusCode::OK, "{v}");

    // The org vault listing.
    let (st, v) = h
        .get(&format!("/v1/orgs/{org}/vaults"), Some(alice.access()))
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v.as_array().unwrap().len(), 1);

    // Revoke: bob loses it.
    let (st, _) = h
        .call(
            "DELETE",
            &format!("/v1/vaults/{vault}/members/{}", bob.user_id),
            None,
            Some(alice.access()),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert!(vaults(h, bob.access()).await.iter().all(|v| v.id != vault));
    let (st, _) = pull_raw(h, bob.access(), vault, 0, None).await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let kinds = h.audit_kinds().await;
    for k in [
        "vault.created",
        "vault.member_granted",
        "vault.member_revoked",
        "vault.items_pushed",
    ] {
        assert!(kinds.iter().any(|x| x == k), "{k} missing in {kinds:?}");
    }
}

/// begin → pushes get 409 → upload → commit checks coverage and members →
/// key version 2; abandonment and GC.
async fn t04_rotation(h: &Server) {
    let (alice, bob, org) = team(h).await;
    let carol = register(h, "carol@example.com", "correct horse battery staple").await;
    let inv = invite(h, &alice, org, None, "member").await;
    let (st, _) = accept(h, &carol, token_of(inv.link.as_deref().unwrap())).await;
    assert_eq!(st, StatusCode::OK);
    let (vault, vk) = create_vault(h, &alice, org).await;
    for m in [&bob, &carol] {
        let (st, _) = grant(h, &alice, vault, m, &vk, 1, "write").await;
        assert_eq!(st, StatusCode::NO_CONTENT);
    }
    let items: Vec<Uuid> = (0..3).map(|_| Uuid::now_v7()).collect();
    let changes = items.iter().map(|i| change(&vk, vault, *i, 0, 1)).collect();
    let (st, _) = push_raw(h, alice.access(), vault, changes).await;
    assert_eq!(st, StatusCode::OK);
    // Bob is revoked.
    let (st, _) = h
        .call(
            "DELETE",
            &format!("/v1/vaults/{vault}/members/{}", bob.user_id),
            None,
            Some(alice.access()),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);

    // Only managers rotate; the version must be current + 1.
    let (st, _) = rotate(
        h,
        &carol,
        vault,
        json!({ "action": "begin", "new_key_version": 2 }),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, _) = rotate(
        h,
        &alice,
        vault,
        json!({ "action": "begin", "new_key_version": 3 }),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, v) = rotate(
        h,
        &alice,
        vault,
        json!({ "action": "begin", "new_key_version": 2 }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["new_key_version"], 2);

    // Pushes are paused; pulls work.
    let (st, v) = push_raw(
        h,
        carol.access(),
        vault,
        vec![change(&vk, vault, items[0], 1, 1)],
    )
    .await;
    assert_error(st, &v, StatusCode::CONFLICT, "rotating");
    let (st, _) = pull_raw(h, carol.access(), vault, 0, None).await;
    assert_eq!(st, StatusCode::OK);
    let list = vaults(h, carol.access()).await;
    let r = list
        .iter()
        .find(|v| v.id == vault)
        .unwrap()
        .rotation
        .clone()
        .unwrap();
    assert_eq!((r.by, r.abandoned), (alice.user_id, false));

    // Upload two of three items; a commit doesn't cover everything.
    let vk2 = random_key32(&mut os_rng());
    let up = |ids: &[Uuid]| {
        json!({
            "action": "upload",
            "items": ids.iter().map(|i| json!({ "id": i, "envelope": b64::encode(&sealed(&vk2, vault, *i, 2)) })).collect::<Vec<_>>(),
        })
    };
    let (st, v) = rotate(h, &alice, vault, up(&items[..2])).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["staged"], 2);
    let full = json!({
        "action": "commit",
        "wrapped_keys": [
            rotation_grant(&alice, &alice, vault, &vk2, 2),
            rotation_grant(&alice, &carol, vault, &vk2, 2),
        ],
    });
    let (st, v) = rotate(h, &alice, vault, full.clone()).await;
    assert_error(st, &v, StatusCode::BAD_REQUEST, "invalid");
    // Others can't upload into alice's rotation.
    let (st, _) = rotate(h, &carol, vault, up(&items[2..])).await;
    assert!(
        st == StatusCode::CONFLICT || st == StatusCode::FORBIDDEN,
        "{st}"
    );
    let (st, _) = rotate(h, &alice, vault, up(&items[2..])).await;
    assert_eq!(st, StatusCode::OK);

    // A commit missing carol, or naming revoked bob, is refused.
    let (st, v) = rotate(
        h,
        &alice,
        vault,
        json!({ "action": "commit", "wrapped_keys": [rotation_grant(&alice, &alice, vault, &vk2, 2)] }),
    )
    .await;
    assert_error(st, &v, StatusCode::BAD_REQUEST, "invalid");
    let (st, _) = rotate(
        h,
        &alice,
        vault,
        json!({ "action": "commit", "wrapped_keys": [
            rotation_grant(&alice, &alice, vault, &vk2, 2),
            rotation_grant(&alice, &carol, vault, &vk2, 2),
            rotation_grant(&alice, &bob, vault, &vk2, 2),
        ] }),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // Begin again by alice resumes (staging kept).
    let (st, v) = rotate(
        h,
        &alice,
        vault,
        json!({ "action": "begin", "new_key_version": 2 }),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["resumed"], true);
    assert_eq!(v["staged"], 3);

    let (st, v) = rotate(h, &alice, vault, full).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["key_version"], 2);
    let (st, v) = pull_raw(h, carol.access(), vault, 0, None).await;
    assert_eq!(st, StatusCode::OK);
    let rows = v["items"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|r| r["key_version"] == 2));
    let list = vaults(h, carol.access()).await;
    let cv = list.iter().find(|v| v.id == vault).unwrap();
    assert_eq!(cv.key_version, 2);
    assert!(cv.rotation.is_none());
    assert!(cv.grants.iter().any(|g| g.key_version == 2));
    // Old-version pushes are refused; new-version pushes work.
    let (st, _) = push_raw(
        h,
        carol.access(),
        vault,
        vec![change(&vk, vault, Uuid::now_v7(), 0, 1)],
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, v) = push_raw(
        h,
        carol.access(),
        vault,
        vec![change(&vk2, vault, Uuid::now_v7(), 0, 2)],
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert!(h.audit_kinds().await.iter().any(|k| k == "vault.rotated"));

    // Abandonment: carol (made manager) can't take over a fresh rotation,
    // but can after 15 minutes; GC discards abandoned ones.
    let (st, _) = grant(h, &alice, vault, &carol, &vk2, 2, "manage").await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, _) = rotate(
        h,
        &alice,
        vault,
        json!({ "action": "begin", "new_key_version": 3 }),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, v) = rotate(
        h,
        &carol,
        vault,
        json!({ "action": "begin", "new_key_version": 3 }),
    )
    .await;
    assert_error(st, &v, StatusCode::CONFLICT, "rotating");
    h.clock.advance(TimeDelta::minutes(16));
    // (Access tokens expired meanwhile.)
    let carol_token = login(h, &carol).await.tokens.access_token;
    let list = vaults(h, &carol_token).await;
    assert!(
        list.iter()
            .find(|v| v.id == vault)
            .unwrap()
            .rotation
            .as_ref()
            .unwrap()
            .abandoned
    );
    let (st, v) = rotate_as(
        h,
        &carol_token,
        vault,
        json!({ "action": "begin", "new_key_version": 3 }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["replaced_abandoned"], true);
    h.clock.advance(TimeDelta::minutes(16));
    let gone = h
        .state
        .sync()
        .store()
        .discard_abandoned_rotations(h.now())
        .await
        .unwrap();
    assert_eq!(gone, vec![vault]);
    let carol_token = login(h, &carol).await.tokens.access_token;
    let list = vaults(h, &carol_token).await;
    assert!(
        list.iter()
            .find(|v| v.id == vault)
            .unwrap()
            .rotation
            .is_none()
    );
    let (st, _) = push_raw(
        h,
        &carol_token,
        vault,
        vec![change(&vk2, vault, Uuid::now_v7(), 0, 2)],
    )
    .await;
    assert_eq!(st, StatusCode::OK);
}

both!(
    t01_orgs_and_invites,
    orgs_and_invites_mem,
    orgs_and_invites_pg
);
both!(
    t02_invite_at_registration,
    org_invite_at_registration_mem,
    org_invite_at_registration_pg
);
both!(t03_shared_vaults, shared_vaults_mem, shared_vaults_pg);
both!(t04_rotation, rotation_mem, rotation_pg);
