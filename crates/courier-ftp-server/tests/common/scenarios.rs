//! The auth scenarios, written once against [`Harness`] and instantiated for
//! both backends in `tests/auth.rs` (the log canary in `tests/logs.rs` reruns
//! some of them).

use axum::http::{Method, StatusCode, header};
use courier_ftp_proto::auth::{DeviceView, SessionResponse, TokenPair};
use courier_ftp_proto::error::LOGIN_FAILED_MESSAGE;
use courier_ftp_server::auth::store::Store;
use courier_ftp_server::auth::store::mem::MemItem;
use courier_ftp_server::auth::tokens::hash_presented;
use courier_ftp_server::events::BusEvent;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::Duration;
use uuid::Uuid;

use super::client::{
    LoginOpts, RegOpts, bundle_opens, change_password, devices_status, enable_totp,
    finish_recovery, login, login_ok, login_start, prepare_recovery, reauth, recovery_code,
    refresh, register, totp_code, try_register,
};
use super::{Harness, code, message};

const PW: &str = "correct horse battery staple";
const PW2: &str = "an entirely new master password";
const TOKEN_INVALID: &str = "invalid or expired token";
const REFRESH_INVALID: &str = "invalid or expired refresh token";

fn pair(v: Value) -> TokenPair {
    serde_json::from_value(v).unwrap()
}

async fn devices(h: &Harness, access: &str) -> Vec<DeviceView> {
    let (s, v) = h.get("/v1/devices", Some(access)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    serde_json::from_value(v).unwrap()
}

async fn audit_count(h: &Harness, kind: &str) -> usize {
    match h.store() {
        Store::Mem(m) => m.with_data(|d| d.audit.iter().filter(|a| a.kind == kind).count()),
        Store::Pg(pool) => {
            let n: i64 = sqlx_core::query_scalar::query_scalar(
                "SELECT count(*) FROM audit_events WHERE kind = $1",
            )
            .bind(kind)
            .fetch_one(pool)
            .await
            .unwrap();
            usize::try_from(n).unwrap()
        }
    }
}

/// Register → login on a second device → refresh → logout (AC1).
pub async fn t01_register_login_refresh_logout(h: &Harness) {
    let a = register(h, "Alice@Example.test", PW).await;
    assert!(!a.is_instance_admin);
    let list = devices(h, &a.access).await;
    assert_eq!(list.len(), 1);
    assert!(list[0].current);
    assert_eq!(list[0].id, a.device_id);

    // Second device (email case does not matter).
    let s2 = login_ok(h, "alice@example.test", PW, LoginOpts::default()).await;
    assert_eq!(s2.user_id, a.user_id);
    assert_ne!(s2.device_id, a.device_id);
    assert_eq!(s2.account_keys.version, 1);
    assert_eq!(s2.account_keys.ed25519_pub, a.keys.public().ed25519.to_vec());
    let list = devices(h, &s2.tokens.access_token).await;
    assert_eq!(
        list.iter().map(|d| d.id).collect::<Vec<_>>(),
        [s2.device_id, a.device_id],
        "newest first"
    );
    assert!(list[0].current && !list[1].current);
    assert_eq!(list[0].name.as_deref(), Some("second"));

    // Refresh.
    h.clock.advance(Duration::minutes(1));
    let (s, v) = refresh(h, &s2.tokens.refresh_token).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let p = pair(v);
    assert_eq!(p.access_expires_in_s, 15 * 60);
    assert_eq!(p.refresh_expires_in_s, 30 * 24 * 3600);
    assert_eq!(devices_status(h, &p.access_token).await, StatusCode::OK);
    assert_eq!(
        devices_status(h, &s2.tokens.access_token).await,
        StatusCode::UNAUTHORIZED,
        "the family's older access token is deleted on rotation"
    );

    // Logout.
    let (s, _, _) = h
        .call(Method::POST, "/v1/auth/logout", Some(&p.access_token), None)
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, v) = h.get("/v1/devices", Some(&p.access_token)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(message(&v), TOKEN_INVALID);
    let (s, v) = refresh(h, &p.refresh_token).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(message(&v), REFRESH_INVALID);
    // The first device is unaffected.
    let list = devices(h, &a.access).await;
    assert!(list.iter().any(|d| d.id == s2.device_id && d.revoked_at.is_some()));
    assert!(h.events.events().contains(&BusEvent::DevicesRevoked {
        device_ids: vec![s2.device_id]
    }));
}

/// Unknown emails look like known ones (AC3).
pub async fn t02_unknown_email_indistinguishable(h: &Harness) {
    register(h, "known@example.test", PW).await;
    let before = h.login_state_count().await;
    let (s1, known, _) = login_start(h, "known@example.test", PW).await;
    let (s2, unknown, _) = login_start(h, "nobody@example.test", PW).await;
    assert_eq!((s1, s2), (StatusCode::OK, StatusCode::OK));
    let shape = |v: &Value| {
        let mut keys: Vec<(String, usize)> = v
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().map_or(0, str::len)))
            .collect();
        keys.sort();
        keys
    };
    assert_eq!(shape(&known), shape(&unknown));
    assert_eq!(h.login_state_count().await, before + 2, "both stored a state");

    let (s_wrong, v_wrong) = login(h, "known@example.test", "wrong password", LoginOpts::default()).await;
    let (s_unknown, v_unknown) = login(h, "nobody@example.test", PW, LoginOpts::default()).await;
    assert_eq!(s_wrong, StatusCode::UNAUTHORIZED);
    assert_eq!((s_wrong, &v_wrong), (s_unknown, &v_unknown));
    assert_eq!(message(&v_wrong), LOGIN_FAILED_MESSAGE);
    assert_eq!(code(&v_wrong), "auth_required");

    // An unknown login state id fails the same way.
    let (s, v) = h
        .post(
            "/v1/auth/login/finish",
            None,
            json!({
                "login_state_id": Uuid::now_v7(),
                "credential_finalization": "AAAA",
                "device": {},
            }),
        )
        .await;
    assert_eq!((s, &v), (s_wrong, &v_wrong));
}

/// A failing registration step leaves nothing behind (AC1).
pub async fn t03_register_is_atomic(h: &Harness) {
    let a = register(h, "first@example.test", PW).await;
    h.set_mode("invite-only").await;
    let invite = h.invite(Some("second@example.test")).await;
    let err = try_register(
        h,
        "second@example.test",
        PW,
        RegOpts {
            invite: Some(invite.clone()),
            vault_id: Some(a.vault_id),
            ..RegOpts::default()
        },
    )
    .await
    .err()
    .expect("duplicate vault id");
    assert_eq!(err.0, StatusCode::CONFLICT);
    assert_eq!(message(&err.1), "vault id already exists");
    assert!(!h.email_exists("second@example.test").await);
    // The invite was not consumed by the failed attempt.
    let b = try_register(
        h,
        "second@example.test",
        PW,
        RegOpts {
            invite: Some(invite),
            ..RegOpts::default()
        },
    )
    .await
    .map_err(|(s, v)| format!("{s} {v}"))
    .unwrap();
    assert!(h.user_exists(b.user_id).await);
    // The same email again: 409 at start.
    h.open().await;
    let err = try_register(h, "SECOND@example.test", PW, RegOpts::default())
        .await
        .err()
        .unwrap();
    assert_eq!(err.0, StatusCode::CONFLICT);
    assert_eq!(message(&err.1), "email already registered");
}

/// Registration modes and invites (AC7).
pub async fn t04_registration_modes_and_invites(h: &Harness) {
    let reg = |email: &'static str, invite: Option<String>| async move {
        try_register(
            h,
            email,
            PW,
            RegOpts {
                invite,
                ..RegOpts::default()
            },
        )
        .await
    };
    let forbidden = |r: Result<_, (StatusCode, Value)>, msg: &str| {
        let (s, v) = r.err().expect("refused");
        assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
        assert_eq!(message(&v), msg);
    };
    // invite-only is the default after the migration.
    forbidden(reg("a@example.test", None).await, "registration requires an invite");
    let bound = h.invite(Some("b@example.test")).await;
    forbidden(
        reg("c@example.test", Some(bound.clone())).await,
        "invalid or expired invite",
    );
    forbidden(
        reg("x@example.test", Some("not-a-real-invite".into())).await,
        "invalid or expired invite",
    );
    assert!(reg("b@example.test", Some(bound.clone())).await.is_ok());
    forbidden(
        reg("b2@example.test", Some(bound)).await,
        "invalid or expired invite",
    );
    // An unbound invite works for any email, once; an expired one does not.
    let any = h.invite(None).await;
    assert!(reg("d@example.test", Some(any)).await.is_ok());
    let late = h.invite(None).await;
    h.clock.advance(Duration::days(1) + Duration::seconds(1));
    forbidden(reg("e@example.test", Some(late)).await, "invalid or expired invite");

    // closed: even a valid invite is refused.
    let inv = h.invite(None).await;
    h.set_mode("closed").await;
    forbidden(reg("f@example.test", Some(inv.clone())).await, "registration is closed");
    forbidden(reg("f@example.test", None).await, "registration is closed");
    // A setup token only works while there are no users.
    h.set_setup_token("setup-token-value").await;
    let r = try_register(
        h,
        "g@example.test",
        PW,
        RegOpts {
            setup: Some("setup-token-value".into()),
            ..RegOpts::default()
        },
    )
    .await;
    forbidden(r, "invalid setup token");

    // open: no invite needed (an invite is optional).
    h.set_mode("open").await;
    assert!(reg("h@example.test", None).await.is_ok());
    assert!(reg("i@example.test", Some(inv)).await.is_ok());
}

/// Token lifetimes: access 15 min, reauth 5 min, refresh 30 days (AC8).
pub async fn t05_access_token_expiry(h: &Harness) {
    let a = register(h, "exp@example.test", PW).await;
    h.clock.advance(Duration::minutes(15) - Duration::seconds(1));
    assert_eq!(devices_status(h, &a.access).await, StatusCode::OK);
    h.clock.advance(Duration::seconds(1));
    let (s, v) = h.get("/v1/devices", Some(&a.access)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(message(&v), TOKEN_INVALID);
    // The refresh token still works.
    let (s, v) = refresh(h, &a.refresh).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let p = pair(v);
    assert_eq!(devices_status(h, &p.access_token).await, StatusCode::OK);

    // Reauth tokens live 5 minutes.
    let token = reauth(h, &a, None).await;
    h.clock.advance(Duration::minutes(5));
    let (s, v) = h
        .delete(
            "/v1/account",
            Some(&p.access_token),
            Some(json!({ "reauth_token": token })),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(message(&v), "reauth required");
    assert!(h.user_exists(a.user_id).await);

    // Refresh tokens live 30 days (each rotation issues a fresh 30 days).
    let (s, v) = refresh(h, &p.refresh_token).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let p = pair(v);
    h.clock.advance(Duration::days(30) - Duration::seconds(1));
    let (s, v) = refresh(h, &p.refresh_token).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let p = pair(v);
    h.clock.advance(Duration::days(30));
    let (s, v) = refresh(h, &p.refresh_token).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(message(&v), REFRESH_INVALID);
}

/// Rotation keeps working along the chain (AC2).
pub async fn t06_refresh_rotation(h: &Harness) {
    let a = register(h, "rot@example.test", PW).await;
    let mut current = TokenPair {
        access_token: a.access.clone(),
        refresh_token: a.refresh.clone(),
        access_expires_in_s: 0,
        refresh_expires_in_s: 0,
    };
    for _ in 0..3 {
        let (s, v) = refresh(h, &current.refresh_token).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let next = pair(v);
        assert_ne!(next.refresh_token, current.refresh_token);
        assert_eq!(devices_status(h, &next.access_token).await, StatusCode::OK);
        assert_eq!(
            devices_status(h, &current.access_token).await,
            StatusCode::UNAUTHORIZED
        );
        current = next;
    }
    let list = devices(h, &current.access_token).await;
    assert_eq!(list.len(), 1);
    // Garbage tokens are invalid, not internal errors.
    let long = "A".repeat(44);
    for bad in ["", "short", long.as_str()] {
        let (s, v) = refresh(h, bad).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{bad}: {v}");
        assert_eq!(message(&v), REFRESH_INVALID);
    }
    // An access token is not a refresh token.
    let (s, _) = refresh(h, &current.access_token).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

/// A used refresh token revokes its whole family (AC2).
pub async fn t07_refresh_reuse_revokes_family(h: &Harness) {
    let a = register(h, "reuse@example.test", PW).await;
    let (s, v) = refresh(h, &a.refresh).await;
    assert_eq!(s, StatusCode::OK);
    let p1 = pair(v);
    assert_eq!(devices_status(h, &p1.access_token).await, StatusCode::OK);
    // The attacker (or a confused client) presents the old token again.
    let (s, v) = refresh(h, &a.refresh).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(
        message(&v),
        "refresh token reuse detected; this device must log in again"
    );
    assert_eq!(h.token_count(a.device_id).await, 0, "family deleted");
    assert_eq!(
        devices_status(h, &p1.access_token).await,
        StatusCode::UNAUTHORIZED
    );
    let (s, v) = refresh(h, &p1.refresh_token).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(message(&v), REFRESH_INVALID);
    assert_eq!(audit_count(h, "auth.refresh_token_reuse").await, 1);
    // The device logs in again and resumes its id.
    let s = login_ok(
        h,
        &a.email,
        PW,
        LoginOpts {
            device_id: Some(a.device_id),
            ..LoginOpts::default()
        },
    )
    .await;
    assert_eq!(s.device_id, a.device_id);
}

/// Logout revokes the calling device (AC1).
pub async fn t08_logout_revokes_device(h: &Harness) {
    let a = register(h, "out@example.test", PW).await;
    let other = login_ok(h, &a.email, PW, LoginOpts::default()).await;
    h.events.clear();
    let (s, _, v) = h
        .call(Method::POST, "/v1/auth/logout", Some(&a.access), None)
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
    assert_eq!(h.token_count(a.device_id).await, 0);
    assert_eq!(devices_status(h, &a.access).await, StatusCode::UNAUTHORIZED);
    assert_eq!(refresh(h, &a.refresh).await.0, StatusCode::UNAUTHORIZED);
    let (s, _, _) = h
        .call(Method::POST, "/v1/auth/logout", Some(&a.access), None)
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(
        h.events.events(),
        [BusEvent::DevicesRevoked {
            device_ids: vec![a.device_id]
        }]
    );
    let list = devices(h, &other.tokens.access_token).await;
    let me = list.iter().find(|d| d.id == a.device_id).unwrap();
    assert!(me.revoked_at.is_some());
    // Logging in with a revoked device id creates a new device.
    let again = login_ok(
        h,
        &a.email,
        PW,
        LoginOpts {
            device_id: Some(a.device_id),
            ..LoginOpts::default()
        },
    )
    .await;
    assert_ne!(again.device_id, a.device_id);
    // Missing and malformed bearer headers.
    let (s, _, v) = h.call(Method::POST, "/v1/auth/logout", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(message(&v), "authentication required");
    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/v1/devices")
        .header(header::AUTHORIZATION, "Basic abc")
        .body(axum::body::Body::empty())
        .unwrap();
    let (s, _, b) = h.send(req).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(message(&super::json(&b)), "authentication required");
}

/// Device list and revocation (foreign → 404, revoked token → 401).
pub async fn t09_devices_list_and_revoke(h: &Harness) {
    let a = register(h, "dev-a@example.test", PW).await;
    let b = register(h, "dev-b@example.test", PW).await;
    let a2 = login_ok(h, &a.email, PW, LoginOpts::default()).await;

    for foreign in [b.device_id, Uuid::now_v7()] {
        let (s, v) = h
            .delete(&format!("/v1/devices/{foreign}"), Some(&a.access), None)
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_eq!(message(&v), "device not found");
    }
    assert_eq!(devices_status(h, &b.access).await, StatusCode::OK);

    h.events.clear();
    let (s, _) = h
        .delete(&format!("/v1/devices/{}", a2.device_id), Some(&a.access), None)
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(
        devices_status(h, &a2.tokens.access_token).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        refresh(h, &a2.tokens.refresh_token).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        h.events.events(),
        [BusEvent::DevicesRevoked {
            device_ids: vec![a2.device_id]
        }]
    );
    let (s, _) = h
        .delete(&format!("/v1/devices/{}", a2.device_id), Some(&a.access), None)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "already revoked");
    let list = devices(h, &a.access).await;
    assert_eq!(list.len(), 2);
    assert!(list.iter().any(|d| d.id == a2.device_id && d.revoked_at.is_some()));

    // Resuming an active device keeps its id and replaces its tokens.
    let again = login_ok(
        h,
        &a.email,
        PW,
        LoginOpts {
            device_id: Some(a.device_id),
            ..LoginOpts::default()
        },
    )
    .await;
    assert_eq!(again.device_id, a.device_id);
    assert_eq!(devices_status(h, &a.access).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        devices_status(h, &again.tokens.access_token).await,
        StatusCode::OK
    );
    // Another user's device id is not resumed.
    let foreign = login_ok(
        h,
        &a.email,
        PW,
        LoginOpts {
            device_id: Some(b.device_id),
            ..LoginOpts::default()
        },
    )
    .await;
    assert_ne!(foreign.device_id, b.device_id);
    assert_eq!(devices_status(h, &b.access).await, StatusCode::OK);

    // Revoking the calling device equals logout.
    let (s, _) = h
        .delete(
            &format!("/v1/devices/{}", a.device_id),
            Some(&again.tokens.access_token),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(
        devices_status(h, &again.tokens.access_token).await,
        StatusCode::UNAUTHORIZED
    );
}

/// TOTP: enable, login without/with code, replay, disable (AC11).
pub async fn t10_totp_enable_login_replay_disable(h: &Harness) {
    let a = register(h, "totp@example.test", PW).await;
    let (s, v) = h
        .post("/v1/account/totp", Some(&a.access), json!({ "code": "123456" }))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(message(&v), "no pending totp setup");
    let secret = enable_totp(h, &a).await;
    let (s, v) = h
        .post("/v1/account/totp", Some(&a.access), json!({ "code": null }))
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(message(&v), "totp already enabled");

    // Login without code.
    h.clock.advance(Duration::seconds(30));
    let (s, v) = login(h, &a.email, PW, LoginOpts::default()).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(message(&v).starts_with("totp_required"), "{v}");
    // A wrong password never reveals the TOTP step.
    let (s, v) = login(h, &a.email, "wrong", LoginOpts::default()).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(message(&v), LOGIN_FAILED_MESSAGE);
    // With code.
    let code_now = totp_code(h, &secret, 0);
    let opts = LoginOpts {
        totp: Some(code_now.clone()),
        ..LoginOpts::default()
    };
    let (s, v) = login(h, &a.email, PW, opts.clone()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // The same code again.
    let (s, v) = login(h, &a.email, PW, opts).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(message(&v), "totp_invalid: invalid or already used TOTP code");
    // An older step than the last accepted one is a replay too.
    let (s, _) = login(
        h,
        &a.email,
        PW,
        LoginOpts {
            totp: Some(totp_code(h, &secret, -1)),
            ..LoginOpts::default()
        },
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Disable needs a current code.
    let (s, v) = h
        .delete(
            "/v1/account/totp",
            Some(&a.access),
            Some(json!({ "code": totp_code(h, &secret, 5) })),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(message(&v).starts_with("totp_invalid"));
    h.clock.advance(Duration::seconds(30));
    let (s, v) = h
        .delete(
            "/v1/account/totp",
            Some(&a.access),
            Some(json!({ "code": totp_code(h, &secret, 0) })),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
    let (s, v) = login(h, &a.email, PW, LoginOpts::default()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = h
        .delete(
            "/v1/account/totp",
            Some(&a.access),
            Some(json!({ "code": "123456" })),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(message(&v), "totp is not enabled");
}

/// Online password change (AC9).
pub async fn t11_password_change(h: &Harness) {
    let mut a = register(h, "pw@example.test", PW).await;
    let other = login_ok(h, &a.email, PW, LoginOpts::default()).await;
    let stranger = register(h, "stranger@example.test", PW).await;
    let foreign_reauth = reauth(h, &stranger, None).await;

    // Without a (valid) reauth token.
    let (s, v) = change_password(h, &a, &foreign_reauth, PW2, 2).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(message(&v), "reauth required");
    let (s, v) = change_password(h, &a, "not-a-token", PW2, 2).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{v}");
    // Wrong version.
    let token = reauth(h, &a, None).await;
    let (s, v) = change_password(h, &a, &token, PW2, 3).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(message(&v), "account key version changed");

    let token = reauth(h, &a, None).await;
    h.events.clear();
    let (s, v) = change_password(h, &a, &token, PW2, 2).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v, json!({ "version": 2 }));
    // The reauth token is single use.
    let (s, _) = change_password(h, &a, &token, PW2, 3).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    assert_eq!(
        h.events.events(),
        [
            BusEvent::AccountChanged {
                user_id: a.user_id,
                key_version: 2,
                origin_device: Some(a.device_id),
            },
            BusEvent::DevicesRevoked {
                device_ids: vec![other.device_id]
            },
        ]
    );
    // This device keeps working, the other one must log in again.
    assert_eq!(devices_status(h, &a.access).await, StatusCode::OK);
    assert_eq!(
        devices_status(h, &other.tokens.access_token).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(h.token_count(other.device_id).await, 0);
    let list = devices(h, &a.access).await;
    assert!(list.iter().all(|d| d.revoked_at.is_none()), "rows stay");

    let (s, v) = login(h, &a.email, PW, LoginOpts::default()).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "old password: {v}");
    a.password = PW2.into();
    assert!(bundle_opens(h, &a.email, PW2, a.user_id).await);
    let resumed = login_ok(
        h,
        &a.email,
        PW2,
        LoginOpts {
            device_id: Some(other.device_id),
            ..LoginOpts::default()
        },
    )
    .await;
    assert_eq!(resumed.device_id, other.device_id);
    assert_eq!(resumed.account_keys.version, 2);
    let keys = h.store().account_keys(a.user_id).await.unwrap().unwrap();
    assert_eq!(keys.version, 2);
}

/// Tokens are stored only as SHA-256 hashes (AC12).
pub async fn t12_tokens_stored_hashed(h: &Harness) {
    let a = register(h, "hash@example.test", PW).await;
    let r = reauth(h, &a, None).await;
    let raw = |wire: &str| -> Vec<u8> { courier_ftp_proto::b64::decode(wire).unwrap() };
    let raws = [raw(&a.access), raw(&a.refresh), raw(&r)];
    let stored: Vec<Vec<u8>> = match h.store() {
        Store::Mem(m) => m.with_data(|d| {
            d.tokens
                .keys()
                .chain(d.reauth.keys())
                .map(|k| k.0.to_vec())
                .collect()
        }),
        Store::Pg(pool) => {
            let mut all: Vec<Vec<u8>> = Vec::new();
            for sql in [
                "SELECT token_hash FROM auth_tokens",
                "SELECT token_hash FROM reauth_tokens",
            ] {
                let rows: Vec<Vec<u8>> = sqlx_core::query_scalar::query_scalar(sql)
                    .fetch_all(pool)
                    .await
                    .unwrap();
                all.extend(rows);
            }
            all
        }
    };
    assert_eq!(stored.len(), 3);
    for (raw, wire) in raws.iter().zip([&a.access, &a.refresh, &r]) {
        assert!(!stored.contains(raw), "raw token stored");
        let hashed: [u8; 32] = Sha256::digest(raw).into();
        assert!(stored.contains(&hashed.to_vec()));
        assert_eq!(hash_presented(wire).unwrap().0, hashed);
    }
    if let Store::Pg(pool) = h.store() {
        // No bytea column anywhere holds a raw token.
        let cols: Vec<(String, String)> = sqlx_core::query_as::query_as(
            "SELECT table_name::text, column_name::text FROM information_schema.columns \
             WHERE table_schema = 'public' AND data_type = 'bytea'",
        )
        .fetch_all(pool)
        .await
        .unwrap();
        for (table, column) in cols {
            let values: Vec<Option<Vec<u8>>> = sqlx_core::query_scalar::query_scalar(&format!(
                "SELECT \"{column}\" FROM \"{table}\""
            ))
            .fetch_all(pool)
            .await
            .unwrap();
            for v in values.into_iter().flatten() {
                for raw in &raws {
                    assert!(
                        !v.windows(raw.len()).any(|w| w == raw.as_slice()),
                        "raw token in {table}.{column}"
                    );
                }
            }
        }
    }
}

/// Disabled accounts: tokens rejected, login fails generically.
pub async fn t13_disabled_account_rejected(h: &Harness) {
    let a = register(h, "off@example.test", PW).await;
    let (_, wrong) = login(h, &a.email, "wrong password", LoginOpts::default()).await;
    h.disable(a.user_id).await;
    let (s, v) = h.get("/v1/devices", Some(&a.access)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(message(&v), TOKEN_INVALID);
    let (s, v) = login(h, &a.email, PW, LoginOpts::default()).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v, wrong, "identical to a wrong password");
    let (s, v) = refresh(h, &a.refresh).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(message(&v), REFRESH_INVALID);
}

async fn add_item(h: &Harness, vault: Uuid) {
    match h.store() {
        Store::Mem(m) => m.with_data(|d| {
            d.items.insert(
                (vault, Uuid::now_v7()),
                MemItem {
                    revision: 1,
                    key_version: 1,
                    envelope: vec![1, 2, 3],
                    deleted: false,
                    updated_at: h.now(),
                },
            );
        }),
        Store::Pg(pool) => {
            sqlx_core::query::query(
                "INSERT INTO items (vault_id, id, revision, key_version, envelope, updated_at) \
                 VALUES ($1, $2, 1, 1, '\\x010203', now())",
            )
            .bind(vault)
            .bind(Uuid::now_v7())
            .execute(pool)
            .await
            .unwrap();
        }
    }
}

async fn leftovers(h: &Harness, user: Uuid, vault: Uuid) -> i64 {
    match h.store() {
        Store::Mem(m) => m.with_data(|d| {
            let n = usize::from(d.users.contains_key(&user))
                + usize::from(d.account_keys.contains_key(&user))
                + d.devices.values().filter(|x| x.user_id == user).count()
                + usize::from(d.vaults.contains_key(&vault))
                + d.vault_members.iter().filter(|m| m.user_id == user).count()
                + d.items.keys().filter(|(v, _)| *v == vault).count()
                + d.reauth.values().filter(|(u, _)| *u == user).count()
                + d.login_states
                    .values()
                    .filter(|l| l.user_id == Some(user))
                    .count()
                + usize::from(d.recovery_codes.contains_key(&user));
            i64::try_from(n).unwrap()
        }),
        Store::Pg(_) => {
            let mut n = 0;
            for sql in [
                "SELECT count(*) FROM users WHERE id = $1",
                "SELECT count(*) FROM account_keys WHERE user_id = $1",
                "SELECT count(*) FROM devices WHERE user_id = $1",
                "SELECT count(*) FROM vault_members WHERE user_id = $1",
                "SELECT count(*) FROM reauth_tokens WHERE user_id = $1",
                "SELECT count(*) FROM login_states WHERE user_id = $1",
                "SELECT count(*) FROM recovery_codes WHERE user_id = $1",
            ] {
                n += h.pg_count(sql, user).await;
            }
            for sql in [
                "SELECT count(*) FROM vaults WHERE id = $1",
                "SELECT count(*) FROM items WHERE vault_id = $1",
            ] {
                n += h.pg_count(sql, vault).await;
            }
            n
        }
    }
}

/// Account deletion removes everything (reauth needed).
pub async fn t14_delete_account_removes_everything(h: &Harness) {
    let a = register(h, "gone@example.test", PW).await;
    let b = register(h, "stays@example.test", PW).await;
    let other = login_ok(h, &a.email, PW, LoginOpts::default()).await;
    add_item(h, a.vault_id).await;
    recovery_code(h, &a.email).await;
    let _ = login_start(h, &a.email, PW).await;
    assert!(leftovers(h, a.user_id, a.vault_id).await > 0);

    let (s, v) = h.delete("/v1/account", Some(&a.access), Some(json!({}))).await;
    assert!(s.is_client_error(), "{v}");
    let (s, v) = h
        .delete(
            "/v1/account",
            Some(&a.access),
            Some(json!({ "reauth_token": "x" })),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(message(&v), "reauth required");
    let b_reauth = reauth(h, &b, None).await;
    let (s, _) = h
        .delete(
            "/v1/account",
            Some(&a.access),
            Some(json!({ "reauth_token": b_reauth })),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "another user's reauth token");

    let token = reauth(h, &a, None).await;
    h.events.clear();
    let (s, v) = h
        .delete(
            "/v1/account",
            Some(&a.access),
            Some(json!({ "reauth_token": token })),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
    assert_eq!(leftovers(h, a.user_id, a.vault_id).await, 0);
    assert_eq!(h.token_count(a.device_id).await, 0);
    assert_eq!(h.token_count(other.device_id).await, 0);
    assert_eq!(devices_status(h, &a.access).await, StatusCode::UNAUTHORIZED);
    let ev = h.events.events();
    let BusEvent::DevicesRevoked { device_ids } = &ev[0] else {
        panic!("{ev:?}");
    };
    let mut ids = device_ids.clone();
    ids.sort();
    let mut want = vec![a.device_id, other.device_id];
    want.sort();
    assert_eq!(ids, want);
    assert_eq!(audit_count(h, "account.deleted").await, 1);
    let (s, _) = login(h, &a.email, PW, LoginOpts::default()).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Others are untouched; the email can be registered again.
    assert_eq!(devices_status(h, &b.access).await, StatusCode::OK);
    let again = register(h, &a.email, PW2).await;
    assert_ne!(again.user_id, a.user_id);
}

/// Recovery with the recovery key and a one-time code (AC10).
pub async fn t15_recovery_flow(h: &Harness) {
    let a = register(h, "lost@example.test", PW).await;
    let other = login_ok(h, &a.email, PW, LoginOpts::default()).await;

    // Unknown emails get 202 too (no SMTP configured here).
    for email in [a.email.as_str(), "nobody@example.test"] {
        let (s, _) = h
            .post("/v1/account/recovery/code", None, json!({ "email": email }))
            .await;
        assert_eq!(s, StatusCode::ACCEPTED);
    }

    // Five wrong codes delete the code.
    let code1 = recovery_code(h, &a.email).await;
    for _ in 0..5 {
        let err = prepare_recovery(h, &a, "0000-0000-0000-0000", PW2)
            .await
            .err()
            .unwrap();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        assert_eq!(message(&err.1), "invalid or expired recovery code");
    }
    let err = prepare_recovery(h, &a, &code1, PW2).await.err().unwrap();
    assert_eq!(err.0, StatusCode::UNAUTHORIZED, "deleted after 5 failures");

    // An invalid signature: 403 and nothing changes.
    let code2 = recovery_code(h, &a.email).await;
    // Dashes and case are ignored on input.
    let typed = code2.replace('-', "").to_lowercase();
    let attempt = prepare_recovery(h, &a, &typed, PW2)
        .await
        .map_err(|(s, v)| format!("{s} {v}"))
        .unwrap();
    let mut bad = attempt.request.clone();
    bad.signature[0] ^= 1;
    let (s, v) = finish_recovery(h, &bad).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(message(&v), "recovery proof signature does not verify");
    let mut wrong_version = attempt.request.clone();
    wrong_version.version = 5;
    let (s, _) = finish_recovery(h, &wrong_version).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(h.store().account_keys(a.user_id).await.unwrap().unwrap().version, 1);
    assert_eq!(devices_status(h, &a.access).await, StatusCode::OK);

    // The valid attempt.
    h.events.clear();
    let (s, v) = finish_recovery(h, &attempt.request).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v, json!({ "version": 2 }));
    let ev = h.events.events();
    assert_eq!(
        ev[0],
        BusEvent::AccountChanged {
            user_id: a.user_id,
            key_version: 2,
            origin_device: None
        }
    );
    let BusEvent::DevicesRevoked { device_ids } = &ev[1] else {
        panic!("{ev:?}");
    };
    assert!(device_ids.contains(&a.device_id) && device_ids.contains(&other.device_id));
    // Every device is revoked; the old password fails, the new one works.
    assert_eq!(devices_status(h, &a.access).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        devices_status(h, &other.tokens.access_token).await,
        StatusCode::UNAUTHORIZED
    );
    let (s, _) = login(h, &a.email, PW, LoginOpts::default()).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(bundle_opens(h, &a.email, PW2, a.user_id).await);
    let s: SessionResponse = login_ok(
        h,
        &a.email,
        PW2,
        LoginOpts {
            device_id: Some(a.device_id),
            ..LoginOpts::default()
        },
    )
    .await;
    assert_ne!(s.device_id, a.device_id, "revoked devices are not resumed");
    let list = devices(h, &s.tokens.access_token).await;
    assert!(
        list.iter()
            .filter(|d| d.id == a.device_id || d.id == other.device_id)
            .all(|d| d.revoked_at.is_some())
    );
    // The code is consumed.
    let (s, _) = finish_recovery(h, &attempt.request).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Expired codes fail.
    let code_old = recovery_code(h, &a.email).await;
    h.clock.advance(Duration::hours(24));
    assert!(prepare_recovery(h, &a, &code_old, PW2).await.is_err());
}

/// Login states expire after 60 s and are single use (AC8).
pub async fn t16_login_state_ttl_and_single_use(h: &Harness) {
    use courier_ftp_crypto::random::os_rng;
    use courier_ftp_proto::auth::LoginStartResponse;

    let a = register(h, "state@example.test", PW).await;
    let finish = |state_id: Uuid, ke3: Vec<u8>| {
        json!({
            "login_state_id": state_id,
            "credential_finalization": courier_ftp_proto::b64::encode(&ke3),
            "device": {},
        })
    };
    // Expired.
    let (s, v, st) = login_start(h, &a.email, PW).await;
    assert_eq!(s, StatusCode::OK);
    let start: LoginStartResponse = serde_json::from_value(v).unwrap();
    let fin = st
        .finish(
            &mut os_rng(),
            PW.as_bytes(),
            &start.credential_response,
            &super::client::ksf(),
        )
        .unwrap();
    h.clock.advance(Duration::seconds(60));
    let (s, v) = h
        .post(
            "/v1/auth/login/finish",
            None,
            finish(start.login_state_id, fin.finalization.clone()),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(message(&v), LOGIN_FAILED_MESSAGE);

    // Within 60 s: works once.
    let (_, v, st) = login_start(h, &a.email, PW).await;
    let start: LoginStartResponse = serde_json::from_value(v).unwrap();
    let fin = st
        .finish(
            &mut os_rng(),
            PW.as_bytes(),
            &start.credential_response,
            &super::client::ksf(),
        )
        .unwrap();
    h.clock.advance(Duration::seconds(59));
    let body = finish(start.login_state_id, fin.finalization);
    let (s, v) = h.post("/v1/auth/login/finish", None, body.clone()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    for t in [&v["tokens"]["access_token"], &v["tokens"]["refresh_token"]] {
        h.canary(t.as_str().unwrap());
    }
    let (s, v) = h.post("/v1/auth/login/finish", None, body).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "single use");
    assert_eq!(message(&v), LOGIN_FAILED_MESSAGE);

    // Expired states are swept by later `login/start`s.
    for _ in 0..3 {
        let _ = login_start(h, &a.email, PW).await;
    }
    h.clock.advance(Duration::seconds(61));
    let _ = login_start(h, &a.email, PW).await;
    assert_eq!(h.login_state_count().await, 1);
}

/// Rate limits per email and per IP (AC5). Needs the default quotas.
pub async fn t17_rate_limits_email_and_ip(h: &Harness) {
    let start = |email: String| async move {
        let (state_unused, ke1) =
            courier_ftp_crypto::opaque::client_login_start(&mut courier_ftp_crypto::random::os_rng(), b"pw")
                .unwrap();
        drop(state_unused);
        h.call(
            Method::POST,
            "/v1/auth/login/start",
            None,
            Some(json!({
                "email": email,
                "credential_request": courier_ftp_proto::b64::encode(&ke1),
            })),
        )
        .await
    };
    let limited = |s: StatusCode, headers: &axum::http::HeaderMap, v: &Value| {
        assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{v}");
        assert_eq!(code(v), "rate_limited");
        assert_eq!(message(v), "too many attempts");
        let retry: u64 = headers[header::RETRY_AFTER].to_str().unwrap().parse().unwrap();
        assert!(retry >= 1);
        assert_eq!(v["error"]["retry_after_s"].as_u64(), Some(retry));
    };
    for _ in 0..5 {
        let (s, _, v) = start("same@example.test".into()).await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }
    // Case and whitespace normalize to the same key.
    let (s, headers, v) = start(" SAME@example.test".into()).await;
    limited(s, &headers, &v);
    // The IP limit: 50 per minute in total (6 so far). GCRA refills one slot
    // every 1.2 s on the real clock, so a slow machine may get a few more in.
    let started = std::time::Instant::now();
    let mut n = 6u64;
    let (s, headers, v) = loop {
        let (s, headers, v) = start(format!("user{n}@example.test")).await;
        if s != StatusCode::OK {
            break (s, headers, v);
        }
        n += 1;
        assert!(n < 200, "the IP limit never triggered");
    };
    limited(s, &headers, &v);
    let refills = started.elapsed().as_millis() / 1200 + 1;
    assert!(
        n >= 50 && u128::from(n) <= 50 + refills,
        "{n} requests allowed from one IP"
    );
    // Registration and recovery share the limiters.
    let (s, v) = h
        .post("/v1/account/recovery/code", None, json!({ "email": "z@example.test" }))
        .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{v}");
}
