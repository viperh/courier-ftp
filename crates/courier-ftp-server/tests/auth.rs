//! Accounts, OPAQUE login, tokens, devices, TOTP, password change, recovery
//! and account deletion (T84), end to end over HTTP against an in-process
//! server, with the real client-side OPAQUE code (cheap test KSF).
//!
//! Every scenario runs twice:
//! * `*_mem`: against the in-memory store (always runs);
//! * `*_pg`: against PostgreSQL (`COURIER_SERVER_PG_TEST=1` + `DATABASE_URL`,
//!   see `common`; otherwise prints "SKIPPED (needs PostgreSQL)").
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

mod common;

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Instant;

use chrono::TimeDelta;
use common::client::*;
use common::{Server, assert_auth_required, assert_error, config, generous};
use courier_ftp_crypto::account::{
    AccountKeys, derive_akek, generate_account_keys, open_private_bundle, seal_private_bundle,
};
use courier_ftp_crypto::grant::self_grant;
use courier_ftp_crypto::keys::{os_rng, random_key32};
use courier_ftp_crypto::opaque::{client_login_start, client_registration_start};
use courier_ftp_crypto::recovery::open_recovery_bundle;
use courier_ftp_proto::auth::{LOGIN_FAILED_MESSAGE, SessionResponse, TOTP_REQUIRED_HINT};
use courier_ftp_proto::b64;
use courier_ftp_server::auth::store::mem::MemStore;
use courier_ftp_server::auth::{AuthRuntime, AuthStore, ManualClock, totp};
use courier_ftp_server::middleware::rate_limit::{LoginLimits, RateLimiters};
use courier_ftp_server::registration::RegistrationMode;
use courier_ftp_server::serve::{self, StartupError};
use courier_ftp_server::{AppState, db};
use reqwest::StatusCode;
use serde_json::{Value, json};
use uuid::Uuid;

// ---------------------------------------------------------------- scenarios

/// Register → login round-trip; export_key equal across logins; the private
/// bundle opens with the AKEK from login.
async fn t01_roundtrip(h: &Server) {
    let a = open_and_register(h, "alice@example.com").await;
    assert_eq!(a.session.user_id, a.user_id);
    assert_eq!(a.session.account_keys.version, 1);
    assert_eq!(a.session.tokens.access_token.len(), 43);
    assert_eq!(a.session.tokens.access_expires_in_s, 900);
    assert_eq!(a.session.tokens.refresh_expires_in_s, 30 * 86_400);

    let l1 = login_with(h, "Alice@EXAMPLE.com", &a.password, json!({})).await;
    assert_eq!(l1.status, StatusCode::OK, "{}", l1.body);
    let l2 = login_with(h, "alice@example.com", &a.password, json!({})).await;
    assert_eq!(l2.status, StatusCode::OK);
    let (e1, e2) = (l1.export_key.unwrap(), l2.export_key.unwrap());
    assert_eq!(e1, e2, "export_key is stable per password");
    let s: SessionResponse = serde_json::from_value(l1.body).unwrap();
    assert_eq!(s.user_id, a.user_id);
    let keys = open_private_bundle(
        &derive_akek(&e1),
        a.user_id.as_bytes(),
        s.account_keys.version,
        &s.account_keys.private_bundle_enc,
    )
    .unwrap();
    assert_eq!(keys.public(), a.keys.public());
    assert_eq!(
        devices_status(h, &s.tokens.access_token).await,
        StatusCode::OK
    );
    // Logout of that device.
    let (st, _) = h
        .call(
            "POST",
            "/v1/auth/logout",
            None,
            Some(&s.tokens.access_token),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
}

/// Wrong password and unknown email fail identically, in the same timing
/// class.
async fn t02_enumeration(h: &Server) {
    let a = open_and_register(h, "bob@example.com").await;
    let wrong = login_with(h, &a.email, b"not the password", json!({})).await;
    let unknown = login_with(h, "nobody@example.com", b"whatever", json!({})).await;
    assert_auth_required(wrong.status, &wrong.body);
    assert_eq!(wrong.body["error"]["message"], LOGIN_FAILED_MESSAGE);
    assert_eq!((wrong.status, &wrong.body), (unknown.status, &unknown.body));

    // login/start answers have the same shape for both.
    let mut rng = os_rng();
    let (_, ke1) = client_login_start(&mut rng, b"x").unwrap();
    let start = |email: &str| json!({ "email": email, "credential_request": b64::encode(&ke1) });
    let (_, known) = h.post("/v1/auth/login/start", start(&a.email), None).await;
    let (_, ghost) = h
        .post("/v1/auth/login/start", start("ghost@example.com"), None)
        .await;
    let keys = |v: &Value| {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    assert_eq!(keys(&known), keys(&ghost));
    assert_eq!(
        known["credential_response"].as_str().unwrap().len(),
        ghost["credential_response"].as_str().unwrap().len()
    );

    // Timing class: medians within a generous factor (both paths do the
    // same OPAQUE work; a factor catches e.g. a skipped KE2 or a slow path).
    let mut known_t = Vec::new();
    let mut unknown_t = Vec::new();
    for _ in 0..21 {
        let t = Instant::now();
        let _ = login_with(h, &a.email, b"nope", json!({})).await;
        known_t.push(t.elapsed());
        let t = Instant::now();
        let _ = login_with(h, "ghost@example.com", b"nope", json!({})).await;
        unknown_t.push(t.elapsed());
    }
    known_t.sort();
    unknown_t.sort();
    let (k, u) = (known_t[10].as_secs_f64(), unknown_t[10].as_secs_f64());
    eprintln!(
        "timing: median known-wrong {:.2} ms, unknown {:.2} ms",
        k * 1e3,
        u * 1e3
    );
    assert!(
        k.max(u) / k.min(u) < 4.0,
        "timing class differs: {k} vs {u}"
    );
}

/// A failure in the vault insert leaves no user, and the invite is not
/// consumed.
async fn t03_register_atomic(h: &Server) {
    let token = h.invite("carol@example.com").await;
    let vault = Uuid::now_v7();
    h.occupy_vault_id(vault).await;
    let err = try_register(
        h,
        "carol@example.com",
        "pw-carol",
        json!({ "invite_token": token }),
        Some(vault),
    )
    .await
    .expect_err("registration must fail");
    assert!(!err.0.is_success(), "{err:?}");
    assert!(!h.user_exists("carol@example.com").await);
    assert_eq!(h.token_rows().await, 0);
    h.release_vault_id(vault).await;
    let a = try_register(
        h,
        "carol@example.com",
        "pw-carol",
        json!({ "invite_token": token }),
        Some(vault),
    )
    .await
    .unwrap();
    assert!(h.user_exists("carol@example.com").await);
    assert!(!a.session.is_instance_admin);
}

/// Registration modes, setup token and invites.
async fn t04_gating(h: &Server) {
    let reg = |email: &'static str, extra: Value| async move {
        try_register(h, email, "pw", extra, None)
            .await
            .map(|a| a.session)
    };
    // Default invite-only: nothing presented → forbidden at start.
    let (st, v) = reg("d1@example.com", json!({})).await.unwrap_err();
    assert_error(st, &v, StatusCode::FORBIDDEN, "forbidden");
    // Setup token → instance admin, once.
    h.set_setup_token("setup-token-123").await;
    let s = reg(
        "admin@example.com",
        json!({ "setup_token": "setup-token-123" }),
    )
    .await
    .unwrap();
    assert!(s.is_instance_admin);
    let (st, _) = reg(
        "d2@example.com",
        json!({ "setup_token": "setup-token-123" }),
    )
    .await
    .unwrap_err();
    assert_eq!(st, StatusCode::FORBIDDEN);
    // Invite: bound to its email, single use.
    let inv = h.invite("invited@example.com").await;
    let (st, _) = reg("other@example.com", json!({ "invite_token": inv }))
        .await
        .unwrap_err();
    assert_eq!(st, StatusCode::FORBIDDEN);
    let s = reg("invited@example.com", json!({ "invite_token": inv }))
        .await
        .unwrap();
    assert!(!s.is_instance_admin);
    let (st, _) = reg("Invited@example.com", json!({ "invite_token": inv }))
        .await
        .unwrap_err();
    assert_eq!(st, StatusCode::FORBIDDEN);
    // Closed → forbidden even with an invite; open → anyone.
    h.set_mode(RegistrationMode::Closed).await;
    let inv2 = h.invite("late@example.com").await;
    let (st, _) = reg("late@example.com", json!({ "invite_token": inv2 }))
        .await
        .unwrap_err();
    assert_eq!(st, StatusCode::FORBIDDEN);
    h.set_mode(RegistrationMode::Open).await;
    reg("anyone@example.com", json!({})).await.unwrap();
    // Duplicate email → conflict.
    let (st, v) = reg("ANYONE@example.com", json!({})).await.unwrap_err();
    assert_error(st, &v, StatusCode::CONFLICT, "conflict");
}

/// Access tokens expire after 15 minutes, refresh tokens after 30 days.
async fn t05_access_expiry(h: &Server) {
    let a = open_and_register(h, "erin@example.com").await;
    assert_eq!(devices_status(h, a.access()).await, StatusCode::OK);
    h.clock.advance(TimeDelta::minutes(14));
    assert_eq!(devices_status(h, a.access()).await, StatusCode::OK);
    h.clock
        .advance(TimeDelta::minutes(1) + TimeDelta::seconds(1));
    let (st, v) = h.get("/v1/devices", Some(a.access())).await;
    assert_auth_required(st, &v);
    let (st, v) = h
        .post(
            "/v1/auth/refresh",
            json!({ "refresh_token": a.session.tokens.refresh_token }),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(
        devices_status(h, v["access_token"].as_str().unwrap()).await,
        StatusCode::OK
    );
    h.clock.advance(TimeDelta::days(30) + TimeDelta::seconds(1));
    let (st, v) = h
        .post(
            "/v1/auth/refresh",
            json!({ "refresh_token": v["refresh_token"] }),
            None,
        )
        .await;
    assert_auth_required(st, &v);
    let (st, v) = h.get("/v1/devices", Some("not-a-token")).await;
    assert_auth_required(st, &v);
    let (st, v) = h.get("/v1/devices", None).await;
    assert_auth_required(st, &v);
}

/// Rotation, then reuse detection revokes the whole family.
async fn t06_rotation_and_reuse(h: &Server) {
    let a = open_and_register(h, "frank@example.com").await;
    let old_refresh = a.session.tokens.refresh_token.clone();
    let (st, new) = h
        .post(
            "/v1/auth/refresh",
            json!({ "refresh_token": old_refresh }),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{new}");
    let new_access = new["access_token"].as_str().unwrap().to_owned();
    let new_refresh = new["refresh_token"].as_str().unwrap().to_owned();
    assert_ne!(new_refresh, old_refresh);
    assert_eq!(devices_status(h, &new_access).await, StatusCode::OK);

    // Replaying the old refresh token → 401 and the family is gone.
    let (st, v) = h
        .post(
            "/v1/auth/refresh",
            json!({ "refresh_token": old_refresh }),
            None,
        )
        .await;
    assert_auth_required(st, &v);
    assert!(v["error"]["message"].as_str().unwrap().contains("reuse"));
    assert_eq!(
        devices_status(h, &new_access).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        devices_status(h, a.access()).await,
        StatusCode::UNAUTHORIZED
    );
    let (st, _) = h
        .post(
            "/v1/auth/refresh",
            json!({ "refresh_token": new_refresh }),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert!(
        h.audit_kinds()
            .await
            .contains(&"refresh_token_reuse".to_owned())
    );
}

/// Logout revokes the current device only.
async fn t08_logout(h: &Server) {
    let a = open_and_register(h, "grace@example.com").await;
    let b = login(h, &a).await;
    assert_ne!(b.device_id, a.session.device_id);
    let (st, _) = h
        .call("POST", "/v1/auth/logout", None, Some(a.access()))
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(
        devices_status(h, a.access()).await,
        StatusCode::UNAUTHORIZED
    );
    let (st, _) = h
        .post(
            "/v1/auth/refresh",
            json!({ "refresh_token": a.session.tokens.refresh_token }),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(
        devices_status(h, &b.tokens.access_token).await,
        StatusCode::OK
    );
    let (st, _) = h.call("POST", "/v1/auth/logout", None, None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

/// Device list and revocation.
async fn t09_devices(h: &Server) {
    let a = open_and_register(h, "heidi@example.com").await;
    let b = login(h, &a).await;
    let (st, list) = h.get("/v1/devices", Some(a.access())).await;
    assert_eq!(st, StatusCode::OK);
    let list = list.as_array().unwrap().clone();
    assert_eq!(list.len(), 2);
    let me = list.iter().find(|d| d["current"] == true).unwrap();
    assert_eq!(me["id"], json!(a.session.device_id));
    assert_eq!(me["name"], "laptop");
    assert_eq!(me["platform"], "linux");
    assert!(me["created_at"].is_string());
    assert!(me["last_seen_at"].is_string());
    let parsed: Vec<courier_ftp_proto::auth::DeviceSummary> =
        serde_json::from_value(Value::Array(list)).unwrap();
    assert_eq!(parsed.iter().filter(|d| d.current).count(), 1);

    let path = format!("/v1/devices/{}", b.device_id);
    let (st, _) = h.call("DELETE", &path, None, Some(a.access())).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(
        devices_status(h, &b.tokens.access_token).await,
        StatusCode::UNAUTHORIZED
    );
    let (st, _) = h
        .post(
            "/v1/auth/refresh",
            json!({ "refresh_token": b.tokens.refresh_token }),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    // Revoked devices are not listed.
    let (_, list) = h.get("/v1/devices", Some(a.access())).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    // Another user's or an unknown device → 404.
    let other = register(h, "ivan@example.com", "pw").await;
    let (st, v) = h
        .call(
            "DELETE",
            &format!("/v1/devices/{}", other.session.device_id),
            None,
            Some(a.access()),
        )
        .await;
    assert_error(st, &v, StatusCode::NOT_FOUND, "not_found");
    assert_eq!(devices_status(h, other.access()).await, StatusCode::OK);
    // A revoked device id cannot be resumed: login creates a new device.
    let l = login_with(
        h,
        &a.email,
        &a.password,
        json!({ "device": { "id": b.device_id } }),
    )
    .await;
    assert_eq!(l.status, StatusCode::OK);
    assert_ne!(l.body["device_id"], json!(b.device_id));
    // An existing device id is resumed (its old tokens are replaced).
    let l = login_with(
        h,
        &a.email,
        &a.password,
        json!({ "device": { "id": a.session.device_id } }),
    )
    .await;
    assert_eq!(l.body["device_id"], json!(a.session.device_id));
    assert_eq!(
        devices_status(h, a.access()).await,
        StatusCode::UNAUTHORIZED
    );
}

/// TOTP enable/confirm, then login needs a valid, fresh code.
async fn t10_totp(h: &Server) {
    let a = open_and_register(h, "judy@example.com").await;
    let (st, setup) = h
        .post("/v1/account/totp", json!({}), Some(a.access()))
        .await;
    assert_eq!(st, StatusCode::OK, "{setup}");
    assert!(
        setup["otpauth_uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/courier-ftp:judy@example.com?")
    );
    let secret = totp_rs::Secret::Encoded(setup["secret_base32"].as_str().unwrap().to_owned())
        .to_bytes()
        .unwrap();
    let now = || u64::try_from(h.now().timestamp()).unwrap();
    let (st, _) = h
        .post(
            "/v1/account/totp",
            json!({ "code": "000000" }),
            Some(a.access()),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, v) = h
        .post(
            "/v1/account/totp",
            json!({ "code": totp::code_at(&secret, now()) }),
            Some(a.access()),
        )
        .await;
    assert_eq!((st, &v), (StatusCode::OK, &json!({ "enabled": true })));

    let l = login_with(h, &a.email, &a.password, json!({})).await;
    assert_auth_required(l.status, &l.body);
    assert!(
        l.body["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with(TOTP_REQUIRED_HINT)
    );
    let l = login_with(h, &a.email, b"wrong", json!({})).await;
    assert_eq!(l.body["error"]["message"], LOGIN_FAILED_MESSAGE);
    let l = login_with(h, &a.email, &a.password, json!({ "totp": "123456" })).await;
    assert_auth_required(l.status, &l.body);
    let l = login_with(
        h,
        &a.email,
        &a.password,
        json!({ "totp": totp::code_at(&secret, now()) }),
    )
    .await;
    assert_auth_required(l.status, &l.body);
    h.clock.advance(TimeDelta::seconds(30));
    let code = totp::code_at(&secret, now());
    let l = login_with(h, &a.email, &a.password, json!({ "totp": code })).await;
    assert_eq!(l.status, StatusCode::OK, "{}", l.body);
    let session: SessionResponse = serde_json::from_value(l.body).unwrap();
    let l = login_with(h, &a.email, &a.password, json!({ "totp": code })).await;
    assert_auth_required(l.status, &l.body);

    let (st, _) = h
        .call(
            "DELETE",
            "/v1/account/totp",
            Some(json!({ "code": code })),
            Some(&session.tokens.access_token),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "replayed code");
    h.clock.advance(TimeDelta::seconds(30));
    let (st, _) = h
        .call(
            "DELETE",
            "/v1/account/totp",
            Some(json!({ "code": totp::code_at(&secret, now()) })),
            Some(&session.tokens.access_token),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    login(h, &a).await;
}

/// Password change.
async fn t11_password_change(h: &Server) {
    let a = open_and_register(h, "mallory@example.com").await;
    let b = login(h, &a).await;
    let token = reauth(h, &a, &a.password).await;
    let (upload, bundle, _) = new_password_material(
        h,
        ("/v1/account/password/start", json!({}), Some(a.access())),
        "registration_response",
        "new password 2",
        a.user_id,
        &a.keys,
        2,
    )
    .await;
    let body = |version: u32, token: &str| {
        json!({
            "reauth_token": token,
            "registration_upload": b64::encode(&upload),
            "private_bundle_enc": b64::encode(&bundle),
            "version": version,
        })
    };
    let (st, _) = h
        .post("/v1/account/password", body(3, &token), Some(a.access()))
        .await;
    assert_eq!(st, StatusCode::CONFLICT);
    let fake = b64::encode(&[7; 32]);
    let (st, _) = h
        .post("/v1/account/password", body(2, &fake), Some(a.access()))
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, v) = h
        .post("/v1/account/password", body(2, &token), Some(a.access()))
        .await;
    assert_eq!((st, &v), (StatusCode::OK, &json!({ "version": 2 })));
    let (st, _) = h
        .post("/v1/account/password", body(3, &token), Some(a.access()))
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    assert_eq!(
        devices_status(h, &b.tokens.access_token).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(devices_status(h, a.access()).await, StatusCode::OK);
    let old = login_with(h, &a.email, &a.password, json!({})).await;
    assert_eq!(old.body["error"]["message"], LOGIN_FAILED_MESSAGE);
    let new = login_with(h, &a.email, b"new password 2", json!({})).await;
    assert_eq!(new.status, StatusCode::OK, "{}", new.body);
    let s: SessionResponse = serde_json::from_value(new.body).unwrap();
    assert_eq!(s.account_keys.version, 2);
    let keys = open_private_bundle(
        &derive_akek(&new.export_key.unwrap()),
        a.user_id.as_bytes(),
        2,
        &s.account_keys.private_bundle_enc,
    )
    .unwrap();
    assert_eq!(keys.public(), a.keys.public());
    assert!(
        h.audit_kinds()
            .await
            .contains(&"password_changed".to_owned())
    );
}

/// Tokens are stored only as hashes.
async fn t12_hashed(h: &Server) {
    let a = open_and_register(h, "niaj@example.com").await;
    let r = reauth(h, &a, &a.password).await;
    let dump = h.dump().await;
    for t in [
        &a.session.tokens.access_token,
        &a.session.tokens.refresh_token,
        &r,
    ] {
        let raw = b64::decode(t).unwrap();
        assert!(!dump.contains(t.as_str()), "raw base64 token in storage");
        assert!(
            !dump.contains(&hex::encode(&raw)),
            "raw token hex in storage"
        );
        assert!(
            !dump.contains(&format!("{raw:?}")),
            "raw token bytes in storage"
        );
        let hash = courier_ftp_server::auth::tokens::hash_raw(&raw);
        let present = dump.contains(&hex::encode(hash)) || dump.contains(&format!("{hash:?}"));
        assert!(present, "the hash is what is stored");
    }
}

/// A disabled account fails exactly like a wrong password.
async fn t13_disabled(h: &Server) {
    let a = open_and_register(h, "olivia@example.com").await;
    let wrong = login_with(h, &a.email, b"wrong", json!({})).await;
    h.disable(&a.email).await;
    let disabled = login_with(h, &a.email, &a.password, json!({})).await;
    assert_auth_required(disabled.status, &disabled.body);
    assert_eq!(
        (wrong.status, &wrong.body),
        (disabled.status, &disabled.body)
    );
    assert_eq!(
        devices_status(h, a.access()).await,
        StatusCode::UNAUTHORIZED
    );
}

/// Deleting the account removes the personal vault and its items; shared
/// vault items stay.
async fn t14_delete(h: &Server) {
    let a = open_and_register(h, "peggy@example.com").await;
    let other = register(h, "rupert@example.com", "pw").await;
    let shared = h.shared_vault(&[other.user_id, a.user_id], "write").await;
    h.add_item(a.vault_id, 1).await;
    h.add_item(a.vault_id, 2).await;
    h.add_item(shared, 1).await;
    h.add_item(other.vault_id, 1).await;

    let (st, _) = h
        .call(
            "DELETE",
            "/v1/account",
            Some(json!({ "reauth_token": b64::encode(&[1; 32]) })),
            Some(a.access()),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let token = reauth(h, &a, &a.password).await;
    let other_token = reauth(h, &other, &other.password).await;
    let (st, _) = h
        .call(
            "DELETE",
            "/v1/account",
            Some(json!({ "reauth_token": other_token })),
            Some(a.access()),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, v) = h
        .call(
            "DELETE",
            "/v1/account",
            Some(json!({ "reauth_token": token })),
            Some(a.access()),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{v}");

    assert!(!h.user_exists(&a.email).await);
    assert!(!h.vault_exists(a.vault_id).await);
    assert_eq!(h.count_items(a.vault_id).await, 0);
    assert_eq!(h.count_items(shared).await, 1);
    assert_eq!(h.count_items(other.vault_id).await, 1);
    assert!(!h.is_member(shared, a.user_id).await);
    assert!(h.is_member(shared, other.user_id).await);
    assert_eq!(
        devices_status(h, a.access()).await,
        StatusCode::UNAUTHORIZED
    );
    let l = login_with(h, &a.email, &a.password, json!({})).await;
    assert_eq!(l.body["error"]["message"], LOGIN_FAILED_MESSAGE);
    assert!(
        h.audit_kinds()
            .await
            .contains(&"account_deleted".to_owned())
    );
    register(h, "peggy@example.com", "again").await;
}

/// Recovery: code + recovery key → new password; every device logged out.
async fn recovery(h: &Server) {
    let a = open_and_register(h, "trent@example.com").await;
    let b = login(h, &a).await;
    let start = |code: &str, email: &str| json!({ "email": email, "code": code, "registration_request": b64::encode(&[0; 32]) });
    let (st, v1) = h
        .post(
            "/v1/account/recovery/start",
            start("AAAA-BBBB", &a.email),
            None,
        )
        .await;
    assert_auth_required(st, &v1);
    let (_, v2) = h
        .post(
            "/v1/account/recovery/start",
            start("AAAA-BBBB", "ghost@example.com"),
            None,
        )
        .await;
    assert_eq!(v1, v2);

    let code = h.recovery_code(&a.email).await;
    let (upload, bundle, v) = new_password_material(
        h,
        (
            "/v1/account/recovery/start",
            json!({ "email": a.email, "code": code.to_lowercase() }),
            None,
        ),
        "registration_response",
        "recovered password",
        a.user_id,
        &a.keys,
        2,
    )
    .await;
    assert_eq!(v["user_id"], json!(a.user_id));
    assert_eq!(v["version"], 1);
    let rb = b64::decode(v["recovery_bundle_enc"].as_str().unwrap()).unwrap();
    let keys = open_recovery_bundle(&a.recovery, a.user_id.as_bytes(), &rb).unwrap();
    assert_eq!(keys.public(), a.keys.public());

    let proof = |version: u32, keys: &AccountKeys| {
        let msg = courier_ftp_crypto::opaque::recovery_proof_message(
            a.user_id.as_bytes(),
            version,
            &upload,
            &bundle,
        );
        courier_ftp_crypto::sign::sign(keys.ed25519_signing_key(), &msg)
    };
    let finish = |sig: [u8; 64]| {
        json!({
            "email": a.email,
            "code": code,
            "registration_upload": b64::encode(&upload),
            "private_bundle_enc": b64::encode(&bundle),
            "version": 2,
            "signature": b64::encode(&sig),
        })
    };
    let stranger = generate_account_keys(&mut os_rng());
    let (st, _) = h
        .post("/v1/account/recovery", finish(proof(2, &stranger)), None)
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, v) = h
        .post("/v1/account/recovery", finish(proof(2, &keys)), None)
        .await;
    assert_eq!((st, &v), (StatusCode::OK, &json!({ "version": 2 })));
    let (st, _) = h
        .post("/v1/account/recovery", finish(proof(2, &keys)), None)
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(
        devices_status(h, a.access()).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        devices_status(h, &b.tokens.access_token).await,
        StatusCode::UNAUTHORIZED
    );
    let l = login_with(h, &a.email, b"recovered password", json!({})).await;
    assert_eq!(l.status, StatusCode::OK, "{}", l.body);
    assert_eq!(l.body["account_keys"]["version"], 2);
    // Five wrong codes discard a code.
    let code2 = h.recovery_code(&a.email).await;
    for _ in 0..5 {
        let (st, _) = h
            .post(
                "/v1/account/recovery/start",
                start("WRONG-CODE", &a.email),
                None,
            )
            .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }
    let (st, _) = h
        .post("/v1/account/recovery/start", start(&code2, &a.email), None)
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

/// Registration input validation.
async fn validation(h: &Server) {
    h.set_mode(RegistrationMode::Open).await;
    let mut rng = os_rng();
    let (state, request) = client_registration_start(&mut rng, b"pw").unwrap();
    let (st, v) = h
        .post(
            "/v1/auth/register/start",
            json!({ "email": "val@example.com", "registration_request": b64::encode(&request) }),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    let user_id: Uuid = serde_json::from_value(v["user_id"].clone()).unwrap();
    let response = b64::decode(v["registration_response"].as_str().unwrap()).unwrap();
    let fin = state.finish(&mut rng, b"pw", &response, &ksf()).unwrap();
    let keys = generate_account_keys(&mut rng);
    let vault = Uuid::now_v7();
    // Signed for another user id → the self-grant does not verify.
    let grant = self_grant(
        &random_key32(&mut rng),
        vault.as_bytes(),
        1,
        Uuid::now_v7().as_bytes(),
        &keys,
        &mut rng,
    )
    .unwrap();
    let akek = derive_akek(&fin.export_key);
    let bundle = seal_private_bundle(&akek, user_id.as_bytes(), 1, &keys, &mut rng).unwrap();
    let body = json!({
        "email": "val@example.com",
        "user_id": user_id,
        "registration_upload": b64::encode(&fin.upload),
        "account_keys": {
            "x25519_pub": b64::encode(&keys.public().x25519),
            "ed25519_pub": b64::encode(&keys.public().ed25519),
            "private_bundle_enc": b64::encode(&bundle),
            "recovery_bundle_enc": b64::encode(&bundle),
            "version": 1,
        },
        "personal_vault": {
            "id": vault,
            "name_enc": "AA",
            "self_grant": {
                "wrapped_vault_key": b64::encode(&grant.wrapped),
                "signature": b64::encode(&grant.signature),
                "key_version": 1,
            },
        },
        "device": { "name": "x", "platform": "linux" },
    });
    let (st, v) = h.post("/v1/auth/register/finish", body.clone(), None).await;
    assert_error(st, &v, StatusCode::BAD_REQUEST, "invalid");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("signature")
    );
    let mut bad = body.clone();
    bad["registration_upload"] = json!("AAAA");
    let (st, _) = h.post("/v1/auth/register/finish", bad, None).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let mut bad = body.clone();
    bad["account_keys"]["x25519_pub"] = json!("AAAA");
    let (st, _) = h.post("/v1/auth/register/finish", bad, None).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let mut bad = body;
    bad["device"]["name"] = json!("x".repeat(101));
    let (st, _) = h.post("/v1/auth/register/finish", bad, None).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(!h.user_exists("val@example.com").await);
    // Malformed JSON and bad emails are 400 envelopes.
    let (st, v) = h
        .post("/v1/auth/login/start", json!({ "email": 3 }), None)
        .await;
    assert_error(st, &v, StatusCode::BAD_REQUEST, "invalid");
    let (st, v) = h
        .post(
            "/v1/auth/login/start",
            json!({ "email": "no-at-sign", "credential_request": "AAAA" }),
            None,
        )
        .await;
    assert_error(st, &v, StatusCode::BAD_REQUEST, "invalid");
    let (st, _) = h
        .post(
            "/v1/auth/login/start",
            json!({ "email": "val@example.com", "credential_request": "AAAA" }),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, v) = h
        .post(
            "/v1/auth/login/finish",
            json!({ "login_state_id": Uuid::now_v7(), "credential_finalization": b64::encode(&[0; 64]) }),
            None,
        )
        .await;
    assert_auth_required(st, &v);
}

/// Login states expire after 60 s.
async fn login_state_ttl(h: &Server) {
    let a = open_and_register(h, "sybil@example.com").await;
    let mut rng = os_rng();
    let (client, ke1) = client_login_start(&mut rng, &a.password).unwrap();
    let (_, v) = h
        .post(
            "/v1/auth/login/start",
            json!({ "email": a.email, "credential_request": b64::encode(&ke1) }),
            None,
        )
        .await;
    let ke2 = b64::decode(v["credential_response"].as_str().unwrap()).unwrap();
    let fin = client.finish(&mut rng, &a.password, &ke2, &ksf()).unwrap();
    h.clock.advance(TimeDelta::seconds(61));
    let (st, v) = h
        .post(
            "/v1/auth/login/finish",
            json!({ "login_state_id": v["login_state_id"], "credential_finalization": b64::encode(&fin.finalization) }),
            None,
        )
        .await;
    assert_auth_required(st, &v);
}

// ------------------------------------------------------------------- tests

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

both!(t01_roundtrip, opaque_roundtrip_mem, opaque_roundtrip_pg);
both!(
    t02_enumeration,
    unknown_email_like_wrong_password_mem,
    unknown_email_like_wrong_password_pg
);
both!(
    t03_register_atomic,
    register_is_atomic_mem,
    register_is_atomic_pg
);
both!(t04_gating, registration_gating_mem, registration_gating_pg);
both!(t05_access_expiry, token_expiry_mem, token_expiry_pg);
both!(
    t06_rotation_and_reuse,
    refresh_rotation_and_reuse_mem,
    refresh_rotation_and_reuse_pg
);
both!(
    t08_logout,
    logout_current_device_only_mem,
    logout_current_device_only_pg
);
both!(t09_devices, devices_mem, devices_pg);
both!(t10_totp, totp_mem, totp_pg);
both!(t11_password_change, password_change_mem, password_change_pg);
both!(
    t12_hashed,
    tokens_stored_hashed_mem,
    tokens_stored_hashed_pg
);
both!(t13_disabled, disabled_user_mem, disabled_user_pg);
both!(t14_delete, account_delete_mem, account_delete_pg);
both!(recovery, recovery_flow_mem, recovery_flow_pg);
both!(
    validation,
    registration_validation_mem,
    registration_validation_pg
);
both!(
    login_state_ttl,
    login_state_expires_mem,
    login_state_expires_pg
);

fn strict(per_email: u32, per_ip: u32) -> RateLimiters {
    RateLimiters::new(LoginLimits {
        per_email_per_minute: NonZeroU32::new(per_email).unwrap(),
        per_ip_per_minute: NonZeroU32::new(per_ip).unwrap(),
    })
}

/// 5 login starts per email per minute, then 429 with `Retry-After`.
#[tokio::test]
async fn login_start_is_rate_limited() {
    let h = Server::mem_with(RateLimiters::default(), config(&[])).await;
    let mut rng = os_rng();
    let (_, ke1) = client_login_start(&mut rng, b"pw").unwrap();
    let body = json!({ "email": "rl@example.com", "credential_request": b64::encode(&ke1) });
    for _ in 0..5 {
        let (st, _) = h.post("/v1/auth/login/start", body.clone(), None).await;
        assert_eq!(st, StatusCode::OK);
    }
    let (st, headers, v) = h
        .request("POST", "/v1/auth/login/start", Some(body), None, &[])
        .await;
    assert_error(st, &v, StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    let retry: u64 = headers["retry-after"].to_str().unwrap().parse().unwrap();
    assert!((1..=60).contains(&retry));
    assert_eq!(v["error"]["retry_after_s"], json!(retry));
    // Registration and recovery share the limiter.
    let (st, _) = h
        .post(
            "/v1/account/recovery/code",
            json!({ "email": "rl@example.com" }),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
}

/// The per-IP limit uses `X-Forwarded-For` only behind a trusted proxy.
#[tokio::test]
async fn client_ip_from_trusted_proxy_only() {
    let mut rng = os_rng();
    let (_, ke1) = client_login_start(&mut rng, b"pw").unwrap();
    let body = |i: u32| json!({ "email": format!("u{i}@example.com"), "credential_request": b64::encode(&ke1) });

    // Untrusted peer: the header is ignored, everything counts as 127.0.0.1.
    let h = Server::mem_with(strict(100, 2), config(&[])).await;
    for (i, xff) in ["203.0.113.1", "203.0.113.2"].into_iter().enumerate() {
        let (st, _, _) = h
            .request(
                "POST",
                "/v1/auth/login/start",
                Some(body(i as u32)),
                None,
                &[("x-forwarded-for", xff)],
            )
            .await;
        assert_eq!(st, StatusCode::OK);
    }
    let (st, _, _) = h
        .request(
            "POST",
            "/v1/auth/login/start",
            Some(body(9)),
            None,
            &[("x-forwarded-for", "203.0.113.3")],
        )
        .await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);

    // Trusted proxy: each forwarded client has its own bucket.
    let h = Server::mem_with(
        strict(100, 2),
        config(&[("COURIER_TRUSTED_PROXIES", "127.0.0.1/32")]),
    )
    .await;
    for i in 0..2 {
        let (st, _, _) = h
            .request(
                "POST",
                "/v1/auth/login/start",
                Some(body(i)),
                None,
                &[("x-forwarded-for", "203.0.113.1")],
            )
            .await;
        assert_eq!(st, StatusCode::OK);
    }
    let (st, _, _) = h
        .request(
            "POST",
            "/v1/auth/login/start",
            Some(body(5)),
            None,
            &[("x-forwarded-for", "203.0.113.1")],
        )
        .await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    let (st, _, _) = h
        .request(
            "POST",
            "/v1/auth/login/start",
            Some(body(6)),
            None,
            &[("x-forwarded-for", "203.0.113.2")],
        )
        .await;
    assert_eq!(st, StatusCode::OK);
}

/// Protocol header, request id and error envelopes from the middleware.
#[tokio::test]
async fn middleware_envelopes_and_headers() {
    let h = Server::mem().await;
    let (st, headers, v) = h.request("GET", "/healthz", None, None, &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["status"], "ok");
    assert_eq!(headers["courier-proto"], "1");
    assert!(headers.contains_key("x-request-id"));
    let (_, headers, _) = h
        .request(
            "GET",
            "/healthz",
            None,
            None,
            &[("x-request-id", "abc-123")],
        )
        .await;
    assert_eq!(headers["x-request-id"], "abc-123");
    // Unsupported version.
    let (st, headers, v) = h
        .request("GET", "/v1/devices", None, None, &[("courier-proto", "2")])
        .await;
    assert_error(st, &v, StatusCode::BAD_REQUEST, "invalid");
    assert_eq!(headers["courier-proto"], "1");
    // Unknown route, wrong method.
    let (st, v) = h.get("/v1/nope", None).await;
    assert_error(st, &v, StatusCode::NOT_FOUND, "not_found");
    let (st, v) = h.get("/v1/auth/login/start", None).await;
    assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(v["error"]["code"], "invalid");
    // Body over 12 MiB.
    let big = "x".repeat(courier_ftp_proto::limits::MAX_BODY_BYTES + 10);
    let resp = h
        .http
        .post(format!("{}/v1/auth/refresh", h.base))
        .header("content-type", "application/json")
        .body(format!("{{\"refresh_token\":\"{big}\"}}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["code"], "invalid");
    // No database behind the memory server: not ready.
    let (st, v) = h.get("/readyz", None).await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v["status"], "not_ready");
}

/// The OPAQUE setup is generated once, reused, and stored sealed.
#[tokio::test]
async fn opaque_setup_is_persisted_sealed() {
    let h = Server::mem().await;
    let a = h
        .state
        .auth()
        .server_setup(h.state.secrets())
        .await
        .unwrap();
    let b = h
        .state
        .auth()
        .server_setup(h.state.secrets())
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&a, &b));
    let mem = h.mem_store().unwrap();
    let sealed = mem
        .with_data(|d| d.secrets.get("opaque_server_setup").cloned())
        .unwrap();
    assert!(
        !sealed
            .windows(32)
            .any(|w| a.to_bytes().windows(32).any(|x| x == w))
    );
    // A second runtime over a copy of the store loads the same setup.
    let m2 = Arc::new(MemStore::new());
    for (k, v) in mem.with_data(|d| d.secrets.clone()) {
        m2.with_data(|d| d.secrets.insert(k, v));
    }
    let auth2 = AuthRuntime::new(AuthStore::Memory(m2), Arc::new(ManualClock::new()));
    let c = auth2.server_setup(h.state.secrets()).await.unwrap();
    assert_eq!(*a.to_bytes(), *c.to_bytes());
}

fn state_on(store: AuthStore, secret: &str) -> AppState {
    let pool = db::connect_lazy(common::UNREACHABLE_DB).unwrap();
    AppState::with_auth(
        config(&[("COURIER_SERVER_SECRET", secret)]),
        pool,
        generous(),
        AuthRuntime::new(store, Arc::new(ManualClock::new())),
    )
}

/// A different `COURIER_SERVER_SECRET` refuses to start on existing data.
#[tokio::test]
async fn wrong_server_secret_refuses_to_start() {
    let mem = Arc::new(MemStore::new());
    let first = state_on(AuthStore::Memory(mem.clone()), common::SECRET_A);
    serve::startup_checks(&first).await.unwrap();
    // A restart with the same secret is fine.
    serve::startup_checks(&state_on(AuthStore::Memory(mem.clone()), common::SECRET_A))
        .await
        .unwrap();
    let err = serve::startup_checks(&state_on(AuthStore::Memory(mem), common::SECRET_B))
        .await
        .unwrap_err();
    assert!(matches!(err, StartupError::Secrets(_)), "{err}");
    assert!(err.to_string().contains("Refusing to start"), "{err}");
}

#[tokio::test]
async fn wrong_server_secret_refuses_to_start_pg() {
    let tdb = db_or_skip!(common::TestDb::fresh());
    let cfg = |s: &str| config(&[("COURIER_SERVER_SECRET", s)]);
    serve::prepare_with_pool(cfg(common::SECRET_A), tdb.pool.clone(), true)
        .await
        .unwrap();
    serve::prepare_with_pool(cfg(common::SECRET_A), tdb.pool.clone(), false)
        .await
        .unwrap();
    let err = serve::prepare_with_pool(cfg(common::SECRET_B), tdb.pool.clone(), false)
        .await
        .unwrap_err();
    assert!(matches!(err, StartupError::Secrets(_)), "{err}");
    tdb.cleanup().await;
}

/// While no account exists, startup stores a fresh setup token whose
/// first use makes the instance admin.
#[tokio::test]
async fn setup_token_bootstrap() {
    let mem = Arc::new(MemStore::new());
    let state = state_on(AuthStore::Memory(mem.clone()), common::SECRET_A);
    let token = courier_ftp_server::registration::bootstrap(state.auth().store())
        .await
        .unwrap()
        .expect("a token while no account exists");
    let stored = mem.with_data(|d| d.setup_token_hash).unwrap();
    assert_eq!(stored, courier_ftp_server::registration::hash_token(&token));
    assert_ne!(stored.to_vec(), token.as_bytes().to_vec());
}
