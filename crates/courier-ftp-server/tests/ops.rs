//! Ops endpoints, the healthcheck probe, the binary's command line and the
//! admin operations (T86).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::process::Command;

use common::client::{login, open_and_register, try_register};
use common::sync::{new_items, push};
use common::{Server, assert_error, config, generous};
use courier_ftp_server::{admin, healthcheck};
use reqwest::StatusCode;
use serde_json::json;

const TOKEN: &str = "metrics-token-for-tests";

/// `/metrics` is off without a token, token-guarded with one, and counts
/// requests and sync traffic.
#[tokio::test]
async fn metrics_endpoint() {
    let h = Server::mem().await;
    let (st, v) = h.get("/metrics", None).await;
    assert_error(st, &v, StatusCode::NOT_FOUND, "not_found");

    let h = Server::mem_with(generous(), config(&[("COURIER_METRICS_TOKEN", TOKEN)])).await;
    let (st, v) = h.get("/metrics", None).await;
    assert_error(st, &v, StatusCode::UNAUTHORIZED, "auth_required");
    let (st, _) = h.get("/metrics", Some("wrong-token-wrong-token")).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    let a = open_and_register(&h, "metrics@example.com").await;
    push(&h, a.access(), a.vault_id, new_items(2, 10)).await;
    let text = h
        .http
        .get(format!("{}/metrics", h.base))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(text.contains("http_requests_total"), "{text}");
    assert!(text.contains("courier_sync_push_items_total"), "{text}");
    assert!(text.contains("route=\"/v1/vaults/{id}/changes\""), "{text}");
    // No user data in labels.
    assert!(!text.contains("metrics@example.com"));
    assert!(!text.contains(&a.vault_id.to_string()));
}

/// The healthcheck probe succeeds against a running server and fails
/// against a closed port.
#[tokio::test]
async fn healthcheck_probe() {
    let h = Server::mem().await;
    healthcheck::run(h.addr, false).await.unwrap();
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    assert!(healthcheck::run(closed, false).await.is_err());
    assert_eq!(
        healthcheck::probe_addr("0.0.0.0:8080".parse().unwrap()),
        "127.0.0.1:8080".parse().unwrap()
    );
}

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_courier-ftp-server"));
    for (k, _) in std::env::vars() {
        if k.starts_with("COURIER_") || k.starts_with("SMTP_") || k == "DATABASE_URL" {
            c.env_remove(k);
        }
    }
    c
}

/// The binary: help, version, usage errors, config errors, healthcheck.
#[tokio::test]
async fn binary_command_line() {
    let out = bin().arg("--help").output().unwrap();
    assert!(out.status.success());
    let help = String::from_utf8_lossy(&out.stdout);
    for cmd in [
        "serve",
        "migrate",
        "admin user",
        "admin invite",
        "admin registration",
        "admin gc",
        "healthcheck",
    ] {
        assert!(help.contains(cmd), "{cmd} missing from --help");
    }
    let out = bin().arg("--version").output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains(env!("CARGO_PKG_VERSION")));

    let out = bin().arg("frobnicate").output().unwrap();
    assert_eq!(out.status.code(), Some(2));

    // No secret: refuses to start with a clear message.
    let dir = std::env::temp_dir();
    let out = bin()
        .current_dir(&dir)
        .env("COURIER_PUBLIC_URL", "https://x.example")
        .arg("serve")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("COURIER_SERVER_SECRET is required"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // healthcheck against a running server, and against nothing.
    let h = Server::mem().await;
    let addr = h.addr.to_string();
    let ok = tokio::task::spawn_blocking(move || {
        bin()
            .args(["healthcheck", "--addr", &addr])
            .status()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(ok.success());
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string();
    let bad = tokio::task::spawn_blocking(move || {
        bin()
            .args(["healthcheck", "--addr", &closed])
            .status()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(!bad.success());
}

/// Admin operations on PostgreSQL: invite → registration, disable, list,
/// recovery code, registration mode, gc.
#[tokio::test]
async fn admin_operations_pg() {
    let h = db_or_skip!(Server::pg());
    let pool = h.pool().unwrap().clone();
    let inv = admin::invite::create(&pool, "Invited@Example.com")
        .await
        .unwrap();
    assert_eq!(inv.email, "Invited@example.com");
    assert!(!format!("{inv:?}").contains(&inv.token));
    let a = try_register(
        &h,
        "invited@example.com",
        "pw",
        json!({ "invite_token": inv.token }),
        None,
    )
    .await
    .unwrap();
    let users = admin::user::list(&pool).await.unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].devices, 1);
    let code = admin::user::recovery_code(&pool, "invited@example.com")
        .await
        .unwrap();
    assert_eq!(code.len(), 29);
    assert!(matches!(
        admin::user::recovery_code(&pool, "nobody@example.com").await,
        Err(admin::AdminError::NoSuchUser(_))
    ));
    let second = login(&h, &a).await;
    let out = admin::user::disable(&pool, "invited@example.com")
        .await
        .unwrap();
    assert!(out.tokens_revoked >= 4);
    let (st, _) = h
        .get("/v1/devices", Some(&second.tokens.access_token))
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    courier_ftp_server::registration::set_mode(
        &pool,
        courier_ftp_server::registration::RegistrationMode::Closed,
    )
    .await
    .unwrap();
    let inv2 = admin::invite::create(&pool, "late@example.com")
        .await
        .unwrap();
    let err = try_register(
        &h,
        "late@example.com",
        "pw",
        json!({ "invite_token": inv2.token }),
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(err.0, StatusCode::FORBIDDEN);
    let report = admin::gc::run(&pool, h.state.config()).await.unwrap();
    assert_eq!(report.purged_tombstones, 0);
    h.cleanup().await;
}

/// `/readyz` on PostgreSQL: ready when migrated.
#[tokio::test]
async fn readyz_pg() {
    let h = db_or_skip!(Server::pg());
    h.state.ws().ensure_started(&h.state);
    let mut ready = false;
    for _ in 0..100 {
        let (st, _) = h.get("/readyz", None).await;
        if st == StatusCode::OK {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(ready);
    h.cleanup().await;
}
