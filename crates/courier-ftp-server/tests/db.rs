//! Migrations, startup checks (wrong server secret) and the setup-token
//! bootstrap. PostgreSQL tests need `DATABASE_URL` (see `common`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::process::Command;
use std::sync::Arc;

use axum::http::StatusCode;
use common::client::{RegOpts, try_register};
use common::{Harness, LogCapture, PUBLIC_URL, SECRET_A, SECRET_B, TestDb, config, message};
use courier_ftp_server::auth::store::Store;
use courier_ftp_server::db::{self, MIGRATIONS, MigrationStatus};
use courier_ftp_server::events::NoopSink;
use courier_ftp_server::serve::{self, ServeError};
use courier_ftp_server::{AppState, settings_kv};

const WRONG_SECRET_TAIL: &str = "COURIER_SERVER_SECRET differs from the one this database was \
                                 created with. Refusing to start.";

#[tokio::test]
async fn migrations_apply_and_are_recorded() {
    let Some(db) = TestDb::fresh().await else {
        return;
    };
    let all: Vec<i64> = MIGRATIONS.iter().map(|m| m.0).collect();
    assert_eq!(
        db::migration_status(&db.pool).await.unwrap(),
        MigrationStatus::Pending(all.clone())
    );
    assert_eq!(db::migrate(&db.pool).await.unwrap(), all);
    let rows: Vec<(i64, String, Vec<u8>)> = sqlx_core::query_as::query_as(
        "SELECT version, name, checksum FROM schema_migrations ORDER BY version",
    )
    .fetch_all(&db.pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), MIGRATIONS.len());
    for ((version, name, checksum), (v, n, sql)) in rows.iter().zip(MIGRATIONS) {
        assert_eq!((version, name.as_str()), (v, *n));
        assert_eq!(checksum, &db::checksum(sql));
    }
    assert_eq!(
        db::migration_status(&db.pool).await.unwrap(),
        MigrationStatus::Current
    );
    assert!(db::migrate(&db.pool).await.unwrap().is_empty(), "idempotent");
    let mode: String =
        sqlx_core::query_scalar::query_scalar("SELECT value FROM settings WHERE key = $1")
            .bind(settings_kv::REGISTRATION_MODE)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(mode, "invite-only");
}

#[tokio::test]
async fn t02_migrations_apply_and_refuse_modified_or_newer() {
    let Some(db) = TestDb::fresh().await else {
        return;
    };
    // Pending migrations: `serve` refuses without `--migrate`, applies with it.
    let err = serve::prepare_with_pool(config(&[]), db.pool.clone(), false)
        .await
        .unwrap_err();
    assert!(matches!(err, ServeError::PendingMigrations(_)), "{err}");
    assert_eq!(err.exit_code(), 3);
    serve::prepare_with_pool(config(&[]), db.pool.clone(), true)
        .await
        .unwrap();

    // A modified migration.
    sqlx_core::query::query("UPDATE schema_migrations SET checksum = '\\x00' WHERE version = 1")
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(
        db::migration_status(&db.pool).await.unwrap(),
        MigrationStatus::Modified(1)
    );
    let err = serve::prepare_with_pool(config(&[]), db.pool.clone(), true)
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "migration 1 was modified");
    assert_eq!(err.exit_code(), 3);
    assert!(db::migrate(&db.pool).await.is_err());
    sqlx_core::query::query("UPDATE schema_migrations SET checksum = $1 WHERE version = 1")
        .bind(db::checksum(MIGRATIONS[0].2))
        .execute(&db.pool)
        .await
        .unwrap();

    // A migration this binary does not know.
    sqlx_core::query::query(
        "INSERT INTO schema_migrations (version, name, checksum, applied_at) \
         VALUES (999, 'future', '\\x00', now())",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    assert_eq!(
        db::migration_status(&db.pool).await.unwrap(),
        MigrationStatus::SchemaTooNew(999)
    );
    let err = serve::prepare_with_pool(config(&[]), db.pool.clone(), true)
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("database schema is newer than this binary"),
        "{err}"
    );
    assert_eq!(err.exit_code(), 3);
}

#[tokio::test]
async fn t09_wrong_server_secret_refuses_to_start() {
    let Some(db) = TestDb::fresh().await else {
        return;
    };
    // First start with secret A initialises the canary and the OPAQUE setup.
    serve::prepare_with_pool(config(&[]), db.pool.clone(), true)
        .await
        .unwrap();
    // The same secret starts again.
    serve::prepare_with_pool(config(&[]), db.pool.clone(), false)
        .await
        .unwrap();
    // Secret B: refused.
    let err = serve::prepare_with_pool(
        config(&[("COURIER_SERVER_SECRET", SECRET_B)]),
        db.pool.clone(),
        false,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, ServeError::WrongSecret { .. }), "{err}");
    assert_eq!(err.exit_code(), 2);
    assert!(
        err.to_string()
            .starts_with("cannot decrypt server_secrets row ")
    );
    assert!(err.to_string().ends_with(WRONG_SECRET_TAIL), "{err}");

    // The binary exits with code 2 and prints the message (AC4).
    let out = Command::new(env!("CARGO_BIN_EXE_courier-ftp-server"))
        .arg("serve")
        .env("DATABASE_URL", &db.url)
        .env("COURIER_SERVER_SECRET", SECRET_B)
        .env("COURIER_PUBLIC_URL", PUBLIC_URL)
        .env("COURIER_BIND", "127.0.0.1:0")
        .env("COURIER_LOG", "off")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(WRONG_SECRET_TAIL), "{stderr}");
    // With the right secret the binary gets past the checks (it then
    // listens; `migrate` is the one-shot command that exits).
    let out = Command::new(env!("CARGO_BIN_EXE_courier-ftp-server"))
        .arg("migrate")
        .env("DATABASE_URL", &db.url)
        .env("COURIER_SERVER_SECRET", SECRET_A)
        .env("COURIER_PUBLIC_URL", PUBLIC_URL)
        .env("COURIER_LOG", "off")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
}

/// Lines of `logs` that carry the setup token, and the token itself.
fn setup_token_lines(logs: &str) -> Vec<(String, String)> {
    logs.lines()
        .filter(|l| l.contains("setup_token="))
        .map(|l| {
            let token = l
                .split("setup_token=")
                .nth(1)
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap()
                .trim_matches('"')
                .to_owned();
            (l.to_owned(), token)
        })
        .collect()
}

/// Bootstrap on `state`, then register with the logged token (AC6).
async fn bootstrap_scenario(state: &AppState, restart: impl Fn() -> AppState) {
    let logs = LogCapture::default();
    let guard = logs.install();
    serve::prepare_state(state).await.unwrap();
    drop(guard);
    let lines = setup_token_lines(&logs.text());
    assert_eq!(lines.len(), 1, "{}", logs.text());
    let (line, token) = &lines[0];
    assert!(line.contains("WARN"), "{line}");
    assert!(line.contains("register the first account with this setup token"));
    assert_eq!(token.len(), 43);

    let h = Harness::on_store(state.store().clone());
    // A wrong token is refused.
    let err = try_register(
        &h,
        "admin@example.test",
        "admin password",
        RegOpts {
            setup: Some("wrong".into()),
            ..RegOpts::default()
        },
    )
    .await
    .err()
    .unwrap();
    assert_eq!(err.0, StatusCode::FORBIDDEN);
    assert_eq!(message(&err.1), "invalid setup token");
    // The first registration with it becomes instance admin (invite-only mode).
    let admin = try_register(
        &h,
        "admin@example.test",
        "admin password",
        RegOpts {
            setup: Some(token.clone()),
            ..RegOpts::default()
        },
    )
    .await
    .map_err(|(s, v)| format!("{s} {v}"))
    .unwrap();
    assert!(admin.is_instance_admin);
    assert_eq!(
        state
            .store()
            .setting(settings_kv::SETUP_TOKEN_HASH)
            .await
            .unwrap(),
        None,
        "consumed"
    );
    // A second use is refused.
    let err = try_register(
        &h,
        "second@example.test",
        "pw",
        RegOpts {
            setup: Some(token.clone()),
            ..RegOpts::default()
        },
    )
    .await
    .err()
    .unwrap();
    assert_eq!(err.0, StatusCode::FORBIDDEN);
    assert_eq!(message(&err.1), "invalid setup token");

    // A restart with an account does not log a token.
    let logs = LogCapture::default();
    let guard = logs.install();
    let state2 = restart();
    serve::prepare_state(&state2).await.unwrap();
    drop(guard);
    assert!(setup_token_lines(&logs.text()).is_empty());
}

#[tokio::test]
async fn t10_bootstrap_setup_token_once_mem() {
    let state = AppState::new(config(&[]), Store::mem(), Arc::new(NoopSink));
    let store = state.store().clone();
    bootstrap_scenario(&state, || {
        AppState::new(config(&[]), store.clone(), Arc::new(NoopSink))
    })
    .await;
}

#[tokio::test]
async fn t10_bootstrap_setup_token_once_pg() {
    let Some(db) = TestDb::migrated().await else {
        return;
    };
    let state = AppState::new(
        config(&[]),
        Store::Pg(db.pool.clone()),
        Arc::new(NoopSink),
    );
    let pool = db.pool.clone();
    bootstrap_scenario(&state, || {
        AppState::new(config(&[]), Store::Pg(pool.clone()), Arc::new(NoopSink))
    })
    .await;
    // Starting twice before any registration replaces the token.
    drop(db);
    let Some(db) = TestDb::migrated().await else {
        return;
    };
    let logs = LogCapture::default();
    let guard = logs.install();
    for _ in 0..2 {
        let s = AppState::new(
            config(&[("COURIER_SERVER_SECRET", SECRET_A)]),
            Store::Pg(db.pool.clone()),
            Arc::new(NoopSink),
        );
        serve::prepare_state(&s).await.unwrap();
    }
    drop(guard);
    let lines = setup_token_lines(&logs.text());
    assert_eq!(lines.len(), 2);
    assert_ne!(lines[0].1, lines[1].1);
    let stored: String =
        sqlx_core::query_scalar::query_scalar("SELECT value FROM settings WHERE key = $1")
            .bind(settings_kv::SETUP_TOKEN_HASH)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(
        stored,
        hex::encode(courier_ftp_server::registration::hash_token(&lines[1].1))
    );
}
