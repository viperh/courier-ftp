//! Shared harness for the courier-ftp-server integration tests (adapted from
//! sverb's `tests/common`).
//!
//! * [`Harness::mem`] builds an [`AppState`] + router on the in-memory store
//!   (always available);
//! * [`Harness::pg`] creates the throw-away database
//!   `courier_test_<uuidv7 simple>` through `DATABASE_URL` (the role needs
//!   `CREATEDB`), runs the migrations and drops the database again when the
//!   harness is dropped.
//!
//! Without `DATABASE_URL` the PostgreSQL variants print
//! `skipping: DATABASE_URL not set` and pass, except when `CI=true`: there they
//! fail (only the `server-db` and `canary` CI jobs run this crate's tests, both
//! with PostgreSQL).
//!
//! Clients use the real `courier-ftp-crypto` client code with the cheap
//! `insecure-test-ksf`; time is a [`TestClock`].
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

pub mod client;
pub mod scenarios;

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use courier_ftp_server::auth::TestClock;
use courier_ftp_server::auth::store::{NewInvite, Store};
use courier_ftp_server::events::RecordingSink;
use courier_ftp_server::middleware::rate_limit::{AuthLimits, RateLimiters};
use courier_ftp_server::registration::{self, hash_token};
use courier_ftp_server::{AppState, Config, app, settings_kv};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx_core::executor::Executor;
use sqlx_postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;

/// 32 bytes of hex: a valid server secret.
pub const SECRET_A: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
/// A different valid server secret.
pub const SECRET_B: &str = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";
/// The public URL of the test configuration.
pub const PUBLIC_URL: &str = "https://sync.example.test";

/// A config from `extra` env pairs on top of a valid baseline.
pub fn config(extra: &[(&str, &str)]) -> Config {
    let mut env: HashMap<String, String> = HashMap::from([
        ("COURIER_SERVER_SECRET".into(), SECRET_A.into()),
        ("COURIER_PUBLIC_URL".into(), PUBLIC_URL.into()),
    ]);
    for (k, v) in extra {
        env.insert((*k).into(), (*v).into());
    }
    Config::from_sources(None, |k| env.get(k).cloned()).expect("valid test config")
}

/// `DATABASE_URL`, or `None` after printing the skip notice. Panics when `CI=true`
/// and the variable is missing.
pub fn database_url() -> Option<String> {
    if let Some(url) = std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty()) {
        return Some(url);
    }
    assert!(
        std::env::var("CI").as_deref() != Ok("true"),
        "DATABASE_URL must be set when CI=true (PostgreSQL tests may not be skipped in CI)"
    );
    eprintln!("skipping: DATABASE_URL not set");
    None
}

/// A throw-away database, dropped on drop.
pub struct TestDb {
    /// Pool on the database.
    pub pool: PgPool,
    /// Connection URL of the database.
    pub url: String,
    name: String,
    admin_url: String,
}

impl std::fmt::Debug for TestDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestDb").field("name", &self.name).finish()
    }
}

/// Replaces the database name of `url`.
fn with_database(url: &str, name: &str) -> String {
    let (base, query) = match url.split_once('?') {
        Some((b, q)) => (b, format!("?{q}")),
        None => (url, String::new()),
    };
    // `postgres://user:pw@host:port/db` → keep everything up to the last '/'
    // after the authority.
    let after_scheme = base.find("://").map_or(0, |i| i + 3);
    let base = match base[after_scheme..].find('/') {
        Some(i) => &base[..after_scheme + i],
        None => base,
    };
    format!("{base}/{name}{query}")
}

impl TestDb {
    /// A fresh, empty (unmigrated) database, or `None` (see [`database_url`]).
    pub async fn fresh() -> Option<Self> {
        let admin_url = database_url()?;
        let name = format!("courier_test_{}", Uuid::now_v7().simple());
        let admin = PgPool::connect(&admin_url)
            .await
            .expect("DATABASE_URL is set but the database is unreachable");
        admin
            .execute(format!("CREATE DATABASE \"{name}\"").as_str())
            .await
            .expect("CREATE DATABASE (the DATABASE_URL role needs CREATEDB)");
        admin.close().await;
        let opts = PgConnectOptions::from_str(&admin_url)
            .unwrap()
            .database(&name);
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await
            .unwrap();
        Some(Self {
            pool,
            url: with_database(&admin_url, &name),
            name,
            admin_url,
        })
    }

    /// A freshly migrated database.
    pub async fn migrated() -> Option<Self> {
        let db = Self::fresh().await?;
        courier_ftp_server::db::migrate(&db.pool).await.unwrap();
        Some(db)
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        // Async work in a destructor: a helper thread with its own runtime.
        let admin_url = self.admin_url.clone();
        let name = self.name.clone();
        let handle = std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            rt.block_on(async move {
                if let Ok(admin) = PgPool::connect(&admin_url).await {
                    let _ = admin
                        .execute(
                            format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)").as_str(),
                        )
                        .await;
                    admin.close().await;
                }
            });
        });
        let _ = handle.join();
    }
}

/// Rate limits that never trigger.
pub fn generous() -> RateLimiters {
    let n = NonZeroU32::new(1_000_000).unwrap();
    RateLimiters::new(AuthLimits {
        per_email_per_minute: n,
        per_ip_per_minute: n,
    })
}

/// One backend under test.
pub struct Harness {
    /// The router with the production middleware stack.
    pub app: Router,
    /// The state behind it.
    pub state: AppState,
    /// The injected clock.
    pub clock: Arc<TestClock>,
    /// Events published by handlers.
    pub events: Arc<RecordingSink>,
    /// Every secret value a client used (tokens, passwords, emails, codes,
    /// OPAQUE messages): the log canary checks that none of them was logged.
    pub canaries: Mutex<Vec<String>>,
    db: Option<TestDb>,
}

impl std::fmt::Debug for Harness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Harness")
            .field("backend", &self.backend())
            .finish_non_exhaustive()
    }
}

impl Harness {
    fn build(store: Store, limits: RateLimiters, cfg: Config, db: Option<TestDb>) -> Self {
        let clock = Arc::new(TestClock::new());
        let events = Arc::new(RecordingSink::new());
        let state = AppState::with_runtime(cfg, store, events.clone(), clock.clone(), limits);
        Self {
            app: app::router(state.clone()),
            state,
            clock,
            events,
            canaries: Mutex::new(Vec::new()),
            db,
        }
    }

    /// In-memory backend with `limits`.
    pub fn mem_with(limits: RateLimiters) -> Self {
        Self::mem_config(config(&[]), limits)
    }

    /// A harness on an existing store (the caller keeps the database alive).
    pub fn on_store(store: Store) -> Self {
        Self::build(store, generous(), config(&[]), None)
    }

    /// In-memory backend with an explicit configuration.
    pub fn mem_config(cfg: Config, limits: RateLimiters) -> Self {
        Self::build(Store::mem(), limits, cfg, None)
    }

    /// In-memory backend with generous rate limits.
    pub fn mem() -> Self {
        Self::mem_with(generous())
    }

    /// PostgreSQL backend with `limits`, or `None` (skipped).
    pub async fn pg_with(limits: RateLimiters) -> Option<Self> {
        let db = TestDb::migrated().await?;
        let store = Store::Pg(db.pool.clone());
        Some(Self::build(store, limits, config(&[]), Some(db)))
    }

    /// PostgreSQL backend with generous rate limits, or `None` (skipped).
    pub async fn pg() -> Option<Self> {
        Self::pg_with(generous()).await
    }

    /// `"mem"` or `"pg"`.
    pub fn backend(&self) -> &'static str {
        if self.db.is_some() { "pg" } else { "mem" }
    }

    /// The store.
    pub fn store(&self) -> &Store {
        self.state.store()
    }

    /// The pool (PostgreSQL backend only).
    pub fn pool(&self) -> Option<&PgPool> {
        self.db.as_ref().map(|d| &d.pool)
    }

    /// The clock's time.
    pub fn now(&self) -> OffsetDateTime {
        self.state.auth().now()
    }

    /// Remembers a secret value for the log canary.
    pub fn canary(&self, value: impl Into<String>) {
        let value = value.into();
        if !value.is_empty() {
            self.canaries.lock().unwrap().push(value);
        }
    }

    /// Sets `settings.registration_mode`.
    pub async fn set_mode(&self, mode: &str) {
        self.store()
            .set_setting(settings_kv::REGISTRATION_MODE, mode, self.now())
            .await
            .unwrap();
    }

    /// Opens registration to everyone.
    pub async fn open(&self) {
        self.set_mode("open").await;
    }

    /// Stores the hash of a setup token.
    pub async fn set_setup_token(&self, token: &str) {
        self.store()
            .set_setting(
                settings_kv::SETUP_TOKEN_HASH,
                &hex::encode(hash_token(token)),
                self.now(),
            )
            .await
            .unwrap();
    }

    /// Stores an instance invite (bound to `email` if given, valid for a day) and
    /// returns its token.
    pub async fn invite(&self, email: Option<&str>) -> String {
        let token = registration::generate_token();
        self.store()
            .insert_invite(&NewInvite {
                id: Uuid::now_v7(),
                org_id: None,
                email: email.map(str::to_owned),
                role: None,
                token_hash: hash_token(&token),
                created_by: None,
                created_at: self.now(),
                expires_at: self.now() + time::Duration::days(1),
            })
            .await
            .unwrap();
        self.canary(token.as_str());
        token.to_string()
    }

    /// Disables an account (as T86's `admin user disable` will).
    pub async fn disable(&self, user_id: Uuid) {
        match self.store() {
            Store::Mem(m) => m.with_data(|d| {
                if let Some(u) = d.users.get_mut(&user_id) {
                    u.disabled = true;
                }
            }),
            Store::Pg(pool) => {
                sqlx_core::query::query("UPDATE users SET disabled = true WHERE id = $1")
                    .bind(user_id)
                    .execute(pool)
                    .await
                    .unwrap();
            }
        }
    }

    /// Runs `SELECT count(*) FROM <table> WHERE <cond>` (PostgreSQL) with one uuid
    /// parameter.
    pub async fn pg_count(&self, sql: &str, id: Uuid) -> i64 {
        let pool = self.pool().expect("pg backend");
        sqlx_core::query_scalar::query_scalar::<_, i64>(sql)
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// Whether a user row with this id exists.
    pub async fn user_exists(&self, user_id: Uuid) -> bool {
        self.store().user_by_id(user_id).await.unwrap().is_some()
    }

    /// Whether a user row with this email exists.
    pub async fn email_exists(&self, email: &str) -> bool {
        self.store().user_by_email(email).await.unwrap().is_some()
    }

    /// Number of `auth_tokens` rows of a device.
    pub async fn token_count(&self, device_id: Uuid) -> i64 {
        match self.store() {
            Store::Mem(m) => m.with_data(|d| {
                i64::try_from(
                    d.tokens
                        .values()
                        .filter(|t| t.device_id == device_id)
                        .count(),
                )
                .unwrap()
            }),
            Store::Pg(_) => {
                self.pg_count(
                    "SELECT count(*) FROM auth_tokens WHERE device_id = $1",
                    device_id,
                )
                .await
            }
        }
    }

    /// Number of `login_states` rows.
    pub async fn login_state_count(&self) -> i64 {
        match self.store() {
            Store::Mem(m) => m.with_data(|d| i64::try_from(d.login_states.len()).unwrap()),
            Store::Pg(pool) => {
                sqlx_core::query_scalar::query_scalar::<_, i64>("SELECT count(*) FROM login_states")
                    .fetch_one(pool)
                    .await
                    .unwrap()
            }
        }
    }

    /// Sends one request through the router.
    pub async fn send(&self, req: Request<Body>) -> (StatusCode, HeaderMap, Bytes) {
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, headers, body)
    }

    /// A JSON call; returns status, headers and the parsed body (`Null` when
    /// empty).
    pub async fn call(
        &self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, HeaderMap, Value) {
        let mut b = Request::builder().method(method).uri(path);
        if let Some(t) = bearer {
            b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        let req = match body {
            Some(v) => b
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&v).unwrap()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let (status, headers, bytes) = self.send(req).await;
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            json(&bytes)
        };
        (status, headers, value)
    }

    /// `POST` with a JSON body.
    pub async fn post(&self, path: &str, bearer: Option<&str>, body: Value) -> (StatusCode, Value) {
        let (s, _, v) = self.call(Method::POST, path, bearer, Some(body)).await;
        (s, v)
    }

    /// `GET`.
    pub async fn get(&self, path: &str, bearer: Option<&str>) -> (StatusCode, Value) {
        let (s, _, v) = self.call(Method::GET, path, bearer, None).await;
        (s, v)
    }

    /// `DELETE`, optionally with a JSON body.
    pub async fn delete(
        &self,
        path: &str,
        bearer: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let (s, _, v) = self.call(Method::DELETE, path, bearer, body).await;
        (s, v)
    }
}

/// Captures log output (all levels, plain text) into a buffer.
#[derive(Clone, Default)]
pub struct LogCapture(Arc<Mutex<Vec<u8>>>);

struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogCapture {
    /// Installs a `trace` subscriber writing into the buffer for the current
    /// thread (`#[tokio::test]` runs everything on it).
    pub fn install(&self) -> tracing::subscriber::DefaultGuard {
        let buf = self.0.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || CaptureWriter(buf.clone()))
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        // Callsite interest is cached process-wide; tests running in parallel can
        // leave it stale, so recompute it now that this subscriber is the default.
        tracing::callsite::rebuild_interest_cache();
        guard
    }

    /// Everything captured so far.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

/// Parses a JSON body.
pub fn json(body: &Bytes) -> Value {
    serde_json::from_slice(body)
        .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(body)))
}

/// The error message of an envelope.
pub fn message(v: &Value) -> &str {
    v["error"]["message"].as_str().unwrap_or_default()
}

/// The error code of an envelope.
pub fn code(v: &Value) -> &str {
    v["error"]["code"].as_str().unwrap_or_default()
}

/// Instantiates `async fn $body(h: &Harness)` for both backends:
/// `both!(t01_x, t01_x_mem, t01_x_pg);`
#[macro_export]
macro_rules! both {
    ($body:path, $mem:ident, $pg:ident) => {
        #[tokio::test]
        async fn $mem() {
            let h = $crate::common::Harness::mem();
            $body(&h).await;
        }

        #[tokio::test]
        async fn $pg() {
            let Some(h) = $crate::common::Harness::pg().await else {
                return;
            };
            $body(&h).await;
        }
    };
}
