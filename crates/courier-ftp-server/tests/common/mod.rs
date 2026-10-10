//! Shared helpers for the courier-ftp-server integration tests.
//!
//! Every test starts a real server in-process on `127.0.0.1:<random port>`
//! and drives it over HTTP (and WebSocket) like the sync client will:
//! * the in-memory store (always runs), or
//! * PostgreSQL: set `COURIER_SERVER_PG_TEST=1` and `DATABASE_URL` to a role
//!   that may `CREATE DATABASE` (CI's `server-db` job does). Each test gets
//!   its own throw-away database. Without them the Postgres variants print a
//!   skip notice and pass.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc
)]

pub mod client;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::str::FromStr;
use std::sync::Arc;

use courier_ftp_server::auth::store::mem::MemStore;
use courier_ftp_server::auth::{AuthRuntime, AuthStore, ManualClock};
use courier_ftp_server::middleware::rate_limit::{LoginLimits, RateLimiters};
use courier_ftp_server::{AppState, Config, app, serve};
use reqwest::header::HeaderMap;
use reqwest::{Method, StatusCode};
use serde_json::Value;
use sqlx_core::executor::Executor;
use sqlx_postgres::{PgConnectOptions, PgPool, PgPoolOptions};

/// 32 bytes of hex: a valid server secret.
pub const SECRET_A: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
/// A different valid server secret.
pub const SECRET_B: &str = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";
/// A URL that never answers (lazy pools that must not be used).
pub const UNREACHABLE_DB: &str = "postgres://courier@127.0.0.1:1/unreachable";

/// A config from the given env pairs on top of a valid baseline.
pub fn config(extra: &[(&str, &str)]) -> Config {
    let mut env: HashMap<String, String> = HashMap::from([
        ("COURIER_SERVER_SECRET".into(), SECRET_A.into()),
        (
            "COURIER_PUBLIC_URL".into(),
            "https://sync.example.test".into(),
        ),
    ]);
    for (k, v) in extra {
        env.insert((*k).into(), (*v).into());
    }
    Config::from_sources(None, |k| env.get(k).cloned()).expect("valid test config")
}

/// Rate limits high enough never to trigger.
pub fn generous() -> RateLimiters {
    let n = NonZeroU32::new(100_000).unwrap();
    RateLimiters::new(LoginLimits {
        per_email_per_minute: n,
        per_ip_per_minute: n,
    })
}

/// Installs rustls' `ring` provider (reqwest is built without one).
pub fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

// --------------------------------------------------------------- database

/// A throw-away PostgreSQL database.
#[derive(Debug)]
pub struct TestDb {
    pub pool: PgPool,
    pub url: String,
    name: String,
    admin_url: String,
}

/// The admin URL when the Postgres tests are enabled.
pub fn pg_admin_url() -> Option<String> {
    if std::env::var("COURIER_SERVER_PG_TEST").ok().as_deref() != Some("1") {
        return None;
    }
    std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty())
}

impl TestDb {
    /// A fresh, empty (unmigrated) database, or `None` when the Postgres
    /// tests are not enabled.
    pub async fn fresh() -> Option<Self> {
        let admin_url = pg_admin_url()?;
        let name = format!("courier_test_{}", uuid::Uuid::now_v7().simple());
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
            .max_connections(10)
            .connect_with(opts)
            .await
            .unwrap();
        let url = match admin_url.rsplit_once('/') {
            Some((base, rest)) if !base.ends_with('/') => {
                let query = rest
                    .split_once('?')
                    .map(|(_, q)| format!("?{q}"))
                    .unwrap_or_default();
                format!("{base}/{name}{query}")
            }
            _ => format!("{admin_url}/{name}"),
        };
        Some(Self {
            pool,
            url,
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

    /// Drops the database.
    pub async fn cleanup(self) {
        self.pool.close().await;
        if let Ok(admin) = PgPool::connect(&self.admin_url).await {
            let _ = admin
                .execute(format!("DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)", self.name).as_str())
                .await;
            admin.close().await;
        }
    }
}

/// `let db = db_or_skip!(TestDb::migrated());` returns early with a notice
/// when the Postgres tests are not enabled.
#[macro_export]
macro_rules! db_or_skip {
    ($e:expr) => {
        match $e.await {
            Some(db) => db,
            None => {
                eprintln!(
                    "SKIPPED (needs PostgreSQL): set COURIER_SERVER_PG_TEST=1 and DATABASE_URL"
                );
                return;
            }
        }
    };
}

// ----------------------------------------------------------------- server

/// The store behind a test server.
#[derive(Debug)]
pub enum Backend {
    /// In-memory model.
    Mem(Arc<MemStore>),
    /// PostgreSQL.
    Pg(TestDb),
}

/// A running in-process server and an HTTP client for it.
#[derive(Debug)]
pub struct Server {
    /// `http://127.0.0.1:<port>`.
    pub base: String,
    /// The server's address.
    pub addr: SocketAddr,
    /// The app state (store, config, clock).
    pub state: AppState,
    /// The injectable clock (time travel).
    pub clock: Arc<ManualClock>,
    /// The store.
    pub backend: Backend,
    /// The HTTP client.
    pub http: reqwest::Client,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Binds `127.0.0.1:0` and serves `state` there, exactly like `serve` does
/// (connect info included, so the client IP is the real peer).
pub async fn spawn(state: AppState) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = app::router(state).into_make_service_with_connect_info::<SocketAddr>();
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, task)
}

impl Server {
    /// Starts a server on `store` with `limits`, running the same startup
    /// checks as `serve` (secret canary, OPAQUE setup, setup token).
    pub async fn start(
        store: AuthStore,
        pool: PgPool,
        limits: RateLimiters,
        cfg: Config,
        backend: Backend,
    ) -> Self {
        install_crypto();
        let clock = Arc::new(ManualClock::new());
        let auth = AuthRuntime::new(store, clock.clone());
        let state = AppState::with_auth(cfg, pool, limits, auth);
        serve::startup_checks(&state).await.expect("startup checks");
        let (addr, task) = spawn(state.clone()).await;
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap();
        Self {
            base: format!("http://{addr}"),
            addr,
            state,
            clock,
            backend,
            http,
            task,
        }
    }

    /// The in-memory server with custom limits and config.
    pub async fn mem_with(limits: RateLimiters, cfg: Config) -> Self {
        let mem = Arc::new(MemStore::new());
        let pool = courier_ftp_server::db::connect_lazy(UNREACHABLE_DB).unwrap();
        Self::start(
            AuthStore::Memory(mem.clone()),
            pool,
            limits,
            cfg,
            Backend::Mem(mem),
        )
        .await
    }

    /// The in-memory server with generous limits.
    pub async fn mem() -> Self {
        Self::mem_with(generous(), config(&[])).await
    }

    /// The PostgreSQL server (`None` when the Postgres tests are off).
    pub async fn pg_with(cfg: Config) -> Option<Self> {
        let db = TestDb::migrated().await?;
        let pool = db.pool.clone();
        Some(
            Self::start(
                AuthStore::Postgres(pool.clone()),
                pool,
                generous(),
                cfg,
                Backend::Pg(db),
            )
            .await,
        )
    }

    /// The PostgreSQL server with the default test config.
    pub async fn pg() -> Option<Self> {
        Self::pg_with(config(&[])).await
    }

    /// Drops the test database.
    pub async fn cleanup(mut self) {
        self.task.abort();
        let backend = std::mem::replace(&mut self.backend, Backend::Mem(Arc::new(MemStore::new())));
        if let Backend::Pg(db) = backend {
            db.cleanup().await;
        }
    }

    /// The in-memory store, if this is a memory server.
    pub fn mem_store(&self) -> Option<&MemStore> {
        match &self.backend {
            Backend::Mem(m) => Some(m),
            Backend::Pg(_) => None,
        }
    }

    /// The database, if this is a Postgres server.
    pub fn pool(&self) -> Option<&PgPool> {
        match &self.backend {
            Backend::Pg(db) => Some(&db.pool),
            Backend::Mem(_) => None,
        }
    }

    /// One request; returns status, headers and the JSON body (`Null` when
    /// empty).
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        bearer: Option<&str>,
        headers: &[(&str, &str)],
    ) -> (StatusCode, HeaderMap, Value) {
        let method = Method::from_bytes(method.as_bytes()).unwrap();
        let mut b = self.http.request(method, format!("{}{path}", self.base));
        if let Some(t) = bearer {
            b = b.bearer_auth(t);
        }
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        if let Some(v) = body {
            b = b.json(&v);
        }
        let resp = b.send().await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = resp.bytes().await.unwrap();
        let v = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(&bytes)))
        };
        (status, headers, v)
    }

    /// One request; status and JSON body.
    pub async fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        bearer: Option<&str>,
    ) -> (StatusCode, Value) {
        let (st, _, v) = self.request(method, path, body, bearer, &[]).await;
        (st, v)
    }

    /// `POST` with a JSON body.
    pub async fn post(&self, path: &str, body: Value, bearer: Option<&str>) -> (StatusCode, Value) {
        self.call("POST", path, Some(body), bearer).await
    }

    /// `GET`.
    pub async fn get(&self, path: &str, bearer: Option<&str>) -> (StatusCode, Value) {
        self.call("GET", path, None, bearer).await
    }

    /// The server clock's current time.
    pub fn now(&self) -> chrono::DateTime<chrono::Utc> {
        use courier_ftp_server::auth::Clock as _;
        self.clock.now()
    }
}

/// Asserts a `401 auth_required` envelope.
pub fn assert_auth_required(st: StatusCode, v: &Value) {
    assert_eq!(st, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(v["error"]["code"], "auth_required", "{v}");
}

/// Asserts an error envelope with `status` and `code`.
pub fn assert_error(st: StatusCode, v: &Value, status: StatusCode, code: &str) {
    assert_eq!(st, status, "{v}");
    assert_eq!(v["error"]["code"], code, "{v}");
}
