//! `courier-ftp-server serve` and `migrate`: startup checks, listeners, graceful
//! shutdown, exit codes.
//!
//! Startup order: load config → connect → migrations check/apply → verify the
//! server secret against every `server_secrets` row → load or create the OPAQUE
//! `ServerSetup` → setup-token bootstrap → rate-limit cleanup task → bind (plain,
//! or built-in rustls when cert and key are set) → serve until SIGINT/SIGTERM
//! (10 s grace).
//!
//! Exit codes: 0 normal, 2 configuration or secret error, 3 database or
//! migration error, 4 bind or TLS error.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use sqlx_postgres::PgPool;
use tracing_subscriber::EnvFilter;

use crate::auth::store::Store;
use crate::config::{Config, ConfigError};
use crate::db::{self, MigrationError, MigrationStatus};
use crate::error::ApiError;
use crate::events::NoopSink;
use crate::registration;
use crate::secrets::SecretsError;
use crate::state::AppState;

/// Grace period for in-flight requests on shutdown.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// Reasons the server refuses to start (or stops).
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// Invalid configuration (exit code 2).
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Database unreachable or failing (exit code 3).
    #[error("database error: {0}")]
    Database(String),
    /// A migration failed (exit code 3).
    #[error("migration failed: {0}")]
    Migration(String),
    /// Pending migrations without `--migrate` (exit code 3).
    #[error(
        "the database has pending migrations {0:?}; run `courier-ftp-server migrate` (after a \
         backup) or start with `courier-ftp-server serve --migrate`"
    )]
    PendingMigrations(Vec<i64>),
    /// The database has a migration this binary does not know (exit code 3).
    #[error("database schema is newer than this binary (it has migration {0})")]
    SchemaTooNew(i64),
    /// An applied migration was modified (exit code 3).
    #[error("migration {0} was modified")]
    MigrationModified(i64),
    /// `COURIER_SERVER_SECRET` is not the one the database was created with
    /// (exit code 2).
    #[error(
        "cannot decrypt server_secrets row {name}: COURIER_SERVER_SECRET differs from the one \
         this database was created with. Refusing to start."
    )]
    WrongSecret {
        /// The row that failed.
        name: String,
    },
    /// The OPAQUE server setup can't be loaded or created (exit code 3).
    #[error("cannot load the OPAQUE server setup: {0}")]
    OpaqueSetup(String),
    /// TLS setup failed (exit code 4).
    #[error("TLS configuration error: {0}")]
    Tls(std::io::Error),
    /// Binding or serving failed (exit code 4).
    #[error("cannot listen on {addr}: {source}")]
    Bind {
        /// The address.
        addr: SocketAddr,
        /// The I/O error.
        source: std::io::Error,
    },
}

impl ServeError {
    /// The process exit code.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Config(_) | Self::WrongSecret { .. } => 2,
            Self::Database(_)
            | Self::Migration(_)
            | Self::PendingMigrations(_)
            | Self::SchemaTooNew(_)
            | Self::MigrationModified(_)
            | Self::OpaqueSetup(_) => 3,
            Self::Tls(_) | Self::Bind { .. } => 4,
        }
    }
}

impl From<sqlx_core::Error> for ServeError {
    fn from(e: sqlx_core::Error) -> Self {
        Self::Database(e.to_string())
    }
}

impl From<MigrationError> for ServeError {
    fn from(e: MigrationError) -> Self {
        match e {
            MigrationError::Db(e) => Self::Migration(e.to_string()),
            MigrationError::SchemaTooNew(v) => Self::SchemaTooNew(v),
            MigrationError::Modified(v) => Self::MigrationModified(v),
        }
    }
}

fn store_error(e: ApiError) -> ServeError {
    match e {
        ApiError::Internal(cause) => ServeError::Database(cause.to_string()),
        other => ServeError::Database(other.to_string()),
    }
}

impl From<SecretsError> for ServeError {
    fn from(e: SecretsError) -> Self {
        match e {
            SecretsError::WrongSecret { name } => Self::WrongSecret { name },
            SecretsError::Store(e) => store_error(e),
            SecretsError::Crypto(e) => Self::OpaqueSetup(e.to_string()),
        }
    }
}

/// Installs the global JSON-lines subscriber on stdout (`COURIER_LOG`, else
/// `RUST_LOG`, else `info`). A second call is ignored. T86 makes the format
/// configurable.
pub fn init_logging() {
    let filter = EnvFilter::try_from_env("COURIER_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let result = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .flatten_event(true)
        .with_current_span(true)
        .with_span_list(false)
        .try_init();
    drop(result);
}

/// The checks every start runs on a ready store: verify the server secret,
/// load or create the OPAQUE setup, bootstrap the setup token.
///
/// # Errors
/// [`ServeError::WrongSecret`], [`ServeError::OpaqueSetup`], store errors.
pub async fn prepare_state(state: &AppState) -> Result<(), ServeError> {
    state.secrets().verify_or_init(state.store()).await?;
    // Load (or generate on first start) the OPAQUE setup now, so a broken secret
    // or database fails the start, not the first login.
    state.server_setup().await.map_err(|e| match e {
        ApiError::Internal(cause) => ServeError::OpaqueSetup(cause.to_string()),
        other => ServeError::OpaqueSetup(other.to_string()),
    })?;
    if let Some(token) = registration::bootstrap(state.store(), state.auth().now())
        .await
        .map_err(store_error)?
    {
        registration::log_setup_token(&token);
    }
    Ok(())
}

/// Checks (or, with `apply_migrations`, applies) migrations on `pool`, builds the
/// production state on it and runs [`prepare_state`].
///
/// # Errors
/// [`ServeError`].
pub async fn prepare_with_pool(
    config: Config,
    pool: PgPool,
    apply_migrations: bool,
) -> Result<AppState, ServeError> {
    match db::migration_status(&pool).await? {
        MigrationStatus::Current => {}
        MigrationStatus::Pending(versions) => {
            if !apply_migrations {
                return Err(ServeError::PendingMigrations(versions));
            }
            tracing::info!(?versions, "applying migrations");
            db::migrate(&pool).await?;
        }
        MigrationStatus::SchemaTooNew(v) => return Err(ServeError::SchemaTooNew(v)),
        MigrationStatus::Modified(v) => return Err(ServeError::MigrationModified(v)),
    }
    let state = AppState::new(config, Store::Pg(pool), Arc::new(NoopSink));
    prepare_state(&state).await?;
    Ok(state)
}

/// Connects to `DATABASE_URL` and [`prepare_with_pool`].
///
/// # Errors
/// [`ServeError`].
pub async fn prepare(config: Config, apply_migrations: bool) -> Result<AppState, ServeError> {
    let pool = db::connect(config.require_database_url()?).await?;
    prepare_with_pool(config, pool, apply_migrations).await
}

/// `courier-ftp-server migrate`.
///
/// # Errors
/// [`ServeError`].
pub async fn migrate(config: &Config) -> Result<Vec<i64>, ServeError> {
    let pool = db::connect(config.require_database_url()?).await?;
    let applied = db::migrate(&pool).await?;
    pool.close().await;
    Ok(applied)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
    tracing::info!("shutdown requested");
}

/// Runs the server until SIGINT/SIGTERM.
///
/// # Errors
/// [`ServeError`].
pub async fn run(config: Config, apply_migrations: bool) -> Result<(), ServeError> {
    // rustls 0.23 needs a process-wide provider; `ring` is the only one built.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let state = prepare(config, apply_migrations).await?;
    let config = state.config().clone();
    let _cleanup = state.rate_limits().clone().spawn_cleanup();

    let app = crate::app::router(state).into_make_service_with_connect_info::<SocketAddr>();
    let addr = config.bind;
    match &config.tls {
        Some(tls) => {
            let rustls_config =
                axum_server::tls_rustls::RustlsConfig::from_pem_file(&tls.cert, &tls.key)
                    .await
                    .map_err(ServeError::Tls)?;
            let handle = axum_server::Handle::new();
            let h = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                h.graceful_shutdown(Some(SHUTDOWN_GRACE));
            });
            tracing::info!(%addr, tls = true, "courier-ftp-server listening");
            axum_server::bind_rustls(addr, rustls_config)
                .handle(handle)
                .serve(app)
                .await
                .map_err(|source| ServeError::Bind { addr, source })?;
        }
        None => {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .map_err(|source| ServeError::Bind { addr, source })?;
            tracing::info!(%addr, tls = false, "courier-ftp-server listening");
            let notify = Arc::new(tokio::sync::Notify::new());
            let signalled = notify.clone();
            let server = axum::serve(listener, app).with_graceful_shutdown(async move {
                shutdown_signal().await;
                signalled.notify_one();
            });
            // In-flight requests get SHUTDOWN_GRACE after the signal.
            let deadline = async {
                notify.notified().await;
                tokio::time::sleep(SHUTDOWN_GRACE).await;
            };
            tokio::select! {
                r = server => r.map_err(|source| ServeError::Bind { addr, source })?,
                () = deadline => tracing::warn!("grace period over; dropping open connections"),
            }
        }
    }
    tracing::info!("courier-ftp-server stopped");
    Ok(())
}

/// Logs a startup error, prints it to stderr and maps it to its exit code.
#[must_use]
pub fn fail(e: &ServeError) -> ExitCode {
    tracing::error!(error = %e, "courier-ftp-server cannot run");
    eprintln!("courier-ftp-server: {e}");
    ExitCode::from(e.exit_code())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes() {
        assert_eq!(
            ServeError::WrongSecret {
                name: "secret_check".into()
            }
            .exit_code(),
            2
        );
        assert_eq!(
            ServeError::Config(ConfigError::MissingSecret).exit_code(),
            2
        );
        assert_eq!(ServeError::PendingMigrations(vec![1]).exit_code(), 3);
        assert_eq!(ServeError::SchemaTooNew(9).exit_code(), 3);
        assert_eq!(ServeError::Database("x".into()).exit_code(), 3);
        assert_eq!(ServeError::Tls(std::io::Error::other("x")).exit_code(), 4);
        assert!(
            ServeError::SchemaTooNew(9)
                .to_string()
                .contains("database schema is newer than this binary")
        );
        assert_eq!(
            ServeError::MigrationModified(1).to_string(),
            "migration 1 was modified"
        );
    }
}
