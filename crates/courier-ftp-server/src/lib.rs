//! Self-hosted, end-to-end encrypted sync server for courier-ftp (T84–T86).
//!
//! The server only ever sees ciphertext: accounts (OPAQUE records, public
//! keys, sealed key bundles), devices and vaults of encrypted items. It shares
//! wire types with the client through `courier-ftp-proto` and never links
//! client crates (`scripts/check-layering.py`). Ported from sverb's
//! `sverb-server` (D13) without terminal sharing.
//!
//! The library holds the server so integration tests can run it in-process;
//! the `courier-ftp-server` binary is a thin entry point.
//!
//! * [`config`]: env + TOML configuration,
//! * [`db`]: pool, embedded migrations, migration status,
//! * [`error`]: `ApiError` → JSON envelope,
//! * [`middleware`]: request ids, protocol version, client IP, rate limits,
//!   error normalisation,
//! * [`app`]: router and middleware stack,
//! * [`routes`]: `/healthz`, `/readyz`, `/metrics`, `/v1/…`,
//! * [`secrets`]: AEAD-encrypted `server_secrets`,
//! * [`registration`]: registration modes, setup-token bootstrap,
//! * [`auth`]: OPAQUE login, tokens, devices, TOTP,
//! * [`sync`]: vaults, pull, push, quota, tombstone GC,
//! * [`ws`]: `/v1/ws` notifications and `LISTEN/NOTIFY` fan-out,
//! * [`mail`]: SMTP for recovery codes and invites,
//! * [`metrics`]: Prometheus metrics,
//! * [`admin`]: admin CLI operations, [`cli`]: argument parsing,
//!   [`healthcheck`]: the container probe,
//! * [`serve`]: startup checks and listeners.

pub mod admin;
pub mod app;
// OPAQUE, tokens, TOTP, the bearer extractor and auth persistence.
pub mod auth;
pub mod cli;
pub mod config;
pub mod db;
pub mod error;
pub mod healthcheck;
pub mod logging;
pub mod mail;
pub mod metrics;
pub mod middleware;
pub mod registration;
pub mod routes;
pub mod secrets;
pub mod serve;
pub mod settings;
pub mod state;
// Vault list, pull, push, quota and tombstone GC (T85).
pub mod sync;
// WebSocket notifications and multi-replica fan-out (T85).
pub mod ws;

pub use config::Config;
pub use error::ApiError;
pub use state::AppState;
