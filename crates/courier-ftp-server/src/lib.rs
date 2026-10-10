//! courier-ftp-server: the self-hosted sync server (D12, adapted from sverb).
//!
//! Accounts, OPAQUE login and devices (T84), vaults, pull/push and live
//! updates (T85), configuration, the admin CLI and deployment (T86). It only
//! stores end-to-end encrypted data it cannot read: the server never learns the
//! master password, the account private keys or any item plaintext.
//!
//! The library holds the server so integration tests can run it in-process;
//! the `courier-ftp-server` binary is a thin entry point.
//!
//! * [`config`]: environment (and optional TOML) configuration,
//! * [`db`]: PostgreSQL pool and the embedded migration runner,
//! * [`error`]: [`ApiError`] → the JSON error envelope,
//! * [`middleware`]: request ids, protocol version, client IP, rate limits,
//!   error normalisation,
//! * [`app`]: router and middleware stack,
//! * [`routes`]: `/v1/auth/*`, `/v1/account*`, `/v1/devices*`,
//! * [`auth`]: OPAQUE, tokens, TOTP, the bearer extractor and the store,
//! * [`secrets`]: the at-rest key for `server_secrets`, TOTP seeds and login states,
//! * [`registration`]: registration modes and the setup-token bootstrap,
//! * [`events`]: what handlers publish for T85's live updates,
//! * [`serve`]: startup checks, listeners, exit codes.
//!
//! Layering: depends only on `courier-ftp-proto` and `courier-ftp-crypto`; never on
//! a client crate, a UI crate, russh or rusqlite.

pub mod app;
pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod events;
pub mod mail;
pub mod middleware;
pub mod registration;
pub mod routes;
pub mod secrets;
pub mod serve;
pub mod settings_kv;
pub mod state;

pub use config::Config;
pub use error::ApiError;
pub use state::AppState;
