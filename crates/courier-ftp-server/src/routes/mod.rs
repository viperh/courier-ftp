//! Route modules. Each task adds a module here and merges its router into
//! [`api_v1`] (`/v1/...`). Endpoint → request → response tables are in the
//! `courier_ftp_proto` module docs.

// Authentication, account and device routes (T84).
pub mod account;
pub mod auth;
pub mod devices;
pub mod ops;
// Vault list, pull and push (T85).
pub mod vaults;
// Orgs, members, invites, the audit log, user public keys (T89).
pub mod orgs;
// Shared vault members and org vault listings (T89).
pub mod shared_vaults;
// Vault key rotation (T89).
pub mod rotate;

use axum::Router;

use crate::state::AppState;

/// The versioned API, nested under `/v1` by [`crate::app::routes`].
pub fn api_v1() -> Router<AppState> {
    Router::new()
        .merge(auth::router())
        .merge(account::router())
        .merge(devices::router())
        .merge(vaults::router())
        .merge(crate::ws::router())
        .merge(orgs::router())
        .merge(shared_vaults::router())
        .merge(rotate::router())
}
