//! Route modules. Each later task adds a module here and merges its router into
//! [`api_v1`].

pub mod account;
pub mod auth;
pub mod devices;

use axum::Router;

use crate::state::AppState;

/// The versioned API, nested under `/v1` by [`crate::app::routes`].
pub fn api_v1() -> Router<AppState> {
    Router::new()
        .merge(auth::router())
        .merge(account::router())
        .merge(devices::router())
}
