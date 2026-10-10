//! Ops endpoints: `/healthz` (process up), `/readyz` (database reachable,
//! migrations current, nothing degraded).

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::json;

use crate::db::{self, MigrationStatus};
use crate::state::AppState;

/// `/healthz` and `/readyz` (outside `/v1`).
pub fn router(_state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
}

/// Process liveness: always 200.
pub async fn healthz() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

/// Readiness: database reachable, migrations current, nothing degraded.
pub async fn readyz(State(state): State<AppState>) -> Response {
    let (ready, detail) = match db::migration_status(state.db()).await {
        Err(e) => {
            tracing::warn!(error = %e, "readiness: database unreachable");
            (false, json!({ "database": "unreachable" }))
        }
        Ok(MigrationStatus::Current) => {
            (true, json!({ "database": "ok", "migrations": "current" }))
        }
        Ok(MigrationStatus::Pending(v)) => (
            false,
            json!({ "database": "ok", "migrations": "pending", "pending": v }),
        ),
        Ok(MigrationStatus::Mismatch(m)) => (
            false,
            json!({ "database": "ok", "migrations": "mismatch", "reason": m }),
        ),
    };
    let degraded = state.readiness().degraded();
    let ready = ready && degraded.is_empty();
    let mut body = detail;
    body["status"] = json!(if ready { "ready" } else { "not_ready" });
    if !degraded.is_empty() {
        body["degraded"] = json!(degraded);
    }
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body)).into_response()
}
