//! `/v1/devices`: device registry and revocation.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get};
use axum::{Json, Router};
use courier_ftp_proto::auth::DeviceSummary;
use uuid::Uuid;

use crate::auth::AuthCtx;
use crate::auth::clock::to_offset;
use crate::error::ApiError;
use crate::state::AppState;

/// `/devices` routes (nested under `/v1`).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/devices", get(list))
        .route("/devices/{id}", delete(revoke))
}

/// The caller's unrevoked devices, oldest first.
async fn list(
    State(state): State<AppState>,
    ctx: AuthCtx,
) -> Result<Json<Vec<DeviceSummary>>, ApiError> {
    let rows = state.auth().store().list_devices(ctx.user_id).await?;
    let now = state.auth().now();
    Ok(Json(
        rows.into_iter()
            .filter(|d| d.revoked_at.is_none())
            .map(|d| DeviceSummary {
                current: d.id == ctx.device_id,
                id: d.id,
                name: d.name.unwrap_or_default(),
                platform: d.platform.unwrap_or_default(),
                created_at: to_offset(d.created_at.unwrap_or(now)),
                last_seen_at: d.last_seen_at.map(to_offset),
            })
            .collect(),
    ))
}

/// Revokes a device: `revoked_at` is set and its tokens are deleted, so its
/// access token fails from the next request on.
async fn revoke(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let auth = state.auth();
    if !auth
        .store()
        .revoke_device(ctx.user_id, id, auth.now())
        .await?
    {
        return Err(ApiError::NotFound("no such device".into()));
    }
    tracing::info!(user_id = %ctx.user_id, device_id = %id, by = %ctx.device_id, "device revoked");
    auth.store()
        .audit(
            Some(ctx.user_id),
            "device_revoked",
            Some(id),
            serde_json::json!({ "by": ctx.device_id }),
            auth.now(),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
