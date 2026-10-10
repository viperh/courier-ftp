//! `/v1/devices`: device registry and revocation.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get};
use axum::{Json, Router};
use courier_ftp_proto::auth::DeviceView;
use uuid::Uuid;

use crate::auth::AuthCtx;
use crate::error::ApiError;
use crate::events::publish_devices_revoked;
use crate::state::AppState;

/// `/devices` routes (nested under `/v1`).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/devices", get(list))
        .route("/devices/{id}", delete(revoke))
}

/// The caller's devices, newest `created_at` first.
async fn list(
    State(state): State<AppState>,
    ctx: AuthCtx,
) -> Result<Json<Vec<DeviceView>>, ApiError> {
    let rows = state.store().list_devices(ctx.user_id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|d| DeviceView {
                current: d.id == ctx.device_id,
                id: d.id,
                name: Some(d.name),
                platform: Some(d.platform),
                created_at: Some(d.created_at),
                last_seen_at: d.last_seen_at,
                revoked_at: d.revoked_at,
            })
            .collect(),
    ))
}

/// Revokes one of the caller's devices (the calling device too, like logout):
/// `revoked_at` is set and its tokens are deleted, so its access token fails
/// from the next request on.
async fn revoke(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    if !state
        .store()
        .revoke_device(ctx.user_id, id, state.auth().now())
        .await?
    {
        return Err(ApiError::NotFound("device not found".into()));
    }
    tracing::info!(user_id = %ctx.user_id, device_id = %id, by = %ctx.device_id, "device revoked");
    publish_devices_revoked(state.events().as_ref(), &[id]);
    Ok(StatusCode::NO_CONTENT)
}
