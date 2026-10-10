//! `/v1/vaults`: vault list, pull and push (T85): request extraction and
//! the post-commit notification. Team vault creation (`POST /v1/vaults`),
//! members and rotation are T89.

use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use courier_ftp_proto::sync::{PullQuery, PullResponse, PushRequest, PushResponse, VaultView};
use uuid::Uuid;

use crate::auth::AuthCtx;
use crate::error::ApiError;
use crate::metrics::{
    SYNC_PULL_BYTES_TOTAL, SYNC_PULL_ITEMS_TOTAL, SYNC_PUSH_BYTES_TOTAL, SYNC_PUSH_ITEMS_TOTAL,
};
use crate::state::AppState;
use crate::sync::{pull, push, rev_from_wire};

/// `/vaults` routes (nested under `/v1`).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/vaults", get(list))
        .route("/vaults/{id}/changes", get(pull_changes).post(push_changes))
}

async fn list(
    State(state): State<AppState>,
    ctx: AuthCtx,
) -> Result<Json<Vec<VaultView>>, ApiError> {
    let mut views = state.sync().store().list_vaults(ctx.user_id).await?;
    // Abandoned rotations (server clock) prompt a restart.
    crate::sync::rotation::mark_abandoned(&mut views, state.auth().now());
    Ok(Json(views))
}

async fn pull_changes(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Path(vault_id): Path<Uuid>,
    Query(q): Query<PullQuery>,
) -> Result<Json<PullResponse>, ApiError> {
    let limit = pull::page_size(&q)?;
    let page = state
        .sync()
        .store()
        .pull(ctx.user_id, vault_id, rev_from_wire(q.since), limit)
        .await?;
    let bytes: usize = page.items.iter().map(|i| i.envelope.len()).sum();
    metrics::counter!(SYNC_PULL_ITEMS_TOTAL).increment(page.items.len() as u64);
    metrics::counter!(SYNC_PULL_BYTES_TOTAL).increment(bytes as u64);
    Ok(Json(page))
}

async fn push_changes(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Path(vault_id): Path<Uuid>,
    Json(req): Json<PushRequest>,
) -> Result<Json<PushResponse>, ApiError> {
    push::validate_batch(&req)?;
    let sync = state.sync();
    let outcome = sync
        .store()
        .push(
            ctx,
            vault_id,
            &req.changes,
            sync.limits(),
            state.auth().now(),
        )
        .await?;
    if let Some(head) = outcome.new_head {
        sync.notify(vault_id, head);
        let (accepted, bytes) = req
            .changes
            .iter()
            .zip(&outcome.results)
            .filter(|(_, r)| r.revision.is_some())
            .fold((0u64, 0u64), |(n, b), (c, _)| {
                (n + 1, b + c.envelope.len() as u64)
            });
        metrics::counter!(SYNC_PUSH_ITEMS_TOTAL).increment(accepted);
        metrics::counter!(SYNC_PUSH_BYTES_TOTAL).increment(bytes);
        tracing::debug!(%vault_id, head, accepted, "push committed");
    }
    Ok(Json(PushResponse {
        results: outcome.results,
    }))
}
