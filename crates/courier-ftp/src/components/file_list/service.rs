//! Listing for the panes: local directories through [`LocalBackend`], remote ones
//! through the tab's session and the [`ListingCache`] (T46). The app runs these on
//! its runner and answers the pane with `PaneInput::ListingLoaded`.

use std::{collections::HashMap, future::Future, sync::Arc, time::Duration};

use courier_ftp_core::{
    Error,
    backend::{Backend, BackendContext, Listing, SessionHandle},
    cache::{ListMode, ListingCache, ListingSource},
    local::{LocalBackend, path_map::to_native},
    model::{LocalPath, RemotePath, ServerIdentity},
};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::state::{PaneDir, PaneId, RequestId};
use crate::runtime::TaskId;

/// The session a remote pane lists through (set by T58/T61 when a tab connects).
#[derive(Clone)]
pub(crate) struct RemoteSource {
    /// The server (cache key).
    pub server: ServerIdentity,
    /// The session.
    pub session: Arc<SessionHandle>,
}

impl std::fmt::Debug for RemoteSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteSource").finish_non_exhaustive()
    }
}

/// What the app keeps for the panes: the cache, the local backend context, the
/// remote sessions and the listing tasks in flight.
#[derive(Debug)]
pub(crate) struct PaneService {
    /// The shared listing cache.
    pub cache: ListingCache,
    /// Context for local backends.
    pub local_ctx: BackendContext,
    /// Remote sessions by pane.
    pub remote: HashMap<PaneId, RemoteSource>,
    /// Listing tasks in flight.
    pub inflight: HashMap<(PaneId, RequestId), TaskId>,
}

impl PaneService {
    /// A service with `cache` and `local_ctx`.
    pub(crate) fn new(cache: ListingCache, local_ctx: BackendContext) -> Self {
        Self {
            cache,
            local_ctx,
            remote: HashMap::new(),
            inflight: HashMap::new(),
        }
    }
}

async fn with_timeout<T>(
    timeout: Duration,
    fut: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    if timeout.is_zero() {
        return fut.await;
    }
    tokio::time::timeout(timeout, fut)
        .await
        .unwrap_or(Err(Error::Timeout))
}

/// Lists a local directory. The returned directory is the normalised path of the
/// listing.
pub(crate) async fn list_local(
    ctx: BackendContext,
    dir: LocalPath,
    timeout: Duration,
    token: CancellationToken,
) -> Result<(PaneDir, Arc<Listing>), Error> {
    let path = PaneDir::Local(dir).backend_path()?;
    let mut backend = LocalBackend::new(ctx);
    let started = tokio::time::Instant::now();
    let listing = with_timeout(timeout, backend.list(&path, token.clone())).await?;
    if token.is_cancelled() {
        return Err(Error::Cancelled);
    }
    debug!(
        entries = listing.entries.len(),
        took_ms = started.elapsed().as_millis(),
        "local listing"
    );
    let dir = PaneDir::Local(to_native(&listing.dir)?);
    Ok((dir, Arc::new(listing)))
}

/// Lists `dir` through the cache: `PreferCache` unless `force` (`Refresh`). A stale
/// cached listing is returned at once and revalidated in the background (the cache
/// announces the new listing with `ListingUpdated`).
pub(crate) async fn list_through_cache<F, Fut>(
    cache: &ListingCache,
    server: &ServerIdentity,
    dir: &RemotePath,
    force: bool,
    fetch: F,
) -> Result<(Arc<Listing>, ListingSource), Error>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Listing, Error>>,
{
    let mode = if force {
        ListMode::Refresh
    } else {
        ListMode::PreferCache
    };
    let got = cache.get_or_fetch(server, dir, mode, fetch).await?;
    Ok((got.listing, got.source))
}

/// Lists a remote directory through the session and the cache.
pub(crate) async fn list_remote(
    cache: ListingCache,
    source: RemoteSource,
    dir: RemotePath,
    force: bool,
    timeout: Duration,
    token: CancellationToken,
) -> Result<(PaneDir, Arc<Listing>), Error> {
    let session = Arc::clone(&source.session);
    let fetch_token = token.clone();
    let fetch_dir = dir.clone();
    let (listing, src) = with_timeout(
        timeout,
        list_through_cache(&cache, &source.server, &dir, force, move || async move {
            session.list(&fetch_dir, &fetch_token).await
        }),
    )
    .await?;
    if src == ListingSource::CacheStale {
        // Revalidate in the background; the pane re-reads on `ListingUpdated`.
        let (cache, server, session, dir) = (
            cache.clone(),
            source.server.clone(),
            source.session,
            dir.clone(),
        );
        tokio::spawn(async move {
            let token = CancellationToken::new();
            let _ = cache
                .get_or_fetch(&server, &dir, ListMode::Refresh, || async {
                    session.list(&dir, &token).await
                })
                .await;
        });
    }
    debug!(entries = listing.entries.len(), "remote listing");
    Ok((PaneDir::Remote(listing.dir.clone()), listing))
}
