//! Router assembly and the middleware stack.
//!
//! Request flow, outermost first (as sverb):
//! 1. request id (keep a valid incoming `x-request-id`, else UUIDv7; echo it),
//! 2. tracing span `request{method, path, request_id}` (route template, never the
//!    query string),
//! 3. error normalisation (bare 404/405/408/413/415/422/5xx → JSON envelope),
//! 4. metrics (T86; nothing here yet),
//! 5. `Courier-Proto` negotiation,
//! 6. compression (gzip ≥ 1 KiB), CORS (deny by default),
//! 7. client IP resolution (trusted proxies),
//! 8. body limit (12 MiB), request timeout (→ 408),
//! 9. the route.

use axum::Router;
use axum::extract::{DefaultBodyLimit, MatchedPath, Request};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::{from_fn, from_fn_with_state};
use courier_ftp_proto::limits::BODY_LIMIT_BYTES;
use courier_ftp_proto::version::{API_PREFIX, PROTO_HEADER, REQUEST_ID_HEADER};
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;
use tower_http::compression::predicate::{NotForContentType, Predicate, SizeAbove};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::middleware::{client_ip, errors, proto_version, request_id};
use crate::routes;
use crate::state::AppState;

/// Request body limit (T83 `limits::BODY_LIMIT_BYTES`, 12 MiB).
pub const BODY_LIMIT: usize = BODY_LIMIT_BYTES;
/// Responses smaller than this are not compressed.
pub const COMPRESS_MIN_BYTES: u16 = 1024;

/// All routes without middleware: the API under `/v1` (T86 adds the ops
/// endpoints at the root).
pub fn routes() -> Router<AppState> {
    Router::new().nest(API_PREFIX, routes::api_v1())
}

/// The complete application.
pub fn router(state: AppState) -> Router {
    with_layers(routes(), state)
}

fn cors(state: &AppState) -> CorsLayer {
    let origins: Vec<HeaderValue> = state
        .config()
        .cors_allowed_origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    // No allowed origins: `CorsLayer::new()` adds no allow-origin header, so
    // browsers reject every cross-origin request (deny by default).
    if origins.is_empty() {
        return CorsLayer::new();
    }
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static(PROTO_HEADER),
            HeaderName::from_static(REQUEST_ID_HEADER),
        ])
        .expose_headers([
            HeaderName::from_static(PROTO_HEADER),
            HeaderName::from_static(REQUEST_ID_HEADER),
            header::RETRY_AFTER,
        ])
}

/// Applies the middleware stack and state to `router`. Tests use this to wrap
/// extra routes in exactly the production stack.
pub fn with_layers(router: Router<AppState>, state: AppState) -> Router {
    let trace = TraceLayer::new_for_http().make_span_with(|req: &Request| {
        let rid = req
            .extensions()
            .get::<request_id::RequestId>()
            .map_or("", |r| r.0.as_str());
        // The route template (`/v1/devices/{id}`), never the query string.
        let path = req
            .extensions()
            .get::<MatchedPath>()
            .map_or_else(|| req.uri().path(), MatchedPath::as_str);
        tracing::info_span!(
            "request",
            method = %req.method(),
            path = %path,
            request_id = %rid,
        )
    });
    let compression = CompressionLayer::new().compress_when(
        SizeAbove::new(COMPRESS_MIN_BYTES)
            .and(NotForContentType::GRPC)
            .and(NotForContentType::IMAGES)
            .and(NotForContentType::SSE),
    );
    let stack = ServiceBuilder::new()
        .layer(from_fn(request_id::layer))
        .layer(trace)
        .layer(from_fn(errors::layer))
        .layer(from_fn(proto_version::layer))
        .layer(compression)
        .layer(cors(&state))
        .layer(from_fn_with_state(state.clone(), client_ip::layer))
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            state.config().request_timeout,
        ))
        .layer(DefaultBodyLimit::max(BODY_LIMIT));
    router.layer(stack).with_state(state)
}
