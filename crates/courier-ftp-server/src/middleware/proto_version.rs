//! `Courier-Proto` negotiation (T83 `version::negotiate`).
//!
//! The server supports the current protocol version `N` and `N-1`; a missing
//! header means "current". A malformed or unsupported version is rejected with
//! `400 invalid`. Every response carries `Courier-Proto: N`.

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use courier_ftp_proto::version::{PROTO_HEADER, PROTO_VERSION, negotiate};

use crate::error::ApiError;

/// The protocol version the client speaks (stored as a request extension).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientProto(pub u32);

/// Rejects unsupported versions and stamps `Courier-Proto` on the response.
pub async fn layer(mut req: Request, next: Next) -> Response {
    let header = req.headers().get(PROTO_HEADER).map(HeaderValue::as_bytes);
    let mut resp = match negotiate(header) {
        Ok(v) => {
            req.extensions_mut().insert(ClientProto(v));
            next.run(req).await
        }
        Err(e) => ApiError::from(e).into_response(),
    };
    resp.headers_mut()
        .insert(PROTO_HEADER, HeaderValue::from(PROTO_VERSION));
    resp
}
