//! `Courier-Proto` negotiation.
//!
//! The server supports the current protocol version `N` and `N-1`
//! ([`courier_ftp_proto::version::negotiate`]). A missing header means
//! "current". A malformed or unsupported version is rejected with
//! `400 invalid`. Every response carries `Courier-Proto: N`.

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use courier_ftp_proto::version::{self, PROTO_HEADER, PROTO_VERSION};

use crate::error::ApiError;

/// The protocol version the client speaks (stored as a request extension).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientProto(pub u32);

/// Parses the header value (`None` = header absent).
///
/// # Errors
/// [`ApiError::Invalid`] for malformed, too old or too new versions.
pub fn negotiate(header: Option<&HeaderValue>) -> Result<ClientProto, ApiError> {
    let raw = match header {
        None => None,
        Some(v) => Some(
            v.to_str()
                .map_err(|_| ApiError::Invalid("malformed Courier-Proto header".into()))?,
        ),
    };
    version::negotiate(raw)
        .map(ClientProto)
        .map_err(|e| ApiError::Invalid(e.to_string()))
}

/// Rejects unsupported versions and stamps `Courier-Proto` on the response.
pub async fn layer(mut req: Request, next: Next) -> Response {
    let mut resp = match negotiate(req.headers().get(PROTO_HEADER)) {
        Ok(proto) => {
            req.extensions_mut().insert(proto);
            next.run(req).await
        }
        Err(err) => err.into_response(),
    };
    resp.headers_mut()
        .insert(PROTO_HEADER, HeaderValue::from(PROTO_VERSION));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(negotiate(None).ok(), Some(ClientProto(PROTO_VERSION)));
        let v = HeaderValue::from(PROTO_VERSION);
        assert_eq!(negotiate(Some(&v)).ok(), Some(ClientProto(PROTO_VERSION)));
        let too_new = HeaderValue::from(PROTO_VERSION + 1);
        assert!(matches!(
            negotiate(Some(&too_new)),
            Err(ApiError::Invalid(_))
        ));
        let junk = HeaderValue::from_static("v1");
        assert!(matches!(negotiate(Some(&junk)), Err(ApiError::Invalid(_))));
    }
}
