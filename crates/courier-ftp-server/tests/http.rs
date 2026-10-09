//! The HTTP layer: error envelopes, request ids, protocol version, body limit,
//! CORS and client IP resolution.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::SocketAddr;
use std::num::NonZeroU32;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use axum::response::IntoResponse;
use common::{Harness, code, config, generous, json, message};
use courier_ftp_proto::ErrorCode;
use courier_ftp_proto::limits::BODY_LIMIT_BYTES;
use courier_ftp_proto::version::{PROTO_HEADER, REQUEST_ID_HEADER};
use courier_ftp_server::ApiError;
use courier_ftp_server::middleware::rate_limit::{AuthLimits, RateLimiters};
use http_body_util::BodyExt;
use serde_json::{Value, json};

fn get(uri: &str) -> axum::http::request::Builder {
    Request::builder().method(Method::GET).uri(uri)
}

async fn render(e: ApiError) -> Value {
    let resp = e.into_response();
    let status = resp.status().as_u16();
    let retry = resp
        .headers()
        .get(header::RETRY_AFTER)
        .map(|v| v.to_str().unwrap().to_owned());
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    json!({ "status": status, "retry_after": retry, "body": json(&body) })
}

#[tokio::test]
async fn t03_error_envelope_for_every_code() {
    let cases: Vec<(ErrorCode, ApiError)> = vec![
        (
            ErrorCode::Conflict,
            ApiError::Conflict("email already registered".into()),
        ),
        (
            ErrorCode::Forbidden,
            ApiError::Forbidden("registration is closed".into()),
        ),
        (
            ErrorCode::NotFound,
            ApiError::NotFound("device not found".into()),
        ),
        (
            ErrorCode::RateLimited,
            ApiError::RateLimited { retry_after_s: 12 },
        ),
        (
            ErrorCode::Invalid,
            ApiError::Invalid("x25519_pub must be 32 bytes".into()),
        ),
        (
            ErrorCode::Gone,
            ApiError::Gone("cursor below gc floor".into()),
        ),
        (
            ErrorCode::Rotating,
            ApiError::Rotating("vault key rotation in progress".into()),
        ),
        (
            ErrorCode::AuthRequired,
            ApiError::AuthRequired("invalid or expired token".into()),
        ),
        (
            ErrorCode::Internal,
            ApiError::internal_msg("secret detail that must not leak"),
        ),
    ];
    let mut all = serde_json::Map::new();
    for (code, err) in cases {
        let key = serde_json::to_value(code).unwrap();
        let rendered = render(err).await;
        assert_eq!(rendered["body"]["error"]["code"], key);
        all.insert(key.as_str().unwrap().to_owned(), rendered);
    }
    let unavailable = render(ApiError::Unavailable).await;
    assert_eq!(unavailable["status"], 503);
    all.insert("unavailable".into(), unavailable);
    assert!(
        !Value::Object(all.clone())
            .to_string()
            .contains("secret detail")
    );
    insta::assert_json_snapshot!("error_envelopes", all);
}

#[tokio::test]
async fn bare_router_errors_become_envelopes() {
    let h = Harness::mem();
    let (s, _, v) = h.call(Method::GET, "/v1/nope", None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(code(&v), "not_found");
    let (s, _, v) = h
        .call(Method::GET, "/v1/auth/login/start", None, None)
        .await;
    assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(code(&v), "invalid");
    // Wrong content type and malformed JSON.
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/auth/login/start")
        .body(Body::from("{}"))
        .unwrap();
    let (s, _, b) = h.send(req).await;
    assert_eq!(s, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(code(&json(&b)), "invalid");
    let (s, v) = h
        .post("/v1/auth/login/start", None, json!({ "email": 5 }))
        .await;
    assert!(s.is_client_error());
    assert_eq!(code(&v), "invalid");
    let (s, v) = h
        .post(
            "/v1/auth/login/start",
            None,
            json!({ "email": "no-at-sign", "credential_request": "" }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
}

#[tokio::test]
async fn t04_request_id_echo_generate_replace() {
    let h = Harness::mem();
    // A valid incoming id is kept.
    let req = get("/v1/devices")
        .header(REQUEST_ID_HEADER, "client-id-123")
        .body(Body::empty())
        .unwrap();
    let (_, headers, _) = h.send(req).await;
    assert_eq!(headers[REQUEST_ID_HEADER], "client-id-123");
    // None: a fresh UUIDv7.
    let (_, headers, _) = h
        .send(get("/v1/devices").body(Body::empty()).unwrap())
        .await;
    let id: uuid::Uuid = headers[REQUEST_ID_HEADER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(id.get_version_num(), 7);
    // Invalid (characters, length): replaced.
    let long = "a".repeat(129);
    for bad in ["has space", "semi;colon", long.as_str()] {
        let req = get("/v1/devices")
            .header(REQUEST_ID_HEADER, bad)
            .body(Body::empty())
            .unwrap();
        let (_, headers, _) = h.send(req).await;
        let echoed = headers[REQUEST_ID_HEADER].to_str().unwrap();
        assert_ne!(echoed, bad);
        assert!(echoed.parse::<uuid::Uuid>().is_ok());
    }
}

#[tokio::test]
async fn t05_protocol_version_negotiation() {
    let h = Harness::mem();
    for (sent, ok) in [
        (None, true),
        (Some("1"), true),
        (Some("0"), true),
        (Some("2"), false),
        (Some("abc"), false),
        (Some(""), false),
        (Some("123456"), false),
    ] {
        let mut b = get("/v1/devices");
        if let Some(v) = sent {
            b = b.header(PROTO_HEADER, v);
        }
        let (s, headers, body) = h.send(b.body(Body::empty()).unwrap()).await;
        assert_eq!(headers[PROTO_HEADER], "1", "{sent:?}");
        if ok {
            // Reaches the route: 401 without a token.
            assert_eq!(s, StatusCode::UNAUTHORIZED, "{sent:?}");
        } else {
            assert_eq!(s, StatusCode::BAD_REQUEST, "{sent:?}");
            assert_eq!(code(&json(&body)), "invalid");
        }
    }
}

#[tokio::test]
async fn t14_body_limit_maps_to_invalid() {
    let h = Harness::mem();
    let big = vec![b' '; BODY_LIMIT_BYTES + 1];
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/auth/login/start")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, big.len())
        .body(Body::from(big))
        .unwrap();
    let (s, _, b) = h.send(req).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    let v = json(&b);
    assert_eq!(code(&v), "invalid");
    assert_eq!(message(&v), "request body too large (limit 12 MiB)");
    // Without a content length (streamed) the limit applies too.
    let chunks =
        futures::stream::iter((0..13).map(|_| Ok::<_, std::io::Error>(bytes_chunk(1024 * 1024))));
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/auth/login/start")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from_stream(chunks))
        .unwrap();
    let (s, _, b) = h.send(req).await;
    assert_eq!(
        s,
        StatusCode::PAYLOAD_TOO_LARGE,
        "{}",
        String::from_utf8_lossy(&b)
    );
    assert_eq!(code(&json(&b)), "invalid");
}

fn bytes_chunk(n: usize) -> axum::body::Bytes {
    axum::body::Bytes::from(vec![b' '; n])
}

fn preflight(origin: &str) -> Request<Body> {
    Request::builder()
        .method(Method::OPTIONS)
        .uri("/v1/auth/login/start")
        .header(header::ORIGIN, origin)
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn cors_denies_by_default() {
    let h = Harness::mem();
    let (_, headers, _) = h.send(preflight("https://evil.example")).await;
    assert!(headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    let req = get("/v1/devices")
        .header(header::ORIGIN, "https://evil.example")
        .body(Body::empty())
        .unwrap();
    let (_, headers, _) = h.send(req).await;
    assert!(headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());

    // Configured origins are allowed (T86 documents the variable).
    let h = Harness::mem_config(
        config(&[("COURIER_CORS_ORIGINS", "https://app.example")]),
        generous(),
    );
    let (_, headers, _) = h.send(preflight("https://app.example")).await;
    assert_eq!(
        headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&HeaderValue::from_static("https://app.example"))
    );
    let (_, headers, _) = h.send(preflight("https://evil.example")).await;
    assert!(headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
}

fn from_peer(peer: &str, forwarded: Option<&str>, email: &str) -> Request<Body> {
    let peer: SocketAddr = peer.parse().unwrap();
    let mut b = Request::builder()
        .method(Method::POST)
        .uri("/v1/account/recovery/code")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(f) = forwarded {
        b = b.header("x-forwarded-for", f);
    }
    b.extensions_mut().unwrap().insert(ConnectInfo(peer));
    b.body(Body::from(json!({ "email": email }).to_string()))
        .unwrap()
}

#[tokio::test]
async fn client_ip_trusted_proxies_and_rate_limit() {
    let limits = RateLimiters::new(AuthLimits {
        per_email_per_minute: NonZeroU32::new(1000).unwrap(),
        per_ip_per_minute: NonZeroU32::new(2).unwrap(),
    });
    let h = Harness::mem_config(
        config(&[("COURIER_TRUSTED_PROXIES", "10.0.0.0/8, 192.0.2.1")]),
        limits,
    );
    let status = |req| async { h.send(req).await.0 };
    // Behind the trusted proxy: keyed by the forwarded client.
    for i in 0..2 {
        let r = from_peer(
            "10.1.1.1:4000",
            Some("203.0.113.5"),
            &format!("a{i}@x.test"),
        );
        assert_eq!(status(r).await, StatusCode::ACCEPTED);
    }
    let r = from_peer("10.1.1.1:4000", Some("203.0.113.5"), "a9@x.test");
    assert_eq!(status(r).await, StatusCode::TOO_MANY_REQUESTS);
    // A chain of trusted proxies is walked right to left.
    let r = from_peer(
        "10.1.1.1:4000",
        Some("203.0.113.6, 192.0.2.1, 10.2.2.2"),
        "b@x.test",
    );
    assert_eq!(status(r).await, StatusCode::ACCEPTED);
    // Spoofed left-most entries do not help: the first untrusted hop counts.
    let r = from_peer("10.1.1.1:4000", Some("1.2.3.4, 203.0.113.5"), "c@x.test");
    assert_eq!(status(r).await, StatusCode::TOO_MANY_REQUESTS);
    // An untrusted peer is keyed by its own address whatever it forwards.
    for (i, fwd) in ["198.18.0.1", "198.18.0.2"].iter().enumerate() {
        let r = from_peer("198.51.100.7:5000", Some(fwd), &format!("d{i}@x.test"));
        assert_eq!(status(r).await, StatusCode::ACCEPTED);
    }
    let r = from_peer("198.51.100.7:5000", Some("198.18.0.3"), "d9@x.test");
    assert_eq!(status(r).await, StatusCode::TOO_MANY_REQUESTS);
}
