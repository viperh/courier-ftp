//! The HTTP client of the sync API: reqwest over rustls (`ring` provider, OS
//! trust store through `rustls-platform-verifier`, D9), `Courier-Proto: 1` on
//! every request, a 30 s timeout, and the base URL from
//! `sync_state.server_url`. There is no default server URL: the user always
//! enters their own.
//!
//! Plain `http://` is accepted for loopback servers only (development and
//! tests); everything else must be `https://`.
//!
//! Adapted from sverb's `sverb-sync/src/http.rs` (D13).

use std::sync::Arc;
use std::time::Duration;

use courier_ftp_proto::ErrorEnvelope;
use courier_ftp_proto::auth::{DeviceSummary, RefreshRequest, TokenPair};
use courier_ftp_proto::sync::{PullResponse, PushRequest, PushResponse, VaultView};
use courier_ftp_proto::version::{API_PREFIX, PROTO_HEADER, PROTO_VERSION};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue, RETRY_AFTER};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::error::SyncError;

/// Request timeout.
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// The sync API client. Cheap to clone.
#[derive(Debug, Clone)]
pub struct ApiClient {
    base: String,
    http: reqwest::Client,
    tls: Arc<rustls::ClientConfig>,
}

/// Whether `url` is `http://` to a loopback host (allowed without TLS).
pub(crate) fn is_loopback_http(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    let host = if let Some(v6) = host.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        host.rsplit_once(':').map_or(host, |(h, _)| h)
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Normalizes and checks a server URL: trimmed, no trailing slash,
/// `https://` (or loopback `http://`).
///
/// # Errors
/// [`SyncError::NotConfigured`].
pub fn normalize_server_url(url: &str) -> Result<String, SyncError> {
    let base = url.trim().trim_end_matches('/').to_owned();
    if base.is_empty() {
        return Err(SyncError::NotConfigured("no server URL"));
    }
    if !base.starts_with("https://") && !is_loopback_http(&base) {
        return Err(SyncError::NotConfigured(
            "the server URL must start with https:// (http:// only for localhost)",
        ));
    }
    Ok(base)
}

/// The default TLS client config: the `ring` provider and the OS trust store.
///
/// # Errors
/// [`SyncError::Transport`] when the OS trust store can't be used.
pub fn default_tls() -> Result<Arc<rustls::ClientConfig>, SyncError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls_platform_verifier::Verifier::new(Arc::clone(&provider))
        .map_err(|e| SyncError::Transport(format!("OS certificate store: {e}")))?;
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| SyncError::Transport(format!("TLS setup: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn retry_after(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse().ok())
}

impl ApiClient {
    /// A client for the server at `base_url` (`https://sync.example.com`).
    /// `tls` defaults to [`default_tls`]; the WebSocket client uses the same
    /// config ([`ApiClient::tls`]).
    ///
    /// # Errors
    /// [`SyncError::NotConfigured`] for an empty or non-https URL,
    /// [`SyncError::Transport`] if the client can't be built.
    pub fn new(
        base_url: &str,
        tls: Option<Arc<rustls::ClientConfig>>,
        timeout: Duration,
    ) -> Result<Self, SyncError> {
        let base = normalize_server_url(base_url)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            PROTO_HEADER,
            HeaderValue::from_str(&PROTO_VERSION.to_string())
                .map_err(|e| SyncError::Transport(e.to_string()))?,
        );
        let tls = match tls {
            Some(t) => t,
            None => default_tls()?,
        };
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout.min(Duration::from_secs(10)))
            .default_headers(headers)
            .use_preconfigured_tls((*tls).clone())
            .build()
            .map_err(|e| SyncError::Transport(e.to_string()))?;
        Ok(Self { base, http, tls })
    }

    /// The base URL (no trailing slash).
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// The TLS config (shared with the WebSocket client).
    #[must_use]
    pub fn tls(&self) -> Arc<rustls::ClientConfig> {
        Arc::clone(&self.tls)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{API_PREFIX}{path}", self.base)
    }

    async fn send<T: DeserializeOwned>(&self, rb: reqwest::RequestBuilder) -> Result<T, SyncError> {
        let (status, _, bytes) = self.fetch(rb).await?;
        serde_json::from_slice(&bytes).map_err(|e| SyncError::Api {
            status,
            code: None,
            message: format!("unexpected response body: {e}"),
            retry_after_s: None,
        })
    }

    /// Sends `rb`; a 2xx gives `(status, headers, body)`, anything else the
    /// error envelope as [`SyncError::Api`].
    async fn fetch(
        &self,
        rb: reqwest::RequestBuilder,
    ) -> Result<(u16, HeaderMap, Vec<u8>), SyncError> {
        let resp = rb
            .send()
            .await
            .map_err(|e| SyncError::Transport(transport_message(&e)))?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| SyncError::Transport(transport_message(&e)))?;
        if status.is_success() {
            return Ok((status.as_u16(), headers, bytes.to_vec()));
        }
        let (code, message, retry) = match serde_json::from_slice::<ErrorEnvelope>(&bytes) {
            Ok(env) => (
                Some(env.error.code),
                env.error.message,
                env.error.retry_after_s,
            ),
            Err(_) => (
                None,
                status.canonical_reason().unwrap_or("error").to_owned(),
                None,
            ),
        };
        Err(SyncError::Api {
            status: status.as_u16(),
            code,
            message,
            retry_after_s: retry.or_else(|| retry_after(&headers)),
        })
    }

    fn authed(rb: reqwest::RequestBuilder, token: &SecretString) -> reqwest::RequestBuilder {
        let mut value = HeaderValue::from_str(&format!("Bearer {}", token.expose_secret()))
            .unwrap_or_else(|_| HeaderValue::from_static("Bearer -"));
        value.set_sensitive(true);
        rb.header(AUTHORIZATION, value)
    }

    /// `POST /v1{path}` with a JSON body and a JSON response.
    pub(crate) async fn post_v1<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        token: Option<&SecretString>,
    ) -> Result<T, SyncError> {
        let mut rb = self.http.post(self.url(path)).json(body);
        if let Some(t) = token {
            rb = Self::authed(rb, t);
        }
        self.send(rb).await
    }

    /// `POST /v1{path}` whose success response has no body (204 / 202).
    pub(crate) async fn post_v1_empty<B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: Option<&B>,
        token: Option<&SecretString>,
    ) -> Result<(), SyncError> {
        let mut rb = self.http.post(self.url(path));
        if let Some(b) = body {
            rb = rb.json(b);
        }
        if let Some(t) = token {
            rb = Self::authed(rb, t);
        }
        self.fetch(rb).await.map(drop)
    }

    /// `DELETE /v1{path}` with an optional JSON body; no response body.
    pub(crate) async fn delete_v1<B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: Option<&B>,
        token: &SecretString,
    ) -> Result<(), SyncError> {
        let mut rb = Self::authed(self.http.delete(self.url(path)), token);
        if let Some(b) = body {
            rb = rb.json(b);
        }
        self.fetch(rb).await.map(drop)
    }

    /// `GET /healthz` (outside `/v1`): whether the server is up, and the
    /// protocol version it echoes in `Courier-Proto` (`None` when absent).
    ///
    /// # Errors
    /// [`SyncError::Transport`] / [`SyncError::Api`].
    pub async fn probe(&self) -> Result<Option<u32>, SyncError> {
        let rb = self.http.get(format!("{}/healthz", self.base));
        let (_, headers, _) = self.fetch(rb).await?;
        Ok(headers
            .get(PROTO_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse().ok()))
    }

    /// `GET /v1/vaults`.
    ///
    /// # Errors
    /// [`SyncError::Api`] / [`SyncError::Transport`].
    pub async fn list_vaults(&self, token: &SecretString) -> Result<Vec<VaultView>, SyncError> {
        let rb = Self::authed(self.http.get(self.url("/vaults")), token);
        self.send(rb).await
    }

    /// `GET /v1/devices` (the caller's unrevoked devices).
    ///
    /// # Errors
    /// [`SyncError::Api`] / [`SyncError::Transport`].
    pub async fn list_devices(
        &self,
        token: &SecretString,
    ) -> Result<Vec<DeviceSummary>, SyncError> {
        let rb = Self::authed(self.http.get(self.url("/devices")), token);
        self.send(rb).await
    }

    /// `DELETE /v1/devices/{id}`: revokes the device and its tokens.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`404 not_found`) / [`SyncError::Transport`].
    pub async fn revoke_device(&self, token: &SecretString, device: Uuid) -> Result<(), SyncError> {
        self.delete_v1::<()>(&format!("/devices/{device}"), None, token)
            .await
    }

    /// `GET /v1/vaults/{id}/changes?since=&limit=`.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`410 gone` below the server's GC floor, `404`) /
    /// [`SyncError::Transport`].
    pub async fn pull(
        &self,
        token: &SecretString,
        vault: Uuid,
        since: u64,
        limit: u32,
    ) -> Result<PullResponse, SyncError> {
        let url = self.url(&format!(
            "/vaults/{vault}/changes?since={since}&limit={limit}"
        ));
        let rb = Self::authed(self.http.get(url), token);
        self.send(rb).await
    }

    /// `POST /v1/vaults/{id}/changes`.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`403 forbidden` read-only, `409 rotating`,
    /// `400 invalid`) / [`SyncError::Transport`].
    pub async fn push(
        &self,
        token: &SecretString,
        vault: Uuid,
        req: &PushRequest,
    ) -> Result<PushResponse, SyncError> {
        self.post_v1(&format!("/vaults/{vault}/changes"), req, Some(token))
            .await
    }

    /// `POST /v1/auth/refresh`: rotates the token pair (refresh tokens are
    /// single-use; presenting a used one revokes the whole family).
    ///
    /// # Errors
    /// [`SyncError::Api`] (`401 auth_required` for an invalid or reused
    /// refresh token) / [`SyncError::Transport`].
    pub async fn refresh(&self, refresh_token: &SecretString) -> Result<TokenPair, SyncError> {
        let req = RefreshRequest {
            refresh_token: refresh_token.expose_secret().to_owned(),
        };
        self.post_v1("/auth/refresh", &req, None).await
    }
}

/// reqwest's error with its source chain (the top-level message alone is
/// often just "error sending request"). URLs carry no secrets (tokens are in
/// headers and bodies only).
fn transport_message(e: &reqwest::Error) -> String {
    use std::error::Error as _;
    let mut msg = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        src = s.source();
    }
    msg
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn https_required_except_loopback() {
        assert!(normalize_server_url("https://sync.example.com/").is_ok());
        assert!(normalize_server_url("http://127.0.0.1:8080").is_ok());
        assert!(normalize_server_url("http://localhost:1/x").is_ok());
        assert!(normalize_server_url("http://[::1]:9").is_ok());
        assert!(normalize_server_url("http://user@127.0.0.1:9").is_ok());
        for bad in [
            "http://sync.example.com",
            "http://127.0.0.1.example.com",
            "ftp://127.0.0.1",
            "",
            "   ",
        ] {
            assert!(
                matches!(normalize_server_url(bad), Err(SyncError::NotConfigured(_))),
                "{bad}"
            );
        }
        assert_eq!(
            normalize_server_url(" https://a.example/ ").unwrap(),
            "https://a.example"
        );
    }

    #[test]
    fn client_urls() {
        let c = ApiClient::new("https://a.example/", None, HTTP_TIMEOUT).unwrap();
        assert_eq!(c.url("/vaults"), "https://a.example/v1/vaults");
        assert_eq!(c.base_url(), "https://a.example");
    }
}
