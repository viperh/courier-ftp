//! [`Toxiproxy`]: network faults between the client and a container
//! (`ghcr.io/shopify/toxiproxy:2.9.0`, pulled, not built), controlled over its HTTP API
//! on port 8474 (`POST /proxies`, `POST /proxies/<name>/toxics`).

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    E2eError, Ftpd, Result, TestNetwork,
    docker::{Fixture, FixtureSpec},
    ftpd::PASV_PORTS,
};

/// The toxiproxy image.
pub const TOXIPROXY_IMAGE: (&str, &str) = ("ghcr.io/shopify/toxiproxy", "2.9.0");
/// The API port.
pub const API_PORT: u16 = 8474;

/// A fault to inject (always on the downstream direction, toxicity 1.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Toxic {
    /// Delay every chunk.
    Latency {
        /// Milliseconds.
        ms: u32,
        /// Jitter in milliseconds.
        jitter_ms: u32,
    },
    /// Limit the rate.
    Bandwidth {
        /// KB/s.
        kbytes_per_s: u32,
    },
    /// Close the connection after this many bytes downstream (resume tests).
    LimitData {
        /// Bytes.
        bytes: u64,
    },
    /// Reset the connection after a delay.
    ResetPeer {
        /// Milliseconds.
        after_ms: u32,
    },
}

impl Toxic {
    fn json(self, name: &str) -> serde_json::Value {
        let (kind, attributes) = match self {
            Self::Latency { ms, jitter_ms } => (
                "latency",
                serde_json::json!({ "latency": ms, "jitter": jitter_ms }),
            ),
            Self::Bandwidth { kbytes_per_s } => {
                ("bandwidth", serde_json::json!({ "rate": kbytes_per_s }))
            }
            Self::LimitData { bytes } => ("limit_data", serde_json::json!({ "bytes": bytes })),
            Self::ResetPeer { after_ms } => {
                ("reset_peer", serde_json::json!({ "timeout": after_ms }))
            }
        };
        serde_json::json!({
            "name": name,
            "type": kind,
            "stream": "downstream",
            "toxicity": 1.0,
            "attributes": attributes,
        })
    }
}

/// One HTTP/1.1 request to the API (`Connection: close`); returns status and body.
async fn http(
    api: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
) -> Result<(u16, String)> {
    let body = body.map(ToString::to_string).unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {api}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let io = async {
        let mut s = tokio::net::TcpStream::connect(api).await?;
        s.write_all(req.as_bytes()).await?;
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await?;
        std::io::Result::Ok(resp)
    };
    let resp = tokio::time::timeout(Duration::from_secs(5), io)
        .await
        .map_err(|_| E2eError::new(format!("toxiproxy {method} {path}: timed out")))?
        .map_err(|e| E2eError::new(format!("toxiproxy {method} {path}: {e}")))?;
    let text = String::from_utf8_lossy(&resp).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| E2eError::new(format!("toxiproxy {method} {path}: bad response")))?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    Ok((status, body))
}

async fn expect_ok(
    api: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
) -> Result<String> {
    let (status, text) = http(api, method, path, body).await?;
    if (200..300).contains(&status) {
        Ok(text)
    } else {
        Err(E2eError::new(format!(
            "toxiproxy {method} {path}: HTTP {status}: {text}"
        )))
    }
}

/// A toxiproxy container on a [`TestNetwork`].
#[derive(Debug)]
pub struct Toxiproxy {
    fixture: Fixture,
}

impl Toxiproxy {
    /// Start toxiproxy on `network` and wait for its API.
    ///
    /// # Errors
    /// Docker failed or the API did not answer.
    pub async fn start(network: &TestNetwork) -> Result<Self> {
        let fixture = Fixture::start(FixtureSpec {
            image: (TOXIPROXY_IMAGE.0.into(), TOXIPROXY_IMAGE.1.into()),
            label: "toxiproxy".into(),
            env: Vec::new(),
            network: Some(network.name().to_owned()),
            cap_add: Vec::new(),
        })
        .await?;
        let api = SocketAddr::new(fixture.ip(), API_PORT);
        crate::poll_until(
            "the toxiproxy API",
            crate::timeout(),
            Duration::from_millis(100),
            || async move {
                matches!(http(api, "GET", "/version", None).await, Ok((200, _))).then_some(())
            },
        )
        .await?;
        Ok(Self { fixture })
    }

    /// The container IP (the address clients connect to).
    pub fn ip(&self) -> IpAddr {
        self.fixture.ip()
    }

    fn api(&self) -> SocketAddr {
        SocketAddr::new(self.fixture.ip(), API_PORT)
    }

    /// Proxy `listen_port` on the toxiproxy container to `upstream`.
    ///
    /// # Errors
    /// The API refused.
    pub async fn proxy(
        &self,
        name: &str,
        listen_port: u16,
        upstream: SocketAddr,
    ) -> Result<ToxicProxy> {
        let body = serde_json::json!({
            "name": name,
            "listen": format!("0.0.0.0:{listen_port}"),
            "upstream": upstream.to_string(),
            "enabled": true,
        });
        expect_ok(self.api(), "POST", "/proxies", Some(&body)).await?;
        Ok(ToxicProxy {
            api: self.api(),
            name: name.to_owned(),
            addr: SocketAddr::new(self.ip(), listen_port),
        })
    }

    /// Front an [`Ftpd`]: its control port and the passive ports 30000–30019 on the
    /// same port numbers. The `Ftpd` must announce `pasv_address = self.ip()`.
    ///
    /// # Errors
    /// The API refused.
    pub async fn front_ftpd(&self, ftpd: &Ftpd) -> Result<Vec<ToxicProxy>> {
        let mut out = Vec::new();
        let control = ftpd.addr().port();
        out.push(
            self.proxy("ftp-control", control, SocketAddr::new(ftpd.ip(), control))
                .await?,
        );
        for port in PASV_PORTS {
            out.push(
                self.proxy(
                    &format!("ftp-data-{port}"),
                    port,
                    SocketAddr::new(ftpd.ip(), port),
                )
                .await?,
            );
        }
        Ok(out)
    }
}

/// One proxied port.
#[derive(Debug, Clone)]
pub struct ToxicProxy {
    api: SocketAddr,
    name: String,
    addr: SocketAddr,
}

impl ToxicProxy {
    /// Where clients connect.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The proxy name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Add `toxic` as `name`.
    ///
    /// # Errors
    /// The API refused.
    pub async fn add(&self, name: &str, toxic: Toxic) -> Result<()> {
        let path = format!("/proxies/{}/toxics", self.name);
        expect_ok(self.api, "POST", &path, Some(&toxic.json(name))).await?;
        Ok(())
    }

    /// Remove toxic `name`.
    ///
    /// # Errors
    /// The API refused.
    pub async fn remove(&self, name: &str) -> Result<()> {
        let path = format!("/proxies/{}/toxics/{name}", self.name);
        expect_ok(self.api, "DELETE", &path, None).await?;
        Ok(())
    }

    async fn set_enabled(&self, enabled: bool) -> Result<()> {
        let path = format!("/proxies/{}", self.name);
        let body = serde_json::json!({ "enabled": enabled });
        expect_ok(self.api, "POST", &path, Some(&body)).await?;
        Ok(())
    }

    /// Close every connection and refuse new ones.
    ///
    /// # Errors
    /// The API refused.
    pub async fn disable(&self) -> Result<()> {
        self.set_enabled(false).await
    }

    /// Accept connections again.
    ///
    /// # Errors
    /// The API refused.
    pub async fn enable(&self) -> Result<()> {
        self.set_enabled(true).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toxic_json_matches_the_api() {
        let j = Toxic::LimitData { bytes: 1000 }.json("cut");
        assert_eq!(j["type"], "limit_data");
        assert_eq!(j["attributes"]["bytes"], 1000);
        assert_eq!(j["stream"], "downstream");
        let j = Toxic::Latency {
            ms: 50,
            jitter_ms: 5,
        }
        .json("slow");
        assert_eq!(j["attributes"]["latency"], 50);
        assert_eq!(j["attributes"]["jitter"], 5);
        assert_eq!(
            Toxic::Bandwidth { kbytes_per_s: 64 }.json("b")["type"],
            "bandwidth"
        );
        assert_eq!(
            Toxic::ResetPeer { after_ms: 10 }.json("r")["type"],
            "reset_peer"
        );
    }
}
