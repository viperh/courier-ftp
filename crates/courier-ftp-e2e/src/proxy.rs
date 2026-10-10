//! [`ProxyServer`]: HTTP CONNECT (squid) and SOCKS 4/5 (dante) proxies in Docker
//! (`tests/fixtures/proxy/`). Credentials for the `*-auth` profiles are
//! [`PROXY_USER`](crate::keys::PROXY_USER) / [`PROXY_PASSWORD`](crate::keys::PROXY_PASSWORD).

use std::{net::SocketAddr, time::Duration};

use crate::{
    Result, TestNetwork,
    docker::{self, Fixture, FixtureSpec},
};

/// A proxy configuration of the proxy image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyProfile {
    /// squid on 3128, no auth.
    Http,
    /// squid on 3128, basic auth.
    HttpAuth,
    /// dante SOCKS4 on 1080.
    Socks4,
    /// dante SOCKS5 on 1080, no auth.
    Socks5,
    /// dante SOCKS5 on 1080, username/password.
    Socks5Auth,
}

impl ProxyProfile {
    /// Every profile.
    pub const ALL: [Self; 5] = [
        Self::Http,
        Self::HttpAuth,
        Self::Socks4,
        Self::Socks5,
        Self::Socks5Auth,
    ];

    /// The profile name (`PROXY_PROFILE=<name>`).
    pub fn name(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::HttpAuth => "http-auth",
            Self::Socks4 => "socks4",
            Self::Socks5 => "socks5",
            Self::Socks5Auth => "socks5-auth",
        }
    }

    /// The listening port.
    pub fn port(self) -> u16 {
        match self {
            Self::Http | Self::HttpAuth => 3128,
            Self::Socks4 | Self::Socks5 | Self::Socks5Auth => 1080,
        }
    }
}

/// A proxy in a container on a [`TestNetwork`] (with the servers behind it).
#[derive(Debug)]
pub struct ProxyServer {
    fixture: Fixture,
    profile: ProxyProfile,
}

impl ProxyServer {
    /// Start `profile` on `network` and wait until it accepts connections.
    ///
    /// # Errors
    /// Docker or the image build failed, or the proxy did not come up.
    pub async fn start(profile: ProxyProfile, network: &TestNetwork) -> Result<Self> {
        let fixture = Fixture::start(FixtureSpec {
            image: docker::image("proxy").await?,
            label: format!("proxy {}", profile.name()),
            env: vec![("PROXY_PROFILE".into(), profile.name().into())],
            network: Some(network.name().to_owned()),
            cap_add: Vec::new(),
        })
        .await?;
        let proxy = Self { fixture, profile };
        let addr = proxy.addr();
        crate::poll_until(
            &format!("proxy {} to accept on {addr}", profile.name()),
            crate::timeout(),
            Duration::from_millis(100),
            || async move {
                let up = tokio::time::timeout(
                    Duration::from_secs(2),
                    tokio::net::TcpStream::connect(addr),
                )
                .await;
                matches!(up, Ok(Ok(_))).then_some(())
            },
        )
        .await
        .inspect_err(|_| proxy.fixture.dump_logs())?;
        Ok(proxy)
    }

    /// The profile.
    pub fn profile(&self) -> ProxyProfile {
        self.profile
    }

    /// Container IP and proxy port.
    pub fn addr(&self) -> SocketAddr {
        SocketAddr::new(self.fixture.ip(), self.profile.port())
    }

    /// The container IP as text.
    pub fn host(&self) -> String {
        self.fixture.ip().to_string()
    }

    /// The container's complete log.
    ///
    /// # Errors
    /// Docker failed.
    pub async fn logs(&self) -> Result<String> {
        self.fixture.logs().await
    }
}
