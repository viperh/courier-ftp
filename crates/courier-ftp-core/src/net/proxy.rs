//! Generic proxies: [`ProxyConfig`] from the settings, and the dial through an HTTP
//! CONNECT, SOCKS4/4a or SOCKS5 proxy.

use std::fmt;

use tokio::net::TcpStream;

use super::{
    HostPort, NetOpts, NetStream,
    dial::{dial_direct, timed_out},
    http_connect::{self, HttpConnectError},
    socks,
};
use crate::{
    Error, Result,
    events::{
        PasswordPrompt, PasswordPurpose, PromptId, PromptKind, PromptResponse, SecretCacheKey,
        SessionLog,
    },
    secret::SecretString,
    settings::{GenericProxySettings, ProxyKind},
};

/// Default HTTP proxy port.
const HTTP_DEFAULT_PORT: u16 = 8080;
/// Default SOCKS proxy port.
const SOCKS_DEFAULT_PORT: u16 = 1080;

/// User and password for a proxy. `Debug` prints the password as `[REDACTED]`.
pub struct ProxyCredentials {
    /// The proxy user.
    pub user: String,
    /// The proxy password, when one is stored.
    pub password: Option<SecretString>,
}

impl fmt::Debug for ProxyCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyCredentials")
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// How to reach the target. Built from the settings and `ConnectInfo` (T03); holds
/// secrets, so `Debug` is redacted.
pub enum ProxyConfig {
    /// No proxy.
    Direct,
    /// HTTP/1.1 CONNECT.
    Http {
        /// The proxy.
        proxy: HostPort,
        /// Basic auth.
        auth: Option<ProxyCredentials>,
    },
    /// SOCKS4a when the target is a hostname; plain SOCKS4 for IPv4 literals.
    Socks4 {
        /// The proxy.
        proxy: HostPort,
        /// The USERID field.
        user: String,
    },
    /// SOCKS5 (RFC 1928), optional RFC 1929 user/password.
    Socks5 {
        /// The proxy.
        proxy: HostPort,
        /// User/password.
        auth: Option<ProxyCredentials>,
    },
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => f.write_str("Direct"),
            Self::Http { proxy, auth } => f
                .debug_struct("Http")
                .field("proxy", proxy)
                .field("auth", auth)
                .finish(),
            Self::Socks4 { proxy, user } => f
                .debug_struct("Socks4")
                .field("proxy", proxy)
                .field("user", user)
                .finish(),
            Self::Socks5 { proxy, auth } => f
                .debug_struct("Socks5")
                .field("proxy", proxy)
                .field("auth", auth)
                .finish(),
        }
    }
}

impl ProxyConfig {
    /// `bypass` (the site's "Bypass proxy") or `settings.kind = none` → `Direct`.
    /// Port 0 → 8080 (HTTP) / 1080 (SOCKS). `password` is the resolved vault item
    /// `settings.password_ref` (`ConnectInfo.proxy_password`); credentials exist only
    /// with a non-empty user.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`]: no proxy host, or `':'` in an HTTP proxy user.
    pub fn from_settings(
        settings: &GenericProxySettings,
        bypass: bool,
        password: Option<SecretString>,
    ) -> Result<Self> {
        if bypass || settings.kind == ProxyKind::None {
            return Ok(Self::Direct);
        }
        let host = settings.host.trim();
        if host.is_empty() {
            return Err(Error::InvalidInput("the proxy host is empty".to_owned()));
        }
        let port = |default| match settings.port {
            0 => default,
            p => p,
        };
        let auth = (!settings.user.is_empty()).then(|| ProxyCredentials {
            user: settings.user.clone(),
            password,
        });
        Ok(match settings.kind {
            ProxyKind::None => Self::Direct,
            ProxyKind::Http => {
                if settings.user.contains(':') {
                    return Err(Error::InvalidInput(
                        "an HTTP proxy user name cannot contain ':'".to_owned(),
                    ));
                }
                Self::Http {
                    proxy: HostPort::new(host, port(HTTP_DEFAULT_PORT)),
                    auth,
                }
            }
            ProxyKind::Socks4 => Self::Socks4 {
                proxy: HostPort::new(host, port(SOCKS_DEFAULT_PORT)),
                user: settings.user.clone(),
            },
            ProxyKind::Socks5 => Self::Socks5 {
                proxy: HostPort::new(host, port(SOCKS_DEFAULT_PORT)),
                auth,
            },
        })
    }

    /// `"direct"`, `"http"`, `"socks4"` or `"socks5"` (logs).
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Http { .. } => "http",
            Self::Socks4 { .. } => "socks4",
            Self::Socks5 { .. } => "socks5",
        }
    }

    /// Inbound connections (FTP active mode) are impossible through any proxy: true
    /// only for `Direct`.
    pub fn allows_inbound(&self) -> bool {
        matches!(self, Self::Direct)
    }

    /// The proxy address, `None` for `Direct`.
    pub fn proxy_addr(&self) -> Option<&HostPort> {
        match self {
            Self::Direct => None,
            Self::Http { proxy, .. } | Self::Socks4 { proxy, .. } | Self::Socks5 { proxy, .. } => {
                Some(proxy)
            }
        }
    }

    fn display_kind(&self) -> &'static str {
        match self {
            Self::Direct => "no",
            Self::Http { .. } => "HTTP",
            Self::Socks4 { .. } => "SOCKS4",
            Self::Socks5 { .. } => "SOCKS5",
        }
    }
}

/// Dial `target` through the proxy of `opts` (not `Direct`).
pub(crate) async fn connect_via_proxy(
    target: &HostPort,
    opts: &NetOpts,
    log: &SessionLog,
) -> Result<NetStream> {
    let Some(proxy) = opts.proxy.proxy_addr() else {
        return Err(Error::Internal(
            "connect_via_proxy without a proxy".to_owned(),
        ));
    };
    log.status(format!(
        "Connecting to {} through {} proxy {}",
        target.authority(),
        opts.proxy.display_kind(),
        proxy.authority()
    ));
    let (tcp, early) = match &opts.proxy {
        ProxyConfig::Direct => {
            return Err(Error::Internal(
                "connect_via_proxy without a proxy".to_owned(),
            ));
        }
        ProxyConfig::Http { proxy, auth } => {
            http_connect_dial(target, proxy, auth.as_ref(), opts, log).await?
        }
        ProxyConfig::Socks4 { proxy, user } => {
            if target.host.parse::<std::net::Ipv6Addr>().is_ok() {
                return Err(Error::Unsupported(
                    "SOCKS4 cannot connect to IPv6 addresses".to_owned(),
                ));
            }
            let (mut tcp, _) = dial_direct(proxy, opts, log).await?;
            let early = bounded(opts, log, socks::socks4_handshake(&mut tcp, target, user)).await?;
            (tcp, early)
        }
        ProxyConfig::Socks5 { proxy, auth } => {
            let (mut tcp, _) = dial_direct(proxy, opts, log).await?;
            let early = bounded(
                opts,
                log,
                socks::socks5_handshake(&mut tcp, target, auth.as_ref()),
            )
            .await?;
            (tcp, early)
        }
    };
    log.status("Connection established through proxy");
    NetStream::new(tcp, early, None).map_err(Error::from)
}

/// Runs a handshake under `opts.timeout`.
async fn bounded<T>(
    opts: &NetOpts,
    log: &SessionLog,
    handshake: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout(opts.timeout, handshake)
        .await
        .unwrap_or_else(|_| Err(timed_out(opts.timeout, log)))
}

/// HTTP CONNECT, with one password prompt and a retry on a new connection when the
/// proxy answers 407, no password was sent and a user is configured.
async fn http_connect_dial(
    target: &HostPort,
    proxy: &HostPort,
    auth: Option<&ProxyCredentials>,
    opts: &NetOpts,
    log: &SessionLog,
) -> Result<(TcpStream, Vec<u8>)> {
    let mut prompted: Option<(SecretString, PromptId)> = None;
    loop {
        let password = prompted
            .as_ref()
            .map(|(p, _)| p)
            .or_else(|| auth.and_then(|a| a.password.as_ref()));
        let creds = auth.zip(password).map(|(a, p)| (a.user.as_str(), p));
        let request = http_connect::connect_request(target, creds)?;
        let (mut tcp, _) = dial_direct(proxy, opts, log).await?;
        let exchange = http_connect::exchange(&mut tcp, request.as_bytes(), creds.is_some());
        let result = match tokio::time::timeout(opts.timeout, exchange).await {
            Err(_) => Err(HttpConnectError::Timeout),
            Ok(r) => r,
        };
        drop(request);
        match result {
            Ok(early) => {
                if let Some((_, id)) = prompted {
                    log.events.credential_accepted(log.session, id);
                }
                return Ok((tcp, early));
            }
            Err(HttpConnectError::AuthRequired { sent: false })
                if prompted.is_none() && auth.is_some_and(|a| !a.user.is_empty()) =>
            {
                let user = auth.map(|a| a.user.clone()).unwrap_or_default();
                prompted = Some(ask_password(proxy, user, log).await?);
            }
            Err(HttpConnectError::Timeout) => return Err(timed_out(opts.timeout, log)),
            Err(err) => return Err(err.into()),
        }
    }
}

/// Asks for the proxy password once (T04 `Prompt(Password { purpose: Proxy })`).
async fn ask_password(
    proxy: &HostPort,
    user: String,
    log: &SessionLog,
) -> Result<(SecretString, PromptId)> {
    let kind = PromptKind::Password(PasswordPrompt {
        purpose: PasswordPurpose::Proxy,
        target: proxy.authority(),
        retry: false,
        attempt: 1,
        max_attempts: 1,
        cache_key: SecretCacheKey::Proxy {
            host: proxy.host.to_ascii_lowercase(),
            port: proxy.port,
            user,
        },
        can_save: false,
    });
    match log.events.prompt_tracked(log.session, kind, None).await? {
        (id, PromptResponse::Secret { value, .. }) => Ok((value, id)),
        _ => Err(Error::Cancelled),
    }
}
