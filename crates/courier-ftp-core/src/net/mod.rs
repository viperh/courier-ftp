//! Network layer: sockets, IPv6, timeouts and generic proxies (T07).
//!
//! Every protocol opens its TCP connections through [`connect_tcp`]: the FTP
//! control and data connections (T10, T11) and the SSH transport (T20). It
//!
//! - resolves the host with the system resolver and orders the addresses by
//!   [`NetOpts::prefer_ipv6`], interleaving the two families;
//! - tries them with a simple Happy Eyeballs (RFC 8305): the next address is
//!   started when the previous attempt fails, or after
//!   [`NetOpts::attempt_delay`] (250 ms) if it hasn't connected yet; the first
//!   connection wins and the others are dropped;
//! - bounds DNS, every attempt and every proxy handshake by
//!   [`NetOpts::timeout`], and aborts all of it as soon as the cancellation
//!   token fires;
//! - goes through the generic proxy ([`Proxy`]: HTTP/1.1 `CONNECT`, SOCKS4/4a,
//!   SOCKS5) when one is configured, sending the target *name* so DNS happens
//!   at the proxy;
//! - logs FileZilla-style `Status` lines (`Resolving address of …`,
//!   `Connecting to …`, `Connection established`). Proxy credentials are never
//!   logged, not even the user name.
//!
//! The returned stream is a plain [`TcpStream`]: proxy handshakes read their
//! replies exactly, so no byte the server sends after the tunnel opens (an SSH
//! banner, an FTP greeting) is swallowed.

mod dial;
mod fuzz;
mod http;
mod socks;

#[cfg(test)]
mod tests;

use std::{fmt, net::SocketAddr, time::Duration};

#[doc(hidden)]
pub use fuzz::fuzz_proxy_reply;

use secrecy::SecretString;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::{
    Error, Result,
    events::{EventSender, LogKind, SessionId},
    model::ServerAddress,
    settings::{GenericProxy, ProxyServer, Settings},
};

/// The default delay between two connection attempts (RFC 8305 recommends
/// 250 ms).
pub const DEFAULT_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// A host name or IP address and a port.
///
/// IPv6 literals are stored without brackets, as in [`ServerAddress`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostPort {
    /// Host name or IP address (no brackets).
    pub host: String,
    /// TCP port.
    pub port: u16,
}

impl HostPort {
    /// `host` (brackets around an IPv6 literal are removed) and `port`.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        let host = host.into();
        let host = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            Some(inner) => inner.to_owned(),
            None => host,
        };
        Self { host, port }
    }

    /// The host as an IP address, when it is a literal.
    pub fn ip(&self) -> Option<std::net::IpAddr> {
        self.host.parse().ok()
    }
}

impl fmt::Display for HostPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

impl From<&ServerAddress> for HostPort {
    fn from(address: &ServerAddress) -> Self {
        Self::new(address.host.clone(), address.port)
    }
}

impl From<SocketAddr> for HostPort {
    fn from(addr: SocketAddr) -> Self {
        Self::new(addr.ip().to_string(), addr.port())
    }
}

/// The kind of a generic proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyKind {
    /// HTTP/1.1 `CONNECT`, optional Basic authentication.
    Http,
    /// SOCKS 4, or 4a when the target is a host name. The user name is sent as
    /// the SOCKS4 user id; SOCKS4 has no password.
    Socks4,
    /// SOCKS 5, without authentication or with user name and password
    /// (RFC 1929).
    Socks5,
}

impl fmt::Display for ProxyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ProxyKind::Http => "HTTP",
            ProxyKind::Socks4 => "SOCKS4",
            ProxyKind::Socks5 => "SOCKS5",
        })
    }
}

/// A proxy login. `Debug` never shows the password.
#[derive(Clone)]
pub struct ProxyAuth {
    /// The user name.
    pub user: String,
    /// The password, when one is stored (in the vault, T30).
    pub password: Option<SecretString>,
}

impl fmt::Debug for ProxyAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyAuth")
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "****"))
            .finish()
    }
}

/// A generic proxy with its resolved credentials.
#[derive(Debug, Clone)]
pub struct Proxy {
    /// HTTP, SOCKS4 or SOCKS5.
    pub kind: ProxyKind,
    /// The proxy's address.
    pub server: HostPort,
    /// The login, if the proxy needs one.
    pub auth: Option<ProxyAuth>,
}

impl Proxy {
    /// The proxy from the settings, without a password (the settings only hold
    /// a vault reference: set [`ProxyAuth::password`] once it is unlocked, or
    /// use [`NetOpts::set_proxy_password`]). `None` for [`GenericProxy::None`].
    pub fn from_settings(generic: &GenericProxy) -> Option<Self> {
        let (kind, server) = match generic {
            GenericProxy::None => return None,
            GenericProxy::Http(s) => (ProxyKind::Http, s),
            GenericProxy::Socks4(s) => (ProxyKind::Socks4, s),
            GenericProxy::Socks5(s) => (ProxyKind::Socks5, s),
        };
        let ProxyServer {
            host, port, user, ..
        } = server;
        Some(Self {
            kind,
            server: HostPort::new(host.clone(), *port),
            auth: user
                .as_ref()
                .filter(|u| !u.is_empty())
                .map(|user| ProxyAuth {
                    user: user.clone(),
                    password: None,
                }),
        })
    }
}

/// How [`connect_tcp`] connects. Build it with [`NetOpts::from_settings`] and
/// adjust it for the site and the connection.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NetOpts {
    /// Bound on the DNS lookup, on each connection attempt and on the proxy
    /// handshake (setting `connection.timeout_secs`).
    pub timeout: Duration,
    /// Try IPv6 addresses before IPv4 (setting `connection.prefer_ipv6`).
    pub prefer_ipv6: bool,
    /// Delay before the next address is tried while an attempt is still
    /// pending (Happy Eyeballs).
    pub attempt_delay: Duration,
    /// Set `TCP_NODELAY` (control connections: yes; data connections: no).
    pub nodelay: bool,
    /// Enable TCP keep-alive probes after this much idleness (from
    /// `connection.keepalive` and `connection.keepalive_interval_secs`).
    pub tcp_keepalive: Option<Duration>,
    /// The generic proxy, or `None` to connect directly.
    pub proxy: Option<Proxy>,
}

impl Default for NetOpts {
    fn default() -> Self {
        Self::from_settings(&Settings::default())
    }
}

impl NetOpts {
    /// Options from the settings: timeout, IPv6 preference, keep-alive and the
    /// generic proxy (without its password). `TCP_NODELAY` is on, as control
    /// connections want it.
    pub fn from_settings(settings: &Settings) -> Self {
        let c = &settings.connection;
        Self {
            timeout: Duration::from_secs(c.timeout_secs.max(1)),
            prefer_ipv6: c.prefer_ipv6,
            attempt_delay: DEFAULT_ATTEMPT_DELAY,
            nodelay: true,
            tcp_keepalive: c
                .keepalive
                .then(|| Duration::from_secs(c.keepalive_interval_secs.max(1))),
            proxy: Proxy::from_settings(&settings.proxy.generic),
        }
    }

    /// Connect directly even when a generic proxy is configured (the site's
    /// "bypass proxy" option, T31).
    #[must_use]
    pub fn bypass_proxy(mut self, bypass: bool) -> Self {
        if bypass {
            self.proxy = None;
        }
        self
    }

    /// Options for an FTP data connection: same as these, without
    /// `TCP_NODELAY` (bulk transfer).
    #[must_use]
    pub fn for_data(mut self) -> Self {
        self.nodelay = false;
        self
    }

    /// Set the proxy password (from the vault). Does nothing without a proxy
    /// or without a proxy user.
    pub fn set_proxy_password(&mut self, password: SecretString) {
        if let Some(auth) = self.proxy.as_mut().and_then(|p| p.auth.as_mut()) {
            auth.password = Some(password);
        }
    }
}

/// Open a TCP connection to `target`, directly or through the generic proxy.
///
/// Logs progress as `Status` lines of `session` and every failed attempt as an
/// `Error` line.
///
/// # Errors
///
/// - [`Error::Cancelled`] when `cancel` fires;
/// - [`Error::Timeout`] when DNS, every attempt or the proxy handshake ran out
///   of time;
/// - [`Error::Connection`] when the host can't be resolved, every address
///   refused, or the proxy refused the tunnel;
/// - [`Error::Auth`] when the proxy rejected the credentials;
/// - [`Error::Unsupported`] / [`Error::InvalidInput`] for targets the proxy
///   protocol can't express (an IPv6 target through SOCKS4, a name longer
///   than 255 bytes through SOCKS5).
pub async fn connect_tcp(
    target: &HostPort,
    opts: &NetOpts,
    cancel: &CancellationToken,
    log: &EventSender,
    session: SessionId,
) -> Result<TcpStream> {
    let stream = match &opts.proxy {
        None => dial::dial(target, opts, cancel, log, session).await?,
        Some(proxy) => {
            log.log(
                session,
                LogKind::Status,
                format!(
                    "Connecting to {target} through {} proxy {}",
                    proxy.kind, proxy.server
                ),
            );
            // Fail before dialing when the proxy protocol can't express the
            // target or the login.
            let valid = match proxy.kind {
                ProxyKind::Http => Ok(()),
                ProxyKind::Socks4 => socks::request_v4(target, proxy.auth.as_ref()).map(drop),
                ProxyKind::Socks5 => socks::request_v5(target).and_then(|_| {
                    proxy
                        .auth
                        .as_ref()
                        .map_or(Ok(()), |a| socks::auth_request_v5(a).map(drop))
                }),
            };
            if let Err(err) = valid {
                log.log(session, LogKind::Error, err.to_string());
                return Err(err);
            }
            let mut stream = dial::dial(&proxy.server, opts, cancel, log, session).await?;
            let handshake = async {
                match proxy.kind {
                    ProxyKind::Http => {
                        http::connect(&mut stream, target, proxy.auth.as_ref()).await
                    }
                    ProxyKind::Socks4 => {
                        socks::connect_v4(&mut stream, target, proxy.auth.as_ref()).await
                    }
                    ProxyKind::Socks5 => {
                        socks::connect_v5(&mut stream, target, proxy.auth.as_ref()).await
                    }
                }
            };
            let result = tokio::select! {
                biased;
                () = cancel.cancelled() => Err(Error::Cancelled),
                r = tokio::time::timeout(opts.timeout, handshake) => {
                    r.unwrap_or(Err(Error::Timeout))
                }
            };
            if let Err(err) = result {
                log.log(
                    session,
                    LogKind::Error,
                    format!("{} proxy {}: {err}", proxy.kind, proxy.server),
                );
                return Err(err);
            }
            log.log(
                session,
                LogKind::Status,
                format!("{} proxy opened a tunnel to {target}", proxy.kind),
            );
            stream
        }
    };
    log.log(session, LogKind::Status, "Connection established");
    Ok(stream)
}

/// The local address of a connected stream, to announce in an active-mode
/// `PORT`/`EPRT` (T11).
///
/// # Errors
///
/// [`Error::Io`] when the socket has no local address (closed).
pub fn local_addr_for(stream: &TcpStream) -> Result<SocketAddr> {
    Ok(stream.local_addr()?)
}

/// Fail with [`Error::Unsupported`] (and log why) when active-mode FTP is asked
/// for while a generic proxy is in use: the server would have to connect back
/// to us, which neither HTTP `CONNECT` nor SOCKS `CONNECT` can carry.
///
/// # Errors
///
/// [`Error::Unsupported`] when `opts` has a proxy.
pub fn ensure_active_mode_allowed(
    opts: &NetOpts,
    log: &EventSender,
    session: SessionId,
) -> Result<()> {
    match &opts.proxy {
        None => Ok(()),
        Some(proxy) => {
            log.log(
                session,
                LogKind::Error,
                format!(
                    "Active mode FTP does not work through a {} proxy; use passive mode",
                    proxy.kind
                ),
            );
            Err(Error::Unsupported(
                "active mode FTP through a generic proxy",
            ))
        }
    }
}
