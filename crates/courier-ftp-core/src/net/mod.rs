//! The network layer: sockets, IPv6, timeouts and generic proxies (T07).
//!
//! [`connect_tcp`] is the one function every protocol uses to open a TCP connection:
//!
//! - DNS on every connection (never cached; IP literals skip it), IPv6 filtering and
//!   RFC 8305 address interleaving ([`interleave`]), Happy Eyeballs with a
//!   [`STAGGER`] of 250 ms between attempts ([`happy_eyeballs`]);
//! - [`NetOpts::timeout`] bounds the DNS lookup, the TCP race and the proxy handshake
//!   (each separately); a [`CancellationToken`] or dropping the future cancels it
//!   (no detached tasks);
//! - socket options: `TCP_NODELAY` for control connections, TCP keep-alive (60 s idle,
//!   10 s interval) and optional buffer sizes;
//! - HTTP/1.1 CONNECT (with Basic auth and one password prompt on 407), SOCKS4/4a and
//!   SOCKS5 (RFC 1928/1929), all hand-written so the reply parsers are fuzzable.
//!
//! The message log gets FileZilla-style Status lines ("Resolving address of …",
//! "Connecting to …", "Connection established"). Proxy passwords never reach a log:
//! the request bytes are never logged, and `Debug` of [`ProxyConfig`] /
//! [`ProxyCredentials`] is redacted. `tracing` events at info level carry only the
//! session id, the proxy kind and [`Error::code`](crate::Error::code); host names
//! and IPs are logged at debug level only (T91 §4).

mod dial;
mod happy;
mod http_connect;
mod http_get;
mod proxy;
mod socks;
mod stream;

#[cfg(test)]
mod tests;

use std::{fmt, time::Duration};

pub use dial::connect_tcp;
pub use happy::{DialFailure, STAGGER, happy_eyeballs, interleave};
pub use http_connect::{
    ConnectResponse, HttpConnectError, MAX_HEADER_BYTES, fuzz_http_connect_response,
    parse_connect_response,
};
pub use http_get::http_get_small;
pub use proxy::{ProxyConfig, ProxyCredentials};
pub use socks::{
    SocketAddrOrDomain, Socks5Reply, SocksError, fuzz_socks_reply, parse_socks4_reply,
    parse_socks5_auth_reply, parse_socks5_connect_reply, parse_socks5_method_reply,
};
pub use stream::NetStream;
pub use tokio_util::sync::CancellationToken;

use crate::settings::Settings;

/// Target of a connection. `host` is a hostname or IP literal WITHOUT brackets.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostPort {
    /// Host name or IP literal (no brackets).
    pub host: String,
    /// TCP port.
    pub port: u16,
}

impl fmt::Display for HostPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.authority())
    }
}

impl HostPort {
    /// `host` and `port`; surrounding brackets of an IPv6 literal are removed.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        let host: String = host.into();
        let host = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            Some(inner) => inner.to_owned(),
            None => host,
        };
        Self { host, port }
    }

    /// `"host:port"` / `"[v6]:port"`.
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Parse `"host:port"` / `"[v6]:port"`. `None` without a valid, non-zero port or
    /// with an empty host.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let (host, port) = if let Some(rest) = s.strip_prefix('[') {
            let (host, rest) = rest.split_once(']')?;
            (host, rest.strip_prefix(':')?)
        } else {
            let (host, port) = s.rsplit_once(':')?;
            if host.contains(':') {
                return None;
            }
            (host, port)
        };
        let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
        (!host.is_empty()).then(|| Self::new(host, port))
    }
}

/// What a connection is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// Control connection (FTP control, SSH): `TCP_NODELAY` is set.
    Control,
    /// Bulk data (FTP data connections).
    Data,
}

/// Options for one dial.
#[derive(Debug)]
pub struct NetOpts {
    /// Bounds DNS, the TCP race and the proxy handshake (each separately).
    pub timeout: Duration,
    /// Try IPv6 addresses first.
    pub prefer_ipv6: bool,
    /// Use IPv6 addresses at all.
    pub allow_ipv6: bool,
    /// `Control` → `TCP_NODELAY`.
    pub purpose: Purpose,
    /// `SO_RCVBUF`/`SO_SNDBUF` request (T41b: 4 MiB for FTP data). `None` = OS default.
    pub socket_buffer: Option<usize>,
    /// How to reach the target.
    pub proxy: ProxyConfig,
}

impl NetOpts {
    /// A snapshot of `connection.timeout_secs`, `connection.prefer_ipv6` and
    /// `connection.ipv6`; later setting changes affect only new connections.
    pub fn from_settings(s: &Settings, purpose: Purpose, proxy: ProxyConfig) -> Self {
        Self {
            timeout: Duration::from_secs(u64::from(s.connection.timeout_secs.max(1))),
            prefer_ipv6: s.connection.prefer_ipv6,
            allow_ipv6: s.connection.ipv6,
            purpose,
            socket_buffer: None,
            proxy,
        }
    }
}

/// Our end of the connection, for FTP active mode `PORT`/`EPRT` (T11).
pub fn local_addr_for(stream: &NetStream) -> std::net::SocketAddr {
    stream.local_addr()
}
