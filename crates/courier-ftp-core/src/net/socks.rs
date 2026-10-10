//! Hand-written SOCKS4/4a and SOCKS5 (RFC 1928, RFC 1929 user/password) clients.
//!
//! The reply parsers are pure functions (`Ok(None)` = need more bytes) so they are
//! fuzzed (`socks_reply`) and property-tested; the handshakes read into one buffer and
//! keep any bytes after the final reply (replayed by the stream).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use super::{HostPort, ProxyCredentials};
use crate::{Error, Result};

/// A SOCKS reply that cannot be parsed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SocksError {
    /// The version byte is not the expected one.
    #[error("invalid SOCKS reply (version {0})")]
    BadVersion(u8),
    /// The reply is structurally invalid.
    #[error("invalid SOCKS reply ({0})")]
    Malformed(&'static str),
    /// A SOCKS4 reply code outside 0x5A..=0x5D.
    #[error("invalid SOCKS4 reply")]
    ReplyCode(u8),
    /// SOCKS5 method `0xFF`: none of the offered methods is acceptable.
    #[error("authentication required (no acceptable method)")]
    NoAcceptableMethod,
}

impl From<SocksError> for Error {
    fn from(err: SocksError) -> Self {
        Error::Proxy(err.to_string())
    }
}

/// The bound address of a SOCKS5 reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocketAddrOrDomain {
    /// ATYP 0x01 / 0x04.
    Addr(SocketAddr),
    /// ATYP 0x03.
    Domain(String, u16),
}

/// A complete SOCKS5 CONNECT reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Socks5Reply {
    /// REP: 0 = succeeded.
    pub code: u8,
    /// BND.ADDR / BND.PORT.
    pub bound: SocketAddrOrDomain,
}

/// SOCKS5 method selection reply: `VER=5, METHOD`.
///
/// # Errors
///
/// [`SocksError::BadVersion`], [`SocksError::NoAcceptableMethod`] (method `0xFF`).
pub fn parse_socks5_method_reply(buf: &[u8]) -> Result<Option<(u8, usize)>, SocksError> {
    match buf {
        [] => Ok(None),
        [v, ..] if *v != 5 => Err(SocksError::BadVersion(*v)),
        [_] => Ok(None),
        [_, 0xFF, ..] => Err(SocksError::NoAcceptableMethod),
        [_, m, ..] => Ok(Some((*m, 2))),
    }
}

/// RFC 1929 sub-negotiation reply: `VER=1, STATUS` (0 = success). Version 5 is also
/// accepted (some proxies answer with it).
///
/// # Errors
///
/// [`SocksError::BadVersion`].
pub fn parse_socks5_auth_reply(buf: &[u8]) -> Result<Option<(bool, usize)>, SocksError> {
    match buf {
        [] => Ok(None),
        [v, ..] if *v != 1 && *v != 5 => Err(SocksError::BadVersion(*v)),
        [_] => Ok(None),
        [_, status, ..] => Ok(Some((*status == 0, 2))),
    }
}

/// SOCKS5 CONNECT reply: `VER=5, REP, RSV, ATYP, BND.ADDR, BND.PORT`.
///
/// # Errors
///
/// [`SocksError::BadVersion`]; [`SocksError::Malformed`] for an unknown address type
/// or an empty or non-UTF-8 domain.
pub fn parse_socks5_connect_reply(buf: &[u8]) -> Result<Option<(Socks5Reply, usize)>, SocksError> {
    let Some(&ver) = buf.first() else {
        return Ok(None);
    };
    if ver != 5 {
        return Err(SocksError::BadVersion(ver));
    }
    let Some(&atyp) = buf.get(3) else {
        return Ok(None);
    };
    let code = buf[1];
    let (addr_len, addr_start) = match atyp {
        0x01 => (4, 4),
        0x04 => (16, 4),
        0x03 => match buf.get(4) {
            None => return Ok(None),
            Some(0) => return Err(SocksError::Malformed("empty domain")),
            Some(&n) => (usize::from(n), 5),
        },
        _ => return Err(SocksError::Malformed("unknown address type")),
    };
    let total = addr_start + addr_len + 2;
    if buf.len() < total {
        return Ok(None);
    }
    let addr = &buf[addr_start..addr_start + addr_len];
    let port = u16::from_be_bytes([buf[total - 2], buf[total - 1]]);
    let bound = match atyp {
        0x01 => {
            let o: [u8; 4] = addr
                .try_into()
                .map_err(|_| SocksError::Malformed("IPv4 address"))?;
            SocketAddrOrDomain::Addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(o)), port))
        }
        0x04 => {
            let o: [u8; 16] = addr
                .try_into()
                .map_err(|_| SocksError::Malformed("IPv6 address"))?;
            SocketAddrOrDomain::Addr(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port))
        }
        _ => {
            let name = std::str::from_utf8(addr)
                .map_err(|_| SocksError::Malformed("domain is not UTF-8"))?;
            SocketAddrOrDomain::Domain(name.to_owned(), port)
        }
    };
    Ok(Some((Socks5Reply { code, bound }, total)))
}

/// SOCKS4 reply: `VN=0, CD, DSTPORT(2), DSTIP(4)`. Returns CD (0x5A..=0x5D).
///
/// # Errors
///
/// [`SocksError::BadVersion`] (VN ≠ 0), [`SocksError::ReplyCode`] (CD outside
/// 0x5A..=0x5D).
pub fn parse_socks4_reply(buf: &[u8]) -> Result<Option<(u8, usize)>, SocksError> {
    match buf {
        [] => Ok(None),
        [v, ..] if *v != 0 => Err(SocksError::BadVersion(*v)),
        [_, cd, ..] if !(0x5A..=0x5D).contains(cd) => Err(SocksError::ReplyCode(*cd)),
        [_] => Ok(None),
        b if b.len() < 8 => Ok(None),
        [_, cd, ..] => Ok(Some((*cd, 8))),
    }
}

/// The readable message of a SOCKS5 reply code (sverb `socks_message` wording).
pub(crate) fn socks5_message(code: u8) -> String {
    match code {
        1 => "general SOCKS server failure".to_owned(),
        2 => "connection not allowed by the proxy's rules".to_owned(),
        3 => "destination network unreachable".to_owned(),
        4 => "destination host unreachable".to_owned(),
        5 => "connection refused by destination".to_owned(),
        6 => "TTL expired".to_owned(),
        7 => "CONNECT not supported".to_owned(),
        8 => "address type not supported".to_owned(),
        other => format!("unknown SOCKS error ({other})"),
    }
}

/// Reads into `buf` until `parse` reports a complete reply; returns it and drains the
/// consumed bytes from `buf`.
async fn read_reply<S, T>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    parse: impl Fn(&[u8]) -> Result<Option<(T, usize)>, SocksError>,
) -> Result<T>
where
    S: AsyncRead + Unpin,
{
    let mut chunk = [0_u8; 512];
    loop {
        if let Some((reply, used)) = parse(buf)? {
            buf.drain(..used);
            return Ok(reply);
        }
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| Error::Connection(format!("proxy connection failed: {e}")))?;
        if n == 0 {
            return Err(Error::Proxy(
                "connection closed during the SOCKS handshake".to_owned(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

async fn send<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> Result<()> {
    stream
        .write_all(bytes)
        .await
        .map_err(|e| Error::Connection(format!("proxy connection failed: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| Error::Connection(format!("proxy connection failed: {e}")))
}

fn too_long(what: &str) -> Error {
    Error::InvalidInput(format!("the SOCKS {what} is longer than 255 bytes"))
}

fn len_u8(bytes: &[u8], what: &str) -> Result<u8> {
    u8::try_from(bytes.len()).map_err(|_| too_long(what))
}

/// The SOCKS5 CONNECT request for `target` (by name unless an IP literal).
pub(crate) fn socks5_connect_request(target: &HostPort) -> Result<Vec<u8>> {
    let mut req = vec![5, 1, 0];
    match target.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            req.push(0x01);
            req.extend(ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            req.push(0x04);
            req.extend(ip.octets());
        }
        Err(_) => {
            let name = target.host.as_bytes();
            if name.is_empty() {
                return Err(Error::InvalidInput("empty host name".to_owned()));
            }
            req.push(0x03);
            req.push(len_u8(name, "host name")?);
            req.extend_from_slice(name);
        }
    }
    req.extend(target.port.to_be_bytes());
    Ok(req)
}

/// SOCKS5 handshake over `stream`. Returns the bytes received after the reply.
pub(crate) async fn socks5_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    target: &HostPort,
    auth: Option<&ProxyCredentials>,
) -> Result<Vec<u8>> {
    let auth = auth.filter(|a| !a.user.is_empty());
    let connect = socks5_connect_request(target)?;
    let password = |a: &ProxyCredentials| -> Vec<u8> {
        a.password
            .as_ref()
            .map_or_else(Vec::new, |p| p.expose().as_bytes().to_vec())
    };
    let auth_request = match auth {
        None => None,
        Some(creds) => {
            let user = creds.user.as_bytes();
            let password = Zeroizing::new(password(creds));
            let mut req = Zeroizing::new(vec![1, len_u8(user, "user name")?]);
            req.extend_from_slice(user);
            req.push(len_u8(&password, "password")?);
            req.extend_from_slice(&password);
            Some(req)
        }
    };
    let greeting: &[u8] = if auth_request.is_some() {
        &[5, 2, 0x00, 0x02]
    } else {
        &[5, 1, 0x00]
    };
    let mut buf = Vec::new();
    send(stream, greeting).await?;
    let method = read_reply(stream, &mut buf, parse_socks5_method_reply).await?;
    match (method, &auth_request) {
        (0x00, _) => {}
        (0x02, Some(req)) => {
            send(stream, req).await?;
            if !read_reply(stream, &mut buf, parse_socks5_auth_reply).await? {
                return Err(Error::Proxy("authentication failed".to_owned()));
            }
        }
        (0x02, None) => {
            return Err(Error::Proxy(
                "authentication required (no acceptable method)".to_owned(),
            ));
        }
        (other, _) => {
            return Err(Error::Proxy(format!(
                "the proxy chose an authentication method that was not offered ({other})"
            )));
        }
    }
    send(stream, &connect).await?;
    let reply = read_reply(stream, &mut buf, parse_socks5_connect_reply).await?;
    if reply.code != 0 {
        return Err(Error::Proxy(socks5_message(reply.code)));
    }
    Ok(buf)
}

/// SOCKS4 (IPv4 literal) or SOCKS4a (host name) handshake. Returns the bytes received
/// after the reply.
pub(crate) async fn socks4_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    target: &HostPort,
    user: &str,
) -> Result<Vec<u8>> {
    let mut req = vec![4, 1];
    req.extend(target.port.to_be_bytes());
    let name = match target.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            req.extend(ip.octets());
            None
        }
        Ok(IpAddr::V6(_)) => {
            return Err(Error::Unsupported(
                "SOCKS4 cannot connect to IPv6 addresses".to_owned(),
            ));
        }
        Err(_) => {
            req.extend([0, 0, 0, 1]);
            Some(target.host.as_bytes())
        }
    };
    let user = user.as_bytes();
    len_u8(user, "user id")?;
    if user.contains(&0) {
        return Err(Error::InvalidInput(
            "the SOCKS user id contains NUL".to_owned(),
        ));
    }
    req.extend_from_slice(user);
    req.push(0);
    if let Some(name) = name {
        len_u8(name, "host name")?;
        req.extend_from_slice(name);
        req.push(0);
    }
    let mut buf = Vec::new();
    send(stream, &req).await?;
    let code = read_reply(stream, &mut buf, parse_socks4_reply).await?;
    if code != 0x5A {
        return Err(Error::Proxy(format!("request rejected ({code})")));
    }
    Ok(buf)
}

/// Fuzz body of the `socks_reply` target (T91 §7): runs all four SOCKS parsers on the
/// input and on every prefix of its first 64 bytes. Must never panic, and a complete
/// reply must never claim more bytes than given.
#[doc(hidden)]
pub fn fuzz_socks_reply(data: &[u8]) {
    let run = |buf: &[u8]| {
        if let Ok(Some((_, n))) = parse_socks5_method_reply(buf) {
            assert!(n <= buf.len());
        }
        if let Ok(Some((_, n))) = parse_socks5_auth_reply(buf) {
            assert!(n <= buf.len());
        }
        if let Ok(Some((_, n))) = parse_socks5_connect_reply(buf) {
            assert!(n <= buf.len());
        }
        if let Ok(Some((code, n))) = parse_socks4_reply(buf) {
            assert!(n <= buf.len() && (0x5A..=0x5D).contains(&code));
        }
    };
    run(data);
    for end in 0..data.len().min(64) {
        run(&data[..end]);
    }
}
