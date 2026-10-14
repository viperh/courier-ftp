//! SOCKS4/4a and SOCKS5 `CONNECT`, hand-written (both are a few dozen bytes).
//!
//! Host names are always sent to the proxy (SOCKS4a, SOCKS5 address type
//! `0x03`), so the target is resolved by the proxy and never looked up
//! locally. IP literals are sent as addresses. Replies are read exactly (their
//! length is known from the header), so nothing the server sends through the
//! tunnel afterwards is consumed.

use std::net::IpAddr;

use secrecy::ExposeSecret;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{HostPort, ProxyAuth};
use crate::{Error, Result};

/// The SOCKS4/4a `CONNECT` request for `target`.
pub(super) fn request_v4(target: &HostPort, auth: Option<&ProxyAuth>) -> Result<Vec<u8>> {
    let user = auth.map_or("", |a| a.user.as_str());
    if user.contains('\0') {
        return Err(Error::InvalidInput(
            "SOCKS4 user id must not contain NUL".into(),
        ));
    }
    let mut req = vec![4, 1];
    req.extend_from_slice(&target.port.to_be_bytes());
    match target.ip() {
        Some(IpAddr::V4(ip)) => {
            req.extend_from_slice(&ip.octets());
            req.extend_from_slice(user.as_bytes());
            req.push(0);
        }
        Some(IpAddr::V6(_)) => {
            return Err(Error::Unsupported(
                "IPv6 targets through a SOCKS4 proxy (use SOCKS5)",
            ));
        }
        None => {
            if target.host.is_empty() || target.host.contains('\0') {
                return Err(Error::InvalidInput(format!(
                    "invalid host name {:?}",
                    target.host
                )));
            }
            // SOCKS4a: 0.0.0.x with x != 0 means "host name follows".
            req.extend_from_slice(&[0, 0, 0, 1]);
            req.extend_from_slice(user.as_bytes());
            req.push(0);
            req.extend_from_slice(target.host.as_bytes());
            req.push(0);
        }
    }
    Ok(req)
}

/// Check the 8-byte SOCKS4 reply.
pub(super) fn check_reply_v4(reply: &[u8; 8]) -> Result<()> {
    // VN is 0 per the spec; some proxies echo 4.
    if reply[0] != 0 && reply[0] != 4 {
        return Err(Error::Connection(format!(
            "invalid SOCKS4 reply (version {})",
            reply[0]
        )));
    }
    match reply[1] {
        90 => Ok(()),
        91 => Err(Error::Connection(
            "SOCKS4 proxy rejected or failed the request".into(),
        )),
        92 => Err(Error::Connection(
            "SOCKS4 proxy could not reach our identd".into(),
        )),
        93 => Err(Error::Auth("SOCKS4 proxy rejected the user id".into())),
        other => Err(Error::Connection(format!(
            "invalid SOCKS4 reply (code {other})"
        ))),
    }
}

/// SOCKS4 (IPv4 literal) or SOCKS4a (host name) `CONNECT` over `stream`.
pub(super) async fn connect_v4<S>(
    stream: &mut S,
    target: &HostPort,
    auth: Option<&ProxyAuth>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = request_v4(target, auth)?;
    stream.write_all(&req).await.map_err(proxy_io)?;
    stream.flush().await.map_err(proxy_io)?;
    let mut reply = [0u8; 8];
    stream.read_exact(&mut reply).await.map_err(proxy_io)?;
    check_reply_v4(&reply)
}

const NO_AUTH: u8 = 0x00;
const USER_PASS: u8 = 0x02;
const NO_ACCEPTABLE: u8 = 0xff;

/// The SOCKS5 method selection message.
pub(super) fn greeting_v5(auth: Option<&ProxyAuth>) -> Vec<u8> {
    if auth.is_some() {
        vec![5, 2, NO_AUTH, USER_PASS]
    } else {
        vec![5, 1, NO_AUTH]
    }
}

/// The RFC 1929 user/password message.
pub(super) fn auth_request_v5(auth: &ProxyAuth) -> Result<Vec<u8>> {
    let user = auth.user.as_bytes();
    let password = auth
        .password
        .as_ref()
        .map_or(&b""[..], |p| p.expose_secret().as_bytes());
    let (Ok(ulen), Ok(plen)) = (u8::try_from(user.len()), u8::try_from(password.len())) else {
        return Err(Error::InvalidInput(
            "SOCKS5 user name and password are limited to 255 bytes".into(),
        ));
    };
    if ulen == 0 {
        return Err(Error::InvalidInput("SOCKS5 user name is empty".into()));
    }
    let mut msg = Vec::with_capacity(3 + user.len() + password.len());
    msg.push(1);
    msg.push(ulen);
    msg.extend_from_slice(user);
    msg.push(plen);
    msg.extend_from_slice(password);
    Ok(msg)
}

/// The SOCKS5 `CONNECT` request for `target`.
pub(super) fn request_v5(target: &HostPort) -> Result<Vec<u8>> {
    let mut req = vec![5, 1, 0];
    match target.ip() {
        Some(IpAddr::V4(ip)) => {
            req.push(1);
            req.extend_from_slice(&ip.octets());
        }
        Some(IpAddr::V6(ip)) => {
            req.push(4);
            req.extend_from_slice(&ip.octets());
        }
        None => {
            let name = target.host.as_bytes();
            let len = u8::try_from(name.len())
                .ok()
                .filter(|&l| l > 0)
                .ok_or_else(|| {
                    Error::InvalidInput(format!(
                        "host name {:?} must be 1 to 255 bytes for SOCKS5",
                        target.host
                    ))
                })?;
            req.push(3);
            req.push(len);
            req.extend_from_slice(name);
        }
    }
    req.extend_from_slice(&target.port.to_be_bytes());
    Ok(req)
}

/// The message for a SOCKS5 reply code.
pub(super) fn reply_error_v5(code: u8) -> Error {
    let what = match code {
        1 => "general SOCKS server failure",
        2 => "connection not allowed by ruleset",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused by the destination",
        6 => "TTL expired",
        7 => "command not supported",
        8 => "address type not supported",
        _ => "unknown error",
    };
    Error::Connection(format!("SOCKS5 proxy: {what} (code {code})"))
}

/// SOCKS5 `CONNECT` over `stream`, with RFC 1929 authentication when `auth`
/// is set and the proxy asks for it.
pub(super) async fn connect_v5<S>(
    stream: &mut S,
    target: &HostPort,
    auth: Option<&ProxyAuth>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Validate everything before sending anything.
    let request = request_v5(target)?;
    let auth_msg = auth.map(auth_request_v5).transpose()?;

    stream
        .write_all(&greeting_v5(auth))
        .await
        .map_err(proxy_io)?;
    stream.flush().await.map_err(proxy_io)?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await.map_err(proxy_io)?;
    if choice[0] != 5 {
        return Err(Error::Connection(format!(
            "invalid SOCKS5 reply (version {})",
            choice[0]
        )));
    }
    match (choice[1], auth_msg) {
        (NO_AUTH, _) => {}
        (USER_PASS, Some(msg)) => {
            stream.write_all(&msg).await.map_err(proxy_io)?;
            stream.flush().await.map_err(proxy_io)?;
            let mut status = [0u8; 2];
            stream.read_exact(&mut status).await.map_err(proxy_io)?;
            if status[1] != 0 {
                return Err(Error::Auth("SOCKS5 proxy rejected the login".into()));
            }
        }
        (NO_ACCEPTABLE, None) => {
            return Err(Error::Auth("SOCKS5 proxy requires a login".into()));
        }
        (NO_ACCEPTABLE, Some(_)) => {
            return Err(Error::Auth(
                "SOCKS5 proxy accepts none of our authentication methods".into(),
            ));
        }
        (other, _) => {
            return Err(Error::Connection(format!(
                "SOCKS5 proxy chose an authentication method we did not offer ({other})"
            )));
        }
    }

    stream.write_all(&request).await.map_err(proxy_io)?;
    stream.flush().await.map_err(proxy_io)?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(proxy_io)?;
    if head[0] != 5 {
        return Err(Error::Connection(format!(
            "invalid SOCKS5 reply (version {})",
            head[0]
        )));
    }
    if head[1] != 0 {
        return Err(reply_error_v5(head[1]));
    }
    // Skip BND.ADDR and BND.PORT so the stream starts at the tunnel's data.
    let addr_len = match head[3] {
        1 => 4,
        4 => 16,
        3 => usize::from(stream.read_u8().await.map_err(proxy_io)?),
        other => {
            return Err(Error::Connection(format!(
                "invalid SOCKS5 reply (address type {other})"
            )));
        }
    };
    let mut bound = vec![0u8; addr_len + 2];
    stream.read_exact(&mut bound).await.map_err(proxy_io)?;
    Ok(())
}

fn proxy_io(err: std::io::Error) -> Error {
    if err.kind() == std::io::ErrorKind::UnexpectedEof {
        Error::Connection("SOCKS proxy closed the connection during the handshake".into())
    } else {
        Error::Connection(format!("SOCKS proxy: {err}"))
    }
}
