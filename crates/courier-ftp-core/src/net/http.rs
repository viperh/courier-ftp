//! HTTP/1.1 `CONNECT` tunnel.
//!
//! Sends `CONNECT host:port HTTP/1.1`, `Host:` and, with a login,
//! `Proxy-Authorization: Basic …`. The reply is read one byte at a time up to
//! the blank line, so nothing the server sends through the tunnel afterwards
//! is consumed. Any `2xx` opens the tunnel (RFC 9110 §9.3.6); `407` is an
//! authentication failure; anything else fails with the (sanitized) status
//! line.

use secrecy::ExposeSecret;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{HostPort, ProxyAuth};
use crate::{Error, Result};

/// The most reply-header bytes accepted.
pub(super) const MAX_HEADER_BYTES: usize = 16 * 1024;

/// The request for `target`.
pub(super) fn request(target: &HostPort, auth: Option<&ProxyAuth>) -> String {
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(auth) = auth {
        let password = auth.password.as_ref().map_or("", |p| p.expose_secret());
        let token = base64(format!("{}:{password}", auth.user).as_bytes());
        req.push_str("Proxy-Authorization: Basic ");
        req.push_str(&token);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    req
}

/// Open the tunnel over `stream` (already connected to the proxy).
pub(super) async fn connect<S>(
    stream: &mut S,
    target: &HostPort,
    auth: Option<&ProxyAuth>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(request(target, auth).as_bytes())
        .await
        .map_err(proxy_io)?;
    stream.flush().await.map_err(proxy_io)?;
    let head = read_head(stream).await?;
    check_status(&head, auth.is_some())
}

/// The reply headers including the final `\r\n\r\n` (a bare `\n\n` is
/// accepted too).
pub(super) async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut head = Vec::with_capacity(256);
    loop {
        let byte = match stream.read_u8().await {
            Ok(b) => b,
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(Error::Connection(
                    "proxy closed the connection during CONNECT".into(),
                ));
            }
            Err(err) => return Err(proxy_io(err)),
        };
        head.push(byte);
        if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
            return Ok(head);
        }
        if head.len() > MAX_HEADER_BYTES {
            return Err(Error::Connection(format!(
                "proxy reply headers exceed {} KiB",
                MAX_HEADER_BYTES / 1024
            )));
        }
    }
}

/// Check the status line of `head`.
pub(super) fn check_status(head: &[u8], sent_auth: bool) -> Result<()> {
    let end = head.iter().position(|&b| b == b'\n').unwrap_or(head.len());
    let line = sanitize(&String::from_utf8_lossy(&head[..end]));
    let mut parts = line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    let code = parts.next().and_then(|c| c.parse::<u16>().ok());
    let code = match code {
        Some(code) if version.starts_with("HTTP/1.") && (100..1000).contains(&code) => code,
        _ => {
            return Err(Error::Connection(format!(
                "invalid reply from HTTP proxy: {line:?}"
            )));
        }
    };
    match code {
        200..=299 => Ok(()),
        407 if sent_auth => Err(Error::Auth(format!(
            "HTTP proxy rejected the login ({line})"
        ))),
        407 => Err(Error::Auth(format!("HTTP proxy requires a login ({line})"))),
        _ => Err(Error::Connection(format!(
            "HTTP proxy refused CONNECT: {line}"
        ))),
    }
}

/// Printable ASCII only, at most 120 characters, trimmed.
fn sanitize(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(120)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn proxy_io(err: std::io::Error) -> Error {
    Error::Connection(format!("HTTP proxy: {err}"))
}

/// Standard base64 with padding (RFC 4648 §4), for the Basic credentials.
pub(super) fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let sextet = |shift: u32| char::from(ALPHABET[((n >> shift) & 0x3f) as usize]);
        out.push(sextet(18));
        out.push(sextet(12));
        out.push(if chunk.len() > 1 { sextet(6) } else { '=' });
        out.push(if chunk.len() > 2 { sextet(0) } else { '=' });
    }
    out
}
