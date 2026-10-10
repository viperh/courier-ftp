//! HTTP/1.1 CONNECT, in-house (sverb `proxy/http_connect.rs`).
//!
//! Send `CONNECT host:port HTTP/1.1`, `Host:` and optionally `Proxy-Authorization:
//! Basic …`, then read the response head up to `\r\n\r\n` (at most
//! [`MAX_HEADER_BYTES`]). 2xx is success; bytes after the head are replayed by the
//! stream. The request is never logged (it may hold the password).

use std::io;

use base64::Engine as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use super::HostPort;
use crate::{Error, Result, secret::SecretString};

/// The most response-head bytes accepted.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;

/// The parsed head of a CONNECT response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectResponse {
    /// The status code (100..=999).
    pub code: u16,
    /// The reason phrase: printable ASCII only, at most 80 characters.
    pub reason: String,
    /// Length of the head including the final `\r\n\r\n`; bytes after it belong to the
    /// tunnel.
    pub header_len: usize,
}

/// Why CONNECT failed.
#[derive(Debug, thiserror::Error)]
pub enum HttpConnectError {
    /// 407 Proxy Authentication Required.
    #[error("authentication {} (407)", if *sent { "failed" } else { "required" })]
    AuthRequired {
        /// Credentials were sent.
        sent: bool,
    },
    /// A non-2xx status.
    #[error("CONNECT refused ({code}{}{reason})", if reason.is_empty() { "" } else { " " })]
    Status {
        /// The code.
        code: u16,
        /// The sanitised reason phrase.
        reason: String,
    },
    /// The head exceeded [`MAX_HEADER_BYTES`].
    #[error("response headers too large (over {} KiB)", MAX_HEADER_BYTES / 1024)]
    HeadersTooLarge,
    /// No complete response within the timeout.
    #[error("no CONNECT response within the timeout")]
    Timeout,
    /// Not an HTTP/1.x response.
    #[error("invalid HTTP response ({0})")]
    Malformed(String),
    /// The proxy closed the connection before the head ended.
    #[error("connection closed during CONNECT")]
    Closed,
    /// I/O.
    #[error("{0}")]
    Io(io::Error),
}

impl From<HttpConnectError> for Error {
    fn from(err: HttpConnectError) -> Self {
        match err {
            HttpConnectError::AuthRequired { .. } => {
                Error::Proxy("authentication failed (407)".to_owned())
            }
            HttpConnectError::Timeout => Error::Timeout,
            HttpConnectError::Io(e) => Error::Connection(format!("proxy connection failed: {e}")),
            other => Error::Proxy(other.to_string()),
        }
    }
}

/// Printable ASCII only, at most 80 characters, trimmed.
pub(crate) fn sanitize_reason(reason: &str) -> String {
    reason
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(80)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Position just after the first `\r\n\r\n` in `buf`, searching from `from`
/// (callers pass the old length minus 3 so a terminator split across reads is found).
pub(crate) fn find_head_end(buf: &[u8], from: usize) -> Option<usize> {
    let from = from.min(buf.len());
    buf[from..]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| from + p + 4)
}

/// Parse a response head (the buffer may continue past it).
///
/// # Errors
///
/// [`HttpConnectError::HeadersTooLarge`] when no `\r\n\r\n` ends within
/// [`MAX_HEADER_BYTES`] and the buffer is longer than that;
/// [`HttpConnectError::Malformed`] for an incomplete head or a status line that is not
/// `HTTP/1.0` / `HTTP/1.1` + a 3-digit code.
pub fn parse_connect_response(head: &[u8]) -> Result<ConnectResponse, HttpConnectError> {
    let header_len = match find_head_end(head, 0) {
        Some(end) if end <= MAX_HEADER_BYTES => end,
        Some(_) => return Err(HttpConnectError::HeadersTooLarge),
        None if head.len() > MAX_HEADER_BYTES => return Err(HttpConnectError::HeadersTooLarge),
        None => return Err(HttpConnectError::Malformed("incomplete head".to_owned())),
    };
    let line_end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(header_len);
    let line = &head[..line_end];
    let rest = line
        .strip_prefix(b"HTTP/1.1 ")
        .or_else(|| line.strip_prefix(b"HTTP/1.0 "))
        .ok_or_else(|| HttpConnectError::Malformed("no HTTP/1.x status line".to_owned()))?;
    let digits = rest
        .get(..3)
        .filter(|d| d.iter().all(u8::is_ascii_digit) && d[0] != b'0')
        .ok_or_else(|| HttpConnectError::Malformed("bad status code".to_owned()))?;
    let code = digits
        .iter()
        .fold(0_u16, |acc, d| acc * 10 + u16::from(d - b'0'));
    let reason = match &rest[3..] {
        [] => String::new(),
        [b' ', reason @ ..] => sanitize_reason(&String::from_utf8_lossy(reason)),
        _ => return Err(HttpConnectError::Malformed("bad status code".to_owned())),
    };
    Ok(ConnectResponse {
        code,
        reason,
        header_len,
    })
}

/// The CONNECT request for `target`; the Basic credentials only with `auth`. The
/// result is wiped on drop (it may hold the password).
///
/// # Errors
///
/// [`Error::InvalidInput`] when the user contains `':'` (Basic auth cannot encode it).
pub(crate) fn connect_request(
    target: &HostPort,
    auth: Option<(&str, &SecretString)>,
) -> Result<Zeroizing<String>> {
    let authority = target.authority();
    let mut req = Zeroizing::new(format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
    ));
    if let Some((user, password)) = auth {
        if user.contains(':') {
            return Err(Error::InvalidInput(
                "an HTTP proxy user name cannot contain ':'".to_owned(),
            ));
        }
        let plain = Zeroizing::new(format!("{user}:{}", password.expose()));
        let token = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(&*plain));
        req.push_str("Proxy-Authorization: Basic ");
        req.push_str(&token);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    Ok(req)
}

/// Reads until the end of the head (at most `max` bytes of head). Returns the bytes
/// read and the head length.
pub(crate) async fn read_head<S: AsyncRead + Unpin>(
    stream: &mut S,
    max: usize,
) -> Result<(Vec<u8>, usize), HttpConnectError> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 2048];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(HttpConnectError::Io)?;
        if n == 0 {
            return Err(HttpConnectError::Closed);
        }
        let from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = find_head_end(&buf, from) {
            if end > max {
                return Err(HttpConnectError::HeadersTooLarge);
            }
            return Ok((buf, end));
        }
        if buf.len() > max {
            return Err(HttpConnectError::HeadersTooLarge);
        }
    }
}

/// Runs CONNECT over `stream` (no timeout here; the caller bounds it). Returns the
/// bytes the proxy sent after the head.
pub(crate) async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &[u8],
    sent_auth: bool,
) -> Result<Vec<u8>, HttpConnectError> {
    stream
        .write_all(request)
        .await
        .map_err(HttpConnectError::Io)?;
    stream.flush().await.map_err(HttpConnectError::Io)?;
    let (mut buf, end) = read_head(stream, MAX_HEADER_BYTES).await?;
    let response = parse_connect_response(&buf[..end])?;
    match response.code {
        200..=299 => Ok(buf.split_off(end)),
        407 => Err(HttpConnectError::AuthRequired { sent: sent_auth }),
        code => Err(HttpConnectError::Status {
            code,
            reason: response.reason,
        }),
    }
}

/// Fuzz body of the `http_connect_response` target (T91 §7): parses the whole input
/// and, for every 2-way split, feeds the two parts through the incremental head search
/// as two reads. Must never panic; on success the parsed head length must match the
/// terminator position.
#[doc(hidden)]
pub fn fuzz_http_connect_response(data: &[u8]) {
    let check = |buf: &[u8]| {
        if let Ok(resp) = parse_connect_response(buf) {
            assert!(resp.header_len <= buf.len() && resp.header_len <= MAX_HEADER_BYTES);
            assert_eq!(&buf[resp.header_len - 4..resp.header_len], b"\r\n\r\n");
            assert!(resp.reason.len() <= 80);
            assert!((100..1000).contains(&resp.code));
        }
    };
    check(data);
    let whole = find_head_end(data, 0);
    for split in 0..=data.len() {
        let (a, b) = data.split_at(split);
        let mut buf = a.to_vec();
        let found = find_head_end(&buf, 0).or_else(|| {
            let from = buf.len().saturating_sub(3);
            buf.extend_from_slice(b);
            find_head_end(&buf, from)
        });
        assert_eq!(found, whole, "terminator search depends on the read split");
        if split.is_multiple_of(64) {
            check(a);
        }
    }
}
