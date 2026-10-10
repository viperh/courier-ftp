//! [`http_get_small`]: a minimal HTTP/1.0 GET for `http://` URLs (T11 "get the
//! external IP from a URL").

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use super::{
    HostPort, NetOpts, connect_tcp,
    dial::timed_out,
    http_connect::{HttpConnectError, MAX_HEADER_BYTES, parse_connect_response, read_head},
};
use crate::{Error, Result, events::SessionLog};

/// The largest body [`http_get_small`] accepts, whatever `max_body` says.
const BODY_CAP: usize = 4096;

/// GET `url` (`http://host[:port][/path]` only) over [`connect_tcp`] (so through the
/// configured proxy). Status 200 is required, redirects are not followed, the body
/// must be at most `max_body` bytes (capped at 4096), and the whole request must finish
/// within `opts.timeout`. The body is returned as (lossy) UTF-8 text; the caller
/// validates it.
///
/// # Errors
///
/// [`Error::InvalidInput`] (not an `http://` URL), [`Error::Protocol`] (non-200
/// status, invalid response, body too large), [`Error::Timeout`],
/// [`Error::Connection`].
pub async fn http_get_small(
    url: &str,
    opts: &NetOpts,
    log: &SessionLog,
    max_body: usize,
) -> Result<String> {
    let (target, path) = parse_http_url(url)?;
    let max_body = max_body.min(BODY_CAP);
    let request = async {
        let mut stream = connect_tcp(&target, opts, CancellationToken::new(), log).await?;
        let req = format!(
            "GET {path} HTTP/1.0\r\nHost: {}\r\nUser-Agent: courier-ftp\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            host_header(&target)
        );
        stream.write_all(req.as_bytes()).await?;
        stream.flush().await?;
        let (mut buf, end) = read_head(&mut stream, MAX_HEADER_BYTES)
            .await
            .map_err(head_error)?;
        let head = parse_connect_response(&buf[..end]).map_err(head_error)?;
        if head.code != 200 {
            let message = if head.reason.is_empty() {
                format!("HTTP status {}", head.code)
            } else {
                format!("HTTP status {} {}", head.code, head.reason)
            };
            return Err(Error::Protocol {
                code: Some(head.code),
                message,
            });
        }
        let mut body = buf.split_off(end);
        let mut chunk = [0_u8; 1024];
        while body.len() <= max_body {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
        if body.len() > max_body {
            return Err(Error::Protocol {
                code: None,
                message: format!("HTTP response body larger than {max_body} bytes"),
            });
        }
        Ok(String::from_utf8_lossy(&body).into_owned())
    };
    match tokio::time::timeout(opts.timeout, request).await {
        Ok(result) => result,
        Err(_) => Err(timed_out(opts.timeout, log)),
    }
}

/// `Host:` value: the port only when it is not 80.
fn host_header(target: &HostPort) -> String {
    if target.port == 80 {
        if target.host.contains(':') {
            format!("[{}]", target.host)
        } else {
            target.host.clone()
        }
    } else {
        target.authority()
    }
}

fn head_error(err: HttpConnectError) -> Error {
    match err {
        HttpConnectError::Io(e) => Error::Connection(format!("HTTP request failed: {e}")),
        HttpConnectError::Closed => {
            Error::Connection("the server closed the connection".to_owned())
        }
        other => Error::Protocol {
            code: None,
            message: other.to_string(),
        },
    }
}

/// Splits `http://host[:port][/path]` into the target and the request path.
fn parse_http_url(url: &str) -> Result<(HostPort, String)> {
    let invalid = || Error::InvalidInput(format!("not an http:// URL: {url}"));
    let rest = url
        .get(..7)
        .filter(|s| s.eq_ignore_ascii_case("http://"))
        .map(|_| &url[7..])
        .ok_or_else(invalid)?;
    let (authority, path) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let path = path.split('#').next().unwrap_or("/");
    let path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(invalid());
    }
    let target = HostPort::parse(authority)
        .or_else(|| {
            let bracketed = authority.starts_with('[') && authority.ends_with(']');
            (bracketed || !authority.contains(':')).then(|| HostPort::new(authority, 80))
        })
        .ok_or_else(invalid)?;
    if target.host.is_empty() || path.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return Err(invalid());
    }
    Ok((target, path))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn parse_http_urls() {
        let (t, p) = parse_http_url("http://ip.example.com/").unwrap();
        assert_eq!((t, p.as_str()), (HostPort::new("ip.example.com", 80), "/"));
        let (t, p) = parse_http_url("HTTP://[::1]:8080/ip?x=1").unwrap();
        assert_eq!((t, p.as_str()), (HostPort::new("::1", 8080), "/ip?x=1"));
        let (t, p) = parse_http_url("http://[::1]").unwrap();
        assert_eq!((t, p.as_str()), (HostPort::new("::1", 80), "/"));
        let (_, p) = parse_http_url("http://h?q").unwrap();
        assert_eq!(p, "/?q");
        for bad in [
            "https://h/",
            "ftp://h/",
            "http://",
            "http://u@h/",
            "http://h:0/",
            "http://h/a b",
            "h/",
        ] {
            assert!(
                matches!(parse_http_url(bad), Err(Error::InvalidInput(_))),
                "{bad}"
            );
        }
    }
}
