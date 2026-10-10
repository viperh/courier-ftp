//! The external IP address for active mode from an IP-echo URL
//! (`ftp.active_external_ip = from_url`): one plain HTTP/1.0 `GET` through
//! the net layer, the body parsed as an IP address.

use std::net::IpAddr;

use courier_ftp_core::{
    Error, Result,
    events::{EventSender, SessionId},
    net::{HostPort, connect_tcp},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use super::DataOptions;

/// The most of the response that is read.
const MAX_RESPONSE: usize = 8 * 1024;

/// `http://host[:port][/path]` split into host, port and path.
fn parse_url(url: &str) -> Result<(HostPort, String)> {
    let rest = url
        .trim()
        .strip_prefix("http://")
        .ok_or_else(|| Error::InvalidInput(format!("only http:// IP lookup URLs work: {url}")))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (
            rest.get(..i).unwrap_or_default(),
            rest.get(i..).unwrap_or("/"),
        ),
        None => (rest, "/"),
    };
    if authority.is_empty() || path.contains(['\r', '\n', ' ']) {
        return Err(Error::InvalidInput(format!("bad IP lookup URL: {url}")));
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6
            .split_once(']')
            .ok_or_else(|| Error::InvalidInput(format!("bad IP lookup URL: {url}")))?;
        let port = after.strip_prefix(':').map(str::parse).transpose();
        (h.to_owned(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), Some(p.parse()).transpose()),
            None => (authority.to_owned(), Ok(None)),
        }
    };
    let port: Option<u16> =
        port.map_err(|_| Error::InvalidInput(format!("bad port in IP lookup URL: {url}")))?;
    Ok((HostPort::new(host, port.unwrap_or(80)), path.to_owned()))
}

/// The IP address in an HTTP response: status 200, the body trimmed.
fn parse_response(response: &[u8]) -> Result<IpAddr> {
    let text = String::from_utf8_lossy(response);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .ok_or_else(|| Error::Connection("incomplete HTTP response".into()))?;
    let status = head.lines().next().unwrap_or_default();
    if status.split_whitespace().nth(1) != Some("200") {
        return Err(Error::Connection(format!("IP lookup failed: {status}")));
    }
    body.trim()
        .parse()
        .map_err(|_| Error::Connection("the IP lookup did not return an IP address".into()))
}

/// Fetch the external address from `url`.
pub(super) async fn fetch(
    url: &str,
    opts: &DataOptions,
    cancel: &CancellationToken,
    events: &EventSender,
    session: SessionId,
) -> Result<IpAddr> {
    let (target, path) = parse_url(url)?;
    let mut tcp = connect_tcp(&target, &opts.net, cancel, events, session).await?;
    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: {}\r\nUser-Agent: courier-ftp\r\nConnection: close\r\n\r\n",
        target.host
    );
    let exchange = async {
        tcp.write_all(request.as_bytes()).await?;
        let mut response = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = tcp.read(&mut buf).await?;
            if n == 0 || response.len() >= MAX_RESPONSE {
                break;
            }
            response.extend_from_slice(buf.get(..n).unwrap_or_default());
        }
        Ok::<_, std::io::Error>(response)
    };
    let response = tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(Error::Cancelled),
        r = tokio::time::timeout(opts.timeout, exchange) => match r {
            Err(_) => return Err(Error::Timeout),
            Ok(r) => r?,
        },
    };
    parse_response(&response)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn urls() {
        let (hp, path) = parse_url("http://ip.example.com/raw").unwrap();
        assert_eq!(
            (hp.host.as_str(), hp.port, path.as_str()),
            ("ip.example.com", 80, "/raw")
        );
        let (hp, path) = parse_url("http://127.0.0.1:8080").unwrap();
        assert_eq!(
            (hp.host.as_str(), hp.port, path.as_str()),
            ("127.0.0.1", 8080, "/")
        );
        let (hp, _) = parse_url("http://[::1]:81/x").unwrap();
        assert_eq!((hp.host.as_str(), hp.port), ("::1", 81));
        assert!(parse_url("https://example.com").is_err());
        assert!(parse_url("http://").is_err());
        assert!(parse_url("http://h:99999/").is_err());
    }

    #[test]
    fn responses() {
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n203.0.113.9\n")
                .unwrap(),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        assert!(parse_response(b"HTTP/1.1 404 Not Found\r\n\r\n1.2.3.4").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\n\r\n<html>").is_err());
    }
}
