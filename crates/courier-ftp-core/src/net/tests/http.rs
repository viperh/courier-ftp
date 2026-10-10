//! HTTP CONNECT against in-process fake proxies, and `http_get_small`.

use std::net::SocketAddr;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_util::sync::CancellationToken;

use super::{Recorded, drain, echo, fake_proxy, opts, read_until, round_trip, session_log, ui};
use crate::{
    Error,
    net::{HostPort, ProxyConfig, ProxyCredentials, http_get_small},
    secret::SecretString,
};

/// What the fake HTTP proxy answers to a CONNECT head.
#[derive(Clone)]
enum Answer {
    /// The bytes to send, then echo (tunnel) when true, else close.
    Send(Vec<u8>, bool),
}

/// A fake HTTP proxy: records each request head, then answers with `answer(head)`.
async fn http_proxy(
    answer: impl Fn(&str) -> Answer + Send + Sync + 'static,
) -> (SocketAddr, Recorded) {
    let answer = std::sync::Arc::new(answer);
    fake_proxy(move |mut s: TcpStream, _i, rec: Recorded| {
        let answer = answer.clone();
        async move {
            let head = read_until(&mut s, b"\r\n\r\n").await;
            rec.lock().unwrap().push(head.clone());
            let Answer::Send(bytes, tunnel) = answer(&String::from_utf8_lossy(&head));
            if s.write_all(&bytes).await.is_err() {
                return;
            }
            if tunnel {
                echo(s).await;
            } else {
                // Close gracefully: closing with unread client bytes (e.g. the tunneled GET)
                // sends RST, and Windows then drops the response the client hasn't read.
                let _ = s.shutdown().await;
                let mut sink = [0u8; 1024];
                while matches!(s.read(&mut sink).await, Ok(n) if n > 0) {}
            }
        }
    })
    .await
}

fn http(addr: SocketAddr, auth: Option<ProxyCredentials>) -> ProxyConfig {
    ProxyConfig::Http {
        proxy: HostPort::new("127.0.0.1", addr.port()),
        auth,
    }
}

fn creds(user: &str, pw: Option<&str>) -> Option<ProxyCredentials> {
    Some(ProxyCredentials {
        user: user.into(),
        password: pw.map(SecretString::from),
    })
}

fn ok_tunnel() -> Answer {
    Answer::Send(
        b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec(),
        true,
    )
}

fn target() -> HostPort {
    HostPort::new("ftp.example.com", 21)
}

#[tokio::test]
async fn http_connect_no_auth() {
    let (proxy, rec) = http_proxy(|_| ok_tunnel()).await;
    let (log, mut rx) = session_log();
    let mut s = connect_tcp_ok(&target(), http(proxy, None), &log).await;
    round_trip(&mut s, b"through the tunnel").await;
    assert!(s.is_proxied());
    assert_eq!(s.target_ip(), None);
    assert_eq!(s.peer_addr(), proxy);
    let heads = rec.lock().unwrap().clone();
    assert_eq!(
        heads,
        [b"CONNECT ftp.example.com:21 HTTP/1.1\r\nHost: ftp.example.com:21\r\n\r\n".to_vec()]
    );
    let status = drain(&mut rx).status().join("\n");
    assert!(
        status.starts_with(&format!(
            "Connecting to ftp.example.com:21 through HTTP proxy 127.0.0.1:{}\n",
            proxy.port()
        )),
        "{status}"
    );
    assert!(
        status.ends_with("Connection established through proxy"),
        "{status}"
    );
}

async fn connect_tcp_ok(
    target: &HostPort,
    proxy: ProxyConfig,
    log: &crate::events::SessionLog,
) -> crate::net::NetStream {
    crate::net::connect_tcp(target, &opts(proxy), CancellationToken::new(), log)
        .await
        .unwrap()
}

async fn connect_err(proxy: ProxyConfig) -> Error {
    let (log, _rx) = session_log();
    crate::net::connect_tcp(&target(), &opts(proxy), CancellationToken::new(), &log)
        .await
        .unwrap_err()
}

/// 200 with the right Basic token (alice:s3cret), else 407.
fn basic_auth_answer(head: &str) -> Answer {
    // base64("alice:s3cret")
    if head.contains("Proxy-Authorization: Basic YWxpY2U6czNjcmV0\r\n") {
        ok_tunnel()
    } else {
        Answer::Send(
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"p\"\r\n\r\n"
                .to_vec(),
            false,
        )
    }
}

#[tokio::test]
async fn http_connect_basic_auth() {
    let (proxy, rec) = http_proxy(basic_auth_answer).await;
    let (log, _rx) = session_log();
    let mut s = connect_tcp_ok(&target(), http(proxy, creds("alice", Some("s3cret"))), &log).await;
    round_trip(&mut s, b"authenticated").await;
    assert_eq!(rec.lock().unwrap().len(), 1);
    // A wrong stored password is not retried and not prompted for.
    let err = connect_err(http(proxy, creds("alice", Some("wrong")))).await;
    assert!(
        matches!(&err, Error::Proxy(m) if m == "authentication failed (407)"),
        "{err:?}"
    );
}

#[tokio::test]
async fn http_connect_replays_early_bytes() {
    let (proxy, _) = http_proxy(|_| {
        Answer::Send(
            b"HTTP/1.1 200 Connection established\r\n\r\n220 hi\r\n".to_vec(),
            true,
        )
    })
    .await;
    let (log, _rx) = session_log();
    let mut s = connect_tcp_ok(&target(), http(proxy, None), &log).await;
    let mut banner = [0_u8; 8];
    s.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"220 hi\r\n");
    round_trip(&mut s, b"then the tunnel").await;
}

#[tokio::test]
async fn http_connect_407_prompts_once_then_fails() {
    let always_407 = |_: &str| {
        Answer::Send(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n".to_vec(),
            false,
        )
    };
    let (proxy, rec) = http_proxy(always_407).await;
    let (log, rx) = session_log();
    let ui = ui(rx, Some("typed"));
    let err = crate::net::connect_tcp(
        &target(),
        &opts(http(proxy, creds("alice", None))),
        CancellationToken::new(),
        &log,
    )
    .await
    .unwrap_err();
    drop(log);
    let seen = ui.await.unwrap();
    assert!(
        matches!(&err, Error::Proxy(m) if m == "authentication failed (407)"),
        "{err:?}"
    );
    assert_eq!(seen.prompts, 1);
    assert_eq!(seen.accepted, 0);
    let heads = rec.lock().unwrap().clone();
    assert_eq!(heads.len(), 2, "one retry on a new connection");
    assert!(!String::from_utf8_lossy(&heads[0]).contains("Proxy-Authorization"));
    // base64("alice:typed")
    assert!(String::from_utf8_lossy(&heads[1]).contains("Basic YWxpY2U6dHlwZWQ="));
}

#[tokio::test]
async fn http_connect_407_prompt_then_success() {
    let (proxy, rec) = http_proxy(basic_auth_answer).await;
    let (log, rx) = session_log();
    let ui = ui(rx, Some("s3cret"));
    let mut s = connect_tcp_ok(&target(), http(proxy, creds("alice", None)), &log).await;
    round_trip(&mut s, b"ok").await;
    drop(log);
    let seen = ui.await.unwrap();
    assert_eq!((seen.prompts, seen.accepted), (1, 1));
    assert_eq!(rec.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn http_connect_407_prompt_cancelled() {
    let (proxy, _) = http_proxy(basic_auth_answer).await;
    let (log, rx) = session_log();
    let ui = ui(rx, None);
    let err = crate::net::connect_tcp(
        &target(),
        &opts(http(proxy, creds("alice", None))),
        CancellationToken::new(),
        &log,
    )
    .await
    .unwrap_err();
    drop(log);
    assert_eq!(ui.await.unwrap().prompts, 1);
    assert!(matches!(err, Error::Cancelled), "{err:?}");
}

#[tokio::test]
async fn http_connect_407_without_user_does_not_prompt() {
    let (proxy, rec) = http_proxy(basic_auth_answer).await;
    let err = connect_err(http(proxy, None)).await;
    assert!(matches!(err, Error::Proxy(_)), "{err:?}");
    assert_eq!(rec.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn http_connect_403_is_proxy_error() {
    let (proxy, _) = http_proxy(|_| {
        Answer::Send(
            b"HTTP/1.1 403 Forbidden\x1b[2J\r\nContent-Length: 0\r\n\r\n".to_vec(),
            false,
        )
    })
    .await;
    let err = connect_err(http(proxy, None)).await;
    assert!(
        matches!(&err, Error::Proxy(m) if m == "CONNECT refused (403 Forbidden[2J)"),
        "{err:?}"
    );
    assert!(!err.is_transient());
}

#[tokio::test]
async fn http_connect_malformed_and_closed() {
    let (proxy, _) = http_proxy(|_| Answer::Send(b"HTTP/2 200\r\n\r\n".to_vec(), false)).await;
    let err = connect_err(http(proxy, None)).await;
    assert!(
        matches!(&err, Error::Proxy(m) if m.starts_with("invalid HTTP response")),
        "{err:?}"
    );
    let (proxy, _) = http_proxy(|_| Answer::Send(b"HTTP/1.1 200".to_vec(), false)).await;
    let err = connect_err(http(proxy, None)).await;
    assert!(
        matches!(&err, Error::Proxy(m) if m == "connection closed during CONNECT"),
        "{err:?}"
    );
}

#[tokio::test]
async fn http_connect_oversized_headers() {
    let (proxy, _) = http_proxy(|_| {
        let mut r = b"HTTP/1.1 200 OK\r\n".to_vec();
        for _ in 0..400 {
            r.extend_from_slice(b"X-Filler: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        }
        r.extend_from_slice(b"\r\n");
        Answer::Send(r, true)
    })
    .await;
    let err = connect_err(http(proxy, None)).await;
    assert!(
        matches!(&err, Error::Proxy(m) if m == "response headers too large (over 16 KiB)"),
        "{err:?}"
    );
}

#[tokio::test]
async fn http_connect_unreachable_proxy_is_connection_error() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let err = connect_err(http(addr, None)).await;
    assert!(matches!(err, Error::Connection(_)), "{err:?}");
}

/// A one-shot HTTP server: answers every request with `response`.
async fn http_server(response: Vec<u8>) -> SocketAddr {
    let (addr, _) = fake_proxy(move |mut s: TcpStream, _i, _rec| {
        let response = response.clone();
        async move {
            let _ = read_until(&mut s, b"\r\n\r\n").await;
            let _ = s.write_all(&response).await;
        }
    })
    .await;
    addr
}

#[tokio::test]
async fn http_get_small_reads_body() {
    let addr =
        http_server(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n203.0.113.5\n".to_vec())
            .await;
    let (log, _rx) = session_log();
    let body = http_get_small(
        &format!("http://127.0.0.1:{}/ip", addr.port()),
        &opts(ProxyConfig::Direct),
        &log,
        4096,
    )
    .await
    .unwrap();
    assert_eq!(body, "203.0.113.5\n");
}

#[tokio::test]
async fn http_get_small_goes_through_the_proxy() {
    let (proxy, rec) = http_proxy(|_| {
        Answer::Send(
            b"HTTP/1.1 200 Connection established\r\n\r\nHTTP/1.0 200 OK\r\n\r\n198.51.100.7"
                .to_vec(),
            false,
        )
    })
    .await;
    let (log, _rx) = session_log();
    let body = http_get_small("http://ip.example/", &opts(http(proxy, None)), &log, 64)
        .await
        .unwrap();
    assert_eq!(body, "198.51.100.7");
    assert!(String::from_utf8_lossy(&rec.lock().unwrap()[0]).starts_with("CONNECT ip.example:80 "));
}

#[tokio::test]
async fn http_get_small_rejects_https_and_redirects() {
    let (log, _rx) = session_log();
    let err = http_get_small("https://ip.example/", &opts(ProxyConfig::Direct), &log, 64)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
    let addr =
        http_server(b"HTTP/1.1 302 Found\r\nLocation: http://elsewhere.example/\r\n\r\n".to_vec())
            .await;
    let err = http_get_small(
        &format!("http://127.0.0.1:{}/", addr.port()),
        &opts(ProxyConfig::Direct),
        &log,
        64,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            &err,
            Error::Protocol {
                code: Some(302),
                ..
            }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn http_get_small_caps_body() {
    let mut big = b"HTTP/1.0 200 OK\r\n\r\n".to_vec();
    big.resize(big.len() + 5000, b'1');
    let addr = http_server(big).await;
    let (log, _rx) = session_log();
    let url = format!("http://127.0.0.1:{}/", addr.port());
    // max_body is capped at 4096 even when the caller asks for more.
    let err = http_get_small(&url, &opts(ProxyConfig::Direct), &log, 1 << 20)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Protocol { code: None, .. }),
        "{err:?}"
    );
    let addr = http_server(b"HTTP/1.0 200 OK\r\n\r\n12345678901".to_vec()).await;
    let url = format!("http://127.0.0.1:{}/", addr.port());
    let err = http_get_small(&url, &opts(ProxyConfig::Direct), &log, 10)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Protocol { code: None, .. }),
        "{err:?}"
    );
    let ok = http_get_small(&url, &opts(ProxyConfig::Direct), &log, 11)
        .await
        .unwrap();
    assert_eq!(ok, "12345678901");
}
