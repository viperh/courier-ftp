//! Tests for the network layer, with in-process fake proxies on 127.0.0.1.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use pretty_assertions::assert_eq;
use proptest::prelude::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};

use super::*;
use crate::events::{self, CoreEvent, EventReceiver};

const BANNER: &[u8] = b"220 hello through the tunnel\r\n";
const CANARY_PW: &str = "CANARY-PW-proxy";
const CANARY_USER: &str = "CANARY-USER-proxy";
/// How late a timeout or cancel may be noticed. The requirement is 100 ms;
/// the assertion leaves headroom for loaded CI machines.
const SLACK: Duration = Duration::from_millis(200);

fn bus() -> (EventSender, EventReceiver) {
    events::channel(4)
}

fn logs(rx: &mut EventReceiver) -> Vec<String> {
    let mut out = Vec::new();
    while let Some(event) = rx.try_recv() {
        if let CoreEvent::Log(m) = event {
            out.push(m.text);
        }
    }
    out
}

fn opts() -> NetOpts {
    NetOpts {
        timeout: Duration::from_secs(5),
        ..NetOpts::default()
    }
}

fn proxy(kind: ProxyKind, addr: SocketAddr, auth: Option<(&str, &str)>) -> Proxy {
    Proxy {
        kind,
        server: addr.into(),
        auth: auth.map(|(u, p)| ProxyAuth {
            user: u.to_owned(),
            password: Some(p.into()),
        }),
    }
}

async fn connect(target: &HostPort, o: &NetOpts) -> (Result<TcpStream>, Vec<String>) {
    let (tx, mut rx) = bus();
    let r = connect_tcp(target, o, &CancellationToken::new(), &tx, SessionId::next()).await;
    (r, logs(&mut rx))
}

/// Read the banner the fake proxies send right after the handshake, then
/// check the tunnel echoes.
async fn assert_tunnel(stream: &mut TcpStream) {
    let mut banner = vec![0u8; BANNER.len()];
    stream.read_exact(&mut banner).await.unwrap();
    assert_eq!(banner, BANNER);
    stream.write_all(b"ping").await.unwrap();
    let mut echo = [0u8; 4];
    stream.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping");
}

async fn echo(mut s: TcpStream) {
    let mut buf = [0u8; 1024];
    while let Ok(n) = s.read(&mut buf).await {
        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
}

async fn echo_server(listener: TcpListener) {
    while let Ok((s, _)) = listener.accept().await {
        tokio::spawn(echo(s));
    }
}

async fn read_until(s: &mut TcpStream, end: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while !out.ends_with(end) {
        out.push(s.read_u8().await.unwrap());
    }
    out
}

// --- fake HTTP proxy -------------------------------------------------------

/// Accepts one client, sends the request head back over `seen`, answers
/// `reply` (and on 2xx, the banner in the same write), then echoes.
async fn http_proxy(reply: &'static str) -> (SocketAddr, oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (seen_tx, seen) = oneshot::channel();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let head = read_until(&mut s, b"\r\n\r\n").await;
        let _ = seen_tx.send(String::from_utf8(head).unwrap());
        let mut out = reply.as_bytes().to_vec();
        let ok = reply.starts_with("HTTP/1.1 2") || reply.starts_with("HTTP/1.0 2");
        if ok {
            out.extend_from_slice(BANNER);
        }
        s.write_all(&out).await.unwrap();
        if ok {
            echo(s).await;
        }
    });
    (addr, seen)
}

#[tokio::test]
async fn http_connect_without_auth() {
    let (addr, seen) = http_proxy("HTTP/1.1 200 Connection established\r\n\r\n").await;
    let mut o = opts();
    o.proxy = Some(proxy(ProxyKind::Http, addr, None));
    let (r, log) = connect(&HostPort::new("ftp.example.com", 21), &o).await;
    let mut stream = r.unwrap();
    assert_tunnel(&mut stream).await;
    let head = seen.await.unwrap();
    assert_eq!(
        head,
        "CONNECT ftp.example.com:21 HTTP/1.1\r\nHost: ftp.example.com:21\r\n\r\n"
    );
    assert!(log.iter().any(|l| l == "Connection established"), "{log:?}");
}

#[tokio::test]
async fn http_connect_with_basic_auth_and_ipv6_target() {
    let (addr, seen) =
        http_proxy("HTTP/1.0 200 OK\r\nProxy-Agent: fake\r\nX-Other: 1\r\n\r\n").await;
    let mut o = opts();
    o.proxy = Some(proxy(
        ProxyKind::Http,
        addr,
        Some(("Aladdin", "open sesame")),
    ));
    let (r, _) = connect(&HostPort::new("[2001:db8::1]", 990), &o).await;
    assert_tunnel(&mut r.unwrap()).await;
    let head = seen.await.unwrap();
    assert!(
        head.starts_with("CONNECT [2001:db8::1]:990 HTTP/1.1\r\n"),
        "{head}"
    );
    assert!(
        head.contains("Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n"),
        "{head}"
    );
}

#[tokio::test]
async fn http_connect_errors_carry_the_status_line() {
    let (addr, _seen) = http_proxy("HTTP/1.1 403 Forbidden\r\n\r\n").await;
    let mut o = opts();
    o.proxy = Some(proxy(ProxyKind::Http, addr, None));
    let (r, log) = connect(&HostPort::new("h", 21), &o).await;
    let err = r.unwrap_err();
    assert!(matches!(err, Error::Connection(_)), "{err:?}");
    assert!(err.to_string().contains("403 Forbidden"), "{err}");
    assert!(log.iter().any(|l| l.contains("403 Forbidden")), "{log:?}");

    let (addr, _seen) = http_proxy("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await;
    o.proxy = Some(proxy(ProxyKind::Http, addr, Some((CANARY_USER, CANARY_PW))));
    let (r, log) = connect(&HostPort::new("h", 21), &o).await;
    assert!(matches!(r, Err(Error::Auth(_))));
    assert_no_canary(&log);
}

// --- fake SOCKS proxies ------------------------------------------------------

/// What a fake SOCKS proxy was asked for.
#[derive(Debug, PartialEq, Eq)]
struct SocksRequest {
    user: Option<String>,
    password: Option<String>,
    host: String,
    port: u16,
}

/// A SOCKS5 proxy for one client. `login`: the required user and password
/// (`None`: no authentication). Replies with a domain-name BND.ADDR to
/// exercise the variable-length skip.
async fn socks5_proxy(
    login: Option<(&'static str, &'static str)>,
) -> (SocketAddr, oneshot::Receiver<SocksRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (seen_tx, seen) = oneshot::channel();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        assert_eq!(s.read_u8().await.unwrap(), 5);
        let n = s.read_u8().await.unwrap();
        let mut methods = vec![0u8; n.into()];
        s.read_exact(&mut methods).await.unwrap();
        let (mut user, mut password) = (None, None);
        match login {
            None => s.write_all(&[5, 0]).await.unwrap(),
            Some(_) if !methods.contains(&2) => {
                s.write_all(&[5, 0xff]).await.unwrap();
                return;
            }
            Some((u, p)) => {
                s.write_all(&[5, 2]).await.unwrap();
                assert_eq!(s.read_u8().await.unwrap(), 1);
                let ul = s.read_u8().await.unwrap();
                let mut ub = vec![0u8; ul.into()];
                s.read_exact(&mut ub).await.unwrap();
                let pl = s.read_u8().await.unwrap();
                let mut pb = vec![0u8; pl.into()];
                s.read_exact(&mut pb).await.unwrap();
                let ok = ub == u.as_bytes() && pb == p.as_bytes();
                user = Some(String::from_utf8(ub).unwrap());
                password = Some(String::from_utf8(pb).unwrap());
                s.write_all(&[1, u8::from(!ok)]).await.unwrap();
                if !ok {
                    return;
                }
            }
        }
        let mut head = [0u8; 4];
        s.read_exact(&mut head).await.unwrap();
        assert_eq!(&head[..3], &[5, 1, 0]);
        let host = match head[3] {
            1 => {
                let mut b = [0u8; 4];
                s.read_exact(&mut b).await.unwrap();
                Ipv4Addr::from(b).to_string()
            }
            4 => {
                let mut b = [0u8; 16];
                s.read_exact(&mut b).await.unwrap();
                Ipv6Addr::from(b).to_string()
            }
            3 => {
                let l = s.read_u8().await.unwrap();
                let mut b = vec![0u8; l.into()];
                s.read_exact(&mut b).await.unwrap();
                String::from_utf8(b).unwrap()
            }
            other => panic!("address type {other}"),
        };
        let port = s.read_u16().await.unwrap();
        let _ = seen_tx.send(SocksRequest {
            user,
            password,
            host,
            port,
        });
        let mut reply = vec![5, 0, 0, 3, 9];
        reply.extend_from_slice(b"bound.lan");
        reply.extend_from_slice(&4321u16.to_be_bytes());
        reply.extend_from_slice(BANNER);
        s.write_all(&reply).await.unwrap();
        echo(s).await;
    });
    (addr, seen)
}

#[tokio::test]
async fn socks5_without_auth_sends_the_host_name() {
    let (addr, seen) = socks5_proxy(None).await;
    let mut o = opts();
    o.proxy = Some(proxy(ProxyKind::Socks5, addr, None));
    let (r, _) = connect(&HostPort::new("sftp.example.org", 22), &o).await;
    assert_tunnel(&mut r.unwrap()).await;
    assert_eq!(
        seen.await.unwrap(),
        SocksRequest {
            user: None,
            password: None,
            host: "sftp.example.org".into(),
            port: 22
        }
    );
}

#[tokio::test]
async fn socks5_with_auth_and_address_types() {
    for (host, expected) in [
        ("203.0.113.5", "203.0.113.5"),
        ("::1", "::1"),
        ("name.example", "name.example"),
    ] {
        let (addr, seen) = socks5_proxy(Some((CANARY_USER, CANARY_PW))).await;
        let mut o = opts();
        o.proxy = Some(proxy(
            ProxyKind::Socks5,
            addr,
            Some((CANARY_USER, CANARY_PW)),
        ));
        let (r, log) = connect(&HostPort::new(host, 2121), &o).await;
        assert_tunnel(&mut r.unwrap()).await;
        let req = seen.await.unwrap();
        assert_eq!(req.host, expected);
        assert_eq!(req.port, 2121);
        assert_eq!(req.user.as_deref(), Some(CANARY_USER));
        assert_eq!(req.password.as_deref(), Some(CANARY_PW));
        assert_no_canary(&log);
    }
}

#[tokio::test]
async fn socks5_auth_failures() {
    // Wrong password.
    let (addr, _seen) = socks5_proxy(Some(("bob", "right"))).await;
    let mut o = opts();
    o.proxy = Some(proxy(ProxyKind::Socks5, addr, Some(("bob", CANARY_PW))));
    let (r, log) = connect(&HostPort::new("h", 22), &o).await;
    assert!(matches!(r, Err(Error::Auth(_))), "{r:?}");
    assert_no_canary(&log);

    // The proxy wants a login, we have none.
    let (addr, _seen) = socks5_proxy(Some(("bob", "right"))).await;
    o.proxy = Some(proxy(ProxyKind::Socks5, addr, None));
    let (r, _) = connect(&HostPort::new("h", 22), &o).await;
    let err = r.unwrap_err();
    assert!(err.to_string().contains("requires a login"), "{err}");
}

/// A SOCKS4 proxy for one client; replies `code` (90 = granted).
async fn socks4_proxy(code: u8) -> (SocketAddr, oneshot::Receiver<SocksRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (seen_tx, seen) = oneshot::channel();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut head = [0u8; 8];
        s.read_exact(&mut head).await.unwrap();
        assert_eq!(&head[..2], &[4, 1]);
        let port = u16::from_be_bytes([head[2], head[3]]);
        let mut user = read_until(&mut s, b"\0").await;
        user.pop();
        let host = if head[4..7] == [0, 0, 0] && head[7] != 0 {
            let mut h = read_until(&mut s, b"\0").await;
            h.pop();
            String::from_utf8(h).unwrap()
        } else {
            Ipv4Addr::new(head[4], head[5], head[6], head[7]).to_string()
        };
        let _ = seen_tx.send(SocksRequest {
            user: Some(String::from_utf8(user).unwrap()).filter(|u| !u.is_empty()),
            password: None,
            host,
            port,
        });
        let mut reply = vec![0, code, 0, 0, 0, 0, 0, 0];
        if code == 90 {
            reply.extend_from_slice(BANNER);
        }
        s.write_all(&reply).await.unwrap();
        if code == 90 {
            echo(s).await;
        }
    });
    (addr, seen)
}

#[tokio::test]
async fn socks4_and_4a() {
    // SOCKS4: IPv4 literal, user id.
    let (addr, seen) = socks4_proxy(90).await;
    let mut o = opts();
    o.proxy = Some(proxy(ProxyKind::Socks4, addr, Some(("alice", CANARY_PW))));
    let (r, log) = connect(&HostPort::new("198.51.100.7", 21), &o).await;
    assert_tunnel(&mut r.unwrap()).await;
    assert_eq!(
        seen.await.unwrap(),
        SocksRequest {
            user: Some("alice".into()),
            password: None,
            host: "198.51.100.7".into(),
            port: 21
        }
    );
    assert_no_canary(&log);

    // SOCKS4a: the name goes to the proxy.
    let (addr, seen) = socks4_proxy(90).await;
    o.proxy = Some(proxy(ProxyKind::Socks4, addr, None));
    let (r, _) = connect(&HostPort::new("files.example.net", 2222), &o).await;
    assert_tunnel(&mut r.unwrap()).await;
    let req = seen.await.unwrap();
    assert_eq!(
        (req.host.as_str(), req.port, req.user),
        ("files.example.net", 2222, None)
    );

    // Rejected.
    let (addr, _seen) = socks4_proxy(91).await;
    o.proxy = Some(proxy(ProxyKind::Socks4, addr, None));
    let (r, _) = connect(&HostPort::new("h", 21), &o).await;
    assert!(matches!(r, Err(Error::Connection(_))), "{r:?}");

    // IPv6 can't be expressed.
    o.proxy = Some(proxy(ProxyKind::Socks4, addr, None));
    let (r, _) = connect(&HostPort::new("2001:db8::2", 21), &o).await;
    assert!(matches!(r, Err(Error::Unsupported(_))), "{r:?}");
}

fn assert_no_canary(log: &[String]) {
    for line in log {
        assert!(
            !line.contains("CANARY") && !line.contains(&http::base64(CANARY_PW.as_bytes())),
            "credential in log line {line:?}"
        );
    }
}

// --- direct connections, IPv6, timeouts, cancel ----------------------------

#[tokio::test]
async fn ipv4_literal_and_logs() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(echo_server(listener));
    let (r, log) = connect(&addr.into(), &opts()).await;
    let stream = r.unwrap();
    assert_eq!(stream.peer_addr().unwrap(), addr);
    assert!(stream.nodelay().unwrap());
    assert_eq!(
        local_addr_for(&stream).unwrap(),
        stream.local_addr().unwrap()
    );
    assert_eq!(
        log,
        [
            format!("Connecting to {addr}..."),
            "Connection established".into()
        ]
    );
}

async fn bind_v6() -> Option<TcpListener> {
    match TcpListener::bind("[::1]:0").await {
        Ok(l) => Some(l),
        Err(err) => {
            eprintln!("skipping: no IPv6 loopback ({err})");
            None
        }
    }
}

#[tokio::test]
async fn ipv6_loopback() {
    let Some(listener) = bind_v6().await else {
        return;
    };
    let addr = listener.local_addr().unwrap();
    tokio::spawn(echo_server(listener));
    let target = HostPort::from(addr);
    assert_eq!(target.to_string(), format!("[::1]:{}", addr.port()));
    let mut stream = connect(&target, &opts()).await.0.unwrap();
    assert_eq!(stream.peer_addr().unwrap(), addr);
    stream.write_all(b"x").await.unwrap();
    assert_eq!(stream.read_u8().await.unwrap(), b'x');
    // Bracketed input works too.
    let bracketed = HostPort::new("[::1]", addr.port());
    assert!(connect(&bracketed, &opts()).await.0.is_ok());
}

#[tokio::test]
async fn host_name_is_resolved_and_logged() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(echo_server(listener));
    // `localhost` may also resolve to ::1, where nothing listens: that attempt
    // fails and 127.0.0.1 is tried, whatever the preference.
    for prefer_ipv6 in [false, true] {
        let mut o = opts();
        o.prefer_ipv6 = prefer_ipv6;
        let (r, log) = connect(&HostPort::new("localhost", port), &o).await;
        let stream = r.unwrap();
        assert_eq!(
            stream.peer_addr().unwrap().ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(log[0], "Resolving address of localhost");
        assert_eq!(log.last().unwrap(), "Connection established");
    }
}

#[tokio::test]
async fn dual_stack_host_honours_the_preference() {
    let Some(v6) = bind_v6().await else {
        return;
    };
    let port = v6.local_addr().unwrap().port();
    let Ok(v4) = TcpListener::bind(("127.0.0.1", port)).await else {
        eprintln!("skipping: port {port} taken on 127.0.0.1");
        return;
    };
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host(("localhost", port))
        .await
        .map(Iterator::collect)
        .unwrap_or_default();
    if !(resolved.iter().any(SocketAddr::is_ipv4) && resolved.iter().any(SocketAddr::is_ipv6)) {
        eprintln!("skipping: localhost is not dual-stack here ({resolved:?})");
        return;
    }
    tokio::spawn(echo_server(v6));
    tokio::spawn(echo_server(v4));
    for prefer_ipv6 in [true, false] {
        let mut o = opts();
        o.prefer_ipv6 = prefer_ipv6;
        let stream = connect(&HostPort::new("localhost", port), &o)
            .await
            .0
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap().is_ipv6(), prefer_ipv6);
    }
}

#[tokio::test]
async fn falls_back_to_the_next_address() {
    let open = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let good = open.local_addr().unwrap();
    tokio::spawn(echo_server(open));
    let closed = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let (tx, mut rx) = bus();
    let stream = dial::connect_any(
        &[closed, good],
        &opts(),
        &CancellationToken::new(),
        &tx,
        SessionId::next(),
    )
    .await
    .unwrap();
    assert_eq!(stream.peer_addr().unwrap(), good);
    let log = logs(&mut rx);
    assert_eq!(log[0], format!("Connecting to {closed}..."));
    assert!(log.contains(&format!("Connecting to {good}...")), "{log:?}");
}

#[tokio::test]
async fn refused_everywhere_is_a_transient_connection_error() {
    let closed = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let (r, log) = connect(&closed.into(), &opts()).await;
    let err = r.unwrap_err();
    assert!(matches!(err, Error::Connection(_)), "{err:?}");
    assert!(err.is_transient());
    assert!(
        log.iter().any(|l| l.starts_with("Connection attempt to")),
        "{log:?}"
    );
}

#[tokio::test]
async fn unknown_host_fails_cleanly() {
    let (r, _) = connect(&HostPort::new("no-such-host.invalid", 21), &opts()).await;
    assert!(
        matches!(r, Err(Error::Connection(_) | Error::Timeout)),
        "{r:?}"
    );
}

/// A proxy that accepts and then never says anything.
async fn silent_proxy() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = listener.accept().await {
            held.push(s);
        }
    });
    addr
}

#[tokio::test]
async fn proxy_handshake_times_out() {
    for kind in [ProxyKind::Http, ProxyKind::Socks4, ProxyKind::Socks5] {
        let mut o = opts();
        o.timeout = Duration::from_millis(300);
        o.proxy = Some(proxy(kind, silent_proxy().await, None));
        let start = Instant::now();
        let (r, _) = connect(&HostPort::new("h", 21), &o).await;
        let took = start.elapsed();
        assert!(matches!(r, Err(Error::Timeout)), "{kind}: {r:?}");
        assert!(
            took >= o.timeout && took < o.timeout + SLACK,
            "{kind}: {took:?}"
        );
    }
}

#[tokio::test]
async fn cancel_aborts_a_proxy_handshake() {
    let mut o = opts();
    o.proxy = Some(proxy(ProxyKind::Socks5, silent_proxy().await, None));
    let cancel = CancellationToken::new();
    let (tx, _rx) = bus();
    let task = {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            connect_tcp(&HostPort::new("h", 22), &o, &cancel, &tx, SessionId::next()).await
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    let start = Instant::now();
    cancel.cancel();
    let r = task.await.unwrap();
    assert!(matches!(r, Err(Error::Cancelled)), "{r:?}");
    assert!(start.elapsed() < SLACK, "{:?}", start.elapsed());
}

/// A listener whose accept queue is full, so further connects hang (Linux
/// drops the SYN instead of refusing). Returns the address and the sockets
/// that must stay alive.
#[cfg(target_os = "linux")]
async fn hanging_address() -> Option<(SocketAddr, Vec<TcpStream>, tokio::net::TcpListener)> {
    let socket = tokio::net::TcpSocket::new_v4().ok()?;
    socket.bind("127.0.0.1:0".parse().ok()?).ok()?;
    let listener = socket.listen(1).ok()?;
    let addr = listener.local_addr().ok()?;
    let mut fillers = Vec::new();
    for _ in 0..16 {
        match tokio::time::timeout(Duration::from_millis(200), TcpStream::connect(addr)).await {
            Ok(Ok(s)) => fillers.push(s),
            Ok(Err(_)) => return None,
            Err(_) => return Some((addr, fillers, listener)),
        }
    }
    None
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn connect_attempt_times_out() {
    let Some((addr, _fillers, _listener)) = hanging_address().await else {
        eprintln!("skipping: could not fill the accept queue");
        return;
    };
    let mut o = opts();
    o.timeout = Duration::from_millis(300);
    let start = Instant::now();
    let (r, _) = connect(&addr.into(), &o).await;
    let took = start.elapsed();
    assert!(matches!(r, Err(Error::Timeout)), "{r:?}");
    assert!(took >= o.timeout && took < o.timeout + SLACK, "{took:?}");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn cancel_aborts_a_hanging_connect() {
    let Some((addr, _fillers, _listener)) = hanging_address().await else {
        eprintln!("skipping: could not fill the accept queue");
        return;
    };
    let cancel = CancellationToken::new();
    let (tx, _rx) = bus();
    let task = {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            connect_tcp(&addr.into(), &opts(), &cancel, &tx, SessionId::next()).await
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    let start = Instant::now();
    cancel.cancel();
    let r = task.await.unwrap();
    assert!(matches!(r, Err(Error::Cancelled)), "{r:?}");
    assert!(start.elapsed() < SLACK, "{:?}", start.elapsed());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn happy_eyeballs_starts_the_next_address_while_one_hangs() {
    let Some((hang, _fillers, _listener)) = hanging_address().await else {
        eprintln!("skipping: could not fill the accept queue");
        return;
    };
    let open = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let good = open.local_addr().unwrap();
    tokio::spawn(echo_server(open));
    let (tx, _rx) = bus();
    let start = Instant::now();
    let stream = dial::connect_any(
        &[hang, good],
        &opts(),
        &CancellationToken::new(),
        &tx,
        SessionId::next(),
    )
    .await
    .unwrap();
    assert_eq!(stream.peer_addr().unwrap(), good);
    let took = start.elapsed();
    assert!(
        took >= DEFAULT_ATTEMPT_DELAY && took < DEFAULT_ATTEMPT_DELAY + SLACK,
        "{took:?}"
    );
}

/// Needs a network that black-holes 10.255.255.1 (no route → refused fast on
/// some CI runners, hence ignored by default).
#[tokio::test]
#[ignore = "depends on the host network black-holing 10.255.255.1"]
async fn black_hole_times_out() {
    let mut o = opts();
    o.timeout = Duration::from_millis(500);
    let start = Instant::now();
    let (r, _) = connect(&HostPort::new("10.255.255.1", 21), &o).await;
    assert!(matches!(r, Err(Error::Timeout)), "{r:?}");
    assert!(start.elapsed() < o.timeout + SLACK);
}

// --- options and helpers -----------------------------------------------------

#[test]
fn opts_from_settings() {
    use crate::settings::{GenericProxy, ProxyServer};
    let mut s = Settings::default();
    s.connection.timeout_secs = 7;
    s.connection.prefer_ipv6 = true;
    s.connection.keepalive = false;
    s.proxy.generic = GenericProxy::Socks5(ProxyServer {
        host: "[fd00::1]".into(),
        port: 1080,
        user: Some("bob".into()),
        password_ref: Some("vault-item".into()),
    });
    let mut o = NetOpts::from_settings(&s);
    assert_eq!(o.timeout, Duration::from_secs(7));
    assert!(o.prefer_ipv6 && o.nodelay);
    assert_eq!(o.tcp_keepalive, None);
    assert_eq!(o.attempt_delay, DEFAULT_ATTEMPT_DELAY);
    let p = o.proxy.clone().unwrap();
    assert_eq!(p.kind, ProxyKind::Socks5);
    assert_eq!(p.server, HostPort::new("fd00::1", 1080));
    assert_eq!(p.auth.as_ref().unwrap().user, "bob");
    assert!(p.auth.as_ref().unwrap().password.is_none());

    o.set_proxy_password(CANARY_PW.into());
    let dbg = format!("{o:?}");
    assert!(!dbg.contains("CANARY"), "{dbg}");
    assert!(
        o.proxy
            .as_ref()
            .unwrap()
            .auth
            .as_ref()
            .unwrap()
            .password
            .is_some()
    );

    assert!(!o.clone().for_data().nodelay);
    assert!(o.clone().bypass_proxy(true).proxy.is_none());
    assert!(o.bypass_proxy(false).proxy.is_some());

    let d = NetOpts::default();
    assert_eq!(d.timeout, Duration::from_secs(20));
    assert_eq!(d.tcp_keepalive, Some(Duration::from_secs(30)));
    assert!(d.proxy.is_none());
}

#[test]
fn active_mode_through_a_proxy_is_unsupported() {
    let (tx, mut rx) = bus();
    let session = SessionId::next();
    assert!(ensure_active_mode_allowed(&NetOpts::default(), &tx, session).is_ok());
    let o = NetOpts {
        proxy: Some(proxy(
            ProxyKind::Http,
            "127.0.0.1:3128".parse().unwrap(),
            None,
        )),
        ..NetOpts::default()
    };
    let r = ensure_active_mode_allowed(&o, &tx, session);
    assert!(matches!(r, Err(Error::Unsupported(_))));
    let log = logs(&mut rx);
    assert_eq!(log.len(), 1);
    assert!(log[0].contains("Active mode"), "{log:?}");
}

#[test]
fn address_order() {
    let v4a: SocketAddr = "192.0.2.1:21".parse().unwrap();
    let v4b: SocketAddr = "192.0.2.2:21".parse().unwrap();
    let v6a: SocketAddr = "[2001:db8::1]:21".parse().unwrap();
    let v6b: SocketAddr = "[2001:db8::2]:21".parse().unwrap();
    let input = vec![v4a, v4b, v6a, v4a, v6b];
    assert_eq!(dial::order(input.clone(), false), [v4a, v6a, v4b, v6b]);
    assert_eq!(dial::order(input, true), [v6a, v4a, v6b, v4b]);
    assert_eq!(dial::order(vec![v4a, v4b], true), [v4a, v4b]);
    assert!(dial::order(Vec::new(), false).is_empty());
}

#[test]
fn host_port_parsing_and_display() {
    assert_eq!(HostPort::new("[::1]", 21).host, "::1");
    assert_eq!(HostPort::new("::1", 21).to_string(), "[::1]:21");
    assert_eq!(
        HostPort::new("example.com", 22).to_string(),
        "example.com:22"
    );
    let addr = crate::model::ServerAddress::new(crate::model::Protocol::Sftp, "h");
    assert_eq!(HostPort::from(&addr), HostPort::new("h", 22));
}

#[test]
fn base64_vectors() {
    // RFC 4648 §10.
    for (input, expected) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(http::base64(input.as_bytes()), expected);
    }
}

#[test]
fn http_status_lines() {
    assert!(http::check_status(b"HTTP/1.1 200 Connection established\r\n\r\n", false).is_ok());
    assert!(http::check_status(b"HTTP/1.0 204\r\n\r\n", false).is_ok());
    let err = http::check_status(b"HTTP/1.1 502 Bad \x1b[31mGateway\r\n\r\n", false).unwrap_err();
    assert_eq!(
        err.to_string(),
        "connection failed: HTTP proxy refused CONNECT: HTTP/1.1 502 Bad [31mGateway"
    );
    assert!(matches!(
        http::check_status(b"HTTP/1.1 407 x\r\n\r\n", true),
        Err(Error::Auth(_))
    ));
    assert!(http::check_status(b"SSH-2.0-x\r\n\r\n", false).is_err());
    assert!(http::check_status(b"HTTP/1.1 99999 x\r\n\r\n", false).is_err());
}

#[test]
fn socks_requests() {
    assert_eq!(
        socks::request_v5(&HostPort::new("ab", 258)).unwrap(),
        [5, 1, 0, 3, 2, b'a', b'b', 1, 2]
    );
    let long = "x".repeat(256);
    assert!(matches!(
        socks::request_v5(&HostPort::new(long, 1)),
        Err(Error::InvalidInput(_))
    ));
    assert_eq!(
        socks::request_v4(&HostPort::new("10.0.0.1", 21), None).unwrap(),
        [4, 1, 0, 21, 10, 0, 0, 1, 0]
    );
    assert_eq!(
        socks::request_v4(&HostPort::new("h", 21), None).unwrap(),
        [4, 1, 0, 21, 0, 0, 0, 1, 0, b'h', 0]
    );
    let auth = ProxyAuth {
        user: "u".into(),
        password: Some("pw".into()),
    };
    assert_eq!(
        socks::auth_request_v5(&auth).unwrap(),
        [1, 1, b'u', 2, b'p', b'w']
    );
    assert_eq!(socks::greeting_v5(Some(&auth)), [5, 2, 0, 2]);
    assert_eq!(socks::greeting_v5(None), [5, 1, 0]);
    assert!(socks::check_reply_v4(&[0, 90, 0, 0, 0, 0, 0, 0]).is_ok());
    assert!(socks::check_reply_v4(&[0, 92, 0, 0, 0, 0, 0, 0]).is_err());
    assert!(socks::check_reply_v4(&[5, 90, 0, 0, 0, 0, 0, 0]).is_err());
}

// --- parser robustness (fuzz bodies, T91) ------------------------------------

/// Run a handshake against a scripted proxy that answers `reply` (then end of
/// stream). Must never panic; on success, everything after the reply must
/// still be readable.
fn scripted<F, Fut>(reply: Vec<u8>, handshake: F)
where
    F: FnOnce(tokio::io::DuplexStream) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        server.write_all(&reply).await.unwrap();
        drop(server.shutdown().await);
        // Keep `server` alive so the client's writes don't fail.
        let _keep = server;
        tokio::time::timeout(Duration::from_secs(5), handshake(client))
            .await
            .unwrap();
    });
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn http_reply_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        scripted(data.clone(), |mut s| async move {
            if http::connect(&mut s, &HostPort::new("h", 21), None).await.is_ok() {
                let end = data.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4);
                let end2 = data.windows(2).position(|w| w == b"\n\n").map(|p| p + 2);
                let end = match (end, end2) {
                    (Some(a), Some(b)) => a.min(b),
                    (a, b) => a.or(b).unwrap(),
                };
                let mut rest = Vec::new();
                s.read_to_end(&mut rest).await.unwrap();
                assert_eq!(rest, data[end..]);
            }
        });
    }

    #[test]
    fn http_like_reply_never_panics(
        text in "(HTTP/1\\.[01] |[0-9]{1,5}| |OK|\r\n|\r|\n|:|[a-z]){0,40}",
    ) {
        scripted(text.into_bytes(), |mut s| async move {
            let _ = http::connect(&mut s, &HostPort::new("h", 21), None).await;
        });
    }

    #[test]
    fn socks5_reply_never_panics(data in proptest::collection::vec(any::<u8>(), 0..300), auth in any::<bool>()) {
        scripted(data, |mut s| async move {
            let auth = auth.then(|| ProxyAuth { user: "u".into(), password: None });
            let _ = socks::connect_v5(&mut s, &HostPort::new("h", 22), auth.as_ref()).await;
        });
    }

    #[test]
    fn socks5_success_prefix_never_panics(tail in proptest::collection::vec(any::<u8>(), 0..300)) {
        let mut data = vec![5, 0];
        data.extend_from_slice(&tail);
        scripted(data, |mut s| async move {
            let _ = socks::connect_v5(&mut s, &HostPort::new("h", 22), None).await;
        });
    }

    #[test]
    fn socks4_reply_never_panics(data in proptest::collection::vec(any::<u8>(), 0..16)) {
        scripted(data, |mut s| async move {
            let _ = socks::connect_v4(&mut s, &HostPort::new("h", 22), None).await;
        });
    }

    #[test]
    fn fuzz_proxy_reply_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        super::fuzz_proxy_reply(&data);
    }

    #[test]
    fn fuzz_proxy_reply_http_like_never_panics(
        first in any::<u8>(),
        text in "(HTTP/1\\.[01] |[0-9]{1,5}| |OK|\r\n|\r|\n|:|[a-z]){0,40}",
        tail in proptest::collection::vec(any::<u8>(), 0..32),
    ) {
        let mut data = vec![first & !0b11];
        data.extend_from_slice(text.as_bytes());
        data.extend_from_slice(&tail);
        super::fuzz_proxy_reply(&data);
    }
}

/// Fixed seeds for the `proxy_reply` fuzz target (one per handshake).
#[test]
fn fuzz_proxy_reply_seeds() {
    for seed in [
        &b"\x00HTTP/1.1 200 Connection established\r\n\r\nSSH-2.0-x\r\n"[..],
        b"\x80HTTP/1.0 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n",
        b"\x7cHTTP/1.1 503 \x1b[31mno\r\n\r\n",
        b"\x00HTTP/1.1 200 OK\n\nrest",
        b"\x01\x00\x5a\x00\x00\x00\x00\x00\x00",
        b"\x02\x05\x00\x05\x00\x00\x03\x04host\x00\x16",
        b"\x03\x05\x02\x01\x00\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x16",
        b"\x03\x05\x02\x01\x01",
        b"",
    ] {
        super::fuzz_proxy_reply(seed);
    }
}
