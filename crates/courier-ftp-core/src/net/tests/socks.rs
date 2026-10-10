//! SOCKS4/4a and SOCKS5 against in-process fake (and hostile) proxies.

use std::net::SocketAddr;

use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_util::sync::CancellationToken;

use super::{Recorded, echo, fake_proxy, opts, read_n, round_trip, session_log};
use crate::{
    Error,
    net::{HostPort, NetStream, ProxyConfig, ProxyCredentials, connect_tcp},
    secret::SecretString,
};

/// How the fake SOCKS5 proxy behaves.
#[derive(Clone, Default)]
struct Socks5Script {
    /// Required user/password (method 2), else method 0.
    auth: Option<(&'static str, &'static str)>,
    /// The CONNECT reply; `None` = `[5, 0, 0, 1, 0.0.0.0, 0]`.
    reply: Option<Vec<u8>>,
    /// Bytes sent right after the reply.
    early: Vec<u8>,
}

/// Reads a SOCKS5 CONNECT request; returns its bytes.
async fn read_socks5_request(s: &mut TcpStream) -> Vec<u8> {
    let mut req = read_n(s, 4).await;
    let rest = match req.get(3) {
        Some(1) => 4 + 2,
        Some(4) => 16 + 2,
        Some(3) => {
            let len = read_n(s, 1).await;
            req.extend_from_slice(&len);
            usize::from(len.first().copied().unwrap_or(0)) + 2
        }
        _ => 0,
    };
    req.extend(read_n(s, rest).await);
    req
}

/// A fake SOCKS5 proxy. Records `[greeting, auth?, request]` per connection (joined
/// with a `|` marker entry between them).
async fn socks5_proxy(script: Socks5Script) -> (SocketAddr, Recorded) {
    fake_proxy(move |mut s: TcpStream, _i, rec: Recorded| {
        let script = script.clone();
        async move {
            let head = read_n(&mut s, 2).await;
            if head.len() < 2 {
                return;
            }
            let greeting = [head.clone(), read_n(&mut s, usize::from(head[1])).await].concat();
            rec.lock().unwrap().push(greeting.clone());
            match script.auth {
                None => s.write_all(&[5, 0]).await.unwrap(),
                Some((user, pw)) => {
                    if !greeting[2..].contains(&2) {
                        s.write_all(&[5, 0xFF]).await.unwrap();
                        return;
                    }
                    s.write_all(&[5, 2]).await.unwrap();
                    let ver_ulen = read_n(&mut s, 2).await;
                    let u = read_n(&mut s, usize::from(ver_ulen[1])).await;
                    let plen = read_n(&mut s, 1).await;
                    let p = read_n(&mut s, usize::from(plen[0])).await;
                    rec.lock()
                        .unwrap()
                        .push([ver_ulen, u.clone(), plen, p.clone()].concat());
                    let ok = u == user.as_bytes() && p == pw.as_bytes();
                    s.write_all(&[1, if ok { 0 } else { 1 }]).await.unwrap();
                    if !ok {
                        return;
                    }
                }
            }
            let req = read_socks5_request(&mut s).await;
            rec.lock().unwrap().push(req);
            let reply = script
                .reply
                .clone()
                .unwrap_or_else(|| vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
            let success = reply.get(1) == Some(&0) && reply.len() >= 10;
            let _ = s.write_all(&[reply, script.early.clone()].concat()).await;
            if success {
                echo(s).await;
            }
        }
    })
    .await
}

fn socks5(addr: SocketAddr, auth: Option<(&str, &str)>) -> ProxyConfig {
    ProxyConfig::Socks5 {
        proxy: HostPort::new("127.0.0.1", addr.port()),
        auth: auth.map(|(u, p)| ProxyCredentials {
            user: u.into(),
            password: Some(SecretString::from(p)),
        }),
    }
}

async fn dial(target: &HostPort, proxy: ProxyConfig) -> Result<NetStream, Error> {
    let (log, _rx) = session_log();
    connect_tcp(target, &opts(proxy), CancellationToken::new(), &log).await
}

#[tokio::test]
async fn socks5_no_auth_domain_target() {
    let (proxy, rec) = socks5_proxy(Socks5Script {
        early: b"220 ready\r\n".to_vec(),
        ..Socks5Script::default()
    })
    .await;
    let mut s = dial(&HostPort::new("sftp.example.org", 22), socks5(proxy, None))
        .await
        .unwrap();
    let mut banner = vec![0_u8; 11];
    tokio::io::AsyncReadExt::read_exact(&mut s, &mut banner)
        .await
        .unwrap();
    assert_eq!(banner, b"220 ready\r\n");
    round_trip(&mut s, b"over socks5").await;
    assert!(s.is_proxied());
    let rec = rec.lock().unwrap().clone();
    assert_eq!(rec[0], [5, 1, 0]);
    let mut want = vec![5, 1, 0, 0x03, 16];
    want.extend(b"sftp.example.org");
    want.extend(22_u16.to_be_bytes());
    assert_eq!(rec[1], want, "target sent by name (ATYP 3)");
}

#[tokio::test]
async fn socks5_ip_literal_targets() {
    let (proxy, rec) = socks5_proxy(Socks5Script::default()).await;
    let _s = dial(&HostPort::new("192.0.2.9", 21), socks5(proxy, None))
        .await
        .unwrap();
    let _s = dial(&HostPort::new("2001:db8::1", 21), socks5(proxy, None))
        .await
        .unwrap();
    let rec = rec.lock().unwrap().clone();
    assert_eq!(rec[1], [5, 1, 0, 1, 192, 0, 2, 9, 0, 21]);
    assert_eq!(&rec[3][..4], [5, 1, 0, 4]);
    assert_eq!(rec[3].len(), 4 + 16 + 2);
}

#[tokio::test]
async fn socks5_user_password() {
    let (proxy, rec) = socks5_proxy(Socks5Script {
        auth: Some(("bob", "pw-1")),
        reply: Some({
            let mut r = vec![5, 0, 0, 3, 5];
            r.extend(b"bound");
            r.extend([0, 1]);
            r
        }),
        ..Socks5Script::default()
    })
    .await;
    let mut s = dial(
        &HostPort::new("ftp.example.com", 21),
        socks5(proxy, Some(("bob", "pw-1"))),
    )
    .await
    .unwrap();
    round_trip(&mut s, b"authenticated socks5").await;
    let rec = rec.lock().unwrap().clone();
    assert_eq!(rec[0], [5, 2, 0, 2]);
    assert_eq!(rec[1], [&[1_u8, 3][..], b"bob", &[4], b"pw-1"].concat());

    let err = dial(
        &HostPort::new("ftp.example.com", 21),
        socks5(proxy, Some(("bob", "wrong"))),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, Error::Proxy(m) if m == "authentication failed"),
        "{err:?}"
    );
    let err = dial(&HostPort::new("ftp.example.com", 21), socks5(proxy, None))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Proxy(m) if m == "authentication required (no acceptable method)"),
        "{err:?}"
    );
}

#[tokio::test]
async fn socks5_host_unreachable_message() {
    for (code, msg) in [
        (1, "general SOCKS server failure"),
        (2, "connection not allowed by the proxy's rules"),
        (4, "destination host unreachable"),
        (5, "connection refused by destination"),
        (8, "address type not supported"),
    ] {
        let (proxy, _) = socks5_proxy(Socks5Script {
            reply: Some(vec![5, code, 0, 1, 0, 0, 0, 0, 0, 0]),
            ..Socks5Script::default()
        })
        .await;
        let err = dial(&HostPort::new("h.example", 21), socks5(proxy, None))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Proxy(m) if m == msg),
            "{code}: {err:?}"
        );
    }
}

#[tokio::test]
async fn socks5_truncated_reply_is_proxy_error() {
    let hostile: [&[u8]; 4] = [
        &[5, 0, 0, 1, 127],              // cut short, then closed
        &[4, 0, 0, 1, 0, 0, 0, 0, 0, 0], // wrong version
        &[5, 0, 0, 7, 0, 0],             // unknown address type
        &[5, 0, 0, 3, 0, 0, 0],          // empty domain
    ];
    for reply in hostile {
        let (proxy, _) = socks5_proxy(Socks5Script {
            reply: Some(reply.to_vec()),
            ..Socks5Script::default()
        })
        .await;
        let err = dial(&HostPort::new("h.example", 21), socks5(proxy, None))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Proxy(_)), "{reply:?}: {err:?}");
    }
    // A method reply with the wrong version.
    let (proxy, _) = fake_proxy(|mut s: TcpStream, _i, _rec| async move {
        let _ = read_n(&mut s, 3).await;
        let _ = s.write_all(&[4, 0]).await;
    })
    .await;
    let err = dial(&HostPort::new("h.example", 21), socks5(proxy, None))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Proxy(m) if m == "invalid SOCKS reply (version 4)"),
        "{err:?}"
    );
}

#[tokio::test]
async fn socks5_rejects_overlong_fields() {
    let (proxy, _) = socks5_proxy(Socks5Script::default()).await;
    let err = dial(&HostPort::new("a".repeat(256), 21), socks5(proxy, None))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
    let long = "u".repeat(256);
    let err = dial(&HostPort::new("h", 21), socks5(proxy, Some((&long, "p"))))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
}

/// A fake SOCKS4 proxy answering `cd`; records the request (up to the final NUL(s)).
async fn socks4_proxy(cd: u8) -> (SocketAddr, Recorded) {
    fake_proxy(move |mut s: TcpStream, _i, rec: Recorded| async move {
        let mut req = read_n(&mut s, 8).await;
        let socks4a = req[4..7] == [0, 0, 0] && req[7] != 0;
        let mut nuls = if socks4a { 2 } else { 1 };
        while nuls > 0 {
            let b = read_n(&mut s, 1).await;
            let Some(&byte) = b.first() else { return };
            req.push(byte);
            if byte == 0 {
                nuls -= 1;
            }
        }
        rec.lock().unwrap().push(req);
        let _ = s.write_all(&[0, cd, 0, 0, 0, 0, 0, 0]).await;
        if cd == 0x5A {
            echo(s).await;
        }
    })
    .await
}

fn socks4(addr: SocketAddr, user: &str) -> ProxyConfig {
    ProxyConfig::Socks4 {
        proxy: HostPort::new("127.0.0.1", addr.port()),
        user: user.into(),
    }
}

#[tokio::test]
async fn socks4a_hostname_target() {
    let (proxy, rec) = socks4_proxy(0x5A).await;
    let mut s = dial(&HostPort::new("ftp.example.com", 21), socks4(proxy, "me"))
        .await
        .unwrap();
    round_trip(&mut s, b"over socks4a").await;
    let want = [
        &[4_u8, 1, 0, 21, 0, 0, 0, 1][..],
        b"me\0",
        b"ftp.example.com\0",
    ]
    .concat();
    assert_eq!(rec.lock().unwrap()[0], want);
}

#[tokio::test]
async fn socks4_ipv4_target() {
    let (proxy, rec) = socks4_proxy(0x5A).await;
    let mut s = dial(&HostPort::new("192.0.2.33", 990), socks4(proxy, ""))
        .await
        .unwrap();
    round_trip(&mut s, b"over socks4").await;
    assert_eq!(rec.lock().unwrap()[0], [4, 1, 3, 222, 192, 0, 2, 33, 0]);
}

#[tokio::test]
async fn socks4_ipv6_target_unsupported() {
    let (proxy, rec) = socks4_proxy(0x5A).await;
    let err = dial(&HostPort::new("2001:db8::1", 21), socks4(proxy, ""))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Unsupported(m) if m == "SOCKS4 cannot connect to IPv6 addresses"),
        "{err:?}"
    );
    assert!(
        rec.lock().unwrap().is_empty(),
        "the proxy is not even dialled"
    );
}

#[tokio::test]
async fn socks4_rejected_reply() {
    for cd in [0x5B, 0x5C, 0x5D] {
        let (proxy, _) = socks4_proxy(cd).await;
        let err = dial(&HostPort::new("192.0.2.1", 21), socks4(proxy, ""))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Proxy(m) if *m == format!("request rejected ({cd})")),
            "{err:?}"
        );
    }
    let (proxy, _) = socks4_proxy(0x42).await;
    let err = dial(&HostPort::new("192.0.2.1", 21), socks4(proxy, ""))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Proxy(m) if m == "invalid SOCKS4 reply"),
        "{err:?}"
    );
}
