//! Pure unit tests: addresses, request/response formats, proxy settings.

use std::net::SocketAddr;

use pretty_assertions::assert_eq;

use super::super::{
    HostPort, MAX_HEADER_BYTES, ProxyConfig, ProxyCredentials, SocketAddrOrDomain, Socks5Reply,
    SocksError,
    dial::order_addrs,
    http_connect::{HttpConnectError, connect_request},
    interleave, parse_connect_response, parse_socks4_reply, parse_socks5_auth_reply,
    parse_socks5_connect_reply, parse_socks5_method_reply,
};
use crate::{
    Error,
    secret::SecretString,
    settings::{GenericProxySettings, ProxyKind},
};

fn v4(last: u8) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, last], 21))
}

fn v6(last: u16) -> SocketAddr {
    SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, last], 21))
}

#[test]
fn interleave_ipv4_first_by_default() {
    let (v4a, v4b, v6a, v6b) = (v4(1), v4(2), v6(1), v6(2));
    assert_eq!(
        interleave(&[v4a, v4b, v6a, v6b], false),
        [v4a, v6a, v4b, v6b]
    );
    assert_eq!(
        order_addrs(&[v4a, v4b, v6a, v6b], false, true, "h").unwrap(),
        [v4a, v6a, v4b, v6b]
    );
    assert_eq!(interleave(&[v6a, v6b, v4a], false), [v4a, v6a, v6b]);
    assert!(interleave(&[], false).is_empty());
}

#[test]
fn interleave_ipv6_first_when_preferred() {
    let (v4a, v4b, v6a, v6b) = (v4(1), v4(2), v6(1), v6(2));
    assert_eq!(
        interleave(&[v4a, v4b, v6a, v6b], true),
        [v6a, v4a, v6b, v4b]
    );
    assert_eq!(
        order_addrs(&[v4a, v4b, v6a, v6b], true, true, "h").unwrap(),
        [v6a, v4a, v6b, v4b]
    );
    assert_eq!(interleave(&[v4a, v4b], true), [v4a, v4b]);
}

#[test]
fn ipv6_disabled_filters_addresses() {
    let (v4a, v4b, v6a, v6b) = (v4(1), v4(2), v6(1), v6(2));
    for prefer in [false, true] {
        assert_eq!(
            order_addrs(&[v6a, v4a, v6b, v4b], prefer, false, "h").unwrap(),
            [v4a, v4b]
        );
    }
    let err = order_addrs(&[v6a, v6b], false, false, "only6.example").unwrap_err();
    assert!(
        matches!(&err, Error::Connection(m) if m == "no IPv4 address for only6.example and IPv6 is disabled"),
        "{err:?}"
    );
}

#[test]
fn host_port_parse_and_authority() {
    let hp = HostPort::parse("[::1]:21").unwrap();
    assert_eq!(hp, HostPort::new("::1", 21));
    assert_eq!(hp.authority(), "[::1]:21");
    assert_eq!(HostPort::new("[::1]", 21), hp);
    let hp = HostPort::parse("ftp.example.com:2121").unwrap();
    assert_eq!(hp.authority(), "ftp.example.com:2121");
    assert_eq!(HostPort::parse("10.0.0.1:1080").unwrap().host, "10.0.0.1");
    assert_eq!(HostPort::parse(" h:22 ").unwrap().authority(), "h:22");
    for bad in [
        "h:0", "h", ":21", "::1:21", "[::1]", "[::1]21", "h:99999", "h:x", "",
    ] {
        assert_eq!(HostPort::parse(bad), None, "{bad}");
    }
}

#[test]
fn connect_request_format() {
    let plain = connect_request(&HostPort::new("ftp.example.com", 21), None).unwrap();
    assert_eq!(
        plain.as_str(),
        "CONNECT ftp.example.com:21 HTTP/1.1\r\nHost: ftp.example.com:21\r\n\r\n"
    );
    let pw = SecretString::from("pass");
    let auth = connect_request(&HostPort::new("2001:db8::1", 990), Some(("user", &pw))).unwrap();
    // base64("user:pass") = dXNlcjpwYXNz
    assert_eq!(
        auth.as_str(),
        "CONNECT [2001:db8::1]:990 HTTP/1.1\r\nHost: [2001:db8::1]:990\r\n\
         Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n"
    );
    let err = connect_request(&HostPort::new("h", 21), Some(("a:b", &pw))).unwrap_err();
    assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
}

#[test]
fn parse_connect_response_table() {
    let ok = parse_connect_response(b"HTTP/1.1 200 Connection established\r\n\r\n").unwrap();
    assert_eq!(
        (ok.code, ok.reason.as_str(), ok.header_len),
        (200, "Connection established", 39)
    );
    let head = b"HTTP/1.0 200 OK\r\nVia: x\r\n\r\n220 hi\r\n";
    let ok = parse_connect_response(head).unwrap();
    assert_eq!(&head[ok.header_len..], b"220 hi\r\n");
    let auth = parse_connect_response(
        b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n",
    )
    .unwrap();
    assert_eq!(auth.code, 407);
    let bare = parse_connect_response(b"HTTP/1.1 204\r\n\r\n").unwrap();
    assert_eq!((bare.code, bare.reason.as_str()), (204, ""));
    for bad in [
        &b"HTTP/2 200\r\n\r\n"[..],
        b"HTTP/1.1 20\r\n\r\n",
        b"HTTP/1.1 2000 x\r\n\r\n",
        b"HTTP/1.1 099 x\r\n\r\n",
        b"SSH-2.0-x\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n",
    ] {
        assert!(
            matches!(
                parse_connect_response(bad),
                Err(HttpConnectError::Malformed(_))
            ),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
    let mut huge = b"HTTP/1.1 200 OK\r\n".to_vec();
    huge.resize(MAX_HEADER_BYTES + 1, b'a');
    assert!(matches!(
        parse_connect_response(&huge),
        Err(HttpConnectError::HeadersTooLarge)
    ));
    huge.extend_from_slice(b"\r\n\r\n");
    assert!(matches!(
        parse_connect_response(&huge),
        Err(HttpConnectError::HeadersTooLarge)
    ));
    let esc = parse_connect_response(
        format!("HTTP/1.1 403 \x1b[31mNo\x07 way{}\r\n\r\n", "x".repeat(200)).as_bytes(),
    )
    .unwrap();
    assert!(esc.reason.starts_with("[31mNo way"), "{}", esc.reason);
    assert_eq!(esc.reason.len(), 80);
    assert!(
        esc.reason
            .bytes()
            .all(|b| b.is_ascii_graphic() || b == b' ')
    );
}

fn generic(kind: ProxyKind, port: u16, user: &str) -> GenericProxySettings {
    GenericProxySettings {
        kind,
        host: "proxy.example".into(),
        port,
        user: user.into(),
        password_ref: None,
    }
}

#[test]
fn proxy_config_from_settings() {
    let none = generic(ProxyKind::None, 0, "");
    assert!(matches!(
        ProxyConfig::from_settings(&none, false, None).unwrap(),
        ProxyConfig::Direct
    ));
    let http = generic(ProxyKind::Http, 0, "");
    assert!(matches!(
        ProxyConfig::from_settings(&http, true, None).unwrap(),
        ProxyConfig::Direct
    ));
    match ProxyConfig::from_settings(&http, false, None).unwrap() {
        ProxyConfig::Http { proxy, auth: None } => {
            assert_eq!(proxy, HostPort::new("proxy.example", 8080));
        }
        other => panic!("{other:?}"),
    }
    match ProxyConfig::from_settings(&generic(ProxyKind::Socks5, 0, "u"), false, Some("p".into()))
        .unwrap()
    {
        ProxyConfig::Socks5 {
            proxy,
            auth: Some(a),
        } => {
            assert_eq!(proxy.port, 1080);
            assert_eq!(a.user, "u");
            assert_eq!(a.password.unwrap().expose(), "p");
        }
        other => panic!("{other:?}"),
    }
    match ProxyConfig::from_settings(&generic(ProxyKind::Socks4, 1081, "id"), false, None).unwrap()
    {
        ProxyConfig::Socks4 { proxy, user } => {
            assert_eq!((proxy.port, user.as_str()), (1081, "id"));
        }
        other => panic!("{other:?}"),
    }
    let colon = generic(ProxyKind::Http, 3128, "a:b");
    assert!(matches!(
        ProxyConfig::from_settings(&colon, false, None),
        Err(Error::InvalidInput(_))
    ));
    let mut no_host = generic(ProxyKind::Socks5, 0, "");
    no_host.host = "  ".into();
    assert!(matches!(
        ProxyConfig::from_settings(&no_host, false, None),
        Err(Error::InvalidInput(_))
    ));
}

#[test]
fn allows_inbound_only_direct() {
    let p = || HostPort::new("proxy", 1);
    assert!(ProxyConfig::Direct.allows_inbound());
    for cfg in [
        ProxyConfig::Http {
            proxy: p(),
            auth: None,
        },
        ProxyConfig::Socks4 {
            proxy: p(),
            user: String::new(),
        },
        ProxyConfig::Socks5 {
            proxy: p(),
            auth: None,
        },
    ] {
        assert!(!cfg.allows_inbound(), "{}", cfg.kind());
    }
    assert_eq!(ProxyConfig::Direct.kind(), "direct");
}

#[test]
fn proxy_config_debug_redacted() {
    let creds = || {
        Some(ProxyCredentials {
            user: "alice".into(),
            password: Some(SecretString::from("CANARY-PW-net-7f3a")),
        })
    };
    for cfg in [
        ProxyConfig::Http {
            proxy: HostPort::new("p", 1),
            auth: creds(),
        },
        ProxyConfig::Socks5 {
            proxy: HostPort::new("p", 1),
            auth: creds(),
        },
    ] {
        let dbg = format!("{cfg:?} {cfg:#?}");
        assert!(!dbg.contains("CANARY"), "{dbg}");
        assert!(dbg.contains("[REDACTED]") && dbg.contains("alice"), "{dbg}");
    }
}

#[test]
fn socks_parsers_table() {
    // Partial input → need more.
    assert_eq!(parse_socks5_method_reply(&[]), Ok(None));
    assert_eq!(parse_socks5_method_reply(&[5]), Ok(None));
    assert_eq!(parse_socks5_auth_reply(&[1]), Ok(None));
    assert_eq!(parse_socks4_reply(&[0, 0x5A, 0, 21]), Ok(None));
    for n in 0..10 {
        assert_eq!(
            parse_socks5_connect_reply(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 21][..n]),
            Ok(None),
            "{n}"
        );
    }
    // Complete replies.
    assert_eq!(parse_socks5_method_reply(&[5, 2, 9]), Ok(Some((2, 2))));
    assert_eq!(
        parse_socks5_method_reply(&[5, 0xFF]),
        Err(SocksError::NoAcceptableMethod)
    );
    assert_eq!(parse_socks5_auth_reply(&[1, 0]), Ok(Some((true, 2))));
    assert_eq!(parse_socks5_auth_reply(&[1, 1]), Ok(Some((false, 2))));
    assert_eq!(
        parse_socks5_connect_reply(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 21, 0xAA]),
        Ok(Some((
            Socks5Reply {
                code: 0,
                bound: SocketAddrOrDomain::Addr(SocketAddr::from(([127, 0, 0, 1], 21)))
            },
            10
        )))
    );
    let mut v6 = vec![5, 4, 0, 4];
    v6.extend([0; 15]);
    v6.extend([1, 0x04, 0x38]);
    assert_eq!(
        parse_socks5_connect_reply(&v6),
        Ok(Some((
            Socks5Reply {
                code: 4,
                bound: SocketAddrOrDomain::Addr("[::1]:1080".parse().unwrap())
            },
            22
        )))
    );
    let mut dom = vec![5, 0, 0, 3, 11];
    dom.extend(b"example.com");
    dom.extend([0, 21]);
    assert_eq!(
        parse_socks5_connect_reply(&dom),
        Ok(Some((
            Socks5Reply {
                code: 0,
                bound: SocketAddrOrDomain::Domain("example.com".into(), 21)
            },
            18
        )))
    );
    assert_eq!(
        parse_socks5_connect_reply(&dom[..17]),
        Ok(None),
        "domain cut short"
    );
    assert_eq!(
        parse_socks4_reply(&[0, 0x5A, 0, 21, 1, 2, 3, 4]),
        Ok(Some((0x5A, 8)))
    );
    assert_eq!(
        parse_socks4_reply(&[0, 0x5B, 0, 0, 0, 0, 0, 0]),
        Ok(Some((0x5B, 8)))
    );
    // Errors.
    assert_eq!(
        parse_socks5_method_reply(&[4, 0]),
        Err(SocksError::BadVersion(4))
    );
    assert_eq!(
        parse_socks5_auth_reply(&[2, 0]),
        Err(SocksError::BadVersion(2))
    );
    assert_eq!(
        parse_socks5_connect_reply(&[4, 0, 0, 1]),
        Err(SocksError::BadVersion(4))
    );
    assert_eq!(
        parse_socks4_reply(&[4, 0x5A]),
        Err(SocksError::BadVersion(4))
    );
    assert_eq!(
        parse_socks4_reply(&[0, 0x10]),
        Err(SocksError::ReplyCode(0x10))
    );
    assert!(matches!(
        parse_socks5_connect_reply(&[5, 0, 0, 9, 0, 0]),
        Err(SocksError::Malformed(_))
    ));
    // Domain length field 0, and a domain that is not UTF-8.
    assert!(matches!(
        parse_socks5_connect_reply(&[5, 0, 0, 3, 0, 0, 21]),
        Err(SocksError::Malformed(_))
    ));
    assert!(matches!(
        parse_socks5_connect_reply(&[5, 0, 0, 3, 2, 0xFF, 0xFE, 0, 21]),
        Err(SocksError::Malformed(_))
    ));
}
