//! T07 end to end: `courier_ftp_core::net::connect_tcp` through the squid (HTTP
//! CONNECT) and dante (SOCKS4/5) containers to the sshd and ftpd fixtures. Every test
//! is `#[ignore]` and starts with `require_docker!()`; run with `COURIER_E2E=1 cargo
//! test -p courier-ftp-e2e --test net_proxies -- --ignored`.
//!
//! These check the byte stream (the server banner arrives through each proxy kind);
//! the SFTP/FTP conformance subsets through the proxies (`proxies.rs`) come with the
//! backends (T14, T22).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use courier_ftp_core::{
    Error,
    events::{SessionId, SessionLog, channel},
    net::{
        CancellationToken, HostPort, NetOpts, NetStream, ProxyConfig, ProxyCredentials, Purpose,
        connect_tcp,
    },
    secret::SecretString,
    settings::DebugLevel,
};
use courier_ftp_e2e::{
    Ftpd, FtpdOptions, FtpdProfile, ProxyProfile, ProxyServer, Sshd, SshdOptions, SshdProfile,
    TestNetwork,
    keys::{PROXY_PASSWORD, PROXY_USER},
    require_docker,
};
use tokio::io::AsyncReadExt;

fn proxy_config(proxy: &ProxyServer) -> ProxyConfig {
    let addr = HostPort::new(proxy.host(), proxy.profile().port());
    let auth = || {
        Some(ProxyCredentials {
            user: PROXY_USER.into(),
            password: Some(SecretString::from(PROXY_PASSWORD)),
        })
    };
    match proxy.profile() {
        ProxyProfile::Http => ProxyConfig::Http {
            proxy: addr,
            auth: None,
        },
        ProxyProfile::HttpAuth => ProxyConfig::Http {
            proxy: addr,
            auth: auth(),
        },
        ProxyProfile::Socks4 => ProxyConfig::Socks4 {
            proxy: addr,
            user: "e2e".into(),
        },
        ProxyProfile::Socks5 => ProxyConfig::Socks5 {
            proxy: addr,
            auth: None,
        },
        ProxyProfile::Socks5Auth => ProxyConfig::Socks5 {
            proxy: addr,
            auth: auth(),
        },
    }
}

async fn dial(target: &HostPort, proxy: ProxyConfig) -> Result<NetStream, Error> {
    let (events, _rx) = channel(DebugLevel::Debug);
    let log = SessionLog {
        events,
        session: SessionId::next(),
    };
    let opts = NetOpts {
        timeout: Duration::from_secs(20),
        prefer_ipv6: false,
        allow_ipv6: true,
        purpose: Purpose::Control,
        socket_buffer: None,
        proxy,
    };
    connect_tcp(target, &opts, CancellationToken::new(), &log).await
}

/// Reads until `\n` (the first line of the banner).
async fn first_line(s: &mut NetStream) -> String {
    let mut out = Vec::new();
    let mut b = [0_u8; 1];
    while !out.ends_with(b"\n") {
        let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut b))
            .await
            .unwrap()
            .unwrap();
        if n == 0 {
            break;
        }
        out.push(b[0]);
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn ssh_banner_through_every_proxy_profile() {
    require_docker!();
    let net = TestNetwork::new().await.unwrap();
    let sshd = Sshd::start_with(SshdOptions {
        network: Some(net.name().into()),
        ..SshdOptions::new(SshdProfile::Password)
    })
    .await
    .unwrap();
    let target = HostPort::new(sshd.host(), 22);
    for profile in ProxyProfile::ALL {
        let proxy = ProxyServer::start(profile, &net).await.unwrap();
        let mut s = dial(&target, proxy_config(&proxy)).await.unwrap();
        assert!(s.is_proxied());
        assert_eq!(s.target_ip(), None);
        let banner = first_line(&mut s).await;
        assert!(
            banner.starts_with("SSH-2.0-"),
            "{}: {banner:?}",
            profile.name()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn ftp_banner_through_http_and_socks5() {
    require_docker!();
    let net = TestNetwork::new().await.unwrap();
    let ftpd = Ftpd::start_with(FtpdOptions {
        network: Some(net.name().into()),
        ..FtpdOptions::new(FtpdProfile::VsftpdPlain)
    })
    .await
    .unwrap();
    let target = HostPort::new(ftpd.host(), 21);
    for profile in [ProxyProfile::HttpAuth, ProxyProfile::Socks5Auth] {
        let proxy = ProxyServer::start(profile, &net).await.unwrap();
        let cfg = proxy_config(&proxy);
        assert!(!cfg.allows_inbound());
        let mut s = dial(&target, cfg).await.unwrap();
        let banner = first_line(&mut s).await;
        assert!(banner.starts_with("220"), "{}: {banner:?}", profile.name());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn proxy_auth_failures_are_proxy_errors() {
    require_docker!();
    let net = TestNetwork::new().await.unwrap();
    let sshd = Sshd::start_with(SshdOptions {
        network: Some(net.name().into()),
        ..SshdOptions::new(SshdProfile::Password)
    })
    .await
    .unwrap();
    let target = HostPort::new(sshd.host(), 22);
    for profile in [ProxyProfile::HttpAuth, ProxyProfile::Socks5Auth] {
        let proxy = ProxyServer::start(profile, &net).await.unwrap();
        let addr = HostPort::new(proxy.host(), profile.port());
        let wrong = Some(ProxyCredentials {
            user: PROXY_USER.into(),
            password: Some(SecretString::from("wrong-password")),
        });
        let cfg = match profile {
            ProxyProfile::HttpAuth => ProxyConfig::Http {
                proxy: addr,
                auth: wrong,
            },
            _ => ProxyConfig::Socks5 {
                proxy: addr,
                auth: wrong,
            },
        };
        let err = dial(&target, cfg).await.unwrap_err();
        assert!(
            matches!(err, Error::Proxy(_)),
            "{}: {err:?}",
            profile.name()
        );
    }
}
