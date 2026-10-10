//! Container fixture self-tests (T76). Every test is `#[ignore]` and starts with
//! `require_docker!()`; run with `COURIER_E2E=1 cargo test -p courier-ftp-e2e
//! --test harness_docker -- --ignored`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use courier_ftp_e2e::{
    CertVariant, Ftpd, FtpdOptions, FtpdProfile, ProxyProfile, ProxyServer, Sshd, SshdOptions,
    SshdProfile, TestNetwork, Toxiproxy, diag,
    files::{FIXTURE_TREE, fixture_sha256},
    hostile::MiniFtpClient,
    keys::{FixtureKey, PASSWORD, USER},
    require_docker,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SSH_OPTS: &str = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                        -o LogLevel=ERROR -o ConnectTimeout=5";

/// `ls` of `~/fixtures` over SFTP from inside the container, with the password or the
/// ed25519 fixture key; `None` when the profile takes neither (kbd).
async fn sftp_ls_inside(sshd: &Sshd) -> Option<String> {
    let profile = sshd.profile();
    let mut opts = SSH_OPTS.to_owned();
    if profile == SshdProfile::Legacy {
        opts.push_str(
            " -o KexAlgorithms=diffie-hellman-group14-sha1 -o HostKeyAlgorithms=ssh-rsa \
             -o Ciphers=aes128-cbc -o MACs=hmac-sha1",
        );
    }
    let cmd = match profile {
        SshdProfile::Kbd => return None,
        SshdProfile::Key | SshdProfile::MaxAuth2 => {
            let key = std::fs::read_to_string(FixtureKey::Ed25519.path()).unwrap();
            format!(
                "cat > /tmp/k <<'KEY'\n{key}KEY\nchmod 600 /tmp/k\n\
                 echo 'ls fixtures' | sftp {opts} -i /tmp/k -b - {USER}@127.0.0.1"
            )
        }
        _ => format!(
            "echo 'ls fixtures' | sshpass -p {PASSWORD} sftp {opts} \
             -o PubkeyAuthentication=no -b - {USER}@127.0.0.1"
        ),
    };
    let out = sshd.exec_root(&cmd).await.unwrap();
    assert!(out.success(), "{profile:?}: {out:?}");
    Some(out.stdout)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn sshd_profiles_start_and_accept_password() {
    require_docker!();
    for profile in SshdProfile::ALL {
        let sshd = Sshd::start(profile).await.unwrap();
        assert!(sshd.host_keys().await.unwrap().len() >= 3);
        assert!(
            sshd.host_fingerprint("ed25519")
                .await
                .unwrap()
                .starts_with("SHA256:")
        );
        if let Some(listing) = sftp_ls_inside(&sshd).await {
            assert!(listing.contains("small.bin"), "{profile:?}: {listing}");
        }
        let sha = sshd
            .sha256_of(&format!("/home/{USER}/fixtures/small.bin"))
            .await
            .unwrap();
        assert_eq!(Some(sha), fixture_sha256("small.bin"), "{profile:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn sshd_regenerate_host_key_changes_it() {
    require_docker!();
    let sshd = Sshd::start(SshdProfile::Password).await.unwrap();
    let before = sshd.host_keys().await.unwrap();
    let after = sshd.regenerate_host_key().await.unwrap();
    assert_ne!(before[0], after[0]);
}

async fn ftp_login(ftpd: &Ftpd, client: &mut MiniFtpClient) -> String {
    if ftpd.profile() == FtpdProfile::VsftpdAnonymous {
        client.login("anonymous", "e2e@example.com").await.unwrap()
    } else {
        client.login(USER, PASSWORD).await.unwrap()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn ftpd_profiles_start_and_greet() {
    require_docker!();
    for profile in FtpdProfile::ALL {
        let ftpd = Ftpd::start(profile).await.unwrap();
        if profile == FtpdProfile::VsftpdImplicitTls {
            continue; // TLS from the first byte; the TCP accept was the readiness check.
        }
        let mut c = MiniFtpClient::connect(ftpd.addr()).await.unwrap();
        assert!(c.greeting.starts_with("220"), "{profile:?}: {}", c.greeting);
        let tls_required = matches!(
            profile,
            FtpdProfile::VsftpdExplicitTls
                | FtpdProfile::VsftpdTlsReuse
                | FtpdProfile::ProftpdExplicitTls
                | FtpdProfile::PureftpdExplicitTls
        );
        if tls_required {
            let r = c.cmd("AUTH TLS").await.unwrap();
            assert!(r.starts_with("234"), "{profile:?}: {r}");
            continue;
        }
        let r = ftp_login(&ftpd, &mut c).await;
        assert!(r.starts_with("230"), "{profile:?}: {r}");
        if matches!(
            profile,
            FtpdProfile::VsftpdActiveOnly
                | FtpdProfile::VsftpdPasvUnreachable
                | FtpdProfile::VsftpdMaxConn1
        ) {
            continue;
        }
        let dir = if profile == FtpdProfile::VsftpdAnonymous {
            "/"
        } else {
            "/fixtures"
        };
        assert!(
            c.cmd(&format!("CWD {dir}"))
                .await
                .unwrap()
                .starts_with("250")
        );
        let (listing, done) = c.pasv_transfer("LIST").await.unwrap();
        assert!(done.starts_with("226"), "{profile:?}: {done}");
        let listing = String::from_utf8_lossy(&listing);
        let want = if profile == FtpdProfile::VsftpdAnonymous {
            "readme.txt"
        } else {
            "small.bin"
        };
        assert!(listing.contains(want), "{profile:?}: {listing}");
        if profile.has_mlsd() {
            let (mlsd, _) = c.pasv_transfer("MLSD").await.unwrap();
            assert!(
                String::from_utf8_lossy(&mlsd).contains("type=file"),
                "{profile:?}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn ftpd_fixture_tree_matches_files() {
    require_docker!();
    let ftpd = Ftpd::start(FtpdProfile::VsftpdPlain).await.unwrap();
    for (path, _) in FIXTURE_TREE {
        let remote = format!("/home/{USER}/fixtures/{path}");
        assert_eq!(
            Some(ftpd.sha256_of(&remote).await.unwrap()),
            fixture_sha256(path),
            "{path}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn ftpd_set_cert_keeps_ip() {
    require_docker!();
    let ftpd = Ftpd::start(FtpdProfile::VsftpdExplicitTls).await.unwrap();
    let ip = ftpd.ip();
    let before = ftpd.cert_der().await.unwrap();
    ftpd.set_cert(CertVariant::SelfSigned).await.unwrap();
    let after = ftpd.cert_der().await.unwrap();
    assert_ne!(before, after);
    assert_eq!(ftpd.ip(), ip);
    let mut c = MiniFtpClient::connect(ftpd.addr()).await.unwrap();
    assert!(c.cmd("AUTH TLS").await.unwrap().starts_with("234"));
}

/// The first reply bytes of a proxy handshake.
async fn proxy_handshake(proxy: &ProxyServer, target: std::net::SocketAddr) -> Vec<u8> {
    let mut s = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
    match proxy.profile() {
        ProxyProfile::Http | ProxyProfile::HttpAuth => {
            let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
            s.write_all(req.as_bytes()).await.unwrap();
        }
        ProxyProfile::Socks4 => {
            let std::net::IpAddr::V4(ip) = target.ip() else {
                panic!("IPv4 target expected")
            };
            let mut req = vec![4, 1];
            req.extend(target.port().to_be_bytes());
            req.extend(ip.octets());
            req.extend(b"e2e\0");
            s.write_all(&req).await.unwrap();
        }
        ProxyProfile::Socks5 | ProxyProfile::Socks5Auth => {
            s.write_all(&[5, 2, 0, 2]).await.unwrap();
        }
    }
    let mut buf = vec![0_u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    buf.truncate(n);
    buf
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn proxy_profiles_start() {
    require_docker!();
    let net = TestNetwork::new().await.unwrap();
    let sshd = Sshd::start_with(SshdOptions {
        network: Some(net.name().into()),
        ..SshdOptions::new(SshdProfile::Password)
    })
    .await
    .unwrap();
    for profile in ProxyProfile::ALL {
        let proxy = ProxyServer::start(profile, &net).await.unwrap();
        let reply = proxy_handshake(&proxy, sshd.addr()).await;
        let text = String::from_utf8_lossy(&reply);
        match profile {
            ProxyProfile::Http => assert!(text.starts_with("HTTP/1.1 200"), "{text}"),
            ProxyProfile::HttpAuth => assert!(text.starts_with("HTTP/1.1 407"), "{text}"),
            ProxyProfile::Socks4 => assert_eq!(reply.get(1), Some(&0x5a), "{reply:?}"),
            ProxyProfile::Socks5 => assert_eq!(reply, [5, 0]),
            ProxyProfile::Socks5Auth => assert_eq!(reply, [5, 2]),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn toxiproxy_cuts_connection() {
    require_docker!();
    let net = TestNetwork::new().await.unwrap();
    let ftpd = Ftpd::start_with(FtpdOptions {
        network: Some(net.name().into()),
        ..FtpdOptions::new(FtpdProfile::VsftpdPlain)
    })
    .await
    .unwrap();
    let toxi = Toxiproxy::start(&net).await.unwrap();
    let control = toxi.proxy("control", 2121, ftpd.addr()).await.unwrap();
    let c = MiniFtpClient::connect(control.addr()).await.unwrap();
    assert!(c.greeting.starts_with("220"));
    // Cut after 10 bytes downstream: the greeting arrives truncated, then EOF.
    control
        .add("cut", courier_ftp_e2e::Toxic::LimitData { bytes: 10 })
        .await
        .unwrap();
    let mut s = tokio::net::TcpStream::connect(control.addr())
        .await
        .unwrap();
    let mut all = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut all))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(all.len(), 10, "{all:?}");
    control.remove("cut").await.unwrap();
    control.disable().await.unwrap();
    assert!(MiniFtpClient::connect(control.addr()).await.is_err());
    control.enable().await.unwrap();
    assert!(MiniFtpClient::connect(control.addr()).await.is_ok());
}

/// AC11: a failing test shows the container log tail.
#[test]
#[ignore = "needs Docker (COURIER_E2E=1)"]
fn diag_dumps_container_logs_on_failure() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    // Containers dropped while the deliberate panic unwinds need a runtime context
    // (testcontainers' Drop calls Handle::current()).
    let _rt_guard = rt.enter();
    if let Some(reason) = rt.block_on(courier_ftp_e2e::docker_skip_reason()) {
        eprintln!("skipped: {reason}");
        return;
    }
    let (result, dumps) = diag::capture(|| {
        let sshd = rt.block_on(Sshd::start(SshdProfile::Password)).unwrap();
        let _keep = &sshd;
        panic!("deliberate failure");
    });
    assert!(result.is_err());
    let all = dumps.join("\n");
    assert!(
        all.contains("----- diag: docker logs sshd password"),
        "{all}"
    );
    assert!(all.contains("courier-sshd: profile password"), "{all}");
}
