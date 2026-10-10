//! Harness self-tests that need no Docker (normal `test` job): the PTY driver against
//! the real binary, `Headless` against an in-process `MockServer`, `HostileFtpd`,
//! `FtpRelayProxy` and the failure diagnostics.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{net::SocketAddr, sync::Arc};

use courier_ftp_core::{
    backend::{ConnectInfo, mock::MockServer},
    model::{FtpEncryption, LogonType, Protocol, RemotePath, ServerAddress},
};
use courier_ftp_e2e::{
    FtpRelayMode, FtpRelayProxy, Headless, HeadlessOptions, HostileFtpd, HostileScript, PtyApp,
    PtyOptions, TestHome, diag,
    hostile::MiniFtpClient,
    keys::{PASSWORD, PROXY_PASSWORD, PROXY_USER, USER},
};
use proptest::prelude::*;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

// ---------------------------------------------------------------- PtyApp

#[test]
fn pty_app_starts_and_quits() {
    let home = TestHome::new().unwrap();
    let mut app = PtyApp::launch(&home, PtyOptions::default()).unwrap();
    app.wait_for_text("Local").unwrap();
    assert!(app.alternate_screen());
    app.send_keys("ctrl-q").unwrap();
    let status = app.wait_exit().unwrap();
    assert!(status.success(), "{status:?}");
    assert!(!app.alternate_screen(), "terminal not restored");
}

#[test]
fn pty_app_resize_redraws() {
    let home = TestHome::new().unwrap();
    let mut app = PtyApp::launch(&home, PtyOptions::default()).unwrap();
    app.wait_for_text("Local").unwrap();
    app.resize(100, 30).unwrap();
    app.wait_for_screen("a 100-column frame", |s| {
        s.rows.len() == 30
            && s.rows
                .iter()
                .any(|r| r.starts_with('┌') && r.chars().count() == 100)
    })
    .unwrap();
    app.send_keys("ctrl-q").unwrap();
    assert!(app.wait_exit().unwrap().success());
}

#[test]
fn pty_test_hook_exit_after_panes() {
    let home = TestHome::new().unwrap();
    let mut app = PtyApp::launch(
        &home,
        PtyOptions {
            env: vec![("COURIER_FTP_TEST_HOOK".into(), "exit-after-panes".into())],
            ..PtyOptions::default()
        },
    )
    .unwrap();
    assert!(app.wait_exit().unwrap().success());
    assert!(String::from_utf8_lossy(app.raw_output()).contains("Local"));
}

#[test]
fn pty_test_hook_exit_after_ms() {
    let home = TestHome::new().unwrap();
    let mut app = PtyApp::launch(
        &home,
        PtyOptions {
            env: vec![("COURIER_FTP_TEST_HOOK".into(), "exit:300".into())],
            ..PtyOptions::default()
        },
    )
    .unwrap();
    app.wait_for_text("Local").unwrap();
    assert!(app.wait_exit().unwrap().success());
}

// ---------------------------------------------------------------- Headless

fn mock_info() -> ConnectInfo {
    let address = ServerAddress::new(
        Protocol::Sftp,
        FtpEncryption::default(),
        "mock.invalid",
        None,
        Some(USER.into()),
    )
    .unwrap();
    ConnectInfo::quick(
        address,
        LogonType::Normal {
            password: Some(PASSWORD.into()),
        },
    )
}

/// The in-process stand-in for the SFTP self-test (`MockServer` until T22 provides
/// the in-process russh server).
#[test]
fn headless_lists_mock_server() {
    rt().block_on(async {
        let server = MockServer::new();
        server.add_dir("/scratch");
        server.add_file("/scratch/a.txt", b"hello".to_vec());
        let h = Headless::connect_with(Arc::new(server), mock_info(), HeadlessOptions::default())
            .await
            .unwrap();
        let listing = h
            .list(&RemotePath::parse("/scratch").unwrap())
            .await
            .unwrap();
        let names: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["a.txt"]);
        let err = h
            .list(&RemotePath::parse("/missing").unwrap())
            .await
            .unwrap_err();
        assert!(err.core().is_some(), "{err}");
        assert!(h.prompts_seen().is_empty());
        h.close().await;
    });
}

#[test]
fn headless_factory_reports_missing_backends() {
    rt().block_on(async {
        let err = Headless::connect(None, mock_info(), HeadlessOptions::default())
            .await
            .unwrap_err();
        assert!(
            matches!(err.core(), Some(courier_ftp_core::Error::Unsupported(_))),
            "{err}"
        );
    });
}

// ---------------------------------------------------------------- HostileFtpd

fn hostile_script() -> HostileScript {
    HostileScript {
        banner: "evil \x1b[31mred\x1b[0m server".into(),
        listing: vec![
            "-rw-r--r-- 1 u g 5 Jan 01 2024 a.txt".into(),
            "-rw-r--r-- 1 u g 5 Jan 01 2024 ../../escape".into(),
        ],
        files: vec![("a.txt".into(), b"hello".to_vec())],
        reported_size: Some(u64::MAX),
        ..HostileScript::default()
    }
}

#[test]
fn hostile_ftpd_serves_scripted_listing() {
    rt().block_on(async {
        let server = HostileFtpd::start(hostile_script()).await.unwrap();
        let mut c = MiniFtpClient::connect(server.addr()).await.unwrap();
        assert_eq!(c.greeting, "220 evil \x1b[31mred\x1b[0m server");
        assert!(c.login(USER, PASSWORD).await.unwrap().starts_with("230"));
        let (bytes, done) = c.pasv_transfer("LIST").await.unwrap();
        assert!(done.starts_with("226"), "{done}");
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "-rw-r--r-- 1 u g 5 Jan 01 2024 a.txt\r\n\
             -rw-r--r-- 1 u g 5 Jan 01 2024 ../../escape\r\n"
        );
        assert_eq!(
            c.cmd("SIZE a.txt").await.unwrap(),
            format!("213 {}", u64::MAX)
        );
        let (bytes, _) = c.pasv_transfer("RETR a.txt").await.unwrap();
        assert_eq!(bytes, b"hello");
        assert!(c.cmd("NOOP").await.unwrap().starts_with("502"));
        let commands = server.commands();
        assert!(commands.contains(&"PASS ****".to_owned()), "{commands:?}");
        assert!(
            !commands
                .iter()
                .any(|l| l.contains(PASSWORD) && l.starts_with("PASS"))
        );
    });
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    /// Any listing line without CR/LF reaches the client verbatim.
    #[test]
    fn hostile_listing_lines_round_trip(lines in prop::collection::vec("[^\r\n]{0,40}", 0..6)) {
        let got = rt().block_on(async {
            let server = HostileFtpd::start(HostileScript {
                listing: lines.clone(),
                ..HostileScript::default()
            })
            .await
            .unwrap();
            let mut c = MiniFtpClient::connect(server.addr()).await.unwrap();
            c.login(USER, PASSWORD).await.unwrap();
            c.pasv_transfer("MLSD").await.unwrap().0
        });
        let want: Vec<u8> = lines.iter().flat_map(|l| format!("{l}\r\n").into_bytes()).collect();
        prop_assert_eq!(got, want);
    }
}

// ---------------------------------------------------------------- FtpRelayProxy

async fn relay_round_trip(mode: FtpRelayMode, target: SocketAddr) -> FtpRelayProxy {
    let proxy = FtpRelayProxy::start(mode, true, vec![target])
        .await
        .unwrap();
    let mut c = MiniFtpClient::connect(proxy.addr()).await.unwrap();
    assert_eq!(c.greeting, "220 courier-ftp-e2e relay");
    // Naming the target before the proxy login is refused.
    let early = match mode {
        FtpRelayMode::UserAtHost => format!("USER {USER}@{target}"),
        FtpRelayMode::Site => format!("SITE {target}"),
        FtpRelayMode::Open => format!("OPEN {target}"),
    };
    assert!(c.cmd(&early).await.unwrap().starts_with("530"));
    assert!(
        c.login(PROXY_USER, PROXY_PASSWORD)
            .await
            .unwrap()
            .starts_with("230")
    );
    // A target outside `allowed_targets` is refused, a malformed one gets 501.
    let outside = match mode {
        FtpRelayMode::UserAtHost => format!("USER {USER}@127.0.0.1:1"),
        FtpRelayMode::Site => "SITE 127.0.0.1:1".to_owned(),
        FtpRelayMode::Open => "OPEN 127.0.0.1:1".to_owned(),
    };
    assert!(c.cmd(&outside).await.unwrap().starts_with("550"));
    let bad = match mode {
        FtpRelayMode::UserAtHost => "USER x@not-an-ip",
        FtpRelayMode::Site => "SITE not-an-ip",
        FtpRelayMode::Open => "OPEN not-an-ip",
    };
    assert!(c.cmd(bad).await.unwrap().starts_with("501"));
    let reply = match mode {
        FtpRelayMode::UserAtHost => c.login(&format!("{USER}@{target}"), PASSWORD).await,
        FtpRelayMode::Site | FtpRelayMode::Open => {
            let greeting = c.cmd(&early).await.unwrap();
            assert!(greeting.starts_with("220 evil"), "{greeting}");
            c.login(USER, PASSWORD).await
        }
    };
    assert!(reply.unwrap().starts_with("230"));
    let (listing, _) = c.pasv_transfer("LIST").await.unwrap();
    assert!(String::from_utf8_lossy(&listing).contains("a.txt"));
    let (bytes, done) = c.pasv_transfer("RETR a.txt").await.unwrap();
    assert_eq!(bytes, b"hello");
    assert!(done.starts_with("226"), "{done}");
    assert!(
        c.cmd("PORT 127,0,0,1,1,1")
            .await
            .unwrap()
            .starts_with("502")
    );
    proxy
}

#[test]
fn ftp_relay_proxy_relays_to_hostile_ftpd() {
    rt().block_on(async {
        let server = HostileFtpd::start(hostile_script()).await.unwrap();
        for mode in FtpRelayMode::ALL {
            let proxy = relay_round_trip(mode, server.addr()).await;
            let commands = proxy.commands();
            assert!(commands.contains(&"PASS ****".to_owned()), "{commands:?}");
            assert!(
                !commands
                    .iter()
                    .any(|l| l.contains(PROXY_PASSWORD) || l == &format!("PASS {PASSWORD}")),
                "unmasked PASS: {commands:?}"
            );
        }
        // The target saw the plain user name, never `user@host`.
        let seen = server.commands();
        assert!(seen.contains(&format!("USER {USER}")), "{seen:?}");
        assert!(!seen.iter().any(|l| l.contains('@')), "{seen:?}");
    });
}

// ---------------------------------------------------------------- diagnostics

/// A failing test shows the last screen and the message-log tail (the container log
/// tail is covered by `harness_docker::diag_dumps_container_logs_on_failure`).
#[test]
fn diag_dumps_on_failure() {
    let (result, dumps) = diag::capture(|| {
        let rt = rt();
        let home = TestHome::new().unwrap();
        let mut app = PtyApp::launch(&home, PtyOptions::default()).unwrap();
        app.wait_for_text("Local").unwrap();
        let headless = rt.block_on(async {
            Headless::connect_with(
                Arc::new(MockServer::new()),
                mock_info(),
                HeadlessOptions::default(),
            )
            .await
            .unwrap()
        });
        let _keep = (&app, &headless);
        panic!("deliberate failure");
    });
    assert!(result.is_err());
    let all = dumps.join("\n");
    assert!(all.contains("----- diag: courier-ftp screen"), "{all}");
    assert!(all.contains("Local"), "{all}");
    assert!(all.contains("----- diag: courier-ftp raw output"), "{all}");
    assert!(all.contains("----- diag: message log of session"), "{all}");
    let kept = dumps
        .iter()
        .find(|d| d.contains("----- diag: COURIER_FTP_HOME (kept)"))
        .expect("the home path is dumped");
    // The failing test kept its home for inspection; this one cleans up.
    let path = kept.trim_end().lines().last().unwrap();
    assert!(path.contains("courier-ftp-e2e-home-"), "{path}");
    std::fs::remove_dir_all(path).unwrap();
}
