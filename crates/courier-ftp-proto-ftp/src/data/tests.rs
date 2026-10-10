//! Data connection tests against the in-process server.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use courier_ftp_core::{
    backend::TransferType,
    events::{self, CoreEvent, EventReceiver, LogKind, SessionId},
    model::LogonType,
    net::{Proxy, ProxyKind},
    settings::Settings,
};
use pretty_assertions::assert_eq;
use secrecy::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{ascii::AsciiReader, ascii::AsciiWriter, *};
use crate::{
    control::{FtpContext, FtpOptions, connect},
    test_server::{Node, ServerConfig, TestServer},
};

fn logon() -> LogonType {
    LogonType::Normal {
        user: "bob".into(),
        password: SecretString::from("secret".to_owned()),
    }
}

fn host_of(server: &TestServer) -> HostPort {
    HostPort::from(server.addr)
}

async fn login(server: &TestServer) -> (ControlConnection, EventReceiver) {
    let (tx, rx) = events::channel(4);
    let mut opts = FtpOptions::new(host_of(server), logon(), &Settings::default());
    opts.timeout = Duration::from_secs(5);
    let conn = connect(&opts, FtpContext::new(SessionId::next(), tx))
        .await
        .unwrap();
    (conn, rx)
}

fn session(server: &TestServer, mode: FtpTransferMode) -> DataSession {
    let settings = Settings::default();
    let mut opts = DataOptions::new(
        &settings,
        Some(mode),
        host_of(server),
        &NetOpts::from_settings(&settings),
        Duration::from_secs(5),
    );
    opts.net.timeout = Duration::from_secs(5);
    DataSession::new(opts)
}

fn stream(open: DataOpen) -> DataStream {
    match open {
        DataOpen::Stream(s) => s,
        other => panic!("expected a data connection, got {other:?}"),
    }
}

async fn download(
    data: &mut DataSession,
    conn: &mut ControlConnection,
    cmd: &str,
    rest: Option<u64>,
) -> Vec<u8> {
    let cancel = CancellationToken::new();
    let mut s = stream(data.open(conn, cmd, rest, &cancel).await.unwrap());
    let flags = s.flags();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    drop(s);
    let reply = finish(conn, &flags, false).await.unwrap();
    assert_eq!(reply.code, 226);
    out
}

async fn upload(
    data: &mut DataSession,
    conn: &mut ControlConnection,
    cmd: &str,
    rest: Option<u64>,
    bytes: &[u8],
) {
    let cancel = CancellationToken::new();
    let mut s = stream(data.open(conn, cmd, rest, &cancel).await.unwrap());
    let flags = s.flags();
    s.write_all(bytes).await.unwrap();
    s.shutdown().await.unwrap();
    drop(s);
    let reply = finish(conn, &flags, true).await.unwrap();
    assert_eq!(reply.code, 226);
}

fn status_lines(rx: &mut EventReceiver) -> Vec<String> {
    let mut out = Vec::new();
    while let Some(event) = rx.try_recv() {
        if let CoreEvent::Log(msg) = event
            && msg.kind == LogKind::Status
        {
            out.push(msg.text);
        }
    }
    out
}

fn sample(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 256) as u8).collect()
}

fn data_commands(server: &TestServer) -> Vec<String> {
    server
        .commands()
        .into_iter()
        .filter(|c| {
            let verb = c.split(' ').next().unwrap_or_default();
            [
                "EPSV", "PASV", "PORT", "EPRT", "REST", "RETR", "STOR", "APPE", "ABOR",
            ]
            .contains(&verb)
        })
        .collect()
}

#[tokio::test]
async fn epsv_round_trip() {
    let server = TestServer::start(ServerConfig::default()).await;
    let (mut conn, _rx) = login(&server).await;
    let mut data = session(&server, FtpTransferMode::Passive);
    let bytes = sample(200_000);
    upload(&mut data, &mut conn, "STOR a.bin", None, &bytes).await;
    assert_eq!(server.get("/home/bob/a.bin").unwrap(), bytes);
    assert_eq!(
        download(&mut data, &mut conn, "RETR a.bin", None).await,
        bytes
    );
    assert_eq!(
        data_commands(&server),
        ["EPSV", "STOR a.bin", "EPSV", "RETR a.bin"]
    );
    conn.pwd().await.unwrap();
}

#[tokio::test]
async fn pasv_when_epsv_is_refused_and_remembered() {
    let server = TestServer::start(ServerConfig {
        refuse_epsv: true,
        ..ServerConfig::default()
    })
    .await;
    server.put("/home/bob/x", b"hello");
    let (mut conn, _rx) = login(&server).await;
    let mut data = session(&server, FtpTransferMode::Passive);
    assert_eq!(
        download(&mut data, &mut conn, "RETR x", None).await,
        b"hello"
    );
    assert_eq!(
        download(&mut data, &mut conn, "RETR x", None).await,
        b"hello"
    );
    assert_eq!(
        data_commands(&server),
        ["EPSV", "PASV", "RETR x", "PASV", "RETR x"]
    );
}

#[tokio::test]
async fn pasv_without_epsv_feature() {
    let server = TestServer::start(ServerConfig {
        epsv_feat: false,
        ..ServerConfig::default()
    })
    .await;
    server.put("/home/bob/x", b"hello");
    let (mut conn, _rx) = login(&server).await;
    let mut data = session(&server, FtpTransferMode::Passive);
    assert_eq!(
        download(&mut data, &mut conn, "RETR x", None).await,
        b"hello"
    );
    assert_eq!(data_commands(&server), ["PASV", "RETR x"]);
}

#[tokio::test]
async fn unspecified_pasv_address_is_replaced() {
    let server = TestServer::start(ServerConfig {
        epsv_feat: false,
        pasv_ip: Some(std::net::Ipv4Addr::UNSPECIFIED),
        ..ServerConfig::default()
    })
    .await;
    server.put("/home/bob/x", b"hello");
    let (mut conn, mut rx) = login(&server).await;
    let mut data = session(&server, FtpTransferMode::Passive);
    assert_eq!(
        download(&mut data, &mut conn, "RETR x", None).await,
        b"hello"
    );
    assert!(
        status_lines(&mut rx)
            .iter()
            .any(|l| l.contains("unroutable address 0.0.0.0")),
        "the replacement is logged"
    );
}

#[test]
fn unroutable_pasv_address_with_a_public_peer() {
    let host = HostPort::new("ftp.example.com", 21);
    let public: SocketAddr = "203.0.114.5:21".parse().unwrap();
    let private: SocketAddr = "192.168.1.9:21".parse().unwrap();
    let pasv: SocketAddrV4 = "10.0.0.5:5001".parse().unwrap();
    // Public control peer: replaced by the peer.
    assert_eq!(
        pasv_target(pasv, Some(public), false, &host, true),
        (HostPort::new("203.0.114.5", 5001), true)
    );
    // Setting off: kept.
    assert_eq!(
        pasv_target(pasv, Some(public), false, &host, false),
        (HostPort::new("10.0.0.5", 5001), false)
    );
    // LAN server: kept.
    assert_eq!(
        pasv_target(pasv, Some(private), false, &host, true),
        (HostPort::new("10.0.0.5", 5001), false)
    );
    // Behind a proxy: the server's name.
    assert_eq!(
        pasv_target(pasv, Some(private), true, &host, true),
        (HostPort::new("ftp.example.com", 5001), true)
    );
    // A routable address is never replaced.
    let routable: SocketAddrV4 = "198.51.99.1:5001".parse().unwrap();
    assert_eq!(
        pasv_target(routable, Some(public), false, &host, true),
        (HostPort::new("198.51.99.1", 5001), false)
    );
}

#[tokio::test]
async fn active_mode_with_eprt_then_port_fallback() {
    let server = TestServer::start(ServerConfig::default()).await;
    let (mut conn, _rx) = login(&server).await;
    let mut data = session(&server, FtpTransferMode::Active);
    let bytes = sample(70_000);
    upload(&mut data, &mut conn, "STOR a", None, &bytes).await;
    assert_eq!(download(&mut data, &mut conn, "RETR a", None).await, bytes);
    let cmds = data_commands(&server);
    assert!(cmds[0].starts_with("EPRT |1|127.0.0.1|"), "{cmds:?}");

    let server = TestServer::start(ServerConfig {
        refuse_eprt: true,
        ..ServerConfig::default()
    })
    .await;
    server.put("/home/bob/a", &bytes);
    let (mut conn, _rx) = login(&server).await;
    let mut data = session(&server, FtpTransferMode::Active);
    assert_eq!(download(&mut data, &mut conn, "RETR a", None).await, bytes);
    assert_eq!(download(&mut data, &mut conn, "RETR a", None).await, bytes);
    let cmds = data_commands(&server);
    assert!(cmds[0].starts_with("EPRT "), "{cmds:?}");
    assert!(cmds[1].starts_with("PORT 127,0,0,1,"), "{cmds:?}");
    // The refusal is remembered.
    assert!(cmds[3].starts_with("PORT "), "{cmds:?}");
}

#[tokio::test]
async fn ipv6_data_connections() {
    let Ok(probe) = std::net::TcpListener::bind("[::1]:0") else {
        eprintln!("no IPv6 loopback; skipped");
        return;
    };
    drop(probe);
    let server = TestServer::start_on(
        "[::1]:0".parse().unwrap(),
        ServerConfig {
            epsv_feat: false,
            ..ServerConfig::default()
        },
    )
    .await;
    server.put("/home/bob/x", b"over ipv6");
    let (mut conn, _rx) = login(&server).await;
    // EPSV even without the feature, because the control connection is IPv6.
    let mut data = session(&server, FtpTransferMode::Passive);
    assert_eq!(
        download(&mut data, &mut conn, "RETR x", None).await,
        b"over ipv6"
    );
    let mut data = session(&server, FtpTransferMode::Active);
    assert_eq!(
        download(&mut data, &mut conn, "RETR x", None).await,
        b"over ipv6"
    );
    let cmds = data_commands(&server);
    assert_eq!(cmds[0], "EPSV");
    assert!(cmds[2].starts_with("EPRT |2|::1|"), "{cmds:?}");
}

#[tokio::test]
async fn passive_failure_falls_back_to_active_and_stays() {
    for config in [
        ServerConfig {
            refuse_epsv: true,
            refuse_pasv: true,
            ..ServerConfig::default()
        },
        ServerConfig {
            pasv_dead_port: true,
            ..ServerConfig::default()
        },
    ] {
        let server = TestServer::start(config).await;
        server.put("/home/bob/x", b"data");
        let (mut conn, mut rx) = login(&server).await;
        let mut data = session(&server, FtpTransferMode::Passive);
        assert_eq!(
            download(&mut data, &mut conn, "RETR x", None).await,
            b"data"
        );
        assert_eq!(data.mode(), FtpTransferMode::Active);
        assert_eq!(
            download(&mut data, &mut conn, "RETR x", None).await,
            b"data"
        );
        let cmds = data_commands(&server);
        let passive = cmds.iter().filter(|c| *c == "PASV" || *c == "EPSV").count();
        assert!((1..=2).contains(&passive), "{cmds:?}");
        // The second transfer went straight to active mode.
        assert!(cmds[cmds.len() - 2].starts_with("EPRT"), "{cmds:?}");
        assert!(
            status_lines(&mut rx)
                .iter()
                .any(|l| l.contains("trying active mode"))
        );
    }
}

#[tokio::test]
async fn no_fallback_when_disabled() {
    let server = TestServer::start(ServerConfig {
        refuse_epsv: true,
        refuse_pasv: true,
        ..ServerConfig::default()
    })
    .await;
    let (mut conn, _rx) = login(&server).await;
    let mut data = session(&server, FtpTransferMode::Passive);
    data.opts.fallback_to_active = false;
    let err = data
        .open(&mut conn, "RETR x", None, &CancellationToken::new())
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::Protocol {
                code: Some(502),
                ..
            }
        ),
        "{err}"
    );
    assert!(conn.is_connected());
}

#[tokio::test]
async fn active_mode_through_a_proxy_is_unsupported() {
    let server = TestServer::start(ServerConfig::default()).await;
    let (mut conn, _rx) = login(&server).await;
    let mut data = session(&server, FtpTransferMode::Active);
    data.opts.net.proxy = Some(Proxy {
        kind: ProxyKind::Socks5,
        server: HostPort::new("127.0.0.1", 1),
        auth: None,
    });
    let err = data
        .open(&mut conn, "RETR x", None, &CancellationToken::new())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Unsupported(_)), "{err}");
}

#[tokio::test]
async fn refused_command_is_returned() {
    let server = TestServer::start(ServerConfig::default()).await;
    let (mut conn, _rx) = login(&server).await;
    let mut data = session(&server, FtpTransferMode::Passive);
    let open = data
        .open(&mut conn, "RETR missing", None, &CancellationToken::new())
        .await
        .unwrap();
    assert!(
        matches!(open, DataOpen::Refused(ref r) if r.code == 550),
        "{open:?}"
    );
    // The connection is still in step.
    assert_eq!(conn.pwd().await.unwrap(), "/home/bob");
}

#[tokio::test]
async fn ascii_transfers_convert_line_endings() {
    let server = TestServer::start(ServerConfig::default()).await;
    let (mut conn, _rx) = login(&server).await;
    let mut data = session(&server, FtpTransferMode::Passive);
    conn.set_type(TransferType::Ascii).await.unwrap();
    // Upload with Unix line endings: the server stores its own (LF), having
    // received CRLF.
    let cancel = CancellationToken::new();
    let s = stream(
        data.open(&mut conn, "STOR t.txt", None, &cancel)
            .await
            .unwrap(),
    );
    let flags = s.flags();
    let mut w = AsciiWriter::new(s);
    w.write_all(b"one\ntwo\r\nthree\n").await.unwrap();
    w.shutdown().await.unwrap();
    drop(w);
    finish(&mut conn, &flags, true).await.unwrap();
    assert_eq!(server.get("/home/bob/t.txt").unwrap(), b"one\ntwo\nthree\n");
    // Download: the server sends CRLF, we get the local newline.
    let s = stream(
        data.open(&mut conn, "RETR t.txt", None, &cancel)
            .await
            .unwrap(),
    );
    let flags = s.flags();
    let mut r = AsciiReader::new(s);
    let mut out = Vec::new();
    r.read_to_end(&mut out).await.unwrap();
    drop(r);
    finish(&mut conn, &flags, false).await.unwrap();
    let want: &[u8] = if cfg!(windows) {
        b"one\r\ntwo\r\nthree\r\n"
    } else {
        b"one\ntwo\nthree\n"
    };
    assert_eq!(out, want);
    // TYPE is only sent when it changes.
    conn.set_type(TransferType::Ascii).await.unwrap();
    conn.set_type(TransferType::Binary).await.unwrap();
    let types: Vec<String> = server
        .commands()
        .into_iter()
        .filter(|c| c.starts_with("TYPE"))
        .collect();
    assert_eq!(types, ["TYPE A", "TYPE I"]);
}

#[tokio::test]
async fn resume_download_and_upload() {
    let server = TestServer::start(ServerConfig::default()).await;
    let bytes = sample(100_000);
    server.put("/home/bob/f", &bytes);
    let (mut conn, _rx) = login(&server).await;
    let mut data = session(&server, FtpTransferMode::Passive);
    // Download in two parts.
    let mut local = download(&mut data, &mut conn, "RETR f", None).await;
    local.truncate(40_000);
    let rest = download(&mut data, &mut conn, "RETR f", Some(40_000)).await;
    local.extend_from_slice(&rest);
    assert_eq!(local, bytes);
    // Upload in two parts.
    upload(&mut data, &mut conn, "STOR g", None, &bytes[..30_000]).await;
    upload(
        &mut data,
        &mut conn,
        "STOR g",
        Some(30_000),
        &bytes[30_000..],
    )
    .await;
    assert_eq!(server.get("/home/bob/g").unwrap(), bytes);
    assert!(data_commands(&server).contains(&"REST 40000".to_owned()));
}

#[tokio::test]
async fn rest_offsets_beyond_4_gib() {
    let server = TestServer::start(ServerConfig::default()).await;
    let size = 5_000_000_100u64;
    server.put_node("/home/bob/huge", Node::Virtual { size });
    let (mut conn, _rx) = login(&server).await;
    let mut data = session(&server, FtpTransferMode::Passive);
    let tail = download(&mut data, &mut conn, "RETR huge", Some(5_000_000_000)).await;
    let want: Vec<u8> = (5_000_000_000u64..size).map(|i| (i % 251) as u8).collect();
    assert_eq!(tail, want);
    assert!(data_commands(&server).contains(&"REST 5000000000".to_owned()));
}

#[tokio::test]
async fn cancelled_download_leaves_the_control_connection_usable() {
    let server = TestServer::start(ServerConfig {
        chunk: 4096,
        data_delay: Some(Duration::from_millis(5)),
        ..ServerConfig::default()
    })
    .await;
    server.put("/home/bob/big", &sample(4 * 1024 * 1024));
    let (mut conn, mut rx) = login(&server).await;
    let mut data = session(&server, FtpTransferMode::Passive);
    let mut s = stream(
        data.open(&mut conn, "RETR big", None, &CancellationToken::new())
            .await
            .unwrap(),
    );
    let flags = s.flags();
    let mut buf = [0u8; 1000];
    s.read_exact(&mut buf).await.unwrap();
    drop(s);
    let err = finish(&mut conn, &flags, false).await.unwrap_err();
    assert!(matches!(err, Error::Cancelled), "{err}");
    assert_eq!(conn.outstanding(), 0);
    assert_eq!(conn.pwd().await.unwrap(), "/home/bob");
    assert!(data_commands(&server).contains(&"ABOR".to_owned()));
    assert!(status_lines(&mut rx).contains(&"Aborting the transfer".to_owned()));
    // And another transfer works.
    server.put("/home/bob/small", b"ok");
    assert_eq!(
        download(&mut data, &mut conn, "RETR small", None).await,
        b"ok"
    );
}

#[tokio::test]
async fn cancelled_upload_leaves_the_control_connection_usable() {
    let server = TestServer::start(ServerConfig::default()).await;
    let (mut conn, _rx) = login(&server).await;
    let mut data = session(&server, FtpTransferMode::Passive);
    let mut s = stream(
        data.open(&mut conn, "STOR part", None, &CancellationToken::new())
            .await
            .unwrap(),
    );
    let flags = s.flags();
    s.write_all(b"partial").await.unwrap();
    drop(s);
    let err = finish(&mut conn, &flags, true).await.unwrap_err();
    assert!(matches!(err, Error::Cancelled), "{err}");
    assert_eq!(conn.pwd().await.unwrap(), "/home/bob");
}

#[tokio::test]
async fn cancelling_the_connection_token_interrupts_the_stream() {
    let server = TestServer::start(ServerConfig {
        chunk: 1024,
        data_delay: Some(Duration::from_millis(20)),
        ..ServerConfig::default()
    })
    .await;
    server.put("/home/bob/big", &sample(1024 * 1024));
    let (mut conn, _rx) = login(&server).await;
    let mut data = session(&server, FtpTransferMode::Passive);
    let token = CancellationToken::new();
    let mut s = stream(
        data.open(&mut conn, "RETR big", None, &token)
            .await
            .unwrap(),
    );
    let mut buf = [0u8; 10];
    s.read_exact(&mut buf).await.unwrap();
    conn.cancel_token().cancel();
    let mut rest = Vec::new();
    let err = s.read_to_end(&mut rest).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Interrupted);
}
