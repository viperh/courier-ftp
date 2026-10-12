//! `FtpBackend` against the in-process server: the core conformance suite
//! (plain, vsftpd-like, FTPS), error mapping, learned capabilities, MLSD and
//! LIST, transfers.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{sync::Arc, time::Duration};

use courier_ftp_core::{
    backend::conformance,
    events::{self, EventReceiver, TrustDecision},
    model::{FtpEncryption, LogonType, Protocol},
    trust::MemoryCertTrustStore,
};
use pretty_assertions::assert_eq;
use secrecy::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::{
    test_server::{ServerConfig, TestServer},
    tls::tests::{prompter, self_signed, tls_server_config, untrusting},
};

fn info(server: &TestServer, protocol: Protocol) -> ConnectInfo {
    let mut address = ServerAddress::new(protocol, server.addr.ip().to_string());
    address.port = server.addr.port();
    let mut info = ConnectInfo::new(
        address,
        LogonType::Normal {
            user: "bob".into(),
            password: SecretString::from("secret".to_owned()),
        },
    );
    info.encryption = Some(FtpEncryption::PlainOnly);
    info
}

fn settings() -> Settings {
    let mut s = Settings::default();
    s.connection.timeout_secs = 5;
    s
}

fn backend_for(info: &ConnectInfo, settings: &Settings) -> (FtpBackend, EventReceiver) {
    let (tx, rx) = events::channel(4);
    let trust = untrusting(Arc::new(MemoryCertTrustStore::new()));
    let b = FtpBackend::new(info, settings, trust, SessionId::next(), tx);
    (b, rx)
}

async fn connected(server: &TestServer) -> (FtpBackend, EventReceiver) {
    let (mut b, rx) = backend_for(&info(server, Protocol::Ftp), &settings());
    b.connect(CancellationToken::new()).await.unwrap();
    (b, rx)
}

#[tokio::test]
async fn conformance_with_mlst() {
    let server = TestServer::start(ServerConfig::default()).await;
    server.mkdir("/home/bob/base");
    let (mut b, _rx) = connected(&server).await;
    assert_eq!(b.home_dir().await.unwrap(), RemotePath::new("/home/bob"));
    conformance::run(&mut b, &RemotePath::new("/home/bob/base")).await;
}

#[tokio::test]
async fn conformance_like_vsftpd() {
    // No MLST/MLSD/MFMT, vague error texts, MDTM sets times.
    let server = TestServer::start(ServerConfig {
        mlst: false,
        mfmt: false,
        mdtm_set: true,
        vague_errors: true,
        ..ServerConfig::default()
    })
    .await;
    server.mkdir("/home/bob/base");
    let (mut b, _rx) = connected(&server).await;
    conformance::run(&mut b, &RemotePath::new("/home/bob/base")).await;
    assert!(server.commands().iter().any(|c| c.starts_with("MDTM 2001")));
}

#[tokio::test]
async fn conformance_over_ftps() {
    let cert = self_signed();
    let server = TestServer::start(tls_server_config(&cert, false)).await;
    server.mkdir("/home/bob/base");
    let mut i = info(&server, Protocol::FtpsExplicit);
    i.encryption = None;
    let (mut b, rx) = backend_for(&i, &settings());
    let _p = prompter(rx, TrustDecision::Once);
    b.connect(CancellationToken::new()).await.unwrap();
    let info = b.session_info().unwrap();
    assert!(
        matches!(info.security, SecurityInfo::Tls { .. }),
        "{info:?}"
    );
    conformance::run(&mut b, &RemotePath::new("/home/bob/base")).await;
    assert!(server.data_tls().iter().all(|(t, r)| *t && *r));
}

#[tokio::test]
async fn mlsd_and_list_are_both_used() {
    for use_mlsd in [true, false] {
        let server = TestServer::start(ServerConfig::default()).await;
        server.put("/home/bob/a.txt", b"hello");
        server.mkdir("/home/bob/sub");
        let mut s = settings();
        s.ftp.use_mlsd = use_mlsd;
        let (mut b, _rx) = backend_for(&info(&server, Protocol::Ftp), &s);
        b.connect(CancellationToken::new()).await.unwrap();
        let listing = b
            .list(&RemotePath::new("/home/bob"), CancellationToken::new())
            .await
            .unwrap();
        let mut names: Vec<(String, EntryKind, Option<u64>)> = listing
            .entries
            .iter()
            .map(|e| (e.name.clone(), e.kind.clone(), e.size))
            .collect();
        names.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(names[0], ("a.txt".into(), EntryKind::File, Some(5)));
        assert_eq!(names[1].0, "sub");
        assert_eq!(names[1].1, EntryKind::Dir);
        let cmds = server.commands();
        let used = if use_mlsd { "MLSD" } else { "LIST" };
        assert!(cmds.contains(&used.to_owned()), "{cmds:?}");
        // Listing the same directory again doesn't repeat CWD.
        b.list(&RemotePath::new("/home/bob"), CancellationToken::new())
            .await
            .unwrap();
        let cwds = server
            .commands()
            .iter()
            .filter(|c| c.starts_with("CWD"))
            .count();
        assert_eq!(cwds, 0, "already in /home/bob after login");
    }
}

#[tokio::test]
async fn error_mapping() {
    let server = TestServer::start(ServerConfig::default()).await;
    server.mkdir("/home/bob/d");
    let (mut b, _rx) = connected(&server).await;
    let missing = RemotePath::new("/home/bob/missing");
    assert!(matches!(b.stat(&missing).await, Err(Error::NotFound(_))));
    assert!(matches!(
        b.remove_file(&missing).await,
        Err(Error::NotFound(_))
    ));
    assert!(matches!(
        b.open_read(&missing, 0, &TransferOpts::default()).await,
        Err(Error::NotFound(_))
    ));
    assert!(matches!(
        b.mkdir(&RemotePath::new("/home/bob/d")).await,
        Err(Error::AlreadyExists)
    ));
    assert!(matches!(
        b.list(&missing, CancellationToken::new()).await,
        Err(Error::NotFound(_))
    ));
    // vague texts: still NotFound / AlreadyExists.
    let vague = TestServer::start(ServerConfig {
        vague_errors: true,
        ..ServerConfig::default()
    })
    .await;
    vague.mkdir("/home/bob/d");
    let (mut b, _rx) = connected(&vague).await;
    assert!(matches!(
        b.remove_file(&missing).await,
        Err(Error::NotFound(_))
    ));
    assert!(matches!(b.rmdir(&missing).await, Err(Error::NotFound(_))));
    assert!(matches!(
        b.rename(&missing, &RemotePath::new("/home/bob/x")).await,
        Err(Error::NotFound(_))
    ));
    assert!(matches!(
        b.mkdir(&RemotePath::new("/home/bob/d")).await,
        Err(Error::AlreadyExists)
    ));
}

#[test]
fn permission_denied_is_mapped() {
    let reply = Reply::new(550, vec!["550 /etc/shadow: Permission denied".into()]);
    assert!(matches!(
        reply_error(&reply, &RemotePath::new("/etc/shadow")),
        Error::PermissionDenied
    ));
}

#[tokio::test]
async fn site_chmod_rejection_turns_the_capability_off() {
    let server = TestServer::start(ServerConfig {
        chmod: false,
        ..ServerConfig::default()
    })
    .await;
    server.put("/home/bob/f", b"x");
    let (mut b, _rx) = connected(&server).await;
    assert!(b.capabilities().chmod);
    let err = b
        .chmod(&RemotePath::new("/home/bob/f"), 0o600)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Unsupported(_)), "{err}");
    assert!(!b.capabilities().chmod);
    // Not even sent again.
    let before = server.commands().len();
    assert!(
        b.chmod(&RemotePath::new("/home/bob/f"), 0o600)
            .await
            .is_err()
    );
    assert_eq!(server.commands().len(), before);
}

#[tokio::test]
async fn set_mtime_falls_back_and_learns() {
    let server = TestServer::start(ServerConfig {
        mfmt: false,
        mdtm_set: false,
        ..ServerConfig::default()
    })
    .await;
    server.put("/home/bob/f", b"x");
    let (mut b, _rx) = connected(&server).await;
    assert!(b.capabilities().set_mtime);
    let when = time::macros::datetime!(2001-02-03 04:05:06 UTC);
    let err = b
        .set_mtime(&RemotePath::new("/home/bob/f"), when)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Unsupported(_)), "{err}");
    assert!(!b.capabilities().set_mtime);
    let cmds = server.commands();
    assert!(cmds.contains(&"MDTM 20010203040506 /home/bob/f".to_owned()));
    assert!(cmds.contains(&"SITE UTIME 20010203040506 /home/bob/f".to_owned()));
}

#[tokio::test]
async fn ascii_transfers_and_no_ascii_resume() {
    let server = TestServer::start(ServerConfig::default()).await;
    let (mut b, _rx) = connected(&server).await;
    let path = RemotePath::new("/home/bob/t.txt");
    let ascii = TransferOpts {
        transfer_type: TransferType::Ascii,
        ..TransferOpts::default()
    };
    let mut w = b
        .open_write(&path, WriteMode::Truncate, &ascii)
        .await
        .unwrap();
    w.write_all(b"a\nb\n").await.unwrap();
    w.shutdown().await.unwrap();
    drop(w);
    b.finish_transfer().await.unwrap();
    assert_eq!(server.get("/home/bob/t.txt").unwrap(), b"a\nb\n");
    let mut r = b.open_read(&path, 0, &ascii).await.unwrap();
    let mut out = Vec::new();
    r.read_to_end(&mut out).await.unwrap();
    drop(r);
    b.finish_transfer().await.unwrap();
    let want: &[u8] = if cfg!(windows) {
        b"a\r\nb\r\n"
    } else {
        b"a\nb\n"
    };
    assert_eq!(out, want);
    assert!(matches!(
        b.open_read(&path, 1, &ascii).await,
        Err(Error::Unsupported(_))
    ));
}

#[tokio::test]
async fn a_dropped_transfer_is_aborted_by_the_next_operation() {
    let server = TestServer::start(ServerConfig {
        chunk: 4096,
        data_delay: Some(Duration::from_millis(5)),
        ..ServerConfig::default()
    })
    .await;
    server.put("/home/bob/big", &vec![7u8; 2 * 1024 * 1024]);
    let (mut b, _rx) = connected(&server).await;
    let mut r = b
        .open_read(
            &RemotePath::new("/home/bob/big"),
            0,
            &TransferOpts::default(),
        )
        .await
        .unwrap();
    let mut buf = [0u8; 100];
    r.read_exact(&mut buf).await.unwrap();
    drop(r);
    // No finish_transfer: the next operation cleans up.
    let listing = b
        .list(&RemotePath::new("/home/bob"), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(listing.entries.len(), 1);
    assert!(server.commands().contains(&"ABOR".to_owned()));
    // And the finished transfer reports cancellation when asked directly.
    let mut r = b
        .open_read(
            &RemotePath::new("/home/bob/big"),
            0,
            &TransferOpts::default(),
        )
        .await
        .unwrap();
    r.read_exact(&mut buf).await.unwrap();
    drop(r);
    assert!(matches!(b.finish_transfer().await, Err(Error::Cancelled)));
    assert!(b.keepalive().await.is_ok());
}

#[tokio::test]
async fn raw_commands_and_session_info() {
    let server = TestServer::start(ServerConfig::default()).await;
    let (mut b, _rx) = connected(&server).await;
    let text = b.raw_command("NOOP").await.unwrap();
    assert_eq!(text, "200 NOOP ok.");
    assert!(matches!(
        b.raw_command("LIST").await,
        Err(Error::InvalidInput(_))
    ));
    let info = b.session_info().unwrap();
    assert_eq!(info.server_software.as_deref(), Some("UNIX Type: L8"));
    assert_eq!(info.security, SecurityInfo::Plain);
    b.disconnect().await.unwrap();
    assert!(!b.is_connected());
}

#[tokio::test]
async fn factory_creates_backends_with_the_proxy_password() {
    let server = TestServer::start(ServerConfig::default()).await;
    let trust = untrusting(Arc::new(MemoryCertTrustStore::new()));
    let mut s = settings();
    s.proxy.ftp_proxy =
        courier_ftp_core::settings::FtpProxy::UserAtHost(courier_ftp_core::settings::ProxyServer {
            host: "127.0.0.1".into(),
            port: 1,
            user: Some("puser".into()),
            password_ref: Some("item".into()),
        });
    let factory = FtpBackendFactory::new(s, trust);
    factory.set_ftp_proxy_password(Some(SecretString::from("pp".to_owned())));
    let (tx, _rx) = events::channel(4);
    let mut b = factory.create_ftp(&info(&server, Protocol::Ftp), SessionId::next(), tx);
    let proxy = b.options_mut().ftp_proxy.clone().unwrap();
    assert!(proxy.password.is_some());
    factory.set_settings(settings());
    let (tx, _rx) = events::channel(4);
    let mut b = factory.create(&info(&server, Protocol::Ftp), SessionId::next(), tx);
    b.connect(CancellationToken::new()).await.unwrap();
    assert!(b.is_connected());
}

/// Resolves every queue server to one connect info.
struct FixedResolver(ConnectInfo);

#[async_trait]
impl courier_ftp_core::transfer::ServerResolver for FixedResolver {
    async fn resolve(
        &self,
        _: &courier_ftp_core::queue::QueueServer,
        _: &CancellationToken,
    ) -> Result<ConnectInfo> {
        Ok(self.0.clone())
    }
}

/// Runs one download of `remote` through the transfer engine with
/// `FtpBackendFactory`; returns the local copy.
async fn engine_download(server: &TestServer, remote: &str, size: u64, s: Settings) -> Vec<u8> {
    use courier_ftp_core::{
        events::CoreEvent,
        model::{Direction, LocalPath},
        queue::{NewItem, Queue, QueueServer, SharedQueue},
        transfer::TransferEngine,
    };
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("big.bin");
    let info = info(server, Protocol::Ftp);
    let queue: SharedQueue = Arc::new(std::sync::Mutex::new(Queue::default()));
    let (tx, mut rx) = events::channel(0);
    let trust = untrusting(Arc::new(MemoryCertTrustStore::new()));
    let factory = FtpBackendFactory::new(s.clone(), trust);
    let (engine, handle) = TransferEngine::builder(
        Arc::clone(&queue),
        Arc::new(factory),
        Arc::new(FixedResolver(info.clone())),
        tx,
    )
    .settings(s)
    .build();
    let engine = engine.spawn();
    queue.lock().unwrap().add(
        NewItem::file(
            QueueServer::Quick {
                address: info.address.clone(),
                password: None,
            },
            Direction::Download,
            LocalPath::new(&target),
            RemotePath::new(remote),
            Some(size),
        ),
        time::OffsetDateTime::UNIX_EPOCH,
    );
    handle.start();
    let stats = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Some(CoreEvent::QueueFinished { stats }) = rx.recv().await {
                break stats;
            }
        }
    })
    .await
    .expect("transfer finished");
    assert_eq!((stats.files_ok, stats.files_failed), (1, 0), "{stats:?}");
    handle.shutdown();
    engine.await.unwrap();
    std::fs::read(&target).unwrap()
}

#[tokio::test]
async fn segmented_download_through_the_engine_is_byte_identical() {
    // T41b: ranges fetched over several connections with `REST` + `RETR`,
    // each stopped at its end with `ABOR`.
    let server = TestServer::start(ServerConfig {
        chunk: 64 * 1024,
        data_delay: Some(Duration::from_millis(2)),
        ..ServerConfig::default()
    })
    .await;
    let mib = 1024 * 1024;
    let data: Vec<u8> = (0..12 * mib).map(|i| (i * 7 % 253) as u8).collect();
    server.put("/home/bob/big.bin", &data);
    let mut s = settings();
    s.connection.keepalive = false;
    s.file_types.default_type = courier_ftp_core::settings::TransferTypeChoice::Binary;
    s.transfers.segmented.min_file_size_mib = 1;
    s.transfers.segmented.min_segment_size_mib = 1;
    s.transfers.segmented.max_segments = 4;
    let got = engine_download(&server, "/home/bob/big.bin", data.len() as u64, s).await;
    assert!(got == data, "files differ");
    let commands = server.commands();
    let mut rests: Vec<&String> = commands.iter().filter(|c| c.starts_with("REST ")).collect();
    rests.sort();
    rests.dedup();
    assert!(rests.len() >= 3, "segmented: {rests:?}");
    assert!(commands.iter().any(|c| c == "ABOR"), "ranges end with ABOR");
}
