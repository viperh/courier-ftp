//! Segmented transfers (T41b) through the transfer engine against real
//! servers in Docker: OpenSSH (`atmoz/sftp`; download and upload, each split
//! over several connections) and vsftpd (`delfer/alpine-ftp-server`;
//! download with `REST` + `RETR`, each range stopped with `ABOR`). Every
//! copy is compared byte for byte with the source.
//!
//! `COURIER_E2E=1 cargo test -p courier-ftp-e2e --test segmented -- --ignored`

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use courier_ftp_core::{
    Result,
    backend::{Backend, BackendFactory, ConnectInfo, TransferOpts, WriteMode},
    events::{self, CoreEvent, SessionId},
    model::{Direction, FtpEncryption, LocalPath, LogonType, Protocol, RemotePath, ServerAddress},
    queue::{NewItem, Queue, QueueServer},
    settings::{Settings, TransferTypeChoice},
    transfer::{EngineStatus, ServerResolver, TransferEngine},
    trust::MemoryCertTrustStore,
};
use courier_ftp_e2e::require_docker;
use courier_ftp_proto_ftp::{backend::FtpBackendFactory, tls::TlsTrust};
use courier_ftp_proto_sftp::{SftpBackendFactory, ssh::AcceptAnyHostKey};
use secrecy::SecretString;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt, core::IntoContainerPort, runners::AsyncRunner,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const USER: &str = "courier";
const PASSWORD: &str = "e2e-password";
const MIB: usize = 1024 * 1024;

struct Fixed(ConnectInfo);

#[async_trait]
impl ServerResolver for Fixed {
    async fn resolve(&self, _: &QueueServer, _: &CancellationToken) -> Result<ConnectInfo> {
        Ok(self.0.clone())
    }
}

fn info(protocol: Protocol, host: &str, port: u16) -> ConnectInfo {
    let mut address = ServerAddress::new(protocol, host);
    address.port = port;
    let mut info = ConnectInfo::new(
        address,
        LogonType::Normal {
            user: USER.into(),
            password: SecretString::from(PASSWORD.to_owned()),
        },
    );
    if protocol == Protocol::Ftp {
        info.encryption = Some(FtpEncryption::PlainOnly);
    }
    info
}

/// Segmentation from 8 MiB files, ranges of 2 MiB, up to 4 connections.
fn settings() -> Settings {
    let mut s = Settings::default();
    s.connection.timeout_secs = 20;
    s.connection.keepalive = false;
    s.file_types.default_type = TransferTypeChoice::Binary;
    s.transfers.segmented.min_file_size_mib = 8;
    s.transfers.segmented.min_segment_size_mib = 2;
    s.transfers.segmented.max_segments = 4;
    s
}

fn pattern(len: usize, seed: u64) -> Vec<u8> {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15 ^ seed;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

async fn connect(factory: &dyn BackendFactory, info: &ConnectInfo) -> Box<dyn Backend> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let (tx, _rx) = events::channel(0);
        let mut b = factory.create(info, SessionId::next(), tx);
        match b.connect(CancellationToken::new()).await {
            Ok(()) => return b,
            Err(err) if tokio::time::Instant::now() < deadline => {
                eprintln!("waiting for the server: {err}");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(err) => panic!("the server never accepted the login: {err}"),
        }
    }
}

async fn put(b: &mut dyn Backend, path: &RemotePath, data: &[u8]) {
    let mut w = b
        .open_write(path, WriteMode::Truncate, &TransferOpts::default())
        .await
        .unwrap();
    w.write_all(data).await.unwrap();
    w.shutdown().await.unwrap();
    drop(w);
    b.finish_transfer().await.unwrap();
}

async fn get(b: &mut dyn Backend, path: &RemotePath) -> Vec<u8> {
    let mut r = b
        .open_read(path, 0, &TransferOpts::default())
        .await
        .unwrap();
    let mut data = Vec::new();
    r.read_to_end(&mut data).await.unwrap();
    drop(r);
    b.finish_transfer().await.unwrap();
    data
}

/// Runs `items` through the engine; returns the most slots used at once.
async fn run_engine(
    factory: Arc<dyn BackendFactory>,
    info: &ConnectInfo,
    items: Vec<NewItem>,
) -> usize {
    let queue = Arc::new(Mutex::new(Queue::default()));
    let count = items.len() as u64;
    {
        let mut q = queue.lock().unwrap();
        for item in items {
            q.add(item, time::OffsetDateTime::UNIX_EPOCH);
        }
    }
    let (tx, mut rx) = events::channel(0);
    let (engine, handle) = TransferEngine::builder(
        Arc::clone(&queue),
        factory,
        Arc::new(Fixed(info.clone())),
        tx,
    )
    .settings(settings())
    .build();
    let task = engine.spawn();
    handle.start();
    let mut status = handle.watch_status();
    let mut peak = 0;
    let stats = tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            tokio::select! {
                event = rx.recv() => match event {
                    Some(CoreEvent::QueueFinished { stats }) => return stats,
                    Some(_) => {}
                    None => panic!("event channel closed"),
                },
                Ok(()) = status.changed() => {
                    let s: EngineStatus = status.borrow().clone();
                    peak = peak.max(s.slots);
                }
            }
        }
    })
    .await
    .expect("queue did not finish");
    assert_eq!(
        (stats.files_ok, stats.files_failed),
        (count, 0),
        "{stats:?}"
    );
    handle.shutdown();
    task.await.unwrap();
    peak
}

fn quick(info: &ConnectInfo) -> QueueServer {
    QueueServer::Quick {
        address: info.address.clone(),
        password: None,
    }
}

#[tokio::test]
#[ignore = "needs Docker: COURIER_E2E=1 cargo test -p courier-ftp-e2e -- --ignored"]
async fn openssh_segmented_download_and_upload_are_byte_identical() {
    require_docker!();
    let container: ContainerAsync<GenericImage> = GenericImage::new("atmoz/sftp", "alpine")
        .with_exposed_port(22.tcp())
        .with_cmd([format!("{USER}:{PASSWORD}:1001::upload")])
        .start()
        .await
        .unwrap();
    let host = container.get_host().await.unwrap().to_string();
    let port = container.get_host_port_ipv4(22.tcp()).await.unwrap();
    let info = info(Protocol::Sftp, &host, port);
    let factory = Arc::new(SftpBackendFactory::new(
        settings(),
        Arc::new(AcceptAnyHostKey::insecure_for_tests()),
    ));
    let mut b = connect(&*factory, &info).await;

    let down = pattern(24 * MIB + 333, 1);
    let up = pattern(20 * MIB + 77, 2);
    let remote_down = RemotePath::new("/upload/down.bin");
    let remote_up = RemotePath::new("/upload/up.bin");
    put(&mut *b, &remote_down, &down).await;
    let local = tempfile::tempdir().unwrap();
    std::fs::write(local.path().join("up.bin"), &up).unwrap();

    let peak = run_engine(
        factory.clone(),
        &info,
        vec![
            NewItem::file(
                quick(&info),
                Direction::Download,
                LocalPath::new(local.path().join("down.bin")),
                remote_down,
                Some(down.len() as u64),
            ),
            NewItem::file(
                quick(&info),
                Direction::Upload,
                LocalPath::new(local.path().join("up.bin")),
                remote_up.clone(),
                Some(up.len() as u64),
            ),
        ],
    )
    .await;
    assert!(std::fs::read(local.path().join("down.bin")).unwrap() == down);
    assert!(get(&mut *b, &remote_up).await == up);
    assert!(peak > 2, "segmented: at most {peak} connections");
    b.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "needs Docker: COURIER_E2E=1 cargo test -p courier-ftp-e2e -- --ignored"]
async fn vsftpd_segmented_download_is_byte_identical() {
    require_docker!();
    let ports = 31150..=31159;
    let mut image = GenericImage::new("delfer/alpine-ftp-server", "latest")
        .with_exposed_port(21.tcp())
        .with_env_var("USERS", format!("{USER}|{PASSWORD}"))
        .with_env_var("ADDRESS", "127.0.0.1")
        .with_env_var("MIN_PORT", ports.start().to_string())
        .with_env_var("MAX_PORT", ports.end().to_string());
    for p in ports {
        image = image.with_mapped_port(p, p.tcp());
    }
    let port = courier_ftp_e2e::free_port();
    let _container = image
        .with_mapped_port(port, 21.tcp())
        .start()
        .await
        .unwrap();
    let info = info(Protocol::Ftp, "127.0.0.1", port);
    let trust = Arc::new(TlsTrust::with_system_verifier(
        Arc::new(MemoryCertTrustStore::new()),
        None,
    ));
    let factory = Arc::new(FtpBackendFactory::new(settings(), trust));
    let mut b = connect(&*factory, &info).await;
    let home = b.home_dir().await.unwrap();
    let data = pattern(24 * MIB + 4321, 3);
    let remote = home.join("big.bin").unwrap();
    put(&mut *b, &remote, &data).await;
    b.disconnect().await.unwrap();

    let local = tempfile::tempdir().unwrap();
    let target = local.path().join("big.bin");
    let peak = run_engine(
        factory,
        &info,
        vec![NewItem::file(
            quick(&info),
            Direction::Download,
            LocalPath::new(&target),
            remote,
            Some(data.len() as u64),
        )],
    )
    .await;
    assert!(std::fs::read(&target).unwrap() == data, "files differ");
    assert!(peak > 1, "segmented: at most {peak} connections");
}
