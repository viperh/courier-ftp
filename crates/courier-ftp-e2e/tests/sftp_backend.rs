//! The SFTP backend (T22) against a real OpenSSH server in Docker
//! (`atmoz/sftp`: chrooted `internal-sftp`, a writable `/upload`): the
//! backend conformance suite, symlinks, and byte-identical resumed transfers.
//!
//! `COURIER_E2E=1 cargo test -p courier-ftp-e2e --test sftp_backend -- --ignored`

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{sync::Arc, time::Duration};

use courier_ftp_core::{
    backend::{Backend, ConnectInfo, TransferOpts, WriteMode, conformance},
    events::{self, SessionId},
    model::{EntryKind, LogonType, Protocol, RemotePath, ServerAddress},
    settings::Settings,
};
use courier_ftp_e2e::require_docker;
use courier_ftp_proto_sftp::{SftpBackend, SftpBackendFactory, ssh::AcceptAnyHostKey};
use secrecy::SecretString;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{ExecCommand, IntoContainerPort},
    runners::AsyncRunner,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const USER: &str = "courier";
const PASSWORD: &str = "e2e-password";

fn backend(host: &str, port: u16) -> SftpBackend {
    let mut address = ServerAddress::new(Protocol::Sftp, host);
    address.port = port;
    let info = ConnectInfo::new(
        address,
        LogonType::Normal {
            user: USER.into(),
            password: SecretString::from(PASSWORD.to_owned()),
        },
    );
    let mut settings = Settings::default();
    settings.connection.timeout_secs = 10;
    let factory =
        SftpBackendFactory::new(settings, Arc::new(AcceptAnyHostKey::insecure_for_tests()));
    let (tx, _rx) = events::channel(0);
    factory.create_sftp(&info, SessionId::next(), tx)
}

async fn start() -> (ContainerAsync<GenericImage>, SftpBackend) {
    let container = GenericImage::new("atmoz/sftp", "alpine")
        .with_exposed_port(22.tcp())
        .with_cmd([format!("{USER}:{PASSWORD}:1001::upload")])
        .start()
        .await
        .unwrap();
    let host = container.get_host().await.unwrap().to_string();
    let port = container.get_host_port_ipv4(22.tcp()).await.unwrap();
    // sshd takes a moment after the container starts.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let mut b = backend(&host, port);
        match b.connect(CancellationToken::new()).await {
            Ok(()) => return (container, b),
            Err(err) if tokio::time::Instant::now() < deadline => {
                eprintln!("waiting for sshd: {err}");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(err) => panic!("sshd never accepted the login: {err}"),
        }
    }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + i / 251) as u8).collect()
}

async fn put(b: &mut SftpBackend, path: &RemotePath, mode: WriteMode, data: &[u8]) {
    let mut w = b
        .open_write(path, mode, &TransferOpts::default())
        .await
        .unwrap();
    w.write_all(data).await.unwrap();
    w.shutdown().await.unwrap();
    drop(w);
    b.finish_transfer().await.unwrap();
}

async fn get(b: &mut SftpBackend, path: &RemotePath, offset: u64) -> Vec<u8> {
    let mut r = b
        .open_read(path, offset, &TransferOpts::default())
        .await
        .unwrap();
    let mut data = Vec::new();
    r.read_to_end(&mut data).await.unwrap();
    drop(r);
    b.finish_transfer().await.unwrap();
    data
}

#[tokio::test]
#[ignore = "needs Docker: COURIER_E2E=1 cargo test -p courier-ftp-e2e -- --ignored"]
async fn openssh_backend_conformance() {
    require_docker!();
    let (container, mut b) = start().await;
    // Chrooted: the home directory is inside the chroot.
    assert!(b.home_dir().await.unwrap().as_str().starts_with('/'));

    let base = RemotePath::new("/upload/conformance");
    b.mkdir(&base).await.unwrap();
    conformance::run(&mut b, &base).await;

    // Resume, byte-identical, across many pipelined requests.
    let data = pattern(5 * 1024 * 1024 + 17);
    let file = RemotePath::new("/upload/big.bin");
    let part = 3_000_001;
    put(&mut b, &file, WriteMode::Create, &data[..part]).await;
    put(
        &mut b,
        &file,
        WriteMode::ResumeAt(part as u64),
        &data[part..],
    )
    .await;
    assert_eq!(get(&mut b, &file, 0).await, data);
    assert_eq!(get(&mut b, &file, 1_234_567).await, data[1_234_567..]);

    // A symlink to a directory lists as a symlink with target_kind Dir and
    // can be entered. The Backend has no symlink operation: make it in the
    // container.
    let dir = RemotePath::new("/upload/real");
    b.mkdir(&dir).await.unwrap();
    put(
        &mut b,
        &dir.join("inside.txt").unwrap(),
        WriteMode::Create,
        b"x",
    )
    .await;
    let ln = container
        .exec(ExecCommand::new([
            "ln",
            "-s",
            "real",
            &format!("/home/{USER}/upload/link"),
        ]))
        .await
        .unwrap();
    for _ in 0..50 {
        if ln.exit_code().await.unwrap().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let listing = b
        .list(&RemotePath::new("/upload"), CancellationToken::new())
        .await
        .unwrap();
    let link = listing.entries.iter().find(|e| e.name == "link").unwrap();
    assert_eq!(
        link.kind,
        EntryKind::Symlink {
            target: Some("real".into()),
            target_kind: Some(Box::new(EntryKind::Dir)),
        }
    );
    assert!(link.owner.is_some());
    let inner = b
        .list(&RemotePath::new("/upload/link"), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(inner.entries.len(), 1);
    assert_eq!(inner.entries[0].name, "inside.txt");

    b.disconnect().await.unwrap();
}
