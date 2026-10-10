//! The SFTP backend against the in-process server (`ssh::test_server` with
//! [`super::test_server`] serving a temp directory).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use courier_ftp_core::{
    Error,
    backend::{
        Backend, BackendFactory, ConnectInfo, SecurityInfo, SessionHandle, TransferOpts, WriteMode,
        conformance,
    },
    events::{self, CoreEvent, LogKind, SessionId},
    model::{EntryKind, LogonType, Protocol, RemotePath, ServerAddress},
    settings::Settings,
};
use pretty_assertions::assert_eq;
use secrecy::SecretString;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use super::{
    SftpBackend, SftpBackendFactory,
    test_server::{GROUP, OWNER, SftpRoot},
};
use crate::ssh::{
    AcceptAnyHostKey,
    test_server::{self, Policy},
};

const PASSWORD: &str = "sftp-test-pw";

struct Fixture {
    dir: TempDir,
    backend: SftpBackend,
    logs: Arc<Mutex<Vec<(LogKind, String)>>>,
}

impl Fixture {
    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn logs(&self) -> String {
        self.logs
            .lock()
            .unwrap()
            .iter()
            .map(|(_, t)| t.clone())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn info(port: u16) -> ConnectInfo {
    let mut address = ServerAddress::new(Protocol::Sftp, "127.0.0.1");
    address.port = port;
    address.user = Some("tester".into());
    ConnectInfo::new(
        address,
        LogonType::Normal {
            user: "tester".into(),
            password: SecretString::from(PASSWORD.to_owned()),
        },
    )
}

fn settings() -> Settings {
    let mut settings = Settings::default();
    settings.connection.timeout_secs = 10;
    settings
}

async fn server(posix_rename: bool) -> (TempDir, u16) {
    let dir = tempfile::tempdir().unwrap();
    let policy = Policy {
        password: Some(PASSWORD),
        sftp: Some(SftpRoot::new(dir.path(), posix_rename)),
        ..Policy::default()
    };
    let (addr, _) = test_server::start(policy).await;
    (dir, addr.port())
}

fn factory() -> SftpBackendFactory {
    SftpBackendFactory::new(settings(), Arc::new(AcceptAnyHostKey::insecure_for_tests()))
}

async fn fixture_with(posix_rename: bool) -> Fixture {
    let (dir, port) = server(posix_rename).await;
    let (tx, mut rx) = events::channel(4);
    let logs = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&logs);
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let CoreEvent::Log(m) = event {
                sink.lock().unwrap().push((m.kind, m.text));
            }
        }
    });
    let mut backend = factory().create_sftp(&info(port), SessionId::next(), tx);
    backend.connect(CancellationToken::new()).await.unwrap();
    Fixture { dir, backend, logs }
}

async fn fixture() -> Fixture {
    fixture_with(false).await
}

async fn put(b: &mut dyn Backend, path: &RemotePath, mode: WriteMode, data: &[u8]) {
    let mut w = b
        .open_write(path, mode, &TransferOpts::default())
        .await
        .unwrap();
    w.write_all(data).await.unwrap();
    w.shutdown().await.unwrap();
    drop(w);
    b.finish_transfer().await.unwrap();
}

async fn get(b: &mut dyn Backend, path: &RemotePath, offset: u64) -> Vec<u8> {
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

/// Deterministic, non-repeating-looking test data.
fn pattern(len: usize) -> Vec<u8> {
    let mut x: u32 = 0x1234_5678;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x.to_le_bytes()[0]
        })
        .collect()
}

// --------------------------------------------------------------------- tests

#[tokio::test]
async fn passes_conformance_suite() {
    for posix_rename in [false, true] {
        let mut f = fixture_with(posix_rename).await;
        std::fs::create_dir(f.root().join("base")).unwrap();
        conformance::run(&mut f.backend, &RemotePath::new("/base")).await;
        f.backend.disconnect().await.unwrap();
    }
}

#[tokio::test]
async fn connect_logs_version_and_reports_session() {
    let mut f = fixture().await;
    assert!(f.backend.is_connected());
    assert_eq!(f.backend.home_dir().await.unwrap(), RemotePath::root());
    f.backend.keepalive().await.unwrap();
    let info = f.backend.session_info().unwrap();
    assert!(matches!(info.security, SecurityInfo::Ssh { .. }));
    assert!(info.server_software.is_some());
    assert!(matches!(
        f.backend.raw_command("ls").await,
        Err(Error::Unsupported(_))
    ));
    let caps = f.backend.capabilities();
    assert!(!caps.raw_commands && caps.resume_upload && caps.symlinks);
    for _ in 0..200 {
        if f.logs().contains("SFTP protocol version 3") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(f.logs().contains("SFTP protocol version 3"), "{}", f.logs());
}

#[tokio::test]
async fn listing_has_owner_names_and_raw_lines() {
    let mut f = fixture().await;
    std::fs::write(f.root().join("a.txt"), b"hello").unwrap();
    std::fs::create_dir(f.root().join("sub")).unwrap();
    let listing = f
        .backend
        .list(&RemotePath::root(), CancellationToken::new())
        .await
        .unwrap();
    let mut names: Vec<_> = listing.entries.iter().map(|e| e.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["a.txt", "sub"]);
    let a = listing.entries.iter().find(|e| e.name == "a.txt").unwrap();
    assert_eq!(a.kind, EntryKind::File);
    assert_eq!(a.size, Some(5));
    assert_eq!(a.owner.as_deref(), Some(OWNER));
    assert_eq!(a.group.as_deref(), Some(GROUP));
    assert!(a.modified.is_some());
    assert!(a.raw.as_deref().unwrap().ends_with(" a.txt"));
    let sub = listing.entries.iter().find(|e| e.name == "sub").unwrap();
    assert_eq!(sub.kind, EntryKind::Dir);
    assert!(listing.raw.unwrap().lines().count() == 2);
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_to_dir_is_enterable() {
    let mut f = fixture().await;
    std::fs::create_dir(f.root().join("real")).unwrap();
    std::fs::write(f.root().join("real/inside.txt"), b"x").unwrap();
    std::os::unix::fs::symlink("real", f.root().join("link")).unwrap();
    std::os::unix::fs::symlink("missing", f.root().join("broken")).unwrap();
    std::os::unix::fs::symlink("real/inside.txt", f.root().join("filelink")).unwrap();

    let listing = f
        .backend
        .list(&RemotePath::root(), CancellationToken::new())
        .await
        .unwrap();
    let kind = |name: &str| {
        listing
            .entries
            .iter()
            .find(|e| e.name == name)
            .unwrap()
            .kind
            .clone()
    };
    assert_eq!(
        kind("link"),
        EntryKind::Symlink {
            target: Some("real".into()),
            target_kind: Some(Box::new(EntryKind::Dir)),
        }
    );
    assert!(kind("link").is_dir_like());
    assert_eq!(
        kind("broken"),
        EntryKind::Symlink {
            target: Some("missing".into()),
            target_kind: None,
        }
    );
    assert_eq!(
        kind("filelink"),
        EntryKind::Symlink {
            target: Some("real/inside.txt".into()),
            target_kind: Some(Box::new(EntryKind::File)),
        }
    );

    // Entering the link lists the target directory.
    let inner = f
        .backend
        .list(&RemotePath::new("/link"), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(inner.entries.len(), 1);
    assert_eq!(inner.entries[0].name, "inside.txt");

    // stat reports the link, resolved.
    let entry = f.backend.stat(&RemotePath::new("/link")).await.unwrap();
    assert_eq!(entry.name, "link");
    assert!(entry.is_dir_like() && entry.kind.is_symlink());
}

#[tokio::test]
async fn large_transfers_and_resume_are_byte_identical() {
    let mut f = fixture().await;
    let data = pattern(3 * 1024 * 1024 + 4321);
    let path = RemotePath::new("/big.bin");

    // Upload in one go, download in one go (many pipelined requests).
    put(&mut f.backend, &path, WriteMode::Create, &data).await;
    assert_eq!(std::fs::read(f.root().join("big.bin")).unwrap(), data);
    assert_eq!(get(&mut f.backend, &path, 0).await, data);

    // Resume download from an odd offset.
    let off = 1_234_567;
    let tail = get(&mut f.backend, &path, off).await;
    assert_eq!(tail, data[off as usize..]);

    // Resume upload: a partial (and corrupted-tail) file is completed.
    let part = 2_000_003;
    let mut partial = data[..part].to_vec();
    partial.extend_from_slice(b"garbage beyond the resume point");
    std::fs::write(f.root().join("up.bin"), &partial).unwrap();
    let up = RemotePath::new("/up.bin");
    put(
        &mut f.backend,
        &up,
        WriteMode::ResumeAt(part as u64),
        &data[part..],
    )
    .await;
    assert_eq!(std::fs::read(f.root().join("up.bin")).unwrap(), data);

    // Append.
    put(&mut f.backend, &up, WriteMode::Append, b"!").await;
    assert_eq!(
        std::fs::metadata(f.root().join("up.bin")).unwrap().len(),
        data.len() as u64 + 1
    );
}

#[tokio::test]
async fn dropped_streams_leave_the_session_usable() {
    let mut f = fixture().await;
    let data = pattern(1024 * 1024);
    let path = RemotePath::new("/f.bin");
    put(&mut f.backend, &path, WriteMode::Create, &data).await;

    let mut r = f
        .backend
        .open_read(&path, 0, &TransferOpts::default())
        .await
        .unwrap();
    let mut buf = [0u8; 1000];
    r.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf[..], data[..1000]);
    drop(r);
    f.backend.finish_transfer().await.unwrap();

    let entry = f.backend.stat(&path).await.unwrap();
    assert_eq!(entry.size, Some(data.len() as u64));
}

#[tokio::test]
async fn read_errors_reach_finish_transfer() {
    let mut f = fixture().await;
    let missing = RemotePath::new("/nope.bin");
    assert!(matches!(
        f.backend
            .open_read(&missing, 0, &TransferOpts::default())
            .await,
        Err(Error::NotFound(p)) if p == missing
    ));
    // No transfer pending: finish_transfer is a no-op.
    f.backend.finish_transfer().await.unwrap();
}

#[tokio::test]
async fn rename_replaces_an_existing_file() {
    for posix_rename in [false, true] {
        let mut f = fixture_with(posix_rename).await;
        std::fs::write(f.root().join("a"), b"new").unwrap();
        std::fs::write(f.root().join("b"), b"old").unwrap();
        f.backend
            .rename(&RemotePath::new("/a"), &RemotePath::new("/b"))
            .await
            .unwrap();
        assert_eq!(std::fs::read(f.root().join("b")).unwrap(), b"new");
        assert!(!f.root().join("a").exists());
    }
}

#[tokio::test]
async fn mkdir_existing_is_already_exists() {
    let mut f = fixture().await;
    std::fs::create_dir(f.root().join("d")).unwrap();
    assert!(matches!(
        f.backend.mkdir(&RemotePath::new("/d")).await,
        Err(Error::AlreadyExists)
    ));
}

#[tokio::test]
async fn set_mtime_rejects_unrepresentable_times() {
    let mut f = fixture().await;
    std::fs::write(f.root().join("t"), b"").unwrap();
    let before_epoch = time::macros::datetime!(1960-01-01 00:00 UTC);
    assert!(matches!(
        f.backend
            .set_mtime(&RemotePath::new("/t"), before_epoch)
            .await,
        Err(Error::InvalidInput(_))
    ));
}

#[tokio::test]
async fn disconnect_and_reconnect() {
    let mut f = fixture().await;
    f.backend.disconnect().await.unwrap();
    assert!(!f.backend.is_connected());
    assert!(f.backend.session_info().is_none());
    assert!(matches!(
        f.backend.home_dir().await,
        Err(Error::Connection(_))
    ));
    f.backend.connect(CancellationToken::new()).await.unwrap();
    assert_eq!(f.backend.home_dir().await.unwrap(), RemotePath::root());
}

#[tokio::test]
async fn cancelled_list_returns_cancelled() {
    let mut f = fixture().await;
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(matches!(
        f.backend.list(&RemotePath::root(), cancel).await,
        Err(Error::Cancelled)
    ));
}

#[tokio::test]
async fn works_through_factory_and_session_handle() {
    let (dir, port) = server(false).await;
    std::fs::write(dir.path().join("x"), b"1").unwrap();
    let (tx, _rx) = events::channel(0);
    let backend = factory().create(&info(port), SessionId::next(), tx);
    let handle = SessionHandle::new(backend, None);
    let cancel = CancellationToken::new();
    handle.connect(cancel.clone()).await.unwrap();
    let listing = handle.list(&RemotePath::root(), &cancel).await.unwrap();
    assert_eq!(listing.entries.len(), 1);

    // A dropped connection is reconnected once by the handle.
    handle.lock().await.disconnect().await.unwrap();
    let listing = handle.list(&RemotePath::root(), &cancel).await.unwrap();
    assert_eq!(listing.entries.len(), 1);
}
