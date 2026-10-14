//! Manual check against a real OpenSSH server (driven by
//! `scripts/bench-sftp.sh`, not CI): the backend conformance suite, then a
//! timed upload and download of `COURIER_BENCH_SIZE_MIB` (default 1024) MiB.
//!
//! Environment: `COURIER_BENCH_PORT`, `COURIER_BENCH_USER`,
//! `COURIER_BENCH_KEY` (an unencrypted private key), `COURIER_BENCH_DIR` (an
//! empty remote directory, absolute), optional `COURIER_BENCH_HOST`
//! (default 127.0.0.1). Without them the test does nothing.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{sync::Arc, time::Instant};

use courier_ftp_core::{
    backend::{Backend, ConnectInfo, TransferOpts, WriteMode, conformance},
    events::{self, SessionId},
    model::{LocalPath, LogonType, Protocol, RemotePath, ServerAddress},
    settings::Settings,
};
use courier_ftp_proto_sftp::{SftpBackendFactory, ssh::AcceptAnyHostKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "manual: run through scripts/bench-sftp.sh"]
async fn openssh_conformance_and_throughput() {
    let (Some(port), Some(user), Some(key), Some(dir)) = (
        env("COURIER_BENCH_PORT"),
        env("COURIER_BENCH_USER"),
        env("COURIER_BENCH_KEY"),
        env("COURIER_BENCH_DIR"),
    ) else {
        eprintln!("COURIER_BENCH_* not set: skipping");
        return;
    };
    let host = env("COURIER_BENCH_HOST").unwrap_or_else(|| "127.0.0.1".into());
    let mib: usize = env("COURIER_BENCH_SIZE_MIB").map_or(1024, |v| v.parse().unwrap());

    let mut address = ServerAddress::new(Protocol::Sftp, host);
    address.port = port.parse().unwrap();
    let info = ConnectInfo::new(
        address,
        LogonType::KeyFile {
            user,
            path: LocalPath::new(key),
        },
    );
    let factory = SftpBackendFactory::new(
        Settings::default(),
        Arc::new(AcceptAnyHostKey::insecure_for_tests()),
    );
    let (tx, _rx) = events::channel(0);
    let mut b = factory.create_sftp(&info, SessionId::next(), tx);
    b.connect(CancellationToken::new()).await.unwrap();

    let base = RemotePath::new(&dir);
    let conf = base.join("conformance").unwrap();
    b.mkdir(&conf).await.unwrap();
    conformance::run(&mut b, &conf).await;
    b.rmdir(&conf).await.unwrap();
    eprintln!("conformance: ok");

    // The server is local: make a symlink to a directory next to the files.
    #[cfg(unix)]
    {
        use courier_ftp_core::model::EntryKind;
        std::fs::create_dir(format!("{dir}/real")).unwrap();
        std::fs::write(format!("{dir}/real/inside.txt"), b"x").unwrap();
        std::os::unix::fs::symlink("real", format!("{dir}/link")).unwrap();
        let listing = b.list(&base, CancellationToken::new()).await.unwrap();
        let link = listing.entries.iter().find(|e| e.name == "link").unwrap();
        assert_eq!(
            link.kind,
            EntryKind::Symlink {
                target: Some("real".into()),
                target_kind: Some(Box::new(EntryKind::Dir)),
            }
        );
        assert!(link.owner.as_deref().is_some_and(|o| !o.is_empty()));
        let inner = b
            .list(&base.join("link").unwrap(), CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(inner.entries.len(), 1);
        eprintln!("conformance: symlink ok (owner {:?})", link.owner);
    }

    let block = vec![0x5au8; 1024 * 1024];
    let path = base.join("bench.bin").unwrap();
    let total = (mib * block.len()) as f64 / (1024.0 * 1024.0);

    let start = Instant::now();
    let mut w = b
        .open_write(&path, WriteMode::Truncate, &TransferOpts::default())
        .await
        .unwrap();
    for _ in 0..mib {
        w.write_all(&block).await.unwrap();
    }
    w.shutdown().await.unwrap();
    drop(w);
    b.finish_transfer().await.unwrap();
    let up = start.elapsed().as_secs_f64();
    println!(
        "courier upload: {total:.0} MiB in {up:.2} s = {:.1} MiB/s",
        total / up
    );

    let start = Instant::now();
    let mut r = b
        .open_read(&path, 0, &TransferOpts::default())
        .await
        .unwrap();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut got = 0usize;
    loop {
        let n = r.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        got += n;
    }
    drop(r);
    b.finish_transfer().await.unwrap();
    let down = start.elapsed().as_secs_f64();
    assert_eq!(got, mib * block.len());
    println!(
        "courier download: {total:.0} MiB in {down:.2} s = {:.1} MiB/s",
        total / down
    );

    b.remove_file(&path).await.unwrap();
    b.disconnect().await.unwrap();
}
