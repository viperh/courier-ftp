//! Manual FTP/FTPS transfer benchmark (T41b), driven by
//! `scripts/bench-transfer.sh` (not CI): through the transfer engine, one
//! large download with one connection and with four segments, and many
//! small files downloaded with the default settings. Every copy is compared
//! byte for byte.
//!
//! Environment (all set by the script):
//! - `COURIER_BENCH_FTP_PORT`, `COURIER_BENCH_FTP_USER`,
//!   `COURIER_BENCH_FTP_PASSWORD`: the server on 127.0.0.1;
//! - `COURIER_BENCH_FTP_TLS=1`: explicit FTPS (any certificate is accepted
//!   once);
//! - `COURIER_BENCH_FTP_DIR`: the server's root directory on this machine;
//! - `COURIER_BENCH_SIZE_MIB` (large file, 0 skips), `COURIER_BENCH_SMALL`
//!   (number of 4 KiB files, 0 skips).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use courier_ftp_core::{
    Result,
    backend::ConnectInfo,
    events::{self, CoreEvent, PromptKind, PromptResponse, TrustDecision},
    model::{Direction, FtpEncryption, LocalPath, LogonType, Protocol, RemotePath, ServerAddress},
    queue::{NewItem, Queue, QueueServer, SharedQueue},
    settings::{Settings, TransferTypeChoice},
    transfer::{ServerResolver, TransferEngine},
    trust::MemoryCertTrustStore,
};
use courier_ftp_proto_ftp::{backend::FtpBackendFactory, tls::TlsTrust};
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

struct Fixed(ConnectInfo);

#[async_trait]
impl ServerResolver for Fixed {
    async fn resolve(&self, _: &QueueServer, _: &CancellationToken) -> Result<ConnectInfo> {
        Ok(self.0.clone())
    }
}

/// Deterministic, incompressible test data.
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

/// CPU time (user + system) per thread of this process, Linux only.
fn thread_cpu() -> Vec<(String, f64)> {
    let mut out = Vec::new();
    let Ok(dir) = std::fs::read_dir("/proc/self/task") else {
        return out;
    };
    for task in dir.flatten() {
        let Ok(stat) = std::fs::read_to_string(task.path().join("stat")) else {
            continue;
        };
        // `pid (comm) state ...`: fields after the closing parenthesis.
        let Some((head, rest)) = stat.rsplit_once(") ") else {
            continue;
        };
        let fields: Vec<&str> = rest.split(' ').collect();
        let ticks = |i: usize| fields.get(i).and_then(|v| v.parse::<f64>().ok());
        if let (Some(user), Some(system)) = (ticks(11), ticks(12)) {
            let name = format!("{}:{}", task.file_name().to_string_lossy(), {
                head.split_once('(').map_or("", |(_, c)| c)
            });
            out.push((name, (user + system) / 100.0));
        }
    }
    out
}

/// Prints the busiest threads' CPU use between two [`thread_cpu`] samples.
fn report_cpu(before: &[(String, f64)], after: &[(String, f64)], secs: f64) {
    let mut used: Vec<(String, f64)> = after
        .iter()
        .map(|(name, t)| {
            let start = before
                .iter()
                .find(|(n, _)| n == name)
                .map_or(0.0, |(_, t)| *t);
            (name.clone(), (t - start) / secs * 100.0)
        })
        .filter(|(_, pct)| *pct > 0.5)
        .collect();
    used.sort_by(|a, b| b.1.total_cmp(&a.1));
    let total = used.iter().map(|(_, p)| p).sum::<f64>().max(0.0);
    let top: Vec<String> = used
        .iter()
        .take(6)
        .map(|(_, p)| format!("{p:.0}%"))
        .collect();
    println!(
        "courier cpu: {total:.0}% of one core in total, busiest threads {}",
        top.join(" ")
    );
}

/// Runs `items` through the engine; returns the seconds it took.
async fn run(info: &ConnectInfo, settings: Settings, items: Vec<NewItem>) -> f64 {
    let queue: SharedQueue = Arc::new(Mutex::new(Queue::default()));
    let (tx, mut rx) = events::channel(0);
    let trust = Arc::new(TlsTrust::with_system_verifier(
        Arc::new(MemoryCertTrustStore::new()),
        None,
    ));
    let factory = FtpBackendFactory::new(settings.clone(), trust);
    let (engine, handle) = TransferEngine::builder(
        Arc::clone(&queue),
        Arc::new(factory),
        Arc::new(Fixed(info.clone())),
        tx,
    )
    .settings(settings)
    .build();
    let engine = engine.spawn();
    let count = items.len();
    {
        let mut q = queue.lock().unwrap();
        for item in items {
            q.add(item, time::OffsetDateTime::UNIX_EPOCH);
        }
    }
    let cpu = thread_cpu();
    let start = Instant::now();
    handle.start();
    let stats = tokio::time::timeout(Duration::from_secs(3600), async {
        loop {
            match rx.recv().await {
                Some(CoreEvent::QueueFinished { stats }) => break stats,
                Some(CoreEvent::Prompt(req))
                    if matches!(req.kind, PromptKind::TrustCertificate { .. }) =>
                {
                    let _ = req.reply.send(PromptResponse::Trust(TrustDecision::Once));
                }
                Some(_) => {}
                None => panic!("event channel closed"),
            }
        }
    })
    .await
    .expect("transfer finished");
    let secs = start.elapsed().as_secs_f64();
    report_cpu(&cpu, &thread_cpu(), secs);
    assert_eq!(
        (stats.files_ok as usize, stats.files_failed),
        (count, 0),
        "{stats:?}"
    );
    handle.shutdown();
    engine.await.unwrap();
    secs
}

/// Writes `len` bytes of incompressible test data to `path`, 8 MiB at a
/// time (the large file never sits in memory whole).
fn write_pattern(path: &Path, len: usize, seed: u64) {
    use std::io::Write;
    let mut file = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    let mut left = len;
    let mut chunk_seed = seed;
    while left > 0 {
        let n = left.min(8 << 20);
        chunk_seed = chunk_seed.wrapping_add(0x9e37_79b9);
        file.write_all(&pattern(n, chunk_seed)).unwrap();
        left -= n;
    }
    file.flush().unwrap();
}

/// Compares two files 8 MiB at a time.
fn same(a: &Path, b: &Path) {
    use std::io::Read;
    let (ma, mb) = (std::fs::metadata(a).unwrap(), std::fs::metadata(b).unwrap());
    assert_eq!(ma.len(), mb.len(), "file sizes differ");
    let (mut fa, mut fb) = (
        std::fs::File::open(a).unwrap(),
        std::fs::File::open(b).unwrap(),
    );
    let (mut ba, mut bb) = (vec![0u8; 8 << 20], vec![0u8; 8 << 20]);
    loop {
        let n = fa.read(&mut ba).unwrap();
        if n == 0 {
            break;
        }
        fb.read_exact(&mut bb[..n]).unwrap();
        assert!(ba[..n] == bb[..n], "files differ");
    }
}

fn bench_settings() -> Settings {
    let mut settings = Settings::default();
    settings.connection.keepalive = false;
    settings.connection.timeout_secs = 60;
    settings.file_types.default_type = TransferTypeChoice::Binary;
    settings
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "manual: run through scripts/bench-transfer.sh"]
async fn ftp_transfer_bench() {
    let (Some(port), Some(user), Some(password), Some(dir)) = (
        env("COURIER_BENCH_FTP_PORT"),
        env("COURIER_BENCH_FTP_USER"),
        env("COURIER_BENCH_FTP_PASSWORD"),
        env("COURIER_BENCH_FTP_DIR"),
    ) else {
        eprintln!("COURIER_BENCH_FTP_* not set: skipping");
        return;
    };
    let tls = env("COURIER_BENCH_FTP_TLS").is_some_and(|v| v == "1");
    let protocol = if tls {
        Protocol::FtpsExplicit
    } else {
        Protocol::Ftp
    };
    let label = if tls { "FTPS" } else { "FTP" };
    let mut address = ServerAddress::new(protocol, "127.0.0.1");
    address.port = port.parse().unwrap();
    let mut info = ConnectInfo::new(
        address,
        LogonType::Normal {
            user,
            password: SecretString::from(password),
        },
    );
    if !tls {
        info.encryption = Some(FtpEncryption::PlainOnly);
    }
    let server = QueueServer::Quick {
        address: info.address.clone(),
        password: None,
    };
    let root = Path::new(&dir);
    let local = tempfile::tempdir_in(root.parent().unwrap_or(root)).unwrap();

    let mib: usize = env("COURIER_BENCH_SIZE_MIB").map_or(0, |v| v.parse().unwrap());
    if mib > 0 {
        let source = root.join("ftp-big.bin");
        write_pattern(&source, mib * 1024 * 1024, 1);
        for segments in [1u32, 4] {
            let mut settings = bench_settings();
            settings.transfers.segmented.max_segments = segments;
            let target = local.path().join(format!("down-{segments}.bin"));
            let secs = run(
                &info,
                settings,
                vec![NewItem::file(
                    server.clone(),
                    Direction::Download,
                    LocalPath::new(&target),
                    RemotePath::new("/ftp-big.bin"),
                    Some((mib * 1024 * 1024) as u64),
                )],
            )
            .await;
            same(&source, &target);
            println!(
                "courier {label} download, {segments} segment(s): {mib} MiB in {secs:.2} s = {:.1} MiB/s (byte-identical)",
                mib as f64 / secs
            );
            std::fs::remove_file(&target).unwrap();
        }
        std::fs::remove_file(&source).unwrap();
    }

    let small: usize = env("COURIER_BENCH_SMALL").map_or(0, |v| v.parse().unwrap());
    if small > 0 {
        let src_dir = root.join("small");
        std::fs::create_dir_all(&src_dir).unwrap();
        for i in 0..small {
            std::fs::write(src_dir.join(format!("f{i:05}")), pattern(4096, i as u64)).unwrap();
        }
        for concurrent in [4u32, 2] {
            let dst_dir = local.path().join(format!("small-{concurrent}"));
            std::fs::create_dir_all(&dst_dir).unwrap();
            let items = (0..small)
                .map(|i| {
                    NewItem::file(
                        server.clone(),
                        Direction::Download,
                        LocalPath::new(dst_dir.join(format!("f{i:05}"))),
                        RemotePath::new(format!("/small/f{i:05}")),
                        Some(4096),
                    )
                })
                .collect();
            let mut settings = bench_settings();
            settings.transfers.max_concurrent = concurrent;
            let secs = run(&info, settings, items).await;
            for i in (0..small).step_by(97) {
                let name = format!("f{i:05}");
                same(&src_dir.join(&name), &dst_dir.join(&name));
            }
            println!(
                "courier {label} download of {small} x 4 KiB, {concurrent} connections: {secs:.2} s = {:.0} files/s",
                small as f64 / secs
            );
        }
        std::fs::remove_dir_all(&src_dir).unwrap();
    }
}
