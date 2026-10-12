//! Manual check of segmented transfers (T41b) against a real OpenSSH server,
//! driven by `scripts/bench-sftp.sh` and `scripts/bench-transfer.sh` (not
//! CI): the transfer engine downloads and uploads one
//! `COURIER_BENCH_SIZE_MIB` MiB file with one connection and with four
//! segments, uploads `COURIER_BENCH_SMALL` files of 4 KiB (0 skips), checks
//! every copy byte for byte, and prints the times and the client's CPU use
//! per thread.
//!
//! Environment as in `openssh_bench.rs`; the remote directory must be on
//! this machine (the server is local) so the files can be compared.
//! Optional: `COURIER_BENCH_SEGMENTS` (segment counts to compare, default
//! `1,4`), `COURIER_BENCH_DEPTH` (`sftp.max_outstanding_requests`) and
//! `RUST_LOG` (tracing to stderr, e.g. each segment's ranges and timing).

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
    events::{self, CoreEvent},
    model::{Direction, LocalPath, LogonType, Protocol, RemotePath, ServerAddress},
    queue::{NewItem, Queue, QueueServer, SharedQueue},
    settings::{Settings, TransferTypeChoice},
    transfer::{ServerResolver, TransferEngine},
};
use courier_ftp_proto_sftp::{SftpBackendFactory, ssh::AcceptAnyHostKey};
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
fn pattern_seeded(len: usize, seed: u64) -> Vec<u8> {
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
    let factory = SftpBackendFactory::new(
        settings.clone(),
        Arc::new(AcceptAnyHostKey::insecure_for_tests()),
    );
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
        file.write_all(&pattern_seeded(n, chunk_seed)).unwrap();
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

#[tokio::test(flavor = "multi_thread")]
#[ignore = "manual: run through scripts/bench-sftp.sh"]
async fn openssh_segmented_transfers() {
    let (Some(port), Some(user), Some(key), Some(dir)) = (
        env("COURIER_BENCH_PORT"),
        env("COURIER_BENCH_USER"),
        env("COURIER_BENCH_KEY"),
        env("COURIER_BENCH_DIR"),
    ) else {
        eprintln!("COURIER_BENCH_* not set: skipping");
        return;
    };
    if std::env::var_os("RUST_LOG").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_writer(std::io::stderr)
            .try_init();
    }
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
    let server = QueueServer::Quick {
        address: info.address.clone(),
        password: None,
    };
    let remote_dir = Path::new(&dir);
    // Next to the server's directory: on the same disk, not in RAM.
    let local = tempfile::tempdir_in(remote_dir.parent().unwrap_or(remote_dir)).unwrap();
    if mib > 0 {
        big_file(&info, &server, local.path(), remote_dir, mib).await;
    }
    let small: usize = env("COURIER_BENCH_SMALL").map_or(0, |v| v.parse().unwrap());
    if small > 0 {
        small_files(&info, &server, local.path(), remote_dir, small).await;
    }
}

fn bench_settings() -> Settings {
    let mut settings = Settings::default();
    settings.connection.keepalive = false;
    settings.connection.timeout_secs = 60;
    settings.file_types.default_type = TransferTypeChoice::Binary;
    // COURIER_BENCH_DEPTH: requests in flight per file (default 64).
    if let Some(depth) = env("COURIER_BENCH_DEPTH") {
        settings.sftp.max_outstanding_requests = depth.parse().unwrap();
    }
    settings
}

/// One large file down and up, with one connection and with four segments.
async fn big_file(
    info: &ConnectInfo,
    server: &QueueServer,
    local: &Path,
    remote_dir: &Path,
    mib: usize,
) {
    let source = remote_dir.join("seg-source.bin");
    write_pattern(&source, mib * 1024 * 1024, 0);
    let upload_source = local.join("up-source.bin");
    std::fs::copy(&source, &upload_source).unwrap();
    let size = Some((mib * 1024 * 1024) as u64);

    // COURIER_BENCH_SEGMENTS: the segment counts to compare (default 1,4).
    let counts: Vec<u32> = env("COURIER_BENCH_SEGMENTS").map_or(vec![1, 4], |v| {
        v.split(',').map(|n| n.trim().parse().unwrap()).collect()
    });
    for segments in counts {
        let mut settings = bench_settings();
        settings.transfers.segmented.max_segments = segments;

        let target = local.join(format!("down-{segments}.bin"));
        let secs = run(
            info,
            settings.clone(),
            vec![NewItem::file(
                server.clone(),
                Direction::Download,
                LocalPath::new(&target),
                RemotePath::new(source.to_str().unwrap()),
                size,
            )],
        )
        .await;
        same(&source, &target);
        println!(
            "courier engine download, {segments} segment(s): {mib} MiB in {secs:.2} s = {:.1} MiB/s (byte-identical)",
            mib as f64 / secs
        );

        let remote_target = remote_dir.join(format!("up-{segments}.bin"));
        let secs = run(
            info,
            settings,
            vec![NewItem::file(
                server.clone(),
                Direction::Upload,
                LocalPath::new(&upload_source),
                RemotePath::new(remote_target.to_str().unwrap()),
                size,
            )],
        )
        .await;
        same(&upload_source, &remote_target);
        println!(
            "courier engine upload, {segments} segment(s): {mib} MiB in {secs:.2} s = {:.1} MiB/s (byte-identical)",
            mib as f64 / secs
        );
        std::fs::remove_file(&target).unwrap();
        std::fs::remove_file(&remote_target).unwrap();
    }
    std::fs::remove_file(&source).unwrap();
    std::fs::remove_file(&upload_source).unwrap();
}

/// `count` files of 4 KiB uploaded with the default settings (4
/// connections) and with FileZilla's default of 2 connections.
async fn small_files(
    info: &ConnectInfo,
    server: &QueueServer,
    local: &Path,
    remote_dir: &Path,
    count: usize,
) {
    let src_dir = local.join("small");
    std::fs::create_dir_all(&src_dir).unwrap();
    for i in 0..count {
        std::fs::write(
            src_dir.join(format!("f{i:05}")),
            pattern_seeded(4096, i as u64),
        )
        .unwrap();
    }
    for concurrent in [4u32, 2] {
        let dst_dir = remote_dir.join(format!("small-{concurrent}"));
        std::fs::create_dir_all(&dst_dir).unwrap();
        let items = (0..count)
            .map(|i| {
                NewItem::file(
                    server.clone(),
                    Direction::Upload,
                    LocalPath::new(src_dir.join(format!("f{i:05}"))),
                    RemotePath::new(dst_dir.join(format!("f{i:05}")).to_str().unwrap()),
                    Some(4096),
                )
            })
            .collect();
        let mut settings = bench_settings();
        settings.transfers.max_concurrent = concurrent;
        let secs = run(info, settings, items).await;
        for i in (0..count).step_by(97) {
            let name = format!("f{i:05}");
            same(&src_dir.join(&name), &dst_dir.join(&name));
        }
        println!(
            "courier SFTP upload of {count} x 4 KiB, {concurrent} connections: {secs:.2} s = {:.0} files/s",
            count as f64 / secs
        );
        std::fs::remove_dir_all(&dst_dir).unwrap();
    }
    std::fs::remove_dir_all(&src_dir).unwrap();
}
