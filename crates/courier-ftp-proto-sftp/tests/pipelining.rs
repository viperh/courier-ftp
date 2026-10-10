//! T22 pipelining (D11): request depth, virtual-time throughput, short reads, the
//! `limits@openssh.com` sizes and the 8 MiB in-flight budget, over the duplex SFTP
//! server (no SSH) so paused time measures pure request latency.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use courier_ftp_core::{
    backend::{Backend, TransferEnd, TransferOpts, WriteMode},
    model::RemotePath,
    settings::Settings,
};
use courier_ftp_proto_sftp::{
    backend::ServerLimits,
    testing::{SftpTestKnobs, duplex_backend},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::Instant,
};

const MIB: u64 = 1 << 20;

fn p(s: &str) -> RemotePath {
    RemotePath::parse(s).unwrap()
}

fn pattern(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn latency(ms: u64) -> SftpTestKnobs {
    SftpTestKnobs {
        per_request_latency: Duration::from_millis(ms),
        ..SftpTestKnobs::default()
    }
}

fn outstanding(n: u32) -> Settings {
    let mut s = Settings::default();
    s.sftp.max_outstanding_requests = n;
    s
}

/// A sparse file of `len` bytes.
fn sparse(dir: &std::path::Path, name: &str, len: u64) {
    std::fs::File::create(dir.join(name))
        .unwrap()
        .set_len(len)
        .unwrap();
}

/// Download `path`; returns (bytes, virtual time of the data phase: from the open
/// stream to EOF).
async fn download(b: &mut dyn Backend, path: &str) -> (u64, Duration) {
    let mut r = b
        .open_read(&p(path), 0, &TransferOpts::default())
        .await
        .unwrap();
    let start = Instant::now();
    let n = tokio::io::copy(&mut r, &mut tokio::io::sink())
        .await
        .unwrap();
    let took = start.elapsed();
    drop(r);
    b.finish_transfer(TransferEnd::Complete).await.unwrap();
    (n, took)
}

/// Upload `len` zero bytes; returns the virtual time from the open stream until every
/// WRITE is acknowledged (flush; the CLOSE follows).
async fn upload(b: &mut dyn Backend, path: &str, len: u64) -> Duration {
    let mut w = b
        .open_write(&p(path), WriteMode::Truncate, &TransferOpts::default())
        .await
        .unwrap();
    let block = vec![0u8; MIB as usize];
    let start = Instant::now();
    for _ in 0..len / MIB {
        w.write_all(&block).await.unwrap();
    }
    w.flush().await.unwrap();
    let took = start.elapsed();
    w.shutdown().await.unwrap();
    drop(w);
    b.finish_transfer(TransferEnd::Complete).await.unwrap();
    took
}

/// AC7 (read): 64 READs in flight; 64 MiB at 50 ms per request in ≤ 1.7 s of virtual
/// time with the defaults (32 KiB × 64), ≥ 100 s with one request in flight.
#[tokio::test(start_paused = true)]
async fn pipelining_depth_and_virtual_time_read() {
    let dir = tempfile::tempdir().unwrap();
    sparse(dir.path(), "f", 64 * MIB);

    let (mut b, stats, _rx) = duplex_backend(latency(50), dir.path(), Settings::default()).await;
    let (n, took) = download(&mut b, "/f").await;
    assert_eq!(n, 64 * MIB);
    assert_eq!(stats.max_reads_in_flight(), 64);
    assert!(took <= Duration::from_millis(1700), "took {took:?}");

    let (mut b, stats, _rx) = duplex_backend(latency(50), dir.path(), outstanding(1)).await;
    let (n, took) = download(&mut b, "/f").await;
    assert_eq!(n, 64 * MIB);
    assert_eq!(stats.max_reads_in_flight(), 1);
    assert!(took >= Duration::from_secs(100), "took {took:?}");
}

/// AC7 (write): the same for WRITE.
#[tokio::test(start_paused = true)]
async fn pipelining_depth_and_virtual_time_write() {
    let dir = tempfile::tempdir().unwrap();
    let (mut b, stats, _rx) = duplex_backend(latency(50), dir.path(), Settings::default()).await;
    let took = upload(&mut b, "/up", 64 * MIB).await;
    assert_eq!(stats.max_writes_in_flight(), 64);
    assert!(took <= Duration::from_millis(1700), "took {took:?}");
    assert_eq!(
        std::fs::metadata(dir.path().join("up")).unwrap().len(),
        64 * MIB
    );

    let (mut b, stats, _rx) = duplex_backend(latency(50), dir.path(), outstanding(1)).await;
    let took = upload(&mut b, "/up2", 64 * MIB).await;
    assert_eq!(stats.max_writes_in_flight(), 1);
    assert!(took >= Duration::from_secs(100), "took {took:?}");
}

/// AC8: the server caps reads at 10 000 bytes: the download is byte-identical and,
/// once the chunk adapted, no byte range is requested twice.
#[tokio::test]
async fn short_reads_adapt_without_rerequests() {
    let dir = tempfile::tempdir().unwrap();
    let data = pattern(3 * MIB as usize + 777, 1);
    std::fs::write(dir.path().join("f"), &data).unwrap();
    let knobs = SftpTestKnobs {
        max_read_len: Some(10_000),
        record_requests: true,
        per_request_latency: Duration::from_millis(1),
        ..SftpTestKnobs::default()
    };
    let (mut b, stats, _rx) = duplex_backend(knobs, dir.path(), Settings::default()).await;
    let mut r = b
        .open_read(&p("/f"), 0, &TransferOpts::default())
        .await
        .unwrap();
    let mut back = Vec::new();
    r.read_to_end(&mut back).await.unwrap();
    drop(r);
    b.finish_transfer(TransferEnd::Complete).await.unwrap();
    assert!(back == data, "contents differ");

    let reads = stats.reads();
    let first = reads.iter().position(|&(_, len)| len == 10_000).unwrap();
    let size = data.len() as u64;
    // Byte ranges of the file (requests past the end ask for no data).
    let mut after: Vec<(u64, u64)> = reads[first..]
        .iter()
        .filter(|&&(off, _)| off < size)
        .map(|&(off, len)| (off, (off + u64::from(len)).min(size)))
        .collect();
    assert!(reads[first..].iter().all(|&(_, len)| len <= 10_000));
    after.sort_unstable();
    for w in after.windows(2) {
        assert!(w[0].1 <= w[1].0, "ranges {:?} and {:?} overlap", w[0], w[1]);
    }
}

/// AC9: `limits@openssh.com` with 16 KiB reads/writes: nothing larger is sent.
#[tokio::test]
async fn limits_extension_respected() {
    let dir = tempfile::tempdir().unwrap();
    let data = pattern(MIB as usize, 2);
    std::fs::write(dir.path().join("f"), &data).unwrap();
    let knobs = SftpTestKnobs {
        advertise_limits: Some(ServerLimits {
            max_packet_len: 34_000,
            max_read_len: 16_384,
            max_write_len: 16_384,
            max_open_handles: 0,
        }),
        ..SftpTestKnobs::default()
    };
    let (mut b, stats, _rx) = duplex_backend(knobs, dir.path(), Settings::default()).await;
    let info = b.server_info().unwrap();
    assert_eq!((info.read_chunk, info.write_chunk), (16_384, 16_384));
    assert_eq!(info.extensions.limits.map(|l| l.max_read_len), Some(16_384));
    let (n, _) = download(&mut b, "/f").await;
    assert_eq!(n, MIB);
    let mut w = b
        .open_write(&p("/g"), WriteMode::Truncate, &TransferOpts::default())
        .await
        .unwrap();
    w.write_all(&data).await.unwrap();
    w.shutdown().await.unwrap();
    drop(w);
    b.finish_transfer(TransferEnd::Complete).await.unwrap();
    assert!(std::fs::read(dir.path().join("g")).unwrap() == data);
    assert!(stats.max_read_len() <= 16_384, "{}", stats.max_read_len());
    assert!(stats.max_write_len() <= 16_384, "{}", stats.max_write_len());
    assert!(stats.max_read_len() > 0 && stats.max_write_len() > 0);
}

/// AC10: never more than 8 MiB in flight per open file (256 × 255 KiB requested).
#[tokio::test(start_paused = true)]
async fn inflight_budget_respected() {
    let dir = tempfile::tempdir().unwrap();
    sparse(dir.path(), "big", 256 * MIB);
    let mut settings = Settings::default();
    settings.sftp.max_outstanding_requests = 256;
    settings.sftp.request_size = 261_120;
    let (mut b, stats, _rx) = duplex_backend(latency(5), dir.path(), settings).await;
    let (n, _) = download(&mut b, "/big").await;
    assert_eq!(n, 256 * MIB);
    assert!(
        stats.max_bytes_in_flight() <= 8 * MIB,
        "{}",
        stats.max_bytes_in_flight()
    );
    assert!(
        stats.max_bytes_in_flight() > 4 * MIB,
        "the pipeline was not used"
    );
    stats.reset();
    upload(&mut b, "/up", 64 * MIB).await;
    assert!(
        stats.max_bytes_in_flight() <= 8 * MIB,
        "{}",
        stats.max_bytes_in_flight()
    );
    assert!(stats.max_bytes_in_flight() > 4 * MIB);
}
