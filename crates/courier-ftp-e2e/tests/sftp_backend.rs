//! T22 end to end: `SftpBackend` against the OpenSSH fixture — the
//! `limits@openssh.com` chunk size, a resumed transfer after toxiproxy cuts the
//! connection, a `Headless` session through `E2eBackendFactory`, and the manual
//! throughput benchmark. The T03 conformance suite on the sshd profiles (AC1) is in
//! `backend_conformance.rs` (T76 AC13). Every test is `#[ignore]` and starts with `require_docker!()`; run with
//! `COURIER_E2E=1 cargo test -p courier-ftp-e2e --test sftp_backend -- --ignored`.
//!
//! Host keys are accepted with the test-only `InsecureAcceptAnyHostKey` (the trust
//! flow is covered by `ssh_host_keys.rs`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{net::SocketAddr, sync::Arc};

use courier_ftp_core::{
    Error,
    backend::{Backend, ConnectInfo, TransferEnd, TransferOpts, WriteMode, mock},
    model::{FtpEncryption, LogonType, Protocol, RemotePath, ServerAddress},
    net::CancellationToken,
    secret::SecretString,
    settings::Settings,
};
use courier_ftp_e2e::{
    Sshd, SshdOptions, SshdProfile, TestNetwork, Toxiproxy,
    keys::{PASSWORD, USER},
    require_docker,
};
use courier_ftp_proto_sftp::{SftpBackend, convert::core_error, ssh::InsecureAcceptAnyHostKey};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn info_for(addr: SocketAddr) -> ConnectInfo {
    let address = ServerAddress::new(
        Protocol::Sftp,
        FtpEncryption::ExplicitIfAvailable,
        addr.ip().to_string(),
        Some(addr.port()),
        Some(USER.to_owned()),
    )
    .unwrap();
    ConnectInfo::quick(
        address,
        LogonType::Normal {
            password: Some(SecretString::from(PASSWORD)),
        },
    )
}

fn backend(info: &Arc<ConnectInfo>) -> SftpBackend {
    let (ctx, mut rx) = mock::test_context_with(Settings::default());
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    SftpBackend::new(
        Arc::clone(info),
        ctx,
        Arc::new(InsecureAcceptAnyHostKey),
        None,
    )
}

async fn connected(addr: SocketAddr) -> SftpBackend {
    let mut b = backend(&Arc::new(info_for(addr)));
    b.connect(CancellationToken::new()).await.unwrap();
    b
}

/// AC9: OpenSSH advertises `limits@openssh.com`; the read chunk is 255 KiB.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn e2e_openssh_limits_chunk_is_255k() {
    require_docker!();
    let sshd = Sshd::start(SshdProfile::Password).await.unwrap();
    let mut b = connected(sshd.addr()).await;
    let info = b.server_info().unwrap();
    assert!(info.extensions.limits.is_some(), "{:?}", info.extensions);
    assert!(info.extensions.posix_rename);
    assert_eq!(info.read_chunk, 261_120);
    assert_eq!(info.write_chunk, 261_120);
    assert_eq!(info.outstanding, 32);
    assert_eq!(b.home_dir().await.unwrap().as_str(), "/home/test");
    // A transfer with those sizes works.
    let out = sshd
        .exec("head -c 3000000 /dev/urandom > /home/test/upload/r.bin")
        .await
        .unwrap();
    assert!(out.success(), "{out:?}");
    let mut r = b
        .open_read(
            &RemotePath::parse("/home/test/upload/r.bin").unwrap(),
            0,
            &TransferOpts::default(),
        )
        .await
        .unwrap();
    let mut data = Vec::new();
    r.read_to_end(&mut data).await.unwrap();
    drop(r);
    b.finish_transfer(TransferEnd::Complete).await.unwrap();
    let want = sshd.sha256_of("/home/test/upload/r.bin").await.unwrap();
    assert_eq!(hex(&Sha256::digest(&data)), want);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// AC3: a download and an upload cut by toxiproxy resume at the received offset and
/// end byte-identical.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn e2e_resume_after_toxiproxy_cut() {
    require_docker!();
    let net = TestNetwork::new().await.unwrap();
    let sshd = Sshd::start_with(SshdOptions {
        network: Some(net.name().into()),
        ..SshdOptions::new(SshdProfile::Password)
    })
    .await
    .unwrap();
    let toxi = Toxiproxy::start(&net).await.unwrap();
    let proxy = toxi.proxy("ssh", 2222, sshd.addr()).await.unwrap();
    let out = sshd
        .exec("head -c 20000000 /dev/urandom > /home/test/upload/big.bin")
        .await
        .unwrap();
    assert!(out.success(), "{out:?}");
    let want = sshd.sha256_of("/home/test/upload/big.bin").await.unwrap();
    let path = RemotePath::parse("/home/test/upload/big.bin").unwrap();

    // Download 4 MiB, cut, resume from there.
    let mut b = connected(proxy.addr()).await;
    let mut r = b
        .open_read(&path, 0, &TransferOpts::default())
        .await
        .unwrap();
    let mut got = vec![0; 4 << 20];
    r.read_exact(&mut got).await.unwrap();
    proxy.disable().await.unwrap();
    let mut rest = Vec::new();
    let err = r.read_to_end(&mut rest).await.unwrap_err();
    assert!(
        matches!(core_error(&err), Some(Error::Connection(_))),
        "{err:?}"
    );
    got.extend_from_slice(&rest);
    drop(r);
    let _ = b.finish_transfer(TransferEnd::Abort).await;
    proxy.enable().await.unwrap();
    b.connect(CancellationToken::new()).await.unwrap();
    let mut r = b
        .open_read(&path, got.len() as u64, &TransferOpts::default())
        .await
        .unwrap();
    r.read_to_end(&mut got).await.unwrap();
    drop(r);
    b.finish_transfer(TransferEnd::Complete).await.unwrap();
    assert_eq!(hex(&Sha256::digest(&got)), want);

    // Upload 8 MiB, cut, resume at what the server has.
    let up = RemotePath::parse("/home/test/upload/up.bin").unwrap();
    let mut w = b
        .open_write(&up, WriteMode::Truncate, &TransferOpts::default())
        .await
        .unwrap();
    w.write_all(&got[..8 << 20]).await.unwrap();
    w.flush().await.unwrap();
    proxy.disable().await.unwrap();
    let _ = w.write_all(&got[8 << 20..]).await;
    drop(w);
    let _ = b.finish_transfer(TransferEnd::Abort).await;
    proxy.enable().await.unwrap();
    b.connect(CancellationToken::new()).await.unwrap();
    let have = b.stat(&up).await.unwrap().size.unwrap();
    assert!(have >= 8 << 20 && have <= got.len() as u64, "{have}");
    let mut w = b
        .open_write(&up, WriteMode::ResumeAt(have), &TransferOpts::default())
        .await
        .unwrap();
    w.write_all(&got[usize::try_from(have).unwrap()..])
        .await
        .unwrap();
    w.shutdown().await.unwrap();
    drop(w);
    b.finish_transfer(TransferEnd::Complete).await.unwrap();
    assert_eq!(
        sshd.sha256_of("/home/test/upload/up.bin").await.unwrap(),
        want
    );
}

/// The harness factory (`E2eBackendFactory`) creates `SftpBackend`s: a `Headless`
/// session trusts the host key once and lists the fixture tree.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn e2e_headless_session_over_sftp() {
    require_docker!();
    let sshd = Sshd::start(SshdProfile::Password).await.unwrap();
    let h = courier_ftp_e2e::Headless::connect(
        None,
        info_for(sshd.addr()),
        courier_ftp_e2e::HeadlessOptions {
            host_key: courier_ftp_e2e::PromptPolicy::TrustOnce,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let listing = h
        .list(&RemotePath::parse("/home/test").unwrap())
        .await
        .unwrap();
    let names: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
    assert!(
        names.contains(&"upload") && names.contains(&"fixtures"),
        "{names:?}"
    );
    assert_eq!(h.prompts_seen().len(), 1, "{:?}", h.prompts_seen());
    h.close().await;
}

/// AC16 (manual, `scripts/bench-sftp.sh`): 3 downloads and 3 uploads of a
/// `COURIER_BENCH_MIB` MiB (default 1024) random file with `SftpBackend` and with
/// OpenSSH `sftp -B 261120 -R 64` (run inside the container over loopback, through
/// `sshpass`); prints the median MiB/s of each and the ratio. Only runs with
/// `COURIER_BENCH=1`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "manual benchmark (scripts/bench-sftp.sh)"]
async fn bench_sftp_vs_openssh() {
    require_docker!();
    if std::env::var_os("COURIER_BENCH").is_none() {
        eprintln!("skipped: set COURIER_BENCH=1 (scripts/bench-sftp.sh)");
        return;
    }
    let mib: u64 = std::env::var("COURIER_BENCH_MIB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1024);
    let sshd = Sshd::start(SshdProfile::Password).await.unwrap();
    let src = "/home/test/upload/bench.bin";
    let out = sshd
        .exec(&format!("head -c {} /dev/urandom > {src}", mib << 20))
        .await
        .unwrap();
    assert!(out.success(), "{out:?}");
    let mut b = connected(sshd.addr()).await;
    let path = RemotePath::parse(src).unwrap();
    let rate = |secs: f64| mib as f64 / secs;
    let median = |mut v: Vec<f64>| {
        v.sort_by(f64::total_cmp);
        v[v.len() / 2]
    };

    let (mut ours_down, mut ours_up) = (Vec::new(), Vec::new());
    let mut data = Vec::with_capacity(usize::try_from(mib << 20).unwrap());
    for i in 0..3 {
        data.clear();
        let t = std::time::Instant::now();
        let mut r = b
            .open_read(&path, 0, &TransferOpts::default())
            .await
            .unwrap();
        r.read_to_end(&mut data).await.unwrap();
        drop(r);
        b.finish_transfer(TransferEnd::Complete).await.unwrap();
        ours_down.push(rate(t.elapsed().as_secs_f64()));
        let up = RemotePath::parse(&format!("/home/test/upload/up{i}.bin")).unwrap();
        let t = std::time::Instant::now();
        let mut w = b
            .open_write(&up, WriteMode::Truncate, &TransferOpts::default())
            .await
            .unwrap();
        w.write_all(&data).await.unwrap();
        w.shutdown().await.unwrap();
        drop(w);
        b.finish_transfer(TransferEnd::Complete).await.unwrap();
        ours_up.push(rate(t.elapsed().as_secs_f64()));
        b.remove_file(&up).await.unwrap();
    }

    let (mut ssh_down, mut ssh_up) = (Vec::new(), Vec::new());
    let sftp = "sshpass -p test sftp -q -B 261120 -R 64 -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null -b - test@127.0.0.1";
    for _ in 0..3 {
        for (dir, batch, out) in [
            ("down", format!("get {src} /tmp/bench.get"), &mut ssh_down),
            (
                "up",
                "put /tmp/bench.get /home/test/upload/sftp-up.bin".to_owned(),
                &mut ssh_up,
            ),
        ] {
            let cmd = format!(
                "s=$(date +%s.%N); echo '{batch}' | {sftp} >/dev/null && e=$(date +%s.%N); \
                 echo \"$s $e\""
            );
            let o = sshd.exec(&cmd).await.unwrap();
            assert!(o.success(), "{dir}: {o:?}");
            let t: Vec<f64> = o
                .stdout
                .split_whitespace()
                .filter_map(|v| v.parse().ok())
                .collect();
            out.push(rate(t[1] - t[0]));
        }
    }
    let (od, ou, sd, su) = (
        median(ours_down),
        median(ours_up),
        median(ssh_down),
        median(ssh_up),
    );
    println!(
        "BENCH {mib} MiB: download {od:.1} / {sd:.1} MiB/s ({:.0} %), upload {ou:.1} / {su:.1} MiB/s ({:.0} %)",
        od / sd * 100.0,
        ou / su * 100.0
    );
}
