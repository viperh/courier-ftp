//! T22 integration tests: `SftpBackend` against the in-process SFTP server (over SSH
//! with `SftpTestServer`, or over a duplex stream with `duplex_backend`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{sync::Arc, time::Duration};

use courier_ftp_core::{
    Error,
    backend::{Backend, SessionHandle, SessionOptions, TransferEnd, TransferOpts, WriteMode, mock},
    events::{CoreEvent, EventReceiver, LogKind, PromptResponse},
    model::{EntryKind, LogonType, RemotePath, SymlinkTarget},
    secret::SecretString,
    settings::Settings,
};
use courier_ftp_proto_sftp::{
    SftpBackend,
    backend::ServerLimits,
    convert::{SftpOp, core_error},
    ssh::InsecureAcceptAnyHostKey,
    testing::{SftpTestKnobs, SftpTestServer, duplex_backend},
};
use russh_sftp::protocol::StatusCode;
use sha2::{Digest, Sha256};
use time::{Date, Month, OffsetDateTime, Time};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

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

fn sha(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

async fn connected(server: &SftpTestServer) -> SftpBackend {
    let mut b = server.backend_default();
    b.connect(CancellationToken::new()).await.unwrap();
    b
}

async fn read_all(
    b: &mut dyn Backend,
    path: &RemotePath,
    offset: u64,
    range: Option<u64>,
) -> Vec<u8> {
    let opts = TransferOpts {
        range_len: range,
        ..TransferOpts::default()
    };
    let mut r = b.open_read(path, offset, &opts).await.unwrap();
    let mut out = Vec::new();
    r.read_to_end(&mut out).await.unwrap();
    drop(r);
    b.finish_transfer(TransferEnd::Complete).await.unwrap();
    out
}

async fn write_all(b: &mut dyn Backend, path: &RemotePath, mode: WriteMode, data: &[u8]) {
    let mut w = b
        .open_write(path, mode, &TransferOpts::default())
        .await
        .unwrap();
    w.write_all(data).await.unwrap();
    w.shutdown().await.unwrap();
    drop(w);
    b.finish_transfer(TransferEnd::Complete).await.unwrap();
}

/// Log lines received so far.
fn log_lines(rx: &mut EventReceiver) -> Vec<(LogKind, String)> {
    let mut out = Vec::new();
    while let Some(ev) = rx.try_recv() {
        if let CoreEvent::Log(m) = ev {
            out.push((m.kind, m.text));
        }
    }
    out
}

// ------------------------------------------------------------------ AC18

#[cfg(unix)]
#[tokio::test]
async fn stat_symlink_not_followed() {
    let server = SftpTestServer::start(SftpTestKnobs::default()).await;
    std::fs::write(server.local("/scratch/target"), b"0123456789").unwrap();
    std::os::unix::fs::symlink("target", server.local("/scratch/link")).unwrap();
    let mut b = connected(&server).await;
    let e = b.stat(&p("/scratch/link")).await.unwrap();
    assert_eq!(e.name, "link");
    assert_eq!(
        e.kind,
        EntryKind::Symlink {
            target: Some("target".into()),
            target_kind: Some(SymlinkTarget::File)
        }
    );
    // The link's own attributes (size = length of the link text), not the target's.
    assert_eq!(e.size, Some(6));
    let t = b.stat(&p("/scratch/target")).await.unwrap();
    assert_eq!((t.kind, t.size), (EntryKind::File, Some(10)));
}

#[tokio::test]
async fn range_len_stops_requests_at_segment_end() {
    let dir = tempfile::tempdir().unwrap();
    let data = pattern(3 << 20, 1);
    std::fs::write(dir.path().join("f"), &data).unwrap();
    let knobs = SftpTestKnobs {
        record_requests: true,
        per_request_latency: Duration::from_millis(1),
        ..SftpTestKnobs::default()
    };
    let (mut b, stats, _rx) = duplex_backend(knobs, dir.path(), Settings::default()).await;
    let (offset, n) = (1_000_000u64, 1_234_567u64);
    let back = read_all(&mut b, &p("/f"), offset, Some(n)).await;
    assert_eq!(back.len() as u64, n);
    assert!(back == data[offset as usize..(offset + n) as usize]);
    let reads = stats.reads();
    assert!(!reads.is_empty());
    for (off, len) in reads {
        assert!(off >= offset && off < offset + n, "READ at {off}");
        assert!(
            off + u64::from(len) <= offset + n,
            "READ {off}+{len} past the end"
        );
    }
}

#[tokio::test]
async fn write_at_keeps_other_bytes() {
    let server = SftpTestServer::start(SftpTestKnobs::default()).await;
    let mut want = pattern(200_000, 2);
    std::fs::write(server.local("/scratch/f"), &want).unwrap();
    let mut b = connected(&server).await;
    let patch = pattern(50_000, 3);
    write_all(&mut b, &p("/scratch/f"), WriteMode::WriteAt(70_000), &patch).await;
    want[70_000..120_000].copy_from_slice(&patch);
    assert!(std::fs::read(server.local("/scratch/f")).unwrap() == want);
    // Beyond the end: the gap is zero-filled, nothing before it changes.
    write_all(
        &mut b,
        &p("/scratch/f"),
        WriteMode::WriteAt(250_000),
        b"tail",
    )
    .await;
    let back = std::fs::read(server.local("/scratch/f")).unwrap();
    assert_eq!(back.len(), 250_004);
    assert!(back[..200_000] == want[..]);
    assert!(back[200_000..250_000].iter().all(|&b| b == 0));
}

// ------------------------------------------------------------------ AC2

#[cfg(unix)]
#[tokio::test]
async fn symlink_to_dir_enterable_and_broken_link() {
    let server = SftpTestServer::start(SftpTestKnobs::default()).await;
    std::fs::create_dir(server.local("/scratch/d")).unwrap();
    std::fs::write(server.local("/scratch/d/inner.txt"), b"x").unwrap();
    std::os::unix::fs::symlink("d", server.local("/scratch/ld")).unwrap();
    std::os::unix::fs::symlink("nowhere", server.local("/scratch/lb")).unwrap();
    let mut b = connected(&server).await;
    let listing = b
        .list(&p("/scratch"), CancellationToken::new())
        .await
        .unwrap();
    let find = |n: &str| {
        listing
            .entries
            .iter()
            .find(|e| e.name == n)
            .unwrap()
            .clone()
    };
    assert_eq!(
        find("ld").kind,
        EntryKind::Symlink {
            target: Some("d".into()),
            target_kind: Some(SymlinkTarget::Dir)
        }
    );
    assert!(find("ld").is_dir_like());
    assert_eq!(
        find("lb").kind,
        EntryKind::Symlink {
            target: Some("nowhere".into()),
            target_kind: Some(SymlinkTarget::Broken)
        }
    );
    let inner = b
        .list(&p("/scratch/ld"), CancellationToken::new())
        .await
        .unwrap();
    let names: Vec<&str> = inner.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["inner.txt"]);
    assert_eq!(inner.dir, p("/scratch/ld"));
}

// ------------------------------------------------------------------ AC3

#[tokio::test]
async fn resume_download_and_upload_sha256() {
    let server = SftpTestServer::start(SftpTestKnobs::default()).await;
    let data = pattern(3 << 20, 4);
    std::fs::write(server.local("/scratch/src.bin"), &data).unwrap();
    let mut b = connected(&server).await;

    // Download: the first 1 MiB + a resumed read from there.
    let cut = 1 << 20;
    let mut local = read_all(&mut b, &p("/scratch/src.bin"), 0, Some(cut)).await;
    local.extend(read_all(&mut b, &p("/scratch/src.bin"), cut, None).await);
    assert_eq!(sha(&local), sha(&data));

    // Upload: 1.5 MiB, then a resume at 1 MiB (the remote is truncated to the offset
    // first), then the rest.
    let half = 3 << 19;
    write_all(
        &mut b,
        &p("/scratch/up.bin"),
        WriteMode::Truncate,
        &data[..half],
    )
    .await;
    write_all(
        &mut b,
        &p("/scratch/up.bin"),
        WriteMode::ResumeAt(cut),
        &data[cut as usize..],
    )
    .await;
    let up = std::fs::read(server.local("/scratch/up.bin")).unwrap();
    assert_eq!(sha(&up), sha(&data));

    // Resume beyond the remote size is refused.
    let mut w = b
        .open_write(
            &p("/scratch/up.bin"),
            WriteMode::ResumeAt(10 << 20),
            &TransferOpts::default(),
        )
        .await;
    assert!(matches!(&w, Err(Error::InvalidInput(m)) if m.contains("shorter")));
    if let Ok(w) = &mut w {
        w.shutdown().await.unwrap();
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn resume_above_4gib_sparse() {
    const OFF: u64 = (4 << 30) + 12_345;
    let server = SftpTestServer::start(SftpTestKnobs::default()).await;
    let tail = pattern(300_000, 5);
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::File::create(server.local("/scratch/sparse")).unwrap();
        f.seek(SeekFrom::Start(OFF)).unwrap();
        f.write_all(&tail).unwrap();
    }
    let mut b = connected(&server).await;
    // Resumed download above 4 GiB.
    let back = read_all(&mut b, &p("/scratch/sparse"), OFF + 100_000, None).await;
    assert_eq!(sha(&back), sha(&tail[100_000..]));
    // Resumed upload above 4 GiB: truncate to OFF + 1000, write a new tail.
    let new_tail = pattern(200_000, 6);
    write_all(
        &mut b,
        &p("/scratch/sparse"),
        WriteMode::ResumeAt(OFF + 1000),
        &new_tail,
    )
    .await;
    let e = b.stat(&p("/scratch/sparse")).await.unwrap();
    assert_eq!(e.size, Some(OFF + 1000 + 200_000));
    let back = read_all(&mut b, &p("/scratch/sparse"), OFF, None).await;
    let mut want = tail[..1000].to_vec();
    want.extend_from_slice(&new_tail);
    assert_eq!(sha(&back), sha(&want));
}

// ------------------------------------------------------------------ AC4

#[tokio::test]
async fn fault_injection_error_mapping() {
    let server = SftpTestServer::start(SftpTestKnobs::default()).await;
    std::fs::write(server.local("/scratch/f"), b"x").unwrap();
    let mut b = connected(&server).await;
    let f = p("/scratch/f");
    let stats = server.stats().clone();

    let mut check = async |code: StatusCode, want: &dyn Fn(&Error) -> bool| {
        stats.fail_next(SftpOp::Stat, code);
        let res = b.stat(&f).await;
        match res {
            Err(e) if want(&e) => {}
            other => panic!("{code:?}: {other:?}"),
        }
    };
    check(
        StatusCode::NoSuchFile,
        &|e| matches!(e, Error::NotFound(x) if x.as_str() == "/scratch/f"),
    )
    .await;
    check(StatusCode::PermissionDenied, &|e| {
        matches!(e, Error::PermissionDenied(_))
    })
    .await;
    check(StatusCode::Failure, &|e| {
        matches!(e, Error::Protocol { code: Some(4), .. })
    })
    .await;
    check(StatusCode::BadMessage, &|e| {
        matches!(e, Error::Protocol { code: Some(5), .. })
    })
    .await;
    check(StatusCode::OpUnsupported, &|e| {
        matches!(e, Error::Unsupported(m) if m == "The server does not support this operation")
    })
    .await;
    check(StatusCode::Eof, &|e| {
        matches!(e, Error::Protocol { code: Some(1), .. })
    })
    .await;
    // NO_CONNECTION / CONNECTION_LOST: transient, and the session counts as lost.
    check(StatusCode::NoConnection, &|e| {
        matches!(e, Error::Connection(_))
    })
    .await;
    assert!(!b.is_connected());
    b.connect(CancellationToken::new()).await.unwrap();
    stats.fail_next(SftpOp::Stat, StatusCode::ConnectionLost);
    assert!(matches!(b.stat(&f).await, Err(Error::Connection(_))));
    b.connect(CancellationToken::new()).await.unwrap();

    // FAILURE on mkdir of an existing path → AlreadyExists (one extra LSTAT).
    assert!(matches!(
        b.mkdir(&p("/scratch/f")).await,
        Err(Error::AlreadyExists(_))
    ));
    // FAILURE on mkdir of a missing path → Protocol 4.
    stats.fail_next(SftpOp::Mkdir, StatusCode::Failure);
    assert!(matches!(
        b.mkdir(&p("/scratch/new")).await,
        Err(Error::Protocol { code: Some(4), .. })
    ));

    // A reply of the wrong type → Protocol without a code.
    stats.set_knobs(|k| k.bogus_reply_next = Some(SftpOp::Mkdir));
    assert!(matches!(
        b.mkdir(&p("/scratch/new2")).await,
        Err(Error::Protocol { code: None, .. })
    ));

    // set_mtime outside the v3 range: InvalidInput, nothing sent.
    let before = stats.count("SETSTAT");
    let t1960 = OffsetDateTime::new_utc(
        Date::from_calendar_date(1960, Month::June, 1).unwrap(),
        Time::MIDNIGHT,
    );
    assert!(matches!(
        b.set_mtime(&f, t1960).await,
        Err(Error::InvalidInput(_))
    ));
    assert_eq!(stats.count("SETSTAT"), before);
}

#[tokio::test]
async fn fault_injection_timeout_and_limits() {
    // A reply slower than connection.timeout_secs → Timeout (transient).
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("f"), b"x").unwrap();
    let mut settings = Settings::default();
    settings.connection.timeout_secs = 1;
    let (mut b, stats, _rx) = duplex_backend(SftpTestKnobs::default(), dir.path(), settings).await;
    stats.set_knobs(|k| k.per_request_latency = Duration::from_millis(1500));
    let e = b.stat(&p("/f")).await.unwrap_err();
    assert!(matches!(e, Error::Timeout) && e.is_transient(), "{e:?}");
    assert!(!b.is_connected());

    // A packet over the server's limit is refused locally → Protocol without a code.
    let knobs = SftpTestKnobs {
        advertise_limits: Some(ServerLimits {
            max_packet_len: 2000,
            max_read_len: 0,
            max_write_len: 0,
            max_open_handles: 0,
        }),
        ..SftpTestKnobs::default()
    };
    let (mut b, _stats, _rx) = duplex_backend(knobs, dir.path(), Settings::default()).await;
    let mut w = b
        .open_write(&p("/g"), WriteMode::Truncate, &TransferOpts::default())
        .await
        .unwrap();
    let err = w.write_all(&[0u8; 10_000]).await.unwrap_err();
    assert!(
        matches!(core_error(&err), Some(Error::Protocol { code: None, .. })),
        "{err:?}"
    );
}

#[tokio::test]
async fn connect_errors_pass_through() {
    let server = SftpTestServer::start(SftpTestKnobs::default()).await;
    let mut info = server.connect_info();
    info.logon = LogonType::Normal {
        password: Some(SecretString::from("wrong")),
    };
    let (ctx, mut rx) = mock::test_context();
    // The user keeps typing wrong passwords after the stored one is rejected.
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            if let CoreEvent::Prompt(req) = ev {
                req.respond(PromptResponse::Secret {
                    value: SecretString::from("still wrong"),
                    remember_session: false,
                    save_in_vault: false,
                });
            }
        }
    });
    let mut b = SftpBackend::new(
        Arc::new(info),
        ctx,
        Arc::new(InsecureAcceptAnyHostKey),
        None,
    );
    let e = tokio::time::timeout(Duration::from_secs(30), b.connect(CancellationToken::new()))
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(e, Error::Auth(_)), "{e:?}");
    assert!(!b.is_connected());
    // Operations before a connect: Connection, nothing sent.
    assert!(matches!(b.stat(&p("/")).await, Err(Error::Connection(_))));
}

// ------------------------------------------------------------------ AC5

#[tokio::test]
async fn rename_posix_and_plain() {
    // posix-rename advertised: replace = true overwrites atomically.
    let server = SftpTestServer::start(SftpTestKnobs::default()).await;
    std::fs::write(server.local("/scratch/a"), b"AAA").unwrap();
    std::fs::write(server.local("/scratch/b"), b"BB").unwrap();
    let mut b = connected(&server).await;
    b.rename(&p("/scratch/a"), &p("/scratch/b"), true)
        .await
        .unwrap();
    assert!(!server.local("/scratch/a").exists());
    assert_eq!(std::fs::read(server.local("/scratch/b")).unwrap(), b"AAA");
    assert_eq!(server.stats().extended(), ["posix-rename@openssh.com"]);
    assert_eq!(server.stats().count("RENAME"), 0);

    // replace = false onto an existing file: AlreadyExists without sending RENAME.
    std::fs::write(server.local("/scratch/c"), b"C").unwrap();
    let e = b.rename(&p("/scratch/c"), &p("/scratch/b"), false).await;
    assert!(matches!(e, Err(Error::AlreadyExists(x)) if x.as_str() == "/scratch/b"));
    assert_eq!(server.stats().count("RENAME"), 0);
    // replace = false onto a free name: plain RENAME.
    b.rename(&p("/scratch/c"), &p("/scratch/d"), false)
        .await
        .unwrap();
    assert_eq!(server.stats().count("RENAME"), 1);

    // Without posix-rename: plain RENAME onto an existing target fails →
    // AlreadyExists, both files unchanged.
    let server = SftpTestServer::start(SftpTestKnobs {
        advertise_posix_rename: false,
        ..SftpTestKnobs::default()
    })
    .await;
    std::fs::write(server.local("/scratch/a"), b"AAA").unwrap();
    std::fs::write(server.local("/scratch/b"), b"BB").unwrap();
    let mut b = connected(&server).await;
    let e = b.rename(&p("/scratch/a"), &p("/scratch/b"), true).await;
    assert!(matches!(e, Err(Error::AlreadyExists(_))), "{e:?}");
    assert_eq!(std::fs::read(server.local("/scratch/a")).unwrap(), b"AAA");
    assert_eq!(std::fs::read(server.local("/scratch/b")).unwrap(), b"BB");
    assert_eq!(server.stats().count("RENAME"), 1);
    assert!(server.stats().extended().is_empty());
    // A missing source names the source.
    let e = b.rename(&p("/scratch/zz"), &p("/scratch/yy"), true).await;
    assert!(
        matches!(&e, Err(Error::NotFound(x)) if x.as_str() == "/scratch/zz"),
        "{e:?}"
    );
}

// ------------------------------------------------------------------ AC6

#[tokio::test]
async fn already_exists_probes() {
    let server = SftpTestServer::start(SftpTestKnobs::default()).await;
    std::fs::create_dir(server.local("/scratch/dir")).unwrap();
    std::fs::write(server.local("/scratch/file"), b"keep").unwrap();
    let mut b = connected(&server).await;
    let e = b.mkdir(&p("/scratch/dir")).await;
    assert!(matches!(e, Err(Error::AlreadyExists(x)) if x.as_str() == "/scratch/dir"));
    let e = b
        .open_write(
            &p("/scratch/file"),
            WriteMode::Create,
            &TransferOpts::default(),
        )
        .await;
    assert!(matches!(&e, Err(Error::AlreadyExists(x)) if x.as_str() == "/scratch/file"));
    drop(e);
    assert_eq!(
        std::fs::read(server.local("/scratch/file")).unwrap(),
        b"keep"
    );
    // The session is still usable (no stream is open).
    b.stat(&p("/scratch/file")).await.unwrap();
}

// ------------------------------------------------------------------ AC11

#[tokio::test]
async fn hostile_names_filtered() {
    let esc = "evil\u{1b}[31mred";
    let knobs = SftpTestKnobs {
        inject_names: vec![
            "a/b".into(),
            "nul\0byte".into(),
            ".".into(),
            "..".into(),
            "x".repeat(5000),
            esc.into(),
            String::new(),
        ],
        ..SftpTestKnobs::default()
    };
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("normal"), b"x").unwrap();
    let (mut b, _stats, mut rx) = duplex_backend(knobs, dir.path(), Settings::default()).await;
    let _ = log_lines(&mut rx);
    let listing = b.list(&p("/"), CancellationToken::new()).await.unwrap();
    let mut names: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, [esc, "normal"]);
    let lines = log_lines(&mut rx);
    assert!(
        lines
            .iter()
            .any(|(k, t)| *k == LogKind::Status && t == "Skipped 4 entries with invalid names"),
        "{lines:?}"
    );
    // The names never reach the log.
    assert!(
        !lines
            .iter()
            .any(|(_, t)| t.contains("a/b") || t.contains("xxxxx"))
    );
}

// ------------------------------------------------------------------ AC12

#[tokio::test]
async fn large_directory_and_entry_cap() {
    let dir = tempfile::tempdir().unwrap();
    let mut knobs = SftpTestKnobs {
        readdir_batch: 2000,
        ..SftpTestKnobs::default()
    };
    knobs.synthetic_dirs.insert("/big".into(), (100_000, true));
    knobs
        .synthetic_dirs
        .insert("/huge".into(), (1_000_001, false));
    let (mut b, stats, _rx) = duplex_backend(knobs, dir.path(), Settings::default()).await;
    let listing = b.list(&p("/big"), CancellationToken::new()).await.unwrap();
    assert_eq!(listing.entries.len(), 100_000);
    assert!(
        listing
            .entries
            .iter()
            .all(|e| e.owner.as_deref() == Some("alice") && e.group.as_deref() == Some("staff"))
    );
    assert_eq!(listing.entries[42].size, Some(42));
    let raw = listing.raw.unwrap();
    assert_eq!(raw.lines().count(), 100_000);
    drop(listing.entries);

    let closes = stats.closed().len();
    let e = b
        .list(&p("/huge"), CancellationToken::new())
        .await
        .unwrap_err();
    assert!(
        matches!(&e, Error::Protocol { code: None, message } if message == "Directory has more than 1 000 000 entries"),
        "{e:?}"
    );
    assert_eq!(stats.closed().len(), closes + 1, "the handle is closed");
    assert!(b.is_connected());
}

// ------------------------------------------------------------------ AC13

#[tokio::test(start_paused = true)]
async fn cancel_list_closes_handle() {
    let dir = tempfile::tempdir().unwrap();
    let mut knobs = SftpTestKnobs {
        per_request_latency: Duration::from_millis(50),
        ..SftpTestKnobs::default()
    };
    knobs
        .synthetic_dirs
        .insert("/slow".into(), (100_000, false));
    let (mut b, stats, _rx) = duplex_backend(knobs, dir.path(), Settings::default()).await;
    let cancel = CancellationToken::new();
    let c = cancel.clone();
    let fired = Arc::new(std::sync::Mutex::new(None));
    let f2 = Arc::clone(&fired);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        *f2.lock().unwrap() = Some(tokio::time::Instant::now());
        c.cancel();
    });
    let e = b.list(&p("/slow"), cancel).await.unwrap_err();
    let returned = tokio::time::Instant::now();
    assert!(matches!(e, Error::Cancelled), "{e:?}");
    let fired = fired.lock().unwrap().unwrap();
    assert!(returned - fired <= Duration::from_millis(100));
    // The directory handle is closed in the background.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(stats.closed(), ["h1"]);
    assert!(b.is_connected());
    b.stat(&p("/")).await.unwrap();
}

// ------------------------------------------------------------------ AC14

#[tokio::test]
async fn server_killed_mid_download() {
    let server = SftpTestServer::start(SftpTestKnobs::default()).await;
    let data = pattern(16 << 20, 7);
    std::fs::write(server.local("/scratch/big"), &data).unwrap();
    let mut b = connected(&server).await;
    let mut r = b
        .open_read(&p("/scratch/big"), 0, &TransferOpts::default())
        .await
        .unwrap();
    let mut buf = vec![0; 65_536];
    r.read_exact(&mut buf).await.unwrap();
    server.drop_connections();
    let mut sink = Vec::new();
    let err = r.read_to_end(&mut sink).await.unwrap_err();
    assert!(
        matches!(core_error(&err), Some(Error::Connection(_))),
        "{err:?}"
    );
    assert!(Error::from(err).is_connection_lost());
    drop(r);
    let fin = b.finish_transfer(TransferEnd::Complete).await;
    assert!(matches!(fin, Err(Error::Connection(_))), "{fin:?}");
    // The transport noticed the loss.
    tokio::time::timeout(Duration::from_secs(5), async {
        while b.is_connected() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        b.stat(&p("/scratch")).await,
        Err(Error::Connection(_))
    ));

    // SessionHandle (T03) reconnects once on the next call.
    let (ctx, mut rx) = mock::test_context();
    let backend = server.backend(ctx.clone());
    let handle = SessionHandle::new(
        Box::new(backend),
        ctx,
        SessionOptions::default(),
        "test".into(),
    );
    let cancel = CancellationToken::new();
    handle.connect(&cancel).await.unwrap();
    handle.stat(&p("/scratch/big"), &cancel).await.unwrap();
    server.drop_connections();
    let e = handle.stat(&p("/scratch/big"), &cancel).await.unwrap();
    assert_eq!(e.size, Some(16 << 20));
    let lines = log_lines(&mut rx);
    assert!(
        lines.iter().any(|(_, t)| t.contains("reconnecting")),
        "{lines:?}"
    );
}

// ------------------------------------------------------------------ AC15

#[tokio::test]
async fn chmod_sends_only_permissions_and_mtime_roundtrip() {
    let server = SftpTestServer::start(SftpTestKnobs::default()).await;
    std::fs::write(server.local("/scratch/f"), b"x").unwrap();
    let mut b = connected(&server).await;
    b.chmod(&p("/scratch/f"), 0o100_640).await.unwrap();
    let sent = server.stats().setstats();
    assert_eq!(sent.len(), 1);
    let a = &sent[0];
    assert_eq!(a.permissions, Some(0o640));
    assert_eq!(
        (a.size, a.uid, a.gid, a.atime, a.mtime),
        (None, None, None, None, None)
    );
    let when = OffsetDateTime::from_unix_timestamp(1_600_000_000).unwrap();
    b.set_mtime(&p("/scratch/f"), when).await.unwrap();
    let e = b.stat(&p("/scratch/f")).await.unwrap();
    assert_eq!(e.modified.unwrap().time, when);
    assert!(matches!(
        b.raw_command("NOOP").await,
        Err(Error::Unsupported(_))
    ));
}

#[tokio::test]
async fn transfer_rules_and_logging() {
    let server = SftpTestServer::start(SftpTestKnobs::default()).await;
    std::fs::write(server.local("/scratch/f"), b"hello").unwrap();
    let (ctx, mut rx) = mock::test_context();
    let mut b = server.backend(ctx);
    b.connect(CancellationToken::new()).await.unwrap();
    let lines = log_lines(&mut rx);
    assert!(
        lines
            .iter()
            .any(|(_, t)| t.starts_with("Connected to 127.0.0.1")),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|(_, t)| t.starts_with("SFTP extensions: "))
    );
    // Ops while a stream is open are refused; ASCII is treated as binary.
    let ascii = TransferOpts {
        transfer_type: courier_ftp_core::model::TransferType::Ascii,
        ..TransferOpts::default()
    };
    let mut r = b.open_read(&p("/scratch/f"), 0, &ascii).await.unwrap();
    assert!(matches!(
        b.stat(&p("/scratch/f")).await,
        Err(Error::Internal(_))
    ));
    let mut s = String::new();
    r.read_to_string(&mut s).await.unwrap();
    assert_eq!(s, "hello");
    drop(r);
    b.finish_transfer(TransferEnd::Complete).await.unwrap();
    // A failure is logged as "Error: <op> <path>: <message>".
    let _ = b.rmdir(&p("/scratch/missing")).await;
    let lines = log_lines(&mut rx);
    assert!(
        lines.iter().any(|(k, t)| *k == LogKind::Error
            && t == "Could not remove directory /scratch/missing: No such file or directory"),
        "{lines:?}"
    );
    // home_dir is realpath(".").
    assert_eq!(b.home_dir().await.unwrap(), RemotePath::root());
}
