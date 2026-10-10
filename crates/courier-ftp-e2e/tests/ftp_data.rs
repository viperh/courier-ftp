//! T11 end to end: FTP data connections (`courier_ftp_proto_ftp::FtpData`) against the
//! vsftpd fixtures: passive and active uploads/downloads (SHA-256 verified), the
//! unroutable-PASV profile and cancel + resume on the rate-limited profile. Every test
//! is `#[ignore]` and starts with `require_docker!()`; run with
//! `COURIER_E2E=1 cargo test -p courier-ftp-e2e --test ftp_data -- --ignored`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use courier_ftp_core::{
    Error,
    events::{CoreEvent, EventReceiver, LogKind, SecretCacheKey, SessionId, SessionLog, channel},
    model::{Charset, LogonType, Protocol, TransferType},
    net::{CancellationToken, HostPort, NetOpts, ProxyConfig, Purpose},
    secret::SecretString,
    settings::{ActiveExternalIp, DebugLevel, KeepaliveCommand},
};
use courier_ftp_e2e::{
    Ftpd, FtpdProfile,
    files::{FIXTURE_TREE, fixture_bytes, remote_fixture_dir, sha256_reader},
    keys::{PASSWORD, USER},
    require_docker,
};
use courier_ftp_proto_ftp::{
    ControlConnection, ControlParams, DataConfig, DataMode, DataState, FtpData, LoginPromptInfo,
    LoginScript, TransferCommand, data::DEFAULT_SOCKET_BUFFER,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TEN_MIB: usize = 10 * 1024 * 1024;

fn net_opts(purpose: Purpose) -> NetOpts {
    NetOpts {
        timeout: Duration::from_secs(20),
        prefer_ipv6: false,
        allow_ipv6: true,
        purpose,
        socket_buffer: None,
        proxy: ProxyConfig::Direct,
    }
}

fn data_cfg(ftpd: &Ftpd, mode: DataMode) -> DataConfig {
    DataConfig {
        mode,
        fallback_to_active: false,
        ignore_unroutable_pasv_ip: true,
        external_ip: ActiveExternalIp::Auto,
        no_external_ip_on_local: true,
        port_range: None,
        through_generic_proxy: false,
        net: net_opts(Purpose::Data),
        control_host: ftpd.host(),
        timeout: Duration::from_secs(20),
        socket_buffer: DEFAULT_SOCKET_BUFFER,
    }
}

/// Connect + login + FEAT; returns the connection and the event receiver.
async fn login(ftpd: &Ftpd) -> (ControlConnection, EventReceiver) {
    let (events, rx) = channel(DebugLevel::Debug);
    let log = SessionLog {
        events,
        session: SessionId::next(),
    };
    let p = ControlParams {
        target: HostPort::new(ftpd.host(), ftpd.profile().control_port()),
        server_name: ftpd.host(),
        net: net_opts(Purpose::Control),
        charset: Charset::Auto,
        timeout: Duration::from_secs(20),
        keepalive_command: KeepaliveCommand::Noop,
        log,
    };
    let cancel = CancellationToken::new();
    let (mut conn, _) = ControlConnection::connect(p, None, &cancel).await.unwrap();
    let info = LoginPromptInfo {
        target: format!("{USER}@{}", ftpd.host()),
        cache_key: SecretCacheKey::Password {
            protocol: Protocol::Ftp,
            host: ftpd.host(),
            port: 21,
            user: USER.into(),
        },
        can_save: false,
    };
    let logon = LogonType::Normal {
        password: Some(SecretString::from(PASSWORD)),
    };
    let script = LoginScript::for_logon(Some(USER), &logon, info).unwrap();
    conn.login(script, &cancel).await.unwrap();
    conn.negotiate(&cancel).await.unwrap();
    (conn, rx)
}

fn test_bytes(len: usize) -> Vec<u8> {
    (0..len as u64)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect()
}

fn sha(bytes: &[u8]) -> String {
    sha256_reader(bytes).unwrap()
}

async fn upload(d: &mut FtpData<'_>, path: &str, bytes: &[u8]) {
    let cancel = CancellationToken::new();
    let cmd = TransferCommand::Stor {
        path: path.into(),
        offset: 0,
    };
    let mut s = d
        .open(cmd, TransferType::Binary, None, &cancel)
        .await
        .unwrap();
    s.write_all(bytes).await.unwrap();
    d.finish(Some(s), &cancel).await.unwrap();
}

async fn download(d: &mut FtpData<'_>, path: &str, offset: u64) -> Vec<u8> {
    let cancel = CancellationToken::new();
    let cmd = TransferCommand::Retr {
        path: path.into(),
        offset,
        range_len: None,
    };
    let mut s = d
        .open(cmd, TransferType::Binary, None, &cancel)
        .await
        .unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    d.finish(Some(s), &cancel).await.unwrap();
    out
}

/// Upload + download 10 MiB in `mode`; both hashes must match the original.
async fn roundtrip(profile: FtpdProfile, mode: DataMode, name: &str) {
    let ftpd = Ftpd::start(profile).await.unwrap();
    let (mut conn, _rx) = login(&ftpd).await;
    let cfg = data_cfg(&ftpd, mode);
    let mut state = DataState::default();
    let mut d = FtpData {
        ctrl: &mut conn,
        cfg: &cfg,
        state: &mut state,
    };
    let bytes = test_bytes(TEN_MIB);
    let want = sha(&bytes);
    let remote = format!("/upload/{name}");
    upload(&mut d, &remote, &bytes).await;
    let on_server = ftpd
        .sha256_of(&format!("/home/{USER}/upload/{name}"))
        .await
        .unwrap();
    assert_eq!(on_server, want, "{}: uploaded file", profile.name());
    let back = download(&mut d, &remote, 0).await;
    assert_eq!(sha(&back), want, "{}: downloaded file", profile.name());
    assert_eq!(
        conn.pwd(&CancellationToken::new()).await.unwrap(),
        "/",
        "control usable after the transfers"
    );
    conn.quit().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn ftp_data_passive_roundtrip_vsftpd() {
    require_docker!();
    roundtrip(
        FtpdProfile::VsftpdPlain,
        DataMode::Passive,
        "t11-passive.bin",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn ftp_data_active_roundtrip_vsftpd_active_only() {
    require_docker!();
    roundtrip(
        FtpdProfile::VsftpdActiveOnly,
        DataMode::Active,
        "t11-active.bin",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn ftp_data_passive_unroutable_profile_uses_peer() {
    require_docker!();
    let ftpd = Ftpd::start(FtpdProfile::VsftpdPasvUnreachable)
        .await
        .unwrap();
    let (mut conn, mut rx) = login(&ftpd).await;
    let cfg = data_cfg(&ftpd, DataMode::Passive);
    // Force PASV (vsftpd also speaks EPSV, which carries no address).
    let mut state = DataState {
        epsv_failed: true,
        ..DataState::default()
    };
    let mut d = FtpData {
        ctrl: &mut conn,
        cfg: &cfg,
        state: &mut state,
    };
    let rel = "1MiB.bin";
    let len = FIXTURE_TREE.iter().find(|(p, _)| *p == rel).unwrap().1;
    // The user is chrooted to its home: the fixture tree is `/fixtures/`.
    assert!(remote_fixture_dir(USER).ends_with("/fixtures"));
    let path = format!("/fixtures/{rel}");
    let got = download(&mut d, &path, 0).await;
    assert_eq!(
        sha(&got),
        sha256_reader(fixture_bytes(rel, len)).unwrap(),
        "fixture content"
    );
    conn.quit().await;
    let mut status = Vec::new();
    while let Ok(Some(event)) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
        if let CoreEvent::Log(m) = event
            && m.kind == LogKind::Status
        {
            status.push(m.text);
        }
    }
    assert!(
        status
            .iter()
            .any(|l| l.contains("unroutable address. Using server address instead")),
        "{status:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn ftp_data_resume_after_cut_slow_profile() {
    require_docker!();
    let ftpd = Ftpd::start(FtpdProfile::VsftpdSlow).await.unwrap();
    let (mut conn, _rx) = login(&ftpd).await;
    let cfg = data_cfg(&ftpd, DataMode::Passive);
    let mut state = DataState::default();
    let mut d = FtpData {
        ctrl: &mut conn,
        cfg: &cfg,
        state: &mut state,
    };
    let rel = "1MiB.bin";
    let len = FIXTURE_TREE.iter().find(|(p, _)| *p == rel).unwrap().1;
    let path = format!("/fixtures/{rel}");
    let cancel = CancellationToken::new();
    let cmd = TransferCommand::Retr {
        path: path.clone(),
        offset: 0,
        range_len: None,
    };
    let mut s = d
        .open(cmd, TransferType::Binary, None, &cancel)
        .await
        .unwrap();
    let mut first = vec![0u8; 300 * 1024];
    let mut have = 0;
    while have < first.len() {
        let n = s.read(&mut first[have..]).await.unwrap();
        assert!(n > 0, "server ended early");
        have += n;
    }
    // Cut: the caller drops the stream mid-transfer.
    drop(s);
    let started = std::time::Instant::now();
    let err = d.finish(None, &cancel).await.unwrap_err();
    assert!(matches!(err, Error::Cancelled), "{err:?}");
    assert_eq!(d.ctrl.pwd(&cancel).await.unwrap(), "/");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    let rest = download(&mut d, &path, have as u64).await;
    let mut whole = first;
    whole.extend_from_slice(&rest);
    assert_eq!(whole.len() as u64, len);
    assert_eq!(sha(&whole), sha256_reader(fixture_bytes(rel, len)).unwrap());
    conn.quit().await;
}
