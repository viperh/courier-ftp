//! T10 end to end: the FTP control connection (`courier_ftp_proto_ftp::ControlConnection`)
//! against the vsftpd, proftpd and pure-ftpd fixtures: connect, login, negotiate, `PWD`,
//! `NOOP`, `QUIT`. Every test is `#[ignore]` and starts with `require_docker!()`; run with
//! `COURIER_E2E=1 cargo test -p courier-ftp-e2e --test ftp_control -- --ignored`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use courier_ftp_core::{
    Error,
    events::{EventReceiver, SecretCacheKey, SessionId, SessionLog, channel},
    model::{Charset, LogonType, Protocol},
    net::{CancellationToken, HostPort, NetOpts, ProxyConfig, Purpose},
    secret::SecretString,
    settings::{DebugLevel, KeepaliveCommand},
};
use courier_ftp_e2e::{
    Ftpd, FtpdProfile,
    keys::{PASSWORD, USER},
    require_docker,
};
use courier_ftp_proto_ftp::{
    Command, ControlConnection, ControlParams, ControlState, LoginPromptInfo, LoginScript,
};

fn params(ftpd: &Ftpd) -> (ControlParams, EventReceiver) {
    let (events, rx) = channel(DebugLevel::Debug);
    let log = SessionLog {
        events,
        session: SessionId::next(),
    };
    let p = ControlParams {
        target: HostPort::new(ftpd.host(), ftpd.profile().control_port()),
        server_name: ftpd.host(),
        net: NetOpts {
            timeout: Duration::from_secs(20),
            prefer_ipv6: false,
            allow_ipv6: true,
            purpose: Purpose::Control,
            socket_buffer: None,
            proxy: ProxyConfig::Direct,
        },
        charset: Charset::Auto,
        timeout: Duration::from_secs(20),
        keepalive_command: KeepaliveCommand::Noop,
        log,
    };
    (p, rx)
}

fn prompt_info(ftpd: &Ftpd, user: &str) -> LoginPromptInfo {
    LoginPromptInfo {
        target: format!("{user}@{}", ftpd.host()),
        cache_key: SecretCacheKey::Password {
            protocol: Protocol::Ftp,
            host: ftpd.host(),
            port: 21,
            user: user.into(),
        },
        can_save: false,
    }
}

/// Connect + login + negotiate + PWD + NOOP + QUIT; returns the connection's features
/// via the callback before quitting.
async fn full_session(profile: FtpdProfile, user: Option<&str>, logon: LogonType) {
    let ftpd = Ftpd::start(profile).await.unwrap();
    let (p, _rx) = params(&ftpd);
    let cancel = CancellationToken::new();
    let (mut conn, greeting) = ControlConnection::connect(p, None, &cancel).await.unwrap();
    assert_eq!(greeting.code(), 220);
    assert_eq!(conn.peer_addr(), Some(ftpd.addr()));
    let script = LoginScript::for_logon(
        user,
        &logon,
        prompt_info(&ftpd, user.unwrap_or("anonymous")),
    )
    .unwrap();
    conn.login(script, &cancel).await.unwrap();
    assert_eq!(conn.state(), ControlState::Ready);
    conn.negotiate(&cancel).await.unwrap();
    let features = conn.features().clone();
    assert!(features.feat_supported, "{}: {features:?}", profile.name());
    assert_eq!(
        features.mlsd,
        profile.has_mlsd(),
        "{}: {features:?}",
        profile.name()
    );
    if profile.has_mlsd() {
        assert!(features.mfmt, "{}: {features:?}", profile.name());
    }
    assert!(features.size && features.mdtm && features.rest_stream);
    assert!(
        conn.syst().is_some_and(|s| s.starts_with("UNIX")),
        "{:?}",
        conn.syst()
    );
    assert_eq!(conn.pwd(&cancel).await.unwrap(), "/");
    let noop = conn.send(Command::new("NOOP"), &cancel).await.unwrap();
    assert!(noop.is_ok(), "{noop:?}");
    conn.keepalive(&cancel).await.unwrap();
    conn.quit().await;
}

fn password() -> LogonType {
    LogonType::Normal {
        password: Some(SecretString::from(PASSWORD)),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn ftp_control_login_vsftpd_plain() {
    require_docker!();
    full_session(FtpdProfile::VsftpdPlain, Some(USER), password()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn ftp_control_login_vsftpd_anonymous() {
    require_docker!();
    full_session(FtpdProfile::VsftpdAnonymous, None, LogonType::Anonymous).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn ftp_control_login_proftpd() {
    require_docker!();
    full_session(FtpdProfile::ProftpdPlain, Some(USER), password()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn ftp_control_login_pureftpd() {
    require_docker!();
    full_session(FtpdProfile::PureftpdPlain, Some(USER), password()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn ftp_control_wrong_password_is_auth_error() {
    require_docker!();
    let ftpd = Ftpd::start(FtpdProfile::VsftpdPlain).await.unwrap();
    let (p, _rx) = params(&ftpd);
    let cancel = CancellationToken::new();
    let (mut conn, _) = ControlConnection::connect(p, None, &cancel).await.unwrap();
    let logon = LogonType::Normal {
        password: Some(SecretString::from("definitely-wrong")),
    };
    let script = LoginScript::for_logon(Some(USER), &logon, prompt_info(&ftpd, USER)).unwrap();
    let err = conn.login(script, &cancel).await.unwrap_err();
    assert!(matches!(err, Error::Auth(_)), "{err:?}");
    conn.quit().await;
}
