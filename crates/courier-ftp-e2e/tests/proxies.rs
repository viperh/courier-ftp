//! T76 `proxies.rs`, SFTP part (T22 + T07): a subset of the T03 conformance suite
//! through the dante SOCKS5 and squid HTTP CONNECT (basic auth) proxies to the sshd
//! `password` profile, with backends from `E2eBackendFactory` and the proxy from the
//! settings (`proxy.generic`). The FTP cases (`ftp_passive_via_socks5`,
//! `ftp_active_via_proxy_is_unsupported`) arrive with T14. Every test is `#[ignore]`
//! and starts with `require_docker!()`; run with
//! `COURIER_E2E=1 cargo test -p courier-ftp-e2e --test proxies -- --ignored`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use courier_ftp_core::{
    backend::{
        BackendContext, BackendFactory, ConnectInfo,
        conformance::{CaseOutcome, ConformanceEnv, run_case_outcome},
    },
    events::{CoreEvent, PromptKind, PromptResponse, SessionId, TrustAnswer, channel},
    model::{FtpEncryption, LogonType, Protocol, RemotePath, ServerAddress},
    secret::SecretString,
    settings::{DebugLevel, ProxyKind, Settings},
};
use courier_ftp_e2e::{
    E2eBackendFactory, ProxyProfile, ProxyServer, Sshd, SshdOptions, SshdProfile, TestNetwork,
    keys::{PASSWORD, PROXY_PASSWORD, PROXY_USER, USER},
    require_docker,
};

/// The cases run through each proxy.
const SUBSET: &[&str] = &[
    "home_dir_is_absolute",
    "mkdir_then_list_shows_dir",
    "write_then_read_roundtrip_1mib",
    "read_from_offset",
    "rename_in_same_dir",
    "second_session_sees_changes",
    "disconnect_then_connect_again",
];

fn context(settings: Settings) -> BackendContext {
    let (events, mut rx) = channel(DebugLevel::Debug);
    let (_tx, settings) = tokio::sync::watch::channel(Arc::new(settings));
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            if let CoreEvent::Prompt(req) = ev {
                let answer = match &req.kind {
                    PromptKind::TrustHostKey(_) => PromptResponse::HostKey(TrustAnswer::TrustOnce),
                    _ => PromptResponse::Cancel,
                };
                req.respond(answer);
            }
        }
    });
    BackendContext {
        session: SessionId::next(),
        events,
        settings,
    }
}

async fn subset_via(profile: ProxyProfile) {
    let net = TestNetwork::new().await.unwrap();
    let sshd = Sshd::start_with(SshdOptions {
        network: Some(net.name().into()),
        ..SshdOptions::new(SshdProfile::Password)
    })
    .await
    .unwrap();
    let proxy = ProxyServer::start(profile, &net).await.unwrap();

    let mut settings = Settings::default();
    let g = &mut settings.proxy.generic;
    g.kind = match profile {
        ProxyProfile::Http | ProxyProfile::HttpAuth => ProxyKind::Http,
        ProxyProfile::Socks4 => ProxyKind::Socks4,
        ProxyProfile::Socks5 | ProxyProfile::Socks5Auth => ProxyKind::Socks5,
    };
    g.host = proxy.host();
    g.port = profile.port();
    let auth = matches!(profile, ProxyProfile::HttpAuth | ProxyProfile::Socks5Auth);
    if auth {
        g.user = PROXY_USER.to_owned();
    }

    let address = ServerAddress::new(
        Protocol::Sftp,
        FtpEncryption::ExplicitIfAvailable,
        sshd.host(),
        Some(22),
        Some(USER.to_owned()),
    )
    .unwrap();
    let mut info = ConnectInfo::quick(
        address,
        LogonType::Normal {
            password: Some(SecretString::from(PASSWORD)),
        },
    );
    if auth {
        info.proxy_password = Some(SecretString::from(PROXY_PASSWORD));
    }
    let info = Arc::new(info);
    let env = ConformanceEnv {
        scratch: RemotePath::parse("/home/test/upload").unwrap(),
        make: Box::new(move || {
            E2eBackendFactory.create(Arc::clone(&info), context(settings.clone()))
        }),
        large_files: false,
        skip: Vec::new(),
        make_symlink: None,
    };
    let mut failed = Vec::new();
    for case in SUBSET {
        match run_case_outcome(case, &env).await {
            Ok(CaseOutcome::Passed) => {}
            Ok(CaseOutcome::Skipped(why)) => panic!("{case} skipped: {why}"),
            Err(e) => failed.push(format!("{case}: {e}")),
        }
    }
    assert!(failed.is_empty(), "{}: {failed:#?}", profile.name());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn sftp_via_socks5() {
    require_docker!();
    subset_via(ProxyProfile::Socks5).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn sftp_via_http_connect_auth() {
    require_docker!();
    subset_via(ProxyProfile::HttpAuth).await;
}
