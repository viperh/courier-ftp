//! FTPS (T12) against vsftpd in Docker (`delfer/alpine-ftp-server` with
//! `TLS_CERT`/`TLS_KEY`, which turns on `ssl_enable`, forced TLS for logins
//! and data, and vsftpd's default `require_ssl_reuse=YES`): explicit TLS
//! with a self-signed `rcgen` certificate trusted once, `PROT P` transfers
//! whose data connections must resume the control session.
//!
//! `COURIER_E2E=1 cargo test -p courier-ftp-e2e --test ftps -- --ignored`

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{sync::Arc, time::Duration};

use courier_ftp_core::{
    events::{self, CoreEvent, PromptKind, PromptResponse, SessionId, TrustDecision},
    model::{FtpEncryption, LogonType},
    net::{HostPort, NetOpts},
    settings::{FtpTransferMode, Settings},
    trust::MemoryCertTrustStore,
};
use courier_ftp_e2e::require_docker;
use courier_ftp_proto_ftp::{
    control::{self, ControlConnection, FtpContext, FtpOptions},
    data::{DataOpen, DataOptions, DataSession, finish},
    tls::TlsTrust,
};
use secrecy::SecretString;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt, core::IntoContainerPort, runners::AsyncRunner,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const USER: &str = "courier";
const PASSWORD: &str = "e2e-password";
const PASV_PORTS: std::ops::RangeInclusive<u16> = 31120..=31124;

async fn login(
    host: &HostPort,
    trust: &Arc<TlsTrust>,
) -> courier_ftp_core::Result<ControlConnection> {
    let (tx, mut rx) = events::channel(4);
    // Trust the self-signed certificate once.
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let CoreEvent::Prompt(req) = event
                && matches!(req.kind, PromptKind::TrustCertificate { .. })
            {
                let _ = req.reply.send(PromptResponse::Trust(TrustDecision::Once));
            }
        }
    });
    let mut settings = Settings::default();
    settings.connection.timeout_secs = 10;
    let mut opts = FtpOptions::new(
        host.clone(),
        LogonType::Normal {
            user: USER.into(),
            password: SecretString::from(PASSWORD.to_owned()),
        },
        &settings,
    );
    opts.encryption = FtpEncryption::RequireExplicit;
    opts.tls = Some(Arc::clone(trust));
    control::connect(&opts, FtpContext::new(SessionId::next(), tx)).await
}

#[tokio::test]
#[ignore = "needs Docker: COURIER_E2E=1 cargo test -p courier-ftp-e2e -- --ignored"]
async fn vsftpd_explicit_ftps_with_session_reuse() {
    require_docker!();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".into(), "localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let mut image = GenericImage::new("delfer/alpine-ftp-server", "latest")
        .with_exposed_port(21.tcp())
        .with_env_var("USERS", format!("{USER}|{PASSWORD}"))
        .with_env_var("ADDRESS", "127.0.0.1")
        .with_env_var("MIN_PORT", PASV_PORTS.start().to_string())
        .with_env_var("MAX_PORT", PASV_PORTS.end().to_string())
        .with_env_var("TLS_CERT", "/etc/ssl/courier/cert.pem")
        .with_env_var("TLS_KEY", "/etc/ssl/courier/key.pem")
        .with_copy_to("/etc/ssl/courier/cert.pem", cert.pem().into_bytes())
        .with_copy_to("/etc/ssl/courier/key.pem", key.serialize_pem().into_bytes());
    for port in PASV_PORTS {
        image = image.with_mapped_port(port, port.tcp());
    }
    let container: ContainerAsync<GenericImage> = image.start().await.unwrap();
    let port = container.get_host_port_ipv4(21.tcp()).await.unwrap();
    let host = HostPort::new("127.0.0.1", port);
    let trust = Arc::new(TlsTrust::with_system_verifier(
        Arc::new(MemoryCertTrustStore::new()),
        None,
    ));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut conn = loop {
        match login(&host, &trust).await {
            Ok(conn) => break conn,
            Err(err) if tokio::time::Instant::now() < deadline => {
                eprintln!("waiting for vsftpd: {err}");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(err) => panic!("vsftpd never accepted the FTPS login: {err}"),
        }
    };
    assert!(conn.tls_session().is_some());
    assert!(conn.data_tls().is_some(), "PROT P");

    let settings = Settings::default();
    let mut data = DataSession::new(DataOptions::new(
        &settings,
        Some(FtpTransferMode::Passive),
        host.clone(),
        &NetOpts::from_settings(&settings),
        Duration::from_secs(10),
    ));
    let bytes: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let cancel = CancellationToken::new();
    // Several uploads in a row: each must resume (tickets are kept).
    for n in 0..3 {
        let DataOpen::Stream(mut w) = data
            .open(&mut conn, &format!("STOR f{n}.bin"), None, &cancel)
            .await
            .unwrap()
        else {
            panic!("STOR refused")
        };
        let flags = w.flags();
        w.write_all(&bytes).await.unwrap();
        w.shutdown().await.unwrap();
        drop(w);
        finish(&mut conn, &flags, true).await.unwrap();
    }
    for n in 0..3 {
        let DataOpen::Stream(mut r) = data
            .open(&mut conn, &format!("RETR f{n}.bin"), None, &cancel)
            .await
            .unwrap()
        else {
            panic!("RETR refused")
        };
        let flags = r.flags();
        let mut got = Vec::new();
        r.read_to_end(&mut got).await.unwrap();
        drop(r);
        finish(&mut conn, &flags, false).await.unwrap();
        assert_eq!(got, bytes);
    }
    conn.quit().await;
}
