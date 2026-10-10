//! `FtpBackend` (T14) against vsftpd in Docker (`delfer/alpine-ftp-server`):
//! the core backend conformance suite over plain FTP (MLSD and LIST) and
//! explicit FTPS (vsftpd forces TLS and requires session reuse). The
//! passive port range is mapped 1:1 to the host with `ADDRESS=127.0.0.1`.
//!
//! `COURIER_E2E=1 cargo test -p courier-ftp-e2e --test ftp_backend -- --ignored`

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{sync::Arc, time::Duration};

use courier_ftp_core::{
    backend::{Backend, ConnectInfo, conformance},
    events::{self, CoreEvent, PromptKind, PromptResponse, SessionId, TrustDecision},
    model::{FtpEncryption, LogonType, Protocol, ServerAddress},
    settings::Settings,
    trust::MemoryCertTrustStore,
};
use courier_ftp_e2e::require_docker;
use courier_ftp_proto_ftp::{backend::FtpBackendFactory, tls::TlsTrust};
use secrecy::SecretString;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt, core::IntoContainerPort, runners::AsyncRunner,
};
use tokio_util::sync::CancellationToken;

const USER: &str = "courier";
const PASSWORD: &str = "e2e-password";

async fn start(
    ports: std::ops::RangeInclusive<u16>,
    tls: bool,
) -> (ContainerAsync<GenericImage>, u16) {
    let mut image = GenericImage::new("delfer/alpine-ftp-server", "latest")
        .with_exposed_port(21.tcp())
        .with_env_var("USERS", format!("{USER}|{PASSWORD}"))
        .with_env_var("ADDRESS", "127.0.0.1")
        .with_env_var("MIN_PORT", ports.start().to_string())
        .with_env_var("MAX_PORT", ports.end().to_string());
    if tls {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        image = image
            .with_env_var("TLS_CERT", "/etc/ssl/courier/cert.pem")
            .with_env_var("TLS_KEY", "/etc/ssl/courier/key.pem")
            .with_copy_to("/etc/ssl/courier/cert.pem", cert.pem().into_bytes())
            .with_copy_to("/etc/ssl/courier/key.pem", key.serialize_pem().into_bytes());
    }
    for port in ports {
        image = image.with_mapped_port(port, port.tcp());
    }
    let container = image.start().await.unwrap();
    let port = container.get_host_port_ipv4(21.tcp()).await.unwrap();
    (container, port)
}

async fn run(port: u16, protocol: Protocol, use_mlsd: bool) {
    let (tx, mut rx) = events::channel(4);
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
    settings.ftp.use_mlsd = use_mlsd;
    let trust = Arc::new(TlsTrust::with_system_verifier(
        Arc::new(MemoryCertTrustStore::new()),
        None,
    ));
    let factory = FtpBackendFactory::new(settings, trust);
    let mut address = ServerAddress::new(protocol, "127.0.0.1");
    address.port = port;
    let mut info = ConnectInfo::new(
        address,
        LogonType::Normal {
            user: USER.into(),
            password: SecretString::from(PASSWORD.to_owned()),
        },
    );
    if protocol == Protocol::Ftp {
        info.encryption = Some(FtpEncryption::PlainOnly);
    }
    let mut b = factory.create_ftp(&info, SessionId::next(), tx);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        match b.connect(CancellationToken::new()).await {
            Ok(()) => break,
            Err(err) if tokio::time::Instant::now() < deadline => {
                eprintln!("waiting for vsftpd: {err}");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(err) => panic!("vsftpd never accepted the login: {err}"),
        }
    }
    let home = b.home_dir().await.unwrap();
    let base = home
        .join(if use_mlsd { "conf-mlsd" } else { "conf-list" })
        .unwrap();
    b.mkdir(&base).await.unwrap();
    conformance::run(&mut b, &base).await;
    b.rmdir(&base).await.unwrap();
    b.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "needs Docker: COURIER_E2E=1 cargo test -p courier-ftp-e2e -- --ignored"]
async fn vsftpd_backend_conformance_plain() {
    require_docker!();
    let (_c, port) = start(31130..=31134, false).await;
    run(port, Protocol::Ftp, true).await;
    run(port, Protocol::Ftp, false).await;
}

#[tokio::test]
#[ignore = "needs Docker: COURIER_E2E=1 cargo test -p courier-ftp-e2e -- --ignored"]
async fn vsftpd_backend_conformance_ftps() {
    require_docker!();
    let (_c, port) = start(31140..=31144, true).await;
    run(port, Protocol::FtpsExplicit, true).await;
}
